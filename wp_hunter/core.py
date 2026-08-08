import json
import os
import re
import shutil
import stat
import sys
import tempfile
import threading
import time
from contextlib import contextmanager, suppress
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

from wp_hunter.semgrep_adapter import (
    validate_semgrep_config as _validate_semgrep_config,
)
from wp_hunter.state import (
    MANIFEST_FILE,
    REVIEWED_FILE,
)

API_URL = "https://api.wordpress.org/plugins/info/1.2/"
REQUESTS_MIN_VERSION = (2, 34, 2)
ROOT_MARKER_FILE = ".wp-hunter-root"
ROOT_MARKER_CONTENT = "wp-hunter-root:v1\n"
LEGACY_ROOT_MARKER_CONTENT = "wp-hunter root\n"

# Resource and input safety limits.  Plugin archives are untrusted input: the
# limits prevent a malformed or malicious response from exhausting disk/RAM.
MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
MAX_API_WORKERS = 10
MAX_PATCHSTACK_PAGES = 2_000
MAX_DOWNLOAD_REDIRECTS = 5
SAFE_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
ALLOWED_DOWNLOAD_HOST_SUFFIX = ".wordpress.org"

# Make stdout/stderr tolerant of Unicode (progress bars, box chars, ✓) even when
# the console codepage is cp1252 or output is piped to a file.
for _stream in (sys.stdout, sys.stderr):
    with suppress(AttributeError, ValueError):
        _stream.reconfigure(encoding="utf-8", errors="replace")

DOWNLOAD_MAX_RETRIES = 3
API_RATE_LIMIT_SEC = 0.3
API_PARALLEL_WORKERS = 5


def _safe_triage_workers(requested: int, mem_mb_per_worker: int) -> tuple[int, str]:
    requested = max(1, requested)
    mem_mb_per_worker = max(1, mem_mb_per_worker)
    try:
        import psutil

        available_mb = psutil.virtual_memory().available // (1024 * 1024)
    except ImportError:
        # psutil not installed — fall back to a conservative hard cap
        available_mb = 8 * 1024  # assume 8 GB free
    burst_factor = 2.5
    safe_limit = max(1, int((available_mb * 0.60) / (mem_mb_per_worker * burst_factor)))
    if requested > safe_limit:
        warn = (
            f"[MEM] Reducing triage workers {requested}→{safe_limit} "
            f"(~{available_mb // 1024:.0f} GB free, "
            f"{mem_mb_per_worker} MB soft-limit × {burst_factor:.0f}× burst × {requested} workers "
            f"would need ~{int(mem_mb_per_worker * burst_factor * requested // 1024)} GB)"
        )
        return safe_limit, warn
    return requested, ""


def _display_text(value: object, limit: int | None = None) -> str:
    text = re.sub(r"[\x00-\x1f\x7f\x80-\x9f]", " ", str(value or ""))
    return text[:limit] if limit is not None else text


def _remote_nonnegative_int(
    value: object,
    default: int = 0,
    maximum: int = 1_000_000_000,
) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    if parsed < 0:
        return default
    return min(parsed, maximum)


def _numeric_version_tuple(value: object, width: int = 3) -> tuple[int, ...]:
    parts = [int(part) for part in re.findall(r"\d+", str(value))[:width]]
    return tuple((parts + [0] * width)[:width])


def _is_safe_slug(slug: object) -> bool:
    return isinstance(slug, str) and bool(SAFE_SLUG_RE.fullmatch(slug))


def _is_safe_filename(filename: object) -> bool:
    return isinstance(filename, str) and bool(SAFE_FILENAME_RE.fullmatch(filename))


def _safe_download_url(download_url: object) -> bool:
    if not isinstance(download_url, str):
        return False
    try:
        parsed = urlsplit(download_url)
        host = (parsed.hostname or "").lower().rstrip(".")
        has_credentials = parsed.username is not None or parsed.password is not None
        has_port = parsed.port is not None
    except ValueError:
        return False
    if parsed.scheme.lower() != "https" or not host:
        return False
    if has_credentials or has_port:
        return False
    return host == "wordpress.org" or host.endswith(ALLOWED_DOWNLOAD_HOST_SUFFIX)


def _safe_download_filename(download_url: str, slug: str) -> str:
    try:
        candidate = Path((urlsplit(download_url).path or "").replace("\\", "/")).name
    except ValueError:
        candidate = ""
    if (
        not _is_safe_filename(candidate)
        or candidate in {".", ".."}
        or not candidate.lower().endswith(".zip")
    ):
        return f"{slug}.zip"
    return candidate


def _protected_output_roots() -> set[Path]:
    protected = {
        Path(__file__).resolve().parent,
        Path.home().resolve(),
        Path.cwd().resolve(),
    }
    anchor = Path(Path.cwd().anchor or os.sep).resolve()
    protected.add(anchor)
    return protected


def _validate_root_location(root: Path) -> None:
    if root.parent == root or root in _protected_output_roots():
        raise ValueError(f"Refusing protected output/triage root: {root}")


def _root_marker_state(marker: Path) -> str:
    if marker.is_symlink():
        return "invalid"
    try:
        if not marker.exists():
            return "missing"
        if not marker.is_file():
            return "invalid"
        if marker.stat().st_size > 128:
            return "invalid"
        content = marker.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return "invalid"
    if content in {ROOT_MARKER_CONTENT, LEGACY_ROOT_MARKER_CONTENT}:
        return "valid"
    return "invalid"


def _create_root_marker(marker: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(marker, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fd = -1
            fh.write(ROOT_MARKER_CONTENT)
            fh.flush()
            os.fsync(fh.fileno())
    finally:
        if fd >= 0:
            os.close(fd)


def _directory_needs_adoption(output_dir: str | Path) -> bool:
    raw = Path(output_dir).expanduser()
    if raw.is_symlink() or not raw.exists() or not raw.is_dir():
        return False
    marker_state = _root_marker_state(raw / ROOT_MARKER_FILE)
    if marker_state == "valid":
        return False
    try:
        return any(raw.iterdir())
    except OSError:
        return True


def _looks_like_legacy_hunter_root(output_dir: str | Path) -> bool:
    root = Path(output_dir).expanduser()
    if root.is_symlink() or not root.is_dir():
        return False

    normalized_name = root.name.lower().replace("-", "_")
    if normalized_name.startswith(("wp_plugins_", "wp_hunter_")):
        return True

    root_artifacts = {
        MANIFEST_FILE,
        "vuln_report.txt",
        "vuln_plugins.txt",
        "triage_results.json",
        "deleted_plugins.txt",
        REVIEWED_FILE,
    }
    try:
        for index, child in enumerate(root.iterdir()):
            # A bounded inspection keeps this prompt fast even for broad folders.
            if index >= 100:
                break
            if child.is_symlink():
                continue
            if child.is_file() and (
                child.name in root_artifacts
                or re.fullmatch(r"plugins_.+\.(?:json|csv)", child.name)
            ):
                return True
            if child.is_dir():
                metadata = child / "plugin_info.json"
                if metadata.is_file() and not metadata.is_symlink():
                    return True
    except OSError:
        return False
    return False


def _ensure_hunter_root(
    output_dir: str | Path,
    adopt_existing: bool = False,
) -> Path:
    raw = Path(output_dir).expanduser()
    if raw.is_symlink():
        raise ValueError(f"Refusing symlink output root: {raw}")
    if raw.exists() and not raw.is_dir():
        raise ValueError(f"Output root is not a directory: {raw}")
    raw.mkdir(parents=True, exist_ok=True)
    root = raw.resolve()
    _validate_root_location(root)
    marker = root / ROOT_MARKER_FILE
    marker_state = _root_marker_state(marker)
    if marker_state == "invalid":
        raise ValueError(f"Root marker is invalid or unsafe: {marker}")
    if marker_state == "valid":
        return root

    try:
        nonempty = any(root.iterdir())
    except OSError as exc:
        raise ValueError(f"Cannot inspect output root: {root}") from exc
    if nonempty and not adopt_existing:
        raise ValueError(
            f"Refusing to claim non-empty unmarked directory: {root}. "
            "Use --adopt-output-root and confirm the exact path."
        )
    if marker_state == "missing":
        try:
            _create_root_marker(marker)
        except FileExistsError as exc:
            if _root_marker_state(marker) != "valid":
                raise ValueError(f"Root marker changed while validating: {marker}") from exc
    return root


def _validate_triage_root(output_dir: str | Path, allow_unmarked: bool = False) -> Path:
    raw = Path(output_dir).expanduser()
    if raw.is_symlink() or not raw.is_dir():
        raise ValueError(f"Triage root must be a real directory: {raw}")
    root = raw.resolve()
    _validate_root_location(root)
    marker = root / ROOT_MARKER_FILE
    marker_state = _root_marker_state(marker)
    if marker_state == "invalid":
        raise ValueError(f"Triage root marker is invalid or unsafe: {marker}")
    if not allow_unmarked and marker_state != "valid":
        raise ValueError(
            f"Refusing unmarked triage root: {root}. "
            f"Use --allow-unmarked-triage only after verifying the directory."
        )
    return root


def _is_direct_child(root: Path, candidate: str | Path) -> bool:
    path = Path(candidate)
    if path.is_symlink():
        return False
    try:
        return path.resolve().parent == root.resolve()
    except OSError:
        return False


def _directory_identity(path: str | Path) -> tuple[int, int] | None:
    try:
        details = os.stat(path, follow_symlinks=False)
    except OSError:
        return None
    if not stat.S_ISDIR(details.st_mode):
        return None
    return details.st_dev, details.st_ino


def _csv_safe(value: object) -> object:
    if value is None:
        return ""
    text = str(value)
    index = 0
    while index < len(text) and (text[index].isspace() or ord(text[index]) <= 0x20):
        index += 1
    if text[index : index + 1] in {"=", "+", "-", "@"}:
        return "'" + text
    return text


@contextmanager
def _atomic_text_file(path: str | Path, newline: str | None = None):
    destination = Path(path)
    parent = destination.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError(f"Unsafe output parent: {parent}")
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=str(parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline=newline) as fh:
            fd = -1
            yield fh
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temporary, destination)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)


def _atomic_write_json(path: str | Path, value: object) -> None:
    with _atomic_text_file(path) as fh:
        json.dump(value, fh, indent=2, ensure_ascii=False)


def _atomic_write_text(path: str | Path, value: str) -> None:
    with _atomic_text_file(path) as fh:
        fh.write(value)


SEMGREP_RULES_DEFAULT = Path(__file__).parent / "resources" / "wordpress-triage.yml"


class ProgressBar:
    _WIDTH = 30

    def __init__(self, total: int, label: str = "Progress"):
        self._total = max(total, 1)
        self._label = label
        self._done = 0
        self._lock = threading.Lock()
        self._is_tty = sys.stdout.isatty()
        self._start_time = 0.0
        self._last_render_width = 0
        # Use Unicode blocks only if the output encoding can represent them;
        # otherwise fall back to ASCII (avoids UnicodeEncodeError on cp1252).
        enc = (getattr(sys.stdout, "encoding", "") or "").lower()
        self._fill, self._empty = ("#", "-")
        if "utf" in enc:
            try:
                "█░".encode(sys.stdout.encoding)
                self._fill, self._empty = ("█", "░")
            except (UnicodeEncodeError, LookupError, TypeError):
                pass

    def start(self) -> None:
        self._start_time = time.monotonic()
        if self._is_tty:
            sys.stdout.write("\n")
            sys.stdout.flush()

    def update(self, message: str = "") -> None:
        with self._lock:
            self._done += 1
            done = self._done
        self._render(done, message)

    def finish(self, message: str = "Done") -> None:
        self._render(self._total, message, final=True)
        if self._is_tty:
            sys.stdout.write("\n")
        sys.stdout.flush()

    def _render(self, done: int, message: str, final: bool = False) -> None:
        pct = done / self._total
        filled = int(self._WIDTH * pct)
        bar = self._fill * filled + self._empty * (self._WIDTH - filled)
        elapsed = time.monotonic() - self._start_time
        eta = ""
        if done > 0 and not final and elapsed > 0:
            remaining = (elapsed / done) * (self._total - done)
            m, s = divmod(int(remaining), 60)
            eta = f" ETA {m:02d}:{s:02d}"
        try:
            cols = os.get_terminal_size().columns if self._is_tty else 120
        except OSError:
            cols = 120
        line = f"  {self._label} [{bar}] {done}/{self._total} ({pct:.0%}){eta}"
        if message:
            avail = max(10, cols - len(line) - 3)
            line += f"  {_display_text(message, avail)}"
        if self._is_tty:
            padding = " " * max(0, self._last_render_width - len(line))
            sys.stdout.write(f"\r{line}{padding}")
            sys.stdout.flush()
            self._last_render_width = len(line)
        else:
            milestone = final or (done % max(1, self._total // 20) == 0)
            if milestone:
                print(line, flush=True)


class _AuthorParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self._parts: list[str] = []

    def handle_data(self, data: str) -> None:
        stripped = data.strip()
        if stripped:
            self._parts.append(stripped)

    def result(self) -> str:
        return " ".join(self._parts)


def extract_author_text(html: str) -> str:
    if not html:
        return ""
    if "<" not in html:
        return html.strip()
    parser = _AuthorParser()
    parser.feed(html)
    return parser.result() or html.strip()


VALID_TIERS = [
    10,
    20,
    30,
    40,
    50,
    60,
    70,
    80,
    90,
    100,
    200,
    300,
    400,
    500,
    600,
    700,
    800,
    900,
    1000,
    2000,
    3000,
    4000,
    5000,
    6000,
    7000,
    8000,
    9000,
    10000,
    20000,
    30000,
    40000,
    50000,
    60000,
    70000,
    80000,
    90000,
    100000,
    200000,
    300000,
    400000,
    500000,
    600000,
    700000,
    800000,
    900000,
    1000000,
    2000000,
    3000000,
    4000000,
    5000000,
    10000000,
]


def format_installs(n: int) -> str:
    if n >= 1_000_000:
        return f"{n // 1_000_000}M+"
    if n >= 1_000:
        return f"{n // 1_000}K+"
    return str(n)


def parse_installs_input(value: str) -> int:
    value = value.strip().upper().removesuffix("+").replace(",", "")
    match = re.fullmatch(r"(\d+(?:\.\d+)?)([KM]?)", value)
    if not match:
        raise ValueError("invalid install count")
    number = float(match.group(1))
    multiplier = {"": 1, "K": 1_000, "M": 1_000_000}[match.group(2)]
    if number > 1_000_000_000 / multiplier:
        raise ValueError("install count is unreasonably large")
    result = int(number * multiplier)
    return result


def _date_cli_value(value: str) -> str:
    for date_format in ("%Y-%m-%d", "%Y-%m", "%Y"):
        try:
            datetime.strptime(value, date_format)
            return value
        except ValueError:
            continue
    raise ValueError("must use YYYY-MM-DD, YYYY-MM, or YYYY")


def cmd_check(
    semgrep_path: str | None = None,
    semgrep_rules: str | None = None,
    language: str = "en",
) -> None:
    indonesian = language == "id"

    def local(english: str, indonesia: str) -> str:
        return indonesia if indonesian else english

    print(f"\n  === {local('Setup Check', 'Pemeriksaan Konfigurasi')} ===\n")
    all_ok = True
    pv = sys.version_info
    ok = pv >= (3, 10)
    print(
        f"  {'✓' if ok else '✗'} Python {pv.major}.{pv.minor}.{pv.micro}",
        "" if ok else local("  (need 3.10+)", "  (memerlukan 3.10+)"),
    )
    if not ok:
        all_ok = False
    try:
        import requests as _r

        requests_ok = _numeric_version_tuple(_r.__version__) >= REQUESTS_MIN_VERSION
        minimum = ".".join(str(part) for part in REQUESTS_MIN_VERSION)
        print(
            f"  {'✓' if requests_ok else '✗'} requests {_r.__version__}",
            ""
            if requests_ok
            else local(f"  (need >={minimum},<3)", f"  (memerlukan >={minimum},<3)"),
        )
        if not requests_ok:
            all_ok = False
    except ImportError:
        print(
            local(
                "  ✗ requests — not installed. Fix: pip install requests",
                "  ✗ requests — belum terpasang. Perbaiki: pip install requests",
            )
        )
        all_ok = False
    sg = _find_semgrep(semgrep_path)
    rules = Path(semgrep_rules).expanduser() if semgrep_rules else SEMGREP_RULES_DEFAULT
    if sg and rules.is_file() and not rules.is_symlink():
        print(f"  ✓ Semgrep    →  {sg}")
        valid_rules, diagnostic = _validate_semgrep_config(sg, rules)
        if valid_rules:
            print(f"  ✓ {local('Rules', 'Aturan'):<10} →  {rules} ({local('validated', 'valid')})")
        else:
            print(f"  ✗ {local('Rules invalid', 'Aturan tidak valid')} → {diagnostic}")
            all_ok = False
    else:
        if not sg:
            print(
                local(
                    "  ⚠ Semgrep — not found (optional — only needed for triage)",
                    "  ⚠ Semgrep — tidak ditemukan (opsional — hanya diperlukan untuk triage)",
                )
            )
            print(_indent_lines(_semgrep_install_hint(), "    "))
        if rules.is_symlink() or not rules.is_file():
            print(
                local(
                    f"  ⚠ Semgrep rules — missing or unsafe: {rules}",
                    f"  ⚠ Aturan Semgrep — hilang atau tidak aman: {rules}",
                )
            )
    try:
        usage = shutil.disk_usage(Path(__file__).parent)
        free_gb = usage.free / 1_073_741_824
        ok_disk = free_gb >= 5
        print(
            f"  {'✓' if ok_disk else '!'} {local('Disk free', 'Disk kosong')}: {free_gb:.1f} GB",
            ""
            if ok_disk
            else local(
                "  (< 5 GB — large batches may fail)",
                "  (< 5 GB — batch besar mungkin gagal)",
            ),
        )
    except OSError:
        pass

    print()
    if all_ok:
        print(
            local(
                "  All checks passed. You're ready to hunt.\n",
                "  Semua pemeriksaan lulus. WP Hunter siap digunakan.\n",
            )
        )
    else:
        print(
            local(
                "  Fix critical issues above before running.\n",
                "  Perbaiki masalah kritis di atas sebelum menjalankan WP Hunter.\n",
            )
        )
        sys.exit(1)


def _ask_choice(prompt: str, choices: list[str], default: str) -> str:
    labels = " / ".join(f"[{choice}]" if choice == default else choice for choice in choices)
    while True:
        try:
            value = input(f"  {prompt} ({labels}): ").strip().lower() or default
        except (EOFError, KeyboardInterrupt):
            return default
        if value in choices:
            return value


_WPORG_RATE_LOCK = threading.Lock()
_WPORG_LAST_REQUEST_AT = 0.0


def _find_semgrep(explicit: str | None) -> str | None:
    if explicit:
        if (
            os.path.isfile(explicit)
            and not os.path.islink(explicit)
            and os.access(explicit, os.X_OK)
        ):
            return explicit
        print(f"  [ERROR] Semgrep not found at: {explicit}", file=sys.stderr)
        return None
    return shutil.which("semgrep") or shutil.which("semgrep.exe")


def _semgrep_install_hint() -> str:
    return (
        "Install Semgrep locally with one of:\n"
        "python -m pip install semgrep\n"
        "pipx install semgrep\n"
        "Then verify with: semgrep --version"
    )


def _indent_lines(value: str, prefix: str) -> str:
    return "\n".join(prefix + line for line in value.splitlines())


def _semgrep_or_exit(
    explicit: str | None,
    rules_path: str | None = None,
    validate_rules: bool = True,
) -> tuple[str, Path]:
    semgrep = _find_semgrep(explicit)
    if not semgrep:
        hint = _indent_lines(_semgrep_install_hint(), "  ")
        print(f"\n  [ERROR] Semgrep was not found.\n{hint}\n", file=sys.stderr)
        sys.exit(1)
    rules = Path(rules_path).expanduser() if rules_path else SEMGREP_RULES_DEFAULT
    if rules.is_symlink() or not rules.is_file():
        print(f"\n  [ERROR] Semgrep rules not found: {rules}\n", file=sys.stderr)
        sys.exit(1)
    resolved_rules = rules.resolve()
    if validate_rules:
        valid, diagnostic = _validate_semgrep_config(semgrep, resolved_rules)
        if not valid:
            print("\n  [ERROR] Semgrep rule validation failed.", file=sys.stderr)
            if diagnostic:
                print(f"  {diagnostic}", file=sys.stderr)
            print("  No plugin scan or deletion was started.\n", file=sys.stderr)
            sys.exit(1)
    return semgrep, resolved_rules
