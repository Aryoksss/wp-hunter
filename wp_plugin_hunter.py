"""
WordPress Plugin Hunter - Auto Download by Active Installs
===========================================================
Script untuk bug bounty researcher yang ingin download plugin WordPress
berdasarkan jumlah active installations.

Quick start (no flags needed — interactive mode):
  python wp_plugin_hunter.py

One-liner download + triage preview:
  python wp_plugin_hunter.py --installs 10K --auto-triage

Common workflows:
  # Download only
  python wp_plugin_hunter.py --installs 10K --pages 50

  # Preview what would be downloaded (no actual download)
  python wp_plugin_hunter.py --installs 10K --preview

  # Download + auto triage (preview deletions first)
  python wp_plugin_hunter.py --installs 10K --auto-triage --triage-dry-run

  # Download + auto triage (commit deletions explicitly)
  python wp_plugin_hunter.py --installs 10K --auto-triage --confirm-delete

  # Triage only an existing folder
  python wp_plugin_hunter.py --triage-only "Z:\\Pentest\\Plugin\\wp_plugins_10K"

  # Search + download
  python wp_plugin_hunter.py --installs 5K --search "file manager"

  # Check setup (dependencies + Semgrep status)
  python wp_plugin_hunter.py --check

All flags:
  --installs VALUE        Active installs tier: 1K, 5K, 10K, 100K, 1M …
  --min-installs VALUE    Minimum active installs (threshold mode)
  --patchstack            Collect from the Patchstack VDP directory
  --min-boost N           Patchstack minimum bounty boost percentage
  --include-themes        Include Patchstack themes
  --browse MODE           Sort: popular | new | updated | top-rated (default: popular)
  --pages N               Max API pages (100 plugins/page, default: 50)
  --api-workers N         Parallel API fetchers (default: 5)
  --search KEYWORD        Search by keyword (overrides --browse)
  --tag TAG               Filter by tag
  --output DIR            Output folder (default: ./wp_plugins_<tier>/)
  --adopt-output-root     Explicitly adopt a non-empty legacy output folder
  --workers N             Download threads (default: 3, max: 5)
  --limit N               Cap number of plugins downloaded
  --preview               Show what would download without downloading
  --no-download           Skip download entirely (collect + export list only)
  --update-check          Re-download if a newer version exists on wp.org
  --force                 Re-download even if file already exists on disk
  --reset-manifest        Forget all downloaded plugins (re-downloads on next run)
  --auto-triage           After download: scan and preview no-candidate folders
  --confirm-delete        Allow live deletion after triage confirmation
  --triage-only DIR       Triage an existing folder without downloading anything
  --triage-workers N      Parallel scan workers (default: 4)
  --triage-timeout N      Per-plugin scan timeout seconds (default: 120)
  --triage-dry-run        Triage: show what would be deleted, don't actually delete
  --keep-extracted        Keep extracted/ folders after triage (default: remove them)
  --semgrep PATH          Path to Semgrep executable (auto-detected if omitted)
  --semgrep-rules PATH    Path to Semgrep rule file (repository default)
  --check                 Verify setup (dependencies and Semgrep) then exit
  --quiet                 Suppress plugin list table, show only progress + summary
"""

import csv
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from contextlib import contextmanager
from datetime import datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

# Guard: give a helpful error if requests is not installed.
try:
    import requests
except ImportError:
    print(
        "\n  [ERROR] The 'requests' library is not installed.\n"
        "  Fix: pip install requests\n",
        file=sys.stderr,
    )
    sys.exit(1)

API_URL = "https://api.wordpress.org/plugins/info/1.2/"
REQUESTS_MIN_VERSION = (2, 34, 2)
MANIFEST_FILE = "downloaded_slugs.json"
ROOT_MARKER_FILE = ".wp-hunter-root"
ROOT_MARKER_CONTENT = "wp-hunter-root:v1\n"
LEGACY_ROOT_MARKER_CONTENT = "wp-hunter root\n"

# Resource and input safety limits.  Plugin archives are untrusted input: the
# limits prevent a malformed or malicious response from exhausting disk/RAM.
MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 50_000
MAX_ARCHIVE_MEMBER_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_UNPACKED_BYTES = 1 * 1024 * 1024 * 1024
MAX_API_WORKERS = 10
MAX_PATCHSTACK_PAGES = 2_000
MAX_DOWNLOAD_REDIRECTS = 5
MAX_SEMGREP_JSON_BYTES = 64 * 1024 * 1024
SAFE_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
ALLOWED_DOWNLOAD_HOST_SUFFIX = ".wordpress.org"
SOURCE_SUFFIXES = {".php", ".js", ".jsx", ".mjs", ".cjs"}

# Make stdout/stderr tolerant of Unicode (progress bars, box chars, ✓) even when
# the console codepage is cp1252 or output is piped to a file.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

DOWNLOAD_MAX_RETRIES = 3
API_RATE_LIMIT_SEC = 0.3
API_PARALLEL_WORKERS = 5

# ---------------------------------------------------------------------------
# Safe triage worker calculation
# ---------------------------------------------------------------------------

def _safe_triage_workers(requested: int, mem_mb_per_worker: int) -> tuple[int, str]:
    """
    Return (safe_workers, warning_msg).
    Caps requested workers so total scan RAM stays within ~60% of available RAM.
    Each Semgrep process can burst to 2-3× mem_mb_per_worker on mega-plugins.
    We use a 2.5× burst factor as a conservative estimate.
    """
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
    """Make remote metadata safe to print to a terminal."""
    text = re.sub(r"[\x00-\x1f\x7f\x80-\x9f]", " ", str(value or ""))
    return text[:limit] if limit is not None else text


def _remote_nonnegative_int(
    value: object, default: int = 0, maximum: int = 1_000_000_000,
) -> int:
    """Safely coerce an untrusted API integer into a bounded value."""
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
    """Accept only one simple directory component for a plugin slug."""
    return isinstance(slug, str) and bool(SAFE_SLUG_RE.fullmatch(slug))


def _is_safe_filename(filename: object) -> bool:
    return isinstance(filename, str) and bool(SAFE_FILENAME_RE.fullmatch(filename))


def _safe_download_url(download_url: object) -> bool:
    """Only follow HTTPS WordPress.org download URLs from API metadata."""
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
    """Derive a harmless local filename; never use a URL query as a path."""
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
    """Locations that must never become broad hunter/deletion roots."""
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
    """Return missing/valid/invalid without following a marker symlink."""
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
    """Whether an existing non-empty directory lacks a valid hunter marker."""
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
    """Recognize common output left by hunter versions without a root marker."""
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
    output_dir: str | Path, adopt_existing: bool = False,
) -> Path:
    """Create a hunter root; never claim a non-empty directory implicitly."""
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
        except FileExistsError:
            if _root_marker_state(marker) != "valid":
                raise ValueError(f"Root marker changed while validating: {marker}")
    return root


def _validate_triage_root(output_dir: str | Path, allow_unmarked: bool = False) -> Path:
    """Validate a triage root before any source scan or deletion."""
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
    """Ensure a deletion target is a real direct child of the triage root."""
    path = Path(candidate)
    if path.is_symlink():
        return False
    try:
        return path.resolve().parent == root.resolve()
    except OSError:
        return False


def _directory_identity(path: str | Path) -> tuple[int, int] | None:
    """Return a stable identity used to detect directory replacement races."""
    try:
        details = os.stat(path, follow_symlinks=False)
    except OSError:
        return None
    if not stat.S_ISDIR(details.st_mode):
        return None
    return details.st_dev, details.st_ino


def _csv_safe(value: object) -> object:
    """Prevent spreadsheet formula injection in generated CSV reports."""
    if value is None:
        return ""
    text = str(value)
    index = 0
    while index < len(text) and (text[index].isspace() or ord(text[index]) <= 0x20):
        index += 1
    if text[index:index + 1] in {"=", "+", "-", "@"}:
        return "'" + text
    return text


@contextmanager
def _atomic_text_file(path: str | Path, newline: str | None = None):
    """Write a text file through a random sibling and atomically replace it."""
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

SEMGREP_RULES_DEFAULT = Path(__file__).parent / "rules" / "wordpress-triage.yml"


# ---------------------------------------------------------------------------
# Progress bar (TTY-aware, no external deps)
# ---------------------------------------------------------------------------

class ProgressBar:
    """Thread-safe progress bar. Overwrites line on TTY; prints milestones elsewhere."""

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


# ---------------------------------------------------------------------------
# HTML author extractor
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

class DownloadManifest:
    """Atomic-write manifest so a crash during a long run can't corrupt it."""

    def __init__(self, output_dir: Path):
        self._path = Path(output_dir) / MANIFEST_FILE
        self._lock = threading.Lock()
        self._data: dict = self._load()

    def _load(self) -> dict:
        if self._path.is_symlink():
            raise ValueError(f"Refusing symlink manifest: {self._path}")
        if self._path.exists():
            try:
                with open(self._path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                    return data if isinstance(data, dict) else {}
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_json(self._path, self._data)

    def is_downloaded(self, slug: str) -> bool:
        with self._lock:
            entry = self._data.get(slug)
            if not isinstance(entry, dict):
                return False
            filename = entry.get("filename", "")
        if not _is_safe_slug(slug) or not _is_safe_filename(filename):
            return False
        plugin_dir = self._path.parent / slug
        if plugin_dir.is_symlink():
            return False
        local_file = plugin_dir / filename
        try:
            if (
                local_file.is_symlink()
                or not local_file.is_file()
                or local_file.stat().st_size <= 0
                or not zipfile.is_zipfile(local_file)
            ):
                return False
            expected_sha256 = str(entry.get("sha256", "") or "").lower()
            return not expected_sha256 or _sha256_of_file(local_file).lower() == expected_sha256
        except OSError:
            return False

    def get_version(self, slug: str) -> str:
        with self._lock:
            entry = self._data.get(slug, {})
            return entry.get("version", "") if isinstance(entry, dict) else ""

    def get_filename(self, slug: str) -> str:
        with self._lock:
            entry = self._data.get(slug, {})
            filename = entry.get("filename", "") if isinstance(entry, dict) else ""
        return filename if _is_safe_filename(filename) else ""

    def mark_downloaded(
        self, slug: str, filename: str, size_kb: int, version: str, sha256: str = ""
    ) -> None:
        if not _is_safe_slug(slug) or not _is_safe_filename(filename):
            raise ValueError("Refusing to write an unsafe manifest entry")
        with self._lock:
            self._data[slug] = {
                "filename": filename,
                "size_kb": size_kb,
                "version": version,
                "sha256": sha256,
                "downloaded_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self._save()

    def remove(self, slug: str) -> None:
        with self._lock:
            if slug in self._data:
                del self._data[slug]
                self._save()

    def count(self) -> int:
        with self._lock:
            return len(self._data)


# ---------------------------------------------------------------------------
# Valid install tiers
# ---------------------------------------------------------------------------

VALID_TIERS = [
    10, 20, 30, 40, 50, 60, 70, 80, 90,
    100, 200, 300, 400, 500, 600, 700, 800, 900,
    1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000,
    10000, 20000, 30000, 40000, 50000, 60000, 70000, 80000, 90000,
    100000, 200000, 300000, 400000, 500000, 600000, 700000, 800000, 900000,
    1000000, 2000000, 3000000, 4000000, 5000000, 10000000,
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


def _positive_cli_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError("must be an integer") from exc
    if parsed < 1:
        raise ValueError("must be >= 1")
    return parsed


def _nonnegative_cli_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError("must be an integer") from exc
    if parsed < 0:
        raise ValueError("must be >= 0")
    return parsed


def _date_cli_value(value: str) -> str:
    for date_format in ("%Y-%m-%d", "%Y-%m", "%Y"):
        try:
            datetime.strptime(value, date_format)
            return value
        except ValueError:
            continue
    raise ValueError("must use YYYY-MM-DD, YYYY-MM, or YYYY")


# ---------------------------------------------------------------------------
# Setup check
# ---------------------------------------------------------------------------

def cmd_check(semgrep_path: str | None = None, semgrep_rules: str | None = None) -> None:
    """Verify prerequisites and print a setup status report."""
    print("\n  === Setup Check ===\n")
    all_ok = True

    # 1. Python version
    pv = sys.version_info
    ok = pv >= (3, 10)
    print(f"  {'✓' if ok else '✗'} Python {pv.major}.{pv.minor}.{pv.micro}",
          "" if ok else "  (need 3.10+)")
    if not ok:
        all_ok = False

    # 2. requests
    try:
        import requests as _r
        requests_ok = _numeric_version_tuple(_r.__version__) >= REQUESTS_MIN_VERSION
        minimum = ".".join(str(part) for part in REQUESTS_MIN_VERSION)
        print(
            f"  {'✓' if requests_ok else '✗'} requests {_r.__version__}",
            "" if requests_ok else f"  (need >={minimum},<3)",
        )
        if not requests_ok:
            all_ok = False
    except ImportError:
        print("  ✗ requests — not installed. Fix: pip install requests")
        all_ok = False

    # 3. Semgrep (optional — only needed for triage)
    sg = _find_semgrep(semgrep_path)
    rules = Path(semgrep_rules).expanduser() if semgrep_rules else SEMGREP_RULES_DEFAULT
    if sg and rules.is_file() and not rules.is_symlink():
        print(f"  ✓ Semgrep    →  {sg}")
        valid_rules, diagnostic = _validate_semgrep_config(sg, rules)
        if valid_rules:
            print(f"  ✓ Rules      →  {rules} (validated)")
        else:
            print(f"  ✗ Rules invalid → {diagnostic}")
            all_ok = False
    else:
        if not sg:
            print("  ⚠ Semgrep — not found (optional — only needed for triage)")
            print(_indent_lines(_semgrep_install_hint(), "    "))
        if rules.is_symlink() or not rules.is_file():
            print(f"  ⚠ Semgrep rules — missing or unsafe: {rules}")

    # 4. Disk space (warn if < 5 GB free on the script's drive)
    try:
        usage = shutil.disk_usage(Path(__file__).parent)
        free_gb = usage.free / 1_073_741_824
        ok_disk = free_gb >= 5
        print(f"  {'✓' if ok_disk else '!'} Disk free: {free_gb:.1f} GB",
              "" if ok_disk else "  (< 5 GB — large batches may fail)")
    except OSError:
        pass

    print()
    if all_ok:
        print("  All checks passed. You're ready to hunt.\n")
    else:
        print("  Fix critical issues above before running.\n")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Interactive wizard (runs when no flags are supplied)
# ---------------------------------------------------------------------------

# ANSI colour helpers — auto-disabled when stdout is not a TTY.
def _ansi(code: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"

def _bold(t):    return _ansi("1",     t)
def _green(t):   return _ansi("1;32",  t)
def _yellow(t):  return _ansi("1;33",  t)
def _cyan(t):    return _ansi("1;36",  t)
def _dim(t):     return _ansi("2",     t)
def _red(t):     return _ansi("1;31",  t)


def _hr(char: str = "─", width: int = 56) -> str:
    return "  " + char * width


def _ask(prompt: str, default: str = "") -> str:
    suffix = _dim(f" [{default}]") if default else ""
    try:
        ans = input(f"  {prompt}{suffix}: ").strip()
    except (KeyboardInterrupt, EOFError):
        print(f"\n  {_yellow('Cancelled.')}")
        sys.exit(0)
    return ans or default


def _menu_keys_supported() -> bool:
    """Raw arrow-key menus are safe only on a real interactive terminal."""
    return bool(sys.stdin.isatty() and sys.stdout.isatty())


def _read_menu_key() -> str:
    """Read one navigation key on Windows or POSIX without requiring a dependency."""
    if os.name == "nt":
        try:
            import msvcrt

            key = msvcrt.getwch()
            if key in ("\x00", "\xe0"):
                extended = msvcrt.getwch()
                return {"H": "up", "P": "down", "K": "left", "M": "right"}.get(
                    extended, "unknown"
                )
            if key in ("\r", "\n"):
                return "enter"
            if key in ("\x03", "\x1b"):
                return "cancel"
            return "unknown"
        except (ImportError, OSError):
            return "fallback"

    import select
    import termios
    import tty

    try:
        fd = sys.stdin.fileno()
        previous = termios.tcgetattr(fd)
    except (AttributeError, OSError, termios.error):
        return "fallback"
    try:
        tty.setraw(fd)
        key = os.read(fd, 1)
        if not key:
            return "fallback"
        if key in (b"\r", b"\n"):
            return "enter"
        if key == b"\x03":
            return "cancel"
        if key == b"\x1b":
            # A bare Escape is a cancellation. Arrow sequences arrive as
            # ESC + two bytes; short waits prevent Escape from blocking.
            if not select.select([fd], [], [], 0.08)[0]:
                return "cancel"
            sequence = os.read(fd, 1)
            if select.select([fd], [], [], 0.08)[0]:
                sequence += os.read(fd, 1)
            return {
                b"[A": "up", b"OA": "up",
                b"[B": "down", b"OB": "down",
                b"[D": "left", b"OD": "left",
                b"[C": "right", b"OC": "right",
            }.get(sequence, "unknown")
        return "unknown"
    except (OSError, termios.error):
        return "fallback"
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, previous)
        except (OSError, termios.error):
            pass


# Aliases accepted as canonical choice values.
_CHOICE_ALIASES: dict[str, str] = {
    "y": "yes", "n": "no", "d": "dry-run", "dr": "dry-run",
    "p": "patchstack", "w": "wp.org",
}


def _ask_choice(prompt: str, choices: list[str], default: str) -> str:
    """Prompt with arrow-key navigation, with a line-input fallback."""
    if _menu_keys_supported():
        selected = next(
            (index for index, choice in enumerate(choices) if choice.lower() == default.lower()),
            0,
        )
        previous_length = 0
        while True:
            options = "  ".join(
                f"[{choice}]" if index == selected else f" {choice} "
                for index, choice in enumerate(choices)
            )
            line = f"  {prompt}: {options}  (↑/↓ Enter)"
            padding = " " * max(0, previous_length - len(line))
            sys.stdout.write("\r" + line + padding)
            sys.stdout.flush()
            previous_length = len(line)

            key = _read_menu_key()
            if key in ("up", "left"):
                selected = (selected - 1) % len(choices)
            elif key in ("down", "right"):
                selected = (selected + 1) % len(choices)
            elif key == "enter":
                sys.stdout.write("\n")
                sys.stdout.flush()
                return choices[selected].lower()
            elif key == "cancel":
                sys.stdout.write("\n")
                sys.stdout.flush()
                print(f"  {_yellow('Cancelled.')}")
                sys.exit(0)
            elif key == "fallback":
                sys.stdout.write("\n")
                sys.stdout.flush()
                break

    parts = []
    for c in choices:
        if c == default:
            parts.append(_bold(f"[{c}]"))
        else:
            parts.append(c)
    opts = " / ".join(parts)
    while True:
        raw = _ask(f"{prompt} ({opts})", default).lower()
        resolved = _CHOICE_ALIASES.get(raw, raw)
        if raw.isdigit() and 1 <= int(raw) <= len(choices):
            resolved = choices[int(raw) - 1].lower()
        if resolved in [c.lower() for c in choices]:
            return resolved
        matches = [c for c in choices if c.lower().startswith(raw)]
        if len(matches) == 1:
            return matches[0].lower()
        print(f"    {_yellow('→')} Enter one of: {', '.join(choices)}")


def _print_header():
    print()
    print(_hr("═"))
    print(f"  {_bold(_cyan('WordPress Plugin Hunter'))}"
          f"  {_dim('— Vulnerability Research Toolkit')}")
    print(_hr("═"))
    print()


def _print_section(title: str):
    print()
    print(f"  {_bold(title)}")
    print(_hr())


def _check_status_line() -> str:
    """One-liner setup status for the header."""
    semgrep = _find_semgrep(None)
    sg_ok = _green("Semgrep ✓") if semgrep else _yellow("Semgrep ⚠ (optional)")
    return f"  {_dim('Setup:')}  python {sys.version.split()[0]}  |  {sg_ok}"


def _clean_path_input(value: str) -> str:
    """Accept paths pasted from Explorer/terminals, including quoted paths."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1].strip()
    return os.path.expanduser(value)


def _confirm_exact_path(path: str | Path, action: str) -> bool:
    """Require typing a resolved path before a high-impact root operation."""
    resolved = Path(path).expanduser().resolve()
    print(f"\n  {_red('Safety confirmation required.')}")
    print(f"  Action : {action}")
    print(f"  Folder : {resolved}")
    try:
        entered = input("  Type the exact folder path to continue: ").strip()
    except (KeyboardInterrupt, EOFError):
        return False
    return entered == str(resolved)


def _requires_exact_adoption_confirmation(
    output_dir: str | Path,
    adopt_existing: bool,
    interactive_approval: bool,
) -> bool:
    """CLI adoption is typed; the guided wizard already captured a menu choice."""
    return (
        adopt_existing
        and not interactive_approval
        and _directory_needs_adoption(output_dir)
    )


def _suggest_output_subfolder(parent: str | Path, preferred_output: str | Path) -> Path:
    """Choose an unused or already-safe child for a general-purpose folder."""
    parent_path = Path(parent).expanduser().resolve()
    preferred_name = Path(preferred_output).expanduser().name
    if (
        not _is_safe_filename(preferred_name)
        or preferred_name in {".", ".."}
        or preferred_name == parent_path.name
    ):
        preferred_name = "wp-hunter-output"

    for number in range(1, 10_001):
        suffix = "" if number == 1 else f"-{number}"
        candidate = parent_path / f"{preferred_name}{suffix}"
        if candidate.is_symlink():
            continue
        if not candidate.exists():
            return candidate
        if candidate.is_dir():
            marker_state = _root_marker_state(candidate / ROOT_MARKER_FILE)
            if marker_state == "valid":
                return candidate
            try:
                if marker_state == "missing" and not any(candidate.iterdir()):
                    return candidate
            except OSError:
                pass
    raise ValueError("Could not find an available output subfolder")


def _interactive_output_folder(default_output: str) -> tuple[str, bool]:
    """Select a safe output root without turning a declined choice into an exit."""
    while True:
        selected = _clean_path_input(_ask("Save plugins to", default_output))
        raw = Path(selected).expanduser()

        if raw.is_symlink():
            print(f"    {_yellow('→')} Symlink folders cannot be used. Choose another folder.")
            continue
        if raw.exists() and not raw.is_dir():
            print(f"    {_yellow('→')} That path is a file. Choose a folder instead.")
            continue

        resolved = raw.resolve()
        direct_error: str | None = None
        try:
            _validate_root_location(resolved)
        except ValueError as exc:
            direct_error = str(exc)

        if not raw.exists():
            if direct_error:
                print(f"    {_yellow('→')} {direct_error}")
                continue
            print(f"  {_green('✓')} A new output folder will be created: {resolved}")
            return str(raw), False

        marker_state = _root_marker_state(raw / ROOT_MARKER_FILE)
        if marker_state == "valid" and not direct_error:
            print(f"  {_green('✓')} Existing WP Hunter folder recognized: {resolved}")
            return str(raw), False

        try:
            is_empty = not any(raw.iterdir())
        except OSError as exc:
            print(f"    {_yellow('→')} Cannot inspect this folder: {exc}")
            continue
        if is_empty and marker_state == "missing" and not direct_error:
            print(f"  {_green('✓')} Empty folder ready: {resolved}")
            return str(raw), False

        try:
            suggested = _suggest_output_subfolder(resolved, default_output)
        except ValueError as exc:
            print(f"    {_yellow('→')} {exc}")
            continue

        print()
        print(f"  {_bold('Folder selected:')} {resolved}")
        if direct_error:
            print("  This location is too broad to use directly as a Hunter output root.")
        elif marker_state == "invalid":
            print("  Its WP Hunter marker is invalid, so the folder cannot be reused directly.")
        elif _looks_like_legacy_hunter_root(raw):
            print(f"  {_green('✓')} This looks like output from an older WP Hunter version.")
            print("  Reusing it registers the folder once; existing files remain in place.")
        else:
            print("  This folder already contains files that may be unrelated to WP Hunter.")
            print("  A dedicated subfolder is the safest choice.")

        print()
        can_reuse = not direct_error and marker_state == "missing"
        looks_legacy = can_reuse and _looks_like_legacy_hunter_root(raw)
        if can_reuse:
            print("  use-folder      Register this folder once and continue")
        print(f"  new-subfolder   Use {suggested}")
        print("  choose-another  Enter a different location")
        print("  cancel          Return without starting")
        print()

        choices = ["new-subfolder", "choose-another", "cancel"]
        default = "new-subfolder"
        if can_reuse:
            choices.insert(0, "use-folder")
            if looks_legacy:
                default = "use-folder"
        action = _ask_choice("Output folder action", choices, default)

        if action == "use-folder":
            print(f"  {_green('✓')} Folder will be registered and reused: {resolved}")
            return str(raw), True
        if action == "new-subfolder":
            print(f"  {_green('✓')} Output will be kept in: {suggested}")
            return str(suggested), False
        if action == "choose-another":
            print()
            continue
        print(f"\n  {_yellow('Cancelled.')}")
        sys.exit(0)


def _interactive_semgrep_preflight(
    allow_download_only: bool,
    rules_path: str | Path = SEMGREP_RULES_DEFAULT,
) -> tuple[bool, str | None, str]:
    """Resolve optional triage dependencies before the final Start prompt."""
    selected_executable: str | None = None
    detected_executable: str | None = None

    while not detected_executable:
        detected_executable = _find_semgrep(None)
        if detected_executable:
            break

        print()
        print(f"  {_yellow('Semgrep is not installed or is not available in PATH.')}")
        print("  Semgrep is needed only for triage; plugin downloads work without it.")
        print(_indent_lines(_semgrep_install_hint(), "    "))
        print()
        if allow_download_only:
            print("  download-only  Continue now and run triage later")
        print("  enter-path     Use an existing Semgrep executable")
        print("  cancel         Return without starting")
        print()

        choices = ["enter-path", "cancel"]
        default = "cancel"
        if allow_download_only:
            choices.insert(0, "download-only")
            default = "download-only"
        action = _ask_choice("Semgrep action", choices, default)
        if action == "download-only":
            print(f"  {_green('✓')} Continuing in download-only mode. Triage was disabled.")
            return False, None, str(Path(rules_path).expanduser())
        if action == "cancel":
            print(f"\n  {_yellow('Cancelled.')}")
            sys.exit(0)

        custom = _clean_path_input(_ask("Semgrep executable path"))
        if not custom:
            print(f"    {_yellow('→')} A path is required.")
            continue
        detected_executable = _find_semgrep(custom)
        if detected_executable:
            selected_executable = detected_executable
        else:
            print(f"    {_yellow('→')} That executable could not be used. Try another path.")

    print(f"  {_green('✓')} Semgrep found: {detected_executable}")

    selected_rules = Path(rules_path).expanduser()
    while True:
        rules_problem = ""
        if selected_rules.is_symlink() or not selected_rules.is_file():
            rules_problem = f"Semgrep rules were not found: {selected_rules}"
        else:
            valid, diagnostic = _validate_semgrep_config(
                detected_executable,
                selected_rules,
            )
            if valid:
                resolved_rules = selected_rules.resolve()
                print(f"  {_green('✓')} Rules validated: {resolved_rules}")
                return True, selected_executable, str(resolved_rules)
            rules_problem = f"Semgrep rules are invalid: {diagnostic}"

        print()
        print(f"  {_yellow(rules_problem)}")
        print("  No plugin scanning or deletion has started.")
        if allow_download_only:
            print("  download-only  Continue now and configure triage later")
        print("  enter-path     Select another Semgrep rule file")
        print("  cancel         Return without starting")
        print()

        choices = ["enter-path", "cancel"]
        default = "cancel"
        if allow_download_only:
            choices.insert(0, "download-only")
            default = "download-only"
        action = _ask_choice("Rule file action", choices, default)
        if action == "download-only":
            print(f"  {_green('✓')} Continuing in download-only mode. Triage was disabled.")
            return False, None, str(selected_rules)
        if action == "cancel":
            print(f"\n  {_yellow('Cancelled.')}")
            sys.exit(0)

        custom_rules = _clean_path_input(_ask("Semgrep rule file path"))
        if not custom_rules:
            print(f"    {_yellow('→')} A rule file path is required.")
            continue
        selected_rules = Path(custom_rules).expanduser()


def _interactive_triage_wizard() -> "argparse.Namespace":
    """Collect triage settings without requiring command-line flags."""
    import argparse

    _print_section("Scan an existing plugin folder")
    while True:
        folder = _clean_path_input(_ask("Plugin folder to scan"))
        if not folder:
            print(f"    {_yellow('→')} A folder path is required.")
            continue
        folder_path = Path(folder)
        if not folder_path.is_dir():
            print(f"    {_yellow('→')} Folder not found: {folder}")
            continue
        break

    marker_state = _root_marker_state(folder_path / ROOT_MARKER_FILE)
    if marker_state == "invalid":
        print(
            f"\n  {_red('This folder has an invalid WP Hunter registration file.')}",
            file=sys.stderr,
        )
        sys.exit(2)
    marker_present = marker_state == "valid"
    allow_unmarked = False
    if not marker_present:
        print(f"\n  {_yellow('This folder was not created by the hunter.')}")
        print("  It may still be a valid legacy folder, but verify the path carefully.")
        allow_unmarked = (
            _ask_choice("Continue with this unmarked folder?", ["no", "yes"], "no") == "yes"
        )
        if not allow_unmarked:
            print(f"  {_yellow('Cancelled.')} Use the main menu to choose another action.\n")
            sys.exit(0)

    _enabled, semgrep_path, rules_path = _interactive_semgrep_preflight(
        allow_download_only=False,
    )

    years_str = _ask("Skip plugins older than N years (0 = scan all)", "2")
    try:
        min_updated_years = max(0, int(years_str))
    except ValueError:
        min_updated_years = 2

    mode = _ask_choice(
        "Triage mode",
        ["dry-run", "live"],
        "dry-run",
    )
    keep_extracted = _ask_choice("Keep extracted source folders?", ["no", "yes"], "no") == "yes"

    _print_section("Ready to scan")
    print(f"  Folder     :  {folder_path}")
    print(f"  Date filter:  {min_updated_years} year(s)" if min_updated_years else "  Date filter:  none")
    mode_label = (
        "live — no-candidate folders may be deleted"
        if mode == "live" else "dry-run — no plugin folders deleted"
    )
    print(f"  Mode       :  {mode_label}")
    print(f"  Extracted  :  {'keep' if keep_extracted else 'remove after scan'}")
    print(f"  Semgrep    :  {semgrep_path or 'auto-detect from PATH'}")
    print(f"  Rules      :  {rules_path}")
    print()
    if _ask_choice("Start scan?", ["yes", "no"], "yes") != "yes":
        print(f"\n  {_yellow('Cancelled.')}")
        sys.exit(0)

    return argparse.Namespace(
        check=False,
        triage_only=str(folder_path),
        allow_unmarked_triage=allow_unmarked,
        semgrep=semgrep_path,
        semgrep_rules=rules_path,
        triage_workers=2,
        triage_timeout=120,
        triage_mem_mb=1024,
        triage_dry_run=mode == "dry-run",
        confirm_delete=mode == "live",
        keep_extracted=keep_extracted,
        min_updated_years=min_updated_years,
        semgrep_prevalidated=True,
    )


def interactive_wizard() -> "argparse.Namespace":
    """Main interactive menu and download wizard for flag-free use."""
    import argparse

    _print_header()
    print(_check_status_line())
    print(_dim("\n  Use ↑/↓ to choose and Enter to confirm. Ctrl-C to cancel.\n"))
    print("  1. Download plugins from wp.org or Patchstack")
    print("  2. Scan an existing plugin folder")
    print("  3. Check setup and dependencies")
    print("  4. Exit\n")

    action = _ask_choice(
        "What would you like to do?",
        ["download", "triage", "check", "exit"],
        "download",
    )
    if action == "triage":
        return _interactive_triage_wizard()
    if action == "check":
        return argparse.Namespace(
            check=True, semgrep=None, semgrep_rules=str(SEMGREP_RULES_DEFAULT)
        )
    if action == "exit":
        print(f"\n  {_yellow('Goodbye.')}")
        sys.exit(0)

    print(_dim("\n  Download wizard selected. Press Enter to accept [defaults].\n"))

    # ── Step 1: Source ────────────────────────────────────────────────────
    _print_section("Step 1 of 5  –  Choose plugin source")
    print(f"  {_bold('wp.org')}       Download by exact active-install tier  {_dim('(e.g. the 10K tier)')}")
    print(
        f"  {_bold('patchstack')}   Download from Patchstack VDP directory  "
        f"{_dim('(vendor opt-in, bounty bonuses)')}"
    )
    print()

    source = _ask_choice("Source", ["wp.org", "patchstack"], "wp.org")
    use_patchstack = (source == "patchstack")

    # ── Step 2: Filter ───────────────────────────────────────────────────
    _print_section("Step 2 of 5  –  Filter")

    if use_patchstack:
        print(f"  {_dim('Boost tiers on Patchstack: 0 / 25 / 35 / 100%')}")
        boost_str = _ask("Minimum boost % (0 = all VDP programs)", "0")
        try:
            min_boost = max(0, int(boost_str))
        except ValueError:
            min_boost = 0

        years_str = _ask("Only plugins updated in last N years (0 = all)", "2")
        try:
            min_updated_years = max(0, int(years_str))
        except ValueError:
            min_updated_years = 2

        limit_str = _ask("Max plugins to download (0 = all)", "0")
        try:
            limit = max(0, int(limit_str)) or None
        except ValueError:
            limit = None

        include_themes = (
            _ask_choice("Include themes too?", ["no", "yes"], "no") == "yes"
        )

        # Patchstack defaults
        tier_str = "0"
        installs = 0
        interactive_installs_mode = "exact"
        pages = 1
        default_out = "./wp_plugins_patchstack"
    else:
        interactive_installs_mode = _ask_choice(
            "Install filter", ["exact-tier", "minimum"], "exact-tier"
        )
        print(f"  {_dim('Tiers: 500  1K  2K  3K  5K  10K  50K  100K  1M')}")
        prompt = (
            "Minimum active installs"
            if interactive_installs_mode == "minimum"
            else "Exact active-install tier"
        )
        tier_str = _ask(prompt, "10K")
        try:
            installs = parse_installs_input(tier_str)
        except ValueError:
            print(f"  {_yellow('Invalid — using 10K')}")
            tier_str, installs = "10K", 10000
        if installs < 1:
            print(f"  {_yellow('Invalid — using 10K')}")
            tier_str, installs = "10K", 10000
        if interactive_installs_mode == "exact-tier" and installs not in VALID_TIERS:
            installs = min(VALID_TIERS, key=lambda x: abs(x - installs))
            tier_str = format_installs(installs).replace("+", "")
            print(f"  {_dim(f'→ Snapped to nearest tier: {format_installs(installs)}')}")

        pages_str = _ask("Max API pages to scan  (100 plugins/page)", "50")
        try:
            pages = max(1, int(pages_str))
        except ValueError:
            pages = 50

        years_str = _ask("Only plugins updated in last N years (0 = all)", "2")
        try:
            min_updated_years = max(0, int(years_str))
        except ValueError:
            min_updated_years = 2

        limit_str = _ask("Max plugins to download (0 = all)", "0")
        try:
            limit = max(0, int(limit_str)) or None
        except ValueError:
            limit = None

        min_boost = 0
        include_themes = False
        folder_prefix = "min" if interactive_installs_mode == "minimum" else ""
        default_out = (
            f"./wp_plugins_{folder_prefix}{format_installs(installs).replace('+', '')}"
        )

    # ── Step 3: Output folder ────────────────────────────────────────────
    _print_section("Step 3 of 5  –  Output folder")
    output_dir, adopt_output_root = _interactive_output_folder(default_out)

    # ── Step 4: Download options ─────────────────────────────────────────
    _print_section("Step 4 of 5  –  Download")
    do_download = _ask_choice("Download plugins?", ["yes", "no"], "yes") == "yes"

    # ── Step 5: Auto-triage ──────────────────────────────────────────────
    do_triage = False
    triage_dry = False
    semgrep_path: str | None = None
    semgrep_rules = str(SEMGREP_RULES_DEFAULT)
    if do_download:
        _print_section("Step 5 of 5  –  Auto-triage")
        print(f"  After downloading, scan each plugin with Semgrep and delete")
        print(f"  folders where {_bold('no Semgrep candidate matched')}.")
        print()
        print(f"  {_bold('yes')}       scan + delete no-candidate folders  {_dim('(saves disk, irreversible)')}")
        print(f"  {_bold('dry-run')}   scan + report candidates; no plugin folders deleted")
        print(f"  {_bold('no')}        skip triage, download only  {_dim('(default — triage later anytime)')}")
        print()

        triage_ans = _ask_choice("Auto-triage", ["yes", "dry-run", "no"], "no")
        if triage_ans in ("yes", "dry-run"):
            do_triage = True
            triage_dry = triage_ans == "dry-run"
            do_triage, semgrep_path, semgrep_rules = _interactive_semgrep_preflight(
                allow_download_only=True,
                rules_path=semgrep_rules,
            )
            if not do_triage:
                triage_dry = False
    else:
        print()
        print(f"  {_dim('Step 5 of 5  –  Auto-triage  (skipped, no download)')}")

    # ── Summary ──────────────────────────────────────────────────────────
    print()
    print(_hr("─"))
    print(f"  {_bold('Ready to run')}")
    print(_hr("─"))

    if use_patchstack:
        patchstack_desc = "all VDP programs" if min_boost == 0 else f"boost >= {min_boost}%"
        print(f"  Source     :  Patchstack VDP  ({patchstack_desc})")
        print(f"  Assets     :  {'plugins + themes' if include_themes else 'plugins only'}")
    else:
        est = pages * 100
        install_label = (
            f">= {format_installs(installs).replace('+', '')}"
            if interactive_installs_mode == "minimum"
            else f"exact tier {format_installs(installs)}"
        )
        print(f"  Source     :  wp.org  {_bold(install_label)}  (~{est} plugins scanned)")

    if min_updated_years:
        print(f"  Date filter:  updated in last {min_updated_years} year(s)  (older plugins skipped)")
    else:
        print(f"  Date filter:  none  (all plugins included)")

    if limit:
        print(f"  Limit      :  {limit} plugins max")

    print(f"  Output     :  {output_dir}")
    if adopt_output_root:
        print("  Folder     :  register existing WP Hunter output once")
    print(f"  Download   :  {'yes' if do_download else 'no'}")

    if do_triage:
        if triage_dry:
            print(f"  Triage     :  {_yellow('dry-run')}  (no plugin-folder deletions)")
        else:
            print(f"  Triage     :  {_green('yes')}  (no-candidate folders will be deleted)")
        print(f"  Semgrep    :  {semgrep_path or 'auto-detect from PATH'}")
        print(f"  Rules      :  {semgrep_rules}")
    else:
        print(f"  Triage     :  no")

    print(_hr("─"))
    print()

    confirm = _ask_choice("Start?", ["yes", "no"], "yes")
    if confirm != "yes":
        print(f"\n  {_yellow('Cancelled.')}")
        sys.exit(0)
    print()

    # ── Build Namespace ──────────────────────────────────────────────────
    ns = argparse.Namespace(
        installs=(
            tier_str
            if not use_patchstack and interactive_installs_mode == "exact-tier"
            else None
        ),
        min_installs=(
            tier_str
            if not use_patchstack and interactive_installs_mode == "minimum"
            else None
        ),
        patchstack=use_patchstack,
        min_boost=min_boost,
        include_themes=include_themes,
        browse="popular",
        pages=pages,
        api_workers=API_PARALLEL_WORKERS,
        search=None,
        tag=None,
        output=output_dir,
        no_download=not do_download,
        workers=3,
        max_download_mb=MAX_DOWNLOAD_BYTES // (1024 * 1024),
        limit=limit,
        preview=False,
        force=False,
        update_check=False,
        dry_run_count=False,
        reset_manifest=False,
        auto_triage=do_triage,
        triage_only=None,
        triage_workers=2,
        triage_timeout=120,
        triage_mem_mb=1024,
        triage_dry_run=triage_dry,
        keep_extracted=False,
        allow_unmarked_triage=False,
        confirm_delete=do_triage and not triage_dry,
        semgrep=semgrep_path,
        semgrep_rules=semgrep_rules,
        quiet=False,
        min_updated_years=min_updated_years,
        since=None,
        no_global_dedup=False,
        adopt_output_root=adopt_output_root,
        interactive_approval=True,
        semgrep_prevalidated=do_triage,
        check=False,
    )
    return ns


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

_WPORG_RATE_LOCK = threading.Lock()
_WPORG_LAST_REQUEST_AT = 0.0


def _wporg_get(url: str, **kwargs):
    """Start WordPress.org API requests at a process-wide polite interval."""
    global _WPORG_LAST_REQUEST_AT
    with _WPORG_RATE_LOCK:
        now = time.monotonic()
        wait = API_RATE_LIMIT_SEC - (now - _WPORG_LAST_REQUEST_AT)
        if wait > 0:
            time.sleep(wait)
        _WPORG_LAST_REQUEST_AT = time.monotonic()
    return requests.get(url, **kwargs)

def _build_api_params(
    browse: str, page: int, per_page: int = 100,
    search: str | None = None, tag: str | None = None,
) -> dict:
    params = {
        "action": "query_plugins",
        "request[browse]": browse,
        "request[per_page]": str(per_page),
        "request[page]": str(page),
        "request[fields][active_installs]": "true",
        "request[fields][last_updated]": "true",
        "request[fields][downloaded]": "true",
        "request[fields][tags]": "true",
        "request[fields][requires]": "true",
        "request[fields][requires_php]": "true",
        "request[fields][tested]": "true",
        "request[fields][md5]": "true",
    }
    if search:
        params.pop("request[browse]", None)
        params["request[search]"] = search
    if tag:
        params.pop("request[browse]", None)
        params["request[tag]"] = tag
    return params


def query_plugins_page(
    browse: str = "popular", page: int = 1, per_page: int = 100,
    search: str | None = None, tag: str | None = None, retries: int = 3,
) -> dict | None:
    params = _build_api_params(browse, page, per_page, search, tag)
    for attempt in range(1, retries + 1):
        try:
            resp = _wporg_get(API_URL, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            return data if isinstance(data, dict) else None
        except (requests.exceptions.RequestException, ValueError) as exc:
            if attempt < retries:
                wait = 2 ** attempt
                print(f"  [WARN] API page {page} attempt {attempt}/{retries} failed ({exc}). Retry in {wait}s …",
                      file=sys.stderr)
                time.sleep(wait)
            else:
                print(f"  [ERROR] API page {page} failed: {exc}", file=sys.stderr)
    return None


# ---------------------------------------------------------------------------
# Patchstack VDP source (https://patchstack.com/database/vdp)
# ---------------------------------------------------------------------------

PATCHSTACK_VDP_API = "https://vdp.patchstack.com/api/database/vdp"
WP_PLUGIN_INFO_API = "https://api.wordpress.org/plugins/info/1.2/"
WP_THEME_INFO_API = "https://api.wordpress.org/themes/info/1.2/"


def _fetch_wporg_asset_info(slug: str, asset_kind: str = "plugin") -> dict | None:
    """Fetch downloadable plugin/theme metadata from the matching wp.org API."""
    if not _is_safe_slug(slug):
        return None
    is_theme = asset_kind.lower() == "theme"
    params = {
        "action": "theme_information" if is_theme else "plugin_information",
        "request[slug]": slug,
        "request[fields][active_installs]": "true",
        "request[fields][last_updated]": "true",
        "request[fields][downloaded]": "true",
        "request[fields][md5]": "true",
    }
    try:
        endpoint = WP_THEME_INFO_API if is_theme else WP_PLUGIN_INFO_API
        resp = _wporg_get(endpoint, params=params, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        # wp.org returns {"error": "..."} for unknown/closed plugins
        if not isinstance(data, dict) or data.get("error") or not data.get("slug"):
            return None
        return data
    except (requests.exceptions.RequestException, ValueError):
        return None


def _fetch_wporg_plugin_info(slug: str) -> dict | None:
    return _fetch_wporg_asset_info(slug, "plugin")


def _fetch_wporg_theme_info(slug: str) -> dict | None:
    return _fetch_wporg_asset_info(slug, "theme")


def collect_patchstack_plugins(
    min_boost: int = 0,
    min_updated_years: int = 0,
    since: str | None = None,
    include_themes: bool = False,
    api_workers: int = API_PARALLEL_WORKERS,
    max_entries: int | None = None,
) -> list[dict]:
    """
    Collect plugins from the Patchstack VDP directory (vulnerability disclosure
    programs). These are vendor opt-in targets, often with a bounty boost % and
    max bounty amount.

    Steps:
      1. Page through the Patchstack VDP API (25/page) to get name/slug/boost/
         bounty/installs for every active program.
      2. Filter by kind (Plugin unless --include-themes), min boost %.
      3. Enrich each via wp.org plugin_information (download_link, version,
         last_updated) — needed to download and to apply the date filter.
      4. Drop entries not on wp.org (closed/commercial) or outside the date window.

    Date filter (mutually exclusive, since takes priority): since="YYYY-MM-DD"
    for an explicit cutoff, or min_updated_years=N for "last N years".
    """
    api_workers = max(1, min(api_workers, MAX_API_WORKERS))
    cutoff_dt = _resolve_cutoff_date(min_updated_years, since)

    print(f"\n{'='*60}")
    print("  Collecting from Patchstack VDP directory")
    print(f"  Source : {PATCHSTACK_VDP_API}")
    date_desc = f", updated since {cutoff_dt.date()}" if cutoff_dt else ""
    print(f"  Filter : kind={'plugin+theme' if include_themes else 'plugin only'}"
          + (f", boost>={min_boost}%" if min_boost else "")
          + date_desc)
    print(f"{'='*60}\n")

    # --- Step 1: page through the VDP listing ---
    entries: list[dict] = []
    seen: set[str] = set()

    first = _patchstack_page(1)
    if not first:
        print("  [ERROR] Could not reach Patchstack VDP API.", file=sys.stderr)
        return []

    # Featured entries (page 1 only) often carry the highest boosts.
    for item in (first.get("featured", {}) or {}).get("results", []):
        slug = item.get("slug", "")
        if _is_safe_slug(slug) and slug not in seen:
            seen.add(slug)
            entries.append(item)

    pag = (first.get("recentlyAdded", {}) or {}).get("pagination", {}) or {}
    last_page = max(
        1,
        _remote_nonnegative_int(
            pag.get("last_page", 1), default=1, maximum=MAX_PATCHSTACK_PAGES
        ),
    )
    for item in (first.get("recentlyAdded", {}) or {}).get("results", []):
        slug = item.get("slug", "")
        if _is_safe_slug(slug) and slug not in seen:
            seen.add(slug)
            entries.append(item)

    print(
        f"  VDP programs: {_display_text(first.get('total', '?'), 30)} total "
        f"({last_page} pages)"
    )
    bar = ProgressBar(total=last_page, label="VDP pages")
    bar.start()
    bar.update(message="page 1")

    for pg in range(2, last_page + 1):
        data = _patchstack_page(pg)
        if data:
            for item in (data.get("recentlyAdded", {}) or {}).get("results", []):
                slug = item.get("slug", "")
                if _is_safe_slug(slug) and slug not in seen:
                    seen.add(slug)
                    entries.append(item)
        bar.update(message=f"page {pg}")
        time.sleep(0.25)  # be polite to Patchstack
    bar.finish(f"{len(entries)} programs collected")

    # --- Step 2: filter kind + boost ---
    # Show the boost-tier breakdown so the threshold behaviour is transparent.
    # The Patchstack API only exposes a few discrete boost values (commonly
    # 0/25/35/100); the "+15%" shown on the website is a base bonus not present
    # in this field, so e.g. --min-boost 15 and --min-boost 25 behave the same.
    from collections import Counter as _Counter
    plugin_entries = [
        e for e in entries
        if include_themes or (e.get("kind") or "").lower() in ("", "plugin")
    ]
    boost_dist = _Counter(_remote_nonnegative_int(e.get("boost", 0)) for e in plugin_entries)
    tiers = ", ".join(f"{b}%={n}" for b, n in sorted(boost_dist.items()))
    print(f"\n  Boost tiers available (plugins): {tiers}")
    if min_boost:
        avail = sorted(b for b in boost_dist if b >= min_boost)
        if avail and avail[0] != min_boost:
            print(f"  Note: no entries at exactly {min_boost}% — selecting boost >= {avail[0]}% "
                  f"(nearest tier with data).")

    filtered = []
    for e in entries:
        kind = (e.get("kind") or "").lower()
        if kind not in ("", "plugin", "theme"):
            continue
        if not include_themes and kind == "theme":
            continue
        if min_boost and _remote_nonnegative_int(e.get("boost", 0)) < min_boost:
            continue
        filtered.append(e)

    if max_entries:
        filtered = filtered[:max_entries]

    print(f"\n  After filter: {len(filtered)} programs → enriching via wp.org …\n")

    # --- Step 3: enrich via wp.org (parallel) ---
    results: list[dict] = []
    skipped_offwporg = 0
    skipped_outdated = 0

    bar2 = ProgressBar(total=len(filtered), label="Enriching ")
    bar2.start()

    def enrich(entry: dict) -> dict | None:
        slug = entry["slug"]
        asset_kind = (entry.get("kind") or "plugin").lower()
        info = (
            _fetch_wporg_theme_info(slug)
            if asset_kind == "theme"
            else _fetch_wporg_plugin_info(slug)
        )
        if not info:
            return {"_offwporg": True, "slug": slug}
        last_updated = info.get("last_updated", "") or ""
        rec = _parse_plugin_record(info)
        # attach Patchstack bounty metadata
        rec["patchstack_boost"] = entry.get("boost", 0)
        rec["patchstack_max_bounty"] = entry.get("maxBounty", "")
        rec["patchstack_vendor"] = entry.get("vendor_contact", "")
        rec["last_updated"] = last_updated
        rec["asset_kind"] = asset_kind
        return rec

    with ThreadPoolExecutor(max_workers=api_workers) as ex:
        futs = {ex.submit(enrich, e): e for e in filtered}
        for fut in as_completed(futs):
            try:
                r = fut.result()
            except Exception as exc:
                r = None
                print(
                    f"  [WARN] Could not enrich {futs[fut].get('slug', '?')}: "
                    f"{_display_text(exc, 160)}",
                    file=sys.stderr,
                )
            bar2.update(message=futs[fut]["slug"])
            if not r:
                continue
            if r.get("_offwporg"):
                skipped_offwporg += 1
                continue
            if cutoff_dt:
                last_dt = _plugin_last_updated_dt(r.get("last_updated", "") or "")
                if last_dt and last_dt < cutoff_dt:
                    skipped_outdated += 1
                    continue
            results.append(r)
    bar2.finish()

    # Sort by boost desc, then installs desc — highest-value targets first.
    results.sort(
        key=lambda r: (
            -_remote_nonnegative_int(r.get("patchstack_boost", 0)),
            -_remote_nonnegative_int(r.get("active_installs", 0)),
        )
    )

    print(f"\n  Patchstack collection done:")
    print(f"    Downloadable on wp.org : {len(results)}")
    print(f"    Skipped (not on wp.org): {skipped_offwporg}  (commercial/closed)")
    if cutoff_dt:
        print(f"    Skipped (outdated)     : {skipped_outdated}")
    print()
    return results


def _patchstack_page(page: int, retries: int = 3) -> dict | None:
    params = {"page": str(page)}
    headers = {"Accept": "application/json", "User-Agent": "Mozilla/5.0"}
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(PATCHSTACK_VDP_API, params=params, headers=headers, timeout=25)
            resp.raise_for_status()
            data = resp.json()
            return data if isinstance(data, dict) else None
        except (requests.exceptions.RequestException, ValueError) as exc:
            if attempt < retries:
                time.sleep(2 ** attempt)
            else:
                print(f"  [WARN] Patchstack page {page} failed: {exc}", file=sys.stderr)
    return None


def _parse_plugin_record(plugin: dict) -> dict:
    return {
        "name": plugin.get("name", ""),
        "slug": plugin.get("slug", ""),
        "version": plugin.get("version", ""),
        "active_installs": _remote_nonnegative_int(plugin.get("active_installs", 0)),
        "downloaded": _remote_nonnegative_int(plugin.get("downloaded", 0)),
        "last_updated": plugin.get("last_updated", ""),
        "author": extract_author_text(plugin.get("author", "")),
        "requires": plugin.get("requires", ""),
        "requires_php": plugin.get("requires_php", ""),
        "tested": plugin.get("tested", ""),
        "download_link": plugin.get("download_link", ""),
        "md5": plugin.get("md5", ""),
        "tags": list(plugin["tags"].values())
                if isinstance(plugin.get("tags"), dict)
                else list(plugin.get("tags") or []),
        "homepage": plugin.get("homepage", ""),
    }


# ---------------------------------------------------------------------------
# Parallel API collection
# ---------------------------------------------------------------------------

def _resolve_cutoff_date(min_updated_years: int = 0, since: str | None = None) -> "datetime | None":
    """
    Resolve a single cutoff datetime from either an explicit --since DATE
    (takes priority, more precise) or a --min-updated-years N (relative).
    Returns None if no filter is active.
    """
    if since:
        for fmt in ("%Y-%m-%d", "%Y-%m", "%Y"):
            try:
                return datetime.strptime(since, fmt)
            except ValueError:
                continue
        print(f"  [WARN] Could not parse --since {since!r} (use YYYY-MM-DD) — ignoring date filter.",
              file=sys.stderr)
        return None
    if min_updated_years > 0:
        return datetime.now() - timedelta(days=round(365.2425 * min_updated_years))
    return None


def _plugin_last_updated_dt(last_updated: str) -> "datetime | None":
    """Parse wp.org's last_updated string ('2026-06-07 11:49am GMT') to a datetime."""
    if not last_updated:
        return None
    raw = last_updated.split(" GMT")[0].strip()
    for fmt in ("%Y-%m-%d %I:%M%p", "%Y-%m-%d"):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    # Fall back to just the year (covers malformed/partial strings)
    if len(raw) >= 4 and raw[:4].isdigit():
        try:
            return datetime(int(raw[:4]), 1, 1)
        except ValueError:
            pass
    return None


def collect_plugins(
    target_installs: int, browse: str = "popular", max_pages: int = 50,
    search: str | None = None, tag: str | None = None,
    api_workers: int = API_PARALLEL_WORKERS,
    min_updated_years: int = 0,
    since: str | None = None,
    installs_mode: str = "exact",
) -> list[dict]:
    """
    installs_mode:
      "exact" — active_installs must equal target_installs (wp.org tier semantics).
      "min"   — active_installs must be >= target_installs. Use this when combining
                --tag/--search with an installs threshold, since exact-match tiers
                rarely overlap with a niche tag (a tag might only have a handful
                of plugins, and few of those will have EXACTLY 1000 installs).

    Date filter (mutually exclusive, --since takes priority if both given):
      since             — explicit cutoff date "YYYY-MM-DD" (or "YYYY-MM"/"YYYY").
      min_updated_years — relative cutoff: last N years from today.
    """
    api_workers = max(1, min(api_workers, MAX_API_WORKERS))
    max_pages = max(1, max_pages)
    cutoff_dt = _resolve_cutoff_date(min_updated_years, since)
    is_min_mode = installs_mode == "min"
    can_early_exit = browse == "popular" and not search and not tag

    print(f"\n{'='*60}")
    print("  Collecting plugins from WordPress.org")
    installs_label = (
        f">= {format_installs(target_installs).replace('+', '')}"
        if is_min_mode else format_installs(target_installs)
    )
    print(f"  Installs: {installs_label}  |  Browse: {browse if not search else f'search:{search!r}'}"
          + (f"  |  Tag: {tag}" if tag else ""))
    print(f"  Max pages: {max_pages} (~{max_pages * 100} plugins)  |  API workers: {api_workers}")
    if cutoff_dt:
        print(f"  Date filter: only plugins updated since {cutoff_dt.date()}")
    print(f"{'='*60}\n")

    first = query_plugins_page(browse=browse, page=1, search=search, tag=tag)
    if not first or "plugins" not in first:
        print("  [ERROR] No response from WordPress.org API on page 1.", file=sys.stderr)
        return []

    info = first.get("info", {})
    total_pages = max(1, _remote_nonnegative_int(info.get("pages", 1), default=1))
    total_results = _remote_nonnegative_int(info.get("results", 0))
    actual_pages = min(max_pages, total_pages)

    print(f"  Directory total : {total_results:,} plugins ({total_pages} pages)")
    print(f"  Will fetch      : up to {actual_pages} pages using {api_workers} workers\n")

    pages_data: dict[int, list] = {1: first.get("plugins", [])}

    # Early exit is safe only for unfiltered popular browsing, where active
    # install buckets are descending. Other browse/search/tag modes are not
    # assumed to have that ordering.
    if can_early_exit:
        p1_max = max(
            (_remote_nonnegative_int(p.get("active_installs", 0)) for p in pages_data[1]),
            default=0,
        )
        if p1_max < target_installs:
            print(
                f"  [!] Page 1's highest install count ({p1_max:,}) is already below "
                f"target ({target_installs:,}).\n"
                f"  Try --browse popular or a lower --installs tier.",
                file=sys.stderr,
            )
            return []

    pages_to_fetch = list(range(2, actual_pages + 1))
    stop_at_page = actual_pages

    if pages_to_fetch:
        bar = ProgressBar(total=len(pages_to_fetch) + 1, label="Fetching pages")
        bar.start()
        bar.update(message="page 1 ✓")

        early_exit = threading.Event()
        lock = threading.Lock()

        def fetch_page(pg: int) -> tuple[int, list | None]:
            if early_exit.is_set():
                return pg, None
            data = query_plugins_page(browse=browse, page=pg, search=search, tag=tag)
            if data is None:
                return pg, None
            pl = data.get("plugins", [])
            if can_early_exit and pl:
                pg_max = max(
                    (_remote_nonnegative_int(p.get("active_installs", 0)) for p in pl),
                    default=0,
                )
                if pg_max < target_installs:
                    early_exit.set()
            return pg, pl

        with ThreadPoolExecutor(max_workers=api_workers) as executor:
            fut_map: dict[Future, int] = {
                executor.submit(fetch_page, pg): pg for pg in pages_to_fetch
            }
            for fut in as_completed(fut_map):
                try:
                    pg, result = fut.result()
                except Exception as exc:
                    pg, result = fut_map[fut], None
                    print(
                        f"  [WARN] API page {pg} worker failed: {_display_text(exc, 160)}",
                        file=sys.stderr,
                    )
                with lock:
                    if result is not None:
                        pages_data[pg] = result
                bar.update(message=f"page {pg} ✓")

        if early_exit.is_set():
            last_useful = max(
                (pg for pg, pl in pages_data.items()
                 if any(
                     _remote_nonnegative_int(p.get("active_installs", 0))
                     >= target_installs
                     for p in pl
                 )),
                default=1,
            )
            stop_at_page = last_useful

        bar.finish(f"{len(pages_data)} pages fetched")

    seen_slugs: set[str] = set()
    results: list[dict] = []
    for pg in sorted(pages_data.keys()):
        if pg > stop_at_page:
            break
        for plugin in pages_data.get(pg, []):
            installs = _remote_nonnegative_int(plugin.get("active_installs", 0))
            matches = (installs >= target_installs) if is_min_mode else (installs == target_installs)
            if not matches:
                continue
            slug = plugin.get("slug", "")
            if not _is_safe_slug(slug) or slug in seen_slugs:
                continue
            # Date filter: skip plugins updated before the cutoff date
            if cutoff_dt:
                last_dt = _plugin_last_updated_dt(plugin.get("last_updated", "") or "")
                if last_dt and last_dt < cutoff_dt:
                    continue
            seen_slugs.add(slug)
            results.append(_parse_plugin_record(plugin))

    print(f"\n  Found: {len(results)} plugins ({installs_label} installs)\n")
    return results


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

def version_is_newer(remote: str, local: str) -> bool:
    if not remote or not local:
        return False
    try:
        def to_tuple(v: str) -> tuple[int, ...]:
            return tuple(int(x) for x in re.split(r"[^0-9]+", v.lstrip("vV")) if x.isdigit())
        return to_tuple(remote) > to_tuple(local)
    except Exception:
        return remote != local


# ---------------------------------------------------------------------------
# Checksum
# ---------------------------------------------------------------------------

def _md5_of_file(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65_536), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65_536), b""):
            h.update(chunk)
    return h.hexdigest()


def _validate_download_archive(
    path: Path,
    max_bytes: int = MAX_DOWNLOAD_BYTES,
    expected_md5: str = "",
    expected_sha256: str = "",
) -> tuple[bool, str]:
    """Validate a cached/new archive before it is trusted or indexed."""
    try:
        if path.is_symlink() or not path.is_file():
            return False, "not a regular archive"
        size = path.stat().st_size
        if size <= 0:
            return False, "archive is empty"
        if size > max_bytes:
            return False, f"archive exceeds {max_bytes} byte limit"
        if not zipfile.is_zipfile(path):
            return False, "response is not a ZIP archive"
        with zipfile.ZipFile(path) as zf:
            _validate_zip_members(zf)
        if expected_md5 and _md5_of_file(path).lower() != expected_md5.lower():
            return False, "MD5 mismatch"
        if expected_sha256 and _sha256_of_file(path).lower() != expected_sha256.lower():
            return False, "SHA-256 mismatch"
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        return False, str(exc)
    return True, ""


def _open_safe_download(download_url: str):
    """Open a streaming response after validating every redirect destination."""
    current_url = download_url
    for redirect_count in range(MAX_DOWNLOAD_REDIRECTS + 1):
        if not _safe_download_url(current_url):
            raise ValueError("redirected to a non-WordPress HTTPS URL")
        response = requests.get(
            current_url,
            timeout=(15, 60),
            stream=True,
            allow_redirects=False,
        )
        status = int(getattr(response, "status_code", 200) or 200)
        if status not in {301, 302, 303, 307, 308}:
            return response
        location = response.headers.get("Location")
        response.close()
        if not location:
            raise ValueError("download redirect has no Location header")
        if redirect_count >= MAX_DOWNLOAD_REDIRECTS:
            raise ValueError("too many download redirects")
        current_url = urljoin(current_url, location)
    raise ValueError("too many download redirects")


def _persist_download_state(
    plugin_dir: Path,
    plugin: dict,
    filename: str,
    archive_path: Path,
    sha256: str,
    manifest: DownloadManifest | None,
) -> None:
    """Atomically persist metadata and then update the manifest."""
    meta_file = plugin_dir / "plugin_info.json"
    if meta_file.is_symlink() or (meta_file.exists() and not meta_file.is_file()):
        raise ValueError("rejected unsafe metadata path")
    metadata = dict(plugin)
    metadata["downloaded_sha256"] = sha256
    _atomic_write_json(meta_file, metadata)
    if manifest:
        manifest.mark_downloaded(
            str(plugin["slug"]), filename, archive_path.stat().st_size // 1024,
            str(plugin.get("version", "") or ""), sha256,
        )


# ---------------------------------------------------------------------------
# Single-plugin download
# ---------------------------------------------------------------------------

def build_global_slug_index(base_dir: str | None) -> set[str]:
    """
    Scan marked sibling hunter folders and return the set of slugs already
    downloaded anywhere. Used to prevent cross-folder duplication when running
    the hunter multiple times (e.g. 1K tier then Patchstack tier).
    Returns an empty set if base_dir is None or doesn't exist.
    """
    if not base_dir:
        return set()
    base = Path(base_dir)
    if not base.is_dir():
        return set()
    seen: set[str] = set()
    for folder in base.iterdir():
        if not folder.is_dir() or folder.is_symlink():
            continue
        if _root_marker_state(folder / ROOT_MARKER_FILE) != "valid":
            continue
        for p in folder.iterdir():
            if (
                not p.is_dir()
                or p.is_symlink()
                or p.name.startswith(("_", "."))
                or not _is_safe_slug(p.name)
            ):
                continue
            has_valid_archive = any(
                _validate_download_archive(candidate)[0]
                for candidate in p.glob("*.zip")
            )
            if has_valid_archive:
                seen.add(p.name)
    return seen


def download_plugin(
    plugin: dict, output_dir: str,
    skip_existing: bool = True,
    manifest: DownloadManifest | None = None,
    update_check: bool = False,
    global_slugs: set[str] | None = None,
    max_bytes: int = MAX_DOWNLOAD_BYTES,
) -> tuple[bool, str, str]:
    slug = plugin.get("slug", "")
    if not _is_safe_slug(slug):
        return False, str(slug), "Rejected unsafe plugin slug"
    download_url = plugin.get("download_link", "")
    if not download_url:
        return False, slug, "No download link"
    if not _safe_download_url(download_url):
        return False, slug, "Rejected non-WordPress HTTPS download URL"

    # Global dedup: skip if already present in any other wp_plugins_* folder.
    if skip_existing and not update_check and global_slugs and slug in global_slugs:
        return True, slug, "Already in another folder (dedup)"

    output_path = Path(output_dir)
    if output_path.is_symlink() or not output_path.is_dir():
        return False, slug, "Rejected invalid output root"
    root = output_path.resolve()
    raw_plugin_dir = root / slug
    if raw_plugin_dir.is_symlink():
        return False, slug, "Rejected symlink plugin directory"
    plugin_dir = raw_plugin_dir.resolve()
    if plugin_dir.parent != root:
        return False, slug, "Rejected plugin path outside output root"
    plugin_dir.mkdir(parents=True, exist_ok=True)
    filename = _safe_download_filename(download_url, slug)
    filepath = plugin_dir / filename
    expected_md5 = str(plugin.get("md5") or "")

    if skip_existing and manifest and manifest.is_downloaded(slug):
        cached_filename = manifest.get_filename(slug)
        cached_path = plugin_dir / cached_filename
        local_ver = manifest.get_version(slug)
        remote_ver = str(plugin.get("version", "") or "")
        remote_is_newer = version_is_newer(remote_ver, local_ver)
        valid, _reason = _validate_download_archive(
            cached_path,
            max_bytes=max_bytes,
            # A newer remote release naturally has a different MD5. Without
            # --update-check, validate the cached release by its stored SHA-256.
            expected_md5="" if remote_is_newer else expected_md5,
        )
        version_ok = not update_check or not remote_is_newer
        if valid and version_ok:
            sha256 = _sha256_of_file(cached_path)
            try:
                _persist_download_state(
                    plugin_dir, plugin, cached_filename, cached_path, sha256, manifest
                )
            except (OSError, TypeError, ValueError) as exc:
                return False, slug, f"Could not persist verified download state: {exc}"
            state = f"Up to date (v{local_ver})" if update_check else "Already downloaded (verified)"
            return True, slug, state

    if filepath.is_symlink():
        return False, slug, "Rejected symlink download file"
    if filepath.exists() and not filepath.is_file():
        return False, slug, "Rejected non-file download path"
    if skip_existing and filepath.is_file():
        valid, _reason = _validate_download_archive(
            filepath, max_bytes=max_bytes, expected_md5=expected_md5
        )
        if valid:
            sha256 = _sha256_of_file(filepath)
            try:
                _persist_download_state(
                    plugin_dir, plugin, filename, filepath, sha256, manifest
                )
            except (OSError, TypeError, ValueError) as exc:
                return False, slug, f"Could not persist verified download state: {exc}"
            return True, slug, "Already on disk (verified)"

    last_exc: Exception | None = None
    downloaded_sha256 = ""
    tmp_path: Path | None = None
    for attempt in range(1, DOWNLOAD_MAX_RETRIES + 1):
        try:
            fd, temporary_name = tempfile.mkstemp(
                prefix=f".{filename}.", suffix=".part", dir=str(plugin_dir)
            )
            tmp_path = Path(temporary_name)
            with os.fdopen(fd, "wb") as fh, _open_safe_download(download_url) as resp:
                resp.raise_for_status()
                content_length = resp.headers.get("Content-Length")
                if content_length:
                    try:
                        content_length_int = int(content_length)
                    except (TypeError, ValueError):
                        content_length_int = 0
                    if content_length_int > max_bytes:
                        raise ValueError(f"response exceeds {max_bytes} byte limit")
                written = 0
                for chunk in resp.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    written += len(chunk)
                    if written > max_bytes:
                        raise ValueError(f"download exceeds {max_bytes} byte limit")
                    fh.write(chunk)
                fh.flush()
                os.fsync(fh.fileno())
            valid, reason = _validate_download_archive(
                tmp_path, max_bytes=max_bytes, expected_md5=expected_md5
            )
            if not valid:
                raise ValueError(reason)
            downloaded_sha256 = _sha256_of_file(tmp_path)
            os.replace(tmp_path, filepath)
            tmp_path = None
            last_exc = None
            break
        except Exception as exc:
            last_exc = exc
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)
                tmp_path = None
            if attempt < DOWNLOAD_MAX_RETRIES:
                time.sleep(2 ** attempt)

    if last_exc:
        return False, slug, f"Failed after {DOWNLOAD_MAX_RETRIES} attempts: {last_exc}"

    size_kb = filepath.stat().st_size // 1024
    sha256 = downloaded_sha256 or _sha256_of_file(filepath)

    try:
        _persist_download_state(plugin_dir, plugin, filename, filepath, sha256, manifest)
    except (OSError, TypeError, ValueError) as exc:
        return False, slug, f"Downloaded archive but could not persist metadata: {exc}"

    md5_note = " ✓md5" if expected_md5 else ""
    return True, slug, f"OK ({size_kb} KB) v{plugin.get('version', '')}{md5_note}"


# ---------------------------------------------------------------------------
# Batch download
# ---------------------------------------------------------------------------

def download_all(
    plugins: list[dict], output_dir: str,
    max_workers: int = 3, skip_existing: bool = True, update_check: bool = False,
    global_slugs: set[str] | None = None,
    max_bytes: int = MAX_DOWNLOAD_BYTES,
) -> None:
    max_workers = max(1, min(max_workers, 5))
    max_bytes = max(1, max_bytes)
    output_root = _ensure_hunter_root(output_dir)
    output_dir = str(output_root)
    manifest = DownloadManifest(output_root)

    # Pre-flight summary
    already = sum(1 for p in plugins if skip_existing and manifest.is_downloaded(p["slug"]))
    to_download = len(plugins) - already
    print(f"\n{'='*60}")
    print(f"  Download plan")
    print(f"    Output   : {output_dir}")
    print(f"    Total    : {len(plugins)}")
    print(f"    In cache : {already}  (will skip)")
    print(f"    Fetch    : {to_download}  (new or forced)")
    print(f"{'='*60}")

    if to_download == 0:
        print("\n  Nothing to download — all plugins already in cache.\n")
        print(f"  Tip: use --update-check to re-download newer versions,")
        print(f"       or --force to re-download everything.\n")
        return

    success = updated = failed = skipped = 0
    bar = ProgressBar(total=len(plugins), label="Downloading")
    bar.start()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                download_plugin, p, output_dir, skip_existing, manifest,
                update_check, global_slugs, max_bytes,
            ): p
            for p in plugins
        }
        for future in as_completed(futures):
            try:
                ok, slug, msg = future.result()
            except Exception as exc:
                plugin = futures[future]
                ok = False
                slug = str(plugin.get("slug", "unknown"))
                msg = f"Worker crashed: {_decode_process_output(exc, 160)}"
            msg_lower = msg.lower()
            if ok:
                if any(w in msg_lower for w in ("already", "up to date", "on disk", "dedup")):
                    skipped += 1
                    status = "SKIP"
                elif update_check and "ok" in msg_lower:
                    updated += 1
                    status = " UPD"
                else:
                    success += 1
                    status = " OK "
            else:
                failed += 1
                status = "FAIL"
            bar.update(message=f"[{status}] {slug}")

    bar.finish()
    print(f"\n  Results: {success} new  |  {skipped} skipped  |  {updated} updated  |  {failed} failed")
    if failed:
        print(f"  Tip: re-run with same flags to retry failed downloads (retry logic included).")
    print(f"  Location : {output_dir}\n")


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_results(plugins: list[dict], output_dir: str, target_installs: int) -> tuple[Path, Path]:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    base_name = f"plugins_{format_installs(target_installs).replace('+', '')}"

    json_path = Path(output_dir) / f"{base_name}.json"
    _atomic_write_json(json_path, plugins)

    csv_path = Path(output_dir) / f"{base_name}.csv"
    fieldnames = ["name", "slug", "version", "active_installs", "downloaded",
                  "last_updated", "author", "requires", "requires_php", "tested",
                  "download_link", "homepage", "tags"]
    with _atomic_text_file(csv_path, newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for p in plugins:
            row = dict(p)
            row["tags"] = "|".join(p.get("tags") or [])
            writer.writerow({k: _csv_safe(v) for k, v in row.items()})

    print(f"  Exported: {json_path.name}  +  {csv_path.name}")
    return json_path, csv_path


def export_patchstack_results(plugins: list[dict], output_dir: str) -> tuple[Path, Path]:
    """Export Patchstack VDP targets with boost/bounty columns, sorted by value."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    json_path = Path(output_dir) / "patchstack_targets.json"
    _atomic_write_json(json_path, plugins)

    csv_path = Path(output_dir) / "patchstack_targets.csv"
    fields = ["patchstack_boost", "patchstack_max_bounty", "slug", "name",
              "asset_kind", "version", "active_installs", "last_updated",
              "patchstack_vendor", "download_link"]
    with _atomic_text_file(csv_path, newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for p in plugins:
            writer.writerow({k: _csv_safe(v) for k, v in p.items()})

    print(f"  Exported: {json_path.name}  +  {csv_path.name}")
    return json_path, csv_path


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def print_summary_table(plugins: list[dict], quiet: bool = False) -> None:
    if quiet:
        print(f"  Plugins collected: {len(plugins)}  (use without --quiet to see the full list)")
        return
    if not plugins:
        print("  [!] No plugins found.")
        return
    # Limit table to first 50 rows for large batches
    show = plugins[:50]
    print(f"\n  {'No':<4} {'Plugin Name':<42} {'Slug':<30} {'Ver':<8} {'Updated':<12}")
    print(f"  {'-'*4} {'-'*42} {'-'*30} {'-'*8} {'-'*12}")
    for i, p in enumerate(show, 1):
        name = _display_text(p.get("name", ""), 41)
        slug = _display_text(p.get("slug", ""), 29)
        version = _display_text(p.get("version", ""), 7)
        updated = _display_text(p.get("last_updated") or "N/A", 10)
        print(f"  {i:<4} {name:<42} {slug:<30} "
              f"{version:<8} {updated:<12}")
    if len(plugins) > 50:
        print(f"  … and {len(plugins) - 50} more  (full list in exported JSON/CSV)")


# ---------------------------------------------------------------------------
# Semgrep helpers
# ---------------------------------------------------------------------------

def _find_semgrep(explicit: str | None) -> str | None:
    """Find a real Semgrep executable without installing anything."""
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
    """Return usable Semgrep executable/rules or stop before triage."""
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


# ---------------------------------------------------------------------------
# Triage logic (inline — no dependency on vuln_triage.py)
# ---------------------------------------------------------------------------

_IN_SCOPE_TIERS = {
    "unauthenticated", "subscriber", "contributor", "author",
    "low_privilege", "nonce_only", "permission_callback",
}
_KNOWN_OUT_OF_SCOPE_TIERS = {
    "admin", "administrator", "editor", "super_admin", "capability_checked",
}
_TIER_WEIGHT = {
    "unauthenticated": 1000, "permission_callback": 700, "nonce_only": 600,
    "subscriber": 550, "contributor": 500, "author": 450,
    "low_privilege": 500, "authenticated": 400, "unknown": 300, "": 300,
    "capability_checked": 50,
}


def _validate_zip_members(zf: zipfile.ZipFile) -> None:
    """Reject unsafe names, symlinks, duplicates, and oversized archives."""
    members = zf.infolist()
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise ValueError(f"archive has too many members ({len(members)})")
    total_size = 0
    seen: set[str] = set()
    for info in members:
        raw_name = info.filename.replace("\\", "/")
        if not raw_name or "\x00" in raw_name:
            raise ValueError("archive contains an invalid member name")
        if raw_name.startswith("/") or re.match(r"^[A-Za-z]:", raw_name):
            raise ValueError(f"absolute archive member: {info.filename!r}")
        normalized = raw_name.rstrip("/")
        parts = normalized.split("/")
        if not normalized or any(part in {"", ".", ".."} for part in parts):
            raise ValueError(f"traversal archive member: {info.filename!r}")
        canonical_name = "/".join(parts).casefold()
        if canonical_name in seen:
            raise ValueError(f"duplicate archive member: {info.filename!r}")
        seen.add(canonical_name)
        mode = (info.external_attr >> 16) & 0o170000
        if stat.S_ISLNK(mode):
            raise ValueError(f"symlink archive member: {info.filename!r}")
        if mode and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError(f"special archive member: {info.filename!r}")
        if info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
            raise ValueError(f"archive member exceeds size limit: {info.filename!r}")
        total_size += max(0, info.file_size)
        if total_size > MAX_ARCHIVE_UNPACKED_BYTES:
            raise ValueError("archive exceeds total unpacked size limit")


def _contains_source_file(directory: Path) -> bool:
    """Find PHP/JavaScript source without following directory symlinks."""
    for current, dirnames, filenames in os.walk(directory, followlinks=False):
        current_path = Path(current)
        dirnames[:] = [
            name for name in dirnames
            if not (current_path / name).is_symlink()
        ]
        if any(Path(name).suffix.lower() in SOURCE_SUFFIXES for name in filenames):
            return True
    return False


def _looks_like_plugin_dir(path: Path) -> bool:
    """Exclude unrelated child folders from triage enumeration."""
    if (
        path.is_symlink()
        or not path.is_dir()
        or not _is_safe_slug(path.name)
        or path.name.startswith(("_", "."))
    ):
        return False
    metadata = path / "plugin_info.json"
    if metadata.is_file() and not metadata.is_symlink():
        return True
    extracted = path / "extracted"
    if extracted.is_dir() and not extracted.is_symlink():
        return True
    try:
        if any(
            candidate.is_file() and not candidate.is_symlink()
            for candidate in path.glob("*.zip")
        ):
            return True
    except OSError:
        return False
    return _contains_source_file(path)


def _ensure_extracted(plugin_dir: str) -> tuple[str | None, str | None]:
    """Return (scan target, removable extracted directory)."""
    root = Path(plugin_dir)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("plugin directory is not a real directory")
    ext_dir = root / "extracted"
    if ext_dir.is_symlink():
        raise ValueError("extracted directory is a symlink")
    if ext_dir.is_dir() and any(ext_dir.iterdir()):
        return (str(ext_dir), str(ext_dir)) if _contains_source_file(ext_dir) else (None, str(ext_dir))
    # Find the best zip: prefer the one whose name most closely matches the folder name.
    zips = [
        root / f
        for f in os.listdir(root)
        if f.lower().endswith(".zip") and (root / f).is_file() and not (root / f).is_symlink()
    ]
    if not zips:
        removable = str(ext_dir) if ext_dir.is_dir() else None
        if _contains_source_file(root):
            return str(root), removable
        return None, removable
    if len(zips) > 1:
        folder_name = root.name.lower()
        # Prefer zip whose stem matches the folder name, fall back to largest.
        named_match = next(
            (z for z in zips if z.stem.lower().startswith(folder_name[:8])), None
        )
        zip_path = named_match or max(zips, key=lambda z: z.stat().st_size)
    else:
        zip_path = zips[0]

    temporary_dir: Path | None = None
    try:
        with zipfile.ZipFile(zip_path) as zf:
            _validate_zip_members(zf)
            temporary_dir = Path(tempfile.mkdtemp(prefix=".extract-", dir=str(root)))
            zf.extractall(temporary_dir)
        if ext_dir.exists():
            if not ext_dir.is_dir() or ext_dir.is_symlink():
                raise ValueError("extracted path is not a safe directory")
            if any(ext_dir.iterdir()):
                shutil.rmtree(temporary_dir, ignore_errors=True)
                temporary_dir = None
                target = str(ext_dir) if _contains_source_file(ext_dir) else None
                return target, str(ext_dir)
            ext_dir.rmdir()
        os.replace(temporary_dir, ext_dir)
        temporary_dir = None
        target = str(ext_dir) if _contains_source_file(ext_dir) else None
        return target, str(ext_dir)
    except Exception as e:
        print(f"  [WARN] Extract failed for {root.name}: {e}", file=sys.stderr)
        raise
    finally:
        if temporary_dir is not None:
            shutil.rmtree(temporary_dir, ignore_errors=True)


def _decode_process_output(value: object, limit: int = 512) -> str:
    """Convert subprocess output to bounded, terminal-safe text."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    text = str(value or "")
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = re.sub(r"\s+", " ", _display_text(text)).strip()
    return text[:limit]


def _semgrep_error_detail(stdout: object, stderr: object, limit: int = 500) -> str:
    """Extract one stable diagnostic instead of terminal progress decoration."""
    decoded_stdout = (
        stdout.decode("utf-8", errors="replace") if isinstance(stdout, bytes) else stdout
    )
    try:
        payload = json.loads(str(decoded_stdout or ""))
    except (TypeError, json.JSONDecodeError):
        payload = None
    if isinstance(payload, dict) and isinstance(payload.get("errors"), list):
        for error in payload["errors"]:
            if not isinstance(error, dict):
                continue
            error_type = _decode_process_output(error.get("type"), 80)
            rule_id = _decode_process_output(error.get("rule_id"), 120)
            message = _decode_process_output(error.get("message"), limit)
            heading = error_type or "Semgrep error"
            if rule_id:
                heading += f" in {rule_id}"
            if message.lower().startswith(heading.lower()):
                return message[:limit]
            return f"{heading}: {message}"[:limit] if message else heading[:limit]
    return _decode_process_output(stderr or stdout, limit)


def _semgrep_runtime_environment(state_dir: str | Path) -> dict[str, str]:
    """Keep Semgrep's local state isolated from user config and disable telemetry."""
    state = Path(state_dir)
    cache = state / "cache"
    config = state / "config"
    cache.mkdir(parents=True, exist_ok=True)
    config.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.update({
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
        "SEMGREP_SETTINGS_FILE": str(state / "settings.yml"),
        "SEMGREP_LOG_FILE": str(state / "semgrep.log"),
        "SEMGREP_VERSION_CACHE_PATH": str(cache / "version"),
        "XDG_CACHE_HOME": str(cache),
        "XDG_CONFIG_HOME": str(config),
    })
    return environment


def _validate_semgrep_config(
    semgrep_path: str,
    rules_path: str | Path,
    timeout: int = 30,
) -> tuple[bool, str]:
    """Validate all local rules once before starting a plugin batch."""
    rules = Path(rules_path).expanduser()
    if rules.is_symlink() or not rules.is_file():
        return False, f"Rules file is missing or unsafe: {rules}"
    cmd = [
        semgrep_path,
        "--disable-version-check",
        "--quiet",
        "--validate",
        "--config", str(rules),
    ]
    try:
        with tempfile.TemporaryDirectory(prefix="wp-hunter-semgrep-state-") as state_dir, \
                tempfile.TemporaryFile(mode="w+b") as stdout_file, \
                tempfile.TemporaryFile(mode="w+b") as stderr_file:
            proc = subprocess.run(
                cmd,
                timeout=max(1, timeout),
                stdout=stdout_file,
                stderr=stderr_file,
                check=False,
                stdin=subprocess.DEVNULL,
                shell=False,
                env=_semgrep_runtime_environment(state_dir),
            )
            stdout_file.seek(0)
            stdout = stdout_file.read(64 * 1024)
            stderr_file.seek(0)
            stderr = stderr_file.read(64 * 1024)
    except subprocess.TimeoutExpired:
        return False, "Semgrep rule validation timed out"
    except FileNotFoundError:
        return False, "Semgrep executable was not found"
    except Exception as exc:
        return False, _decode_process_output(exc, 500)
    if proc.returncode == 0:
        return True, ""
    detail = _semgrep_error_detail(stdout, stderr)
    return False, detail or f"Semgrep validation exited with code {proc.returncode}"


def _normalize_semgrep_result(raw: object) -> dict:
    """Map Semgrep's JSON result into the classifier's stable internal shape."""
    if not isinstance(raw, dict):
        return {"check_id": "semgrep.unknown", "extra": {"context": {"access": "unknown"}}}

    extra = raw.get("extra") if isinstance(raw.get("extra"), dict) else {}
    metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
    triage = metadata.get("triage") if isinstance(metadata.get("triage"), dict) else {}
    access = str(triage.get("access", "unknown") or "unknown").lower().strip()
    category = str(triage.get("category", "unknown") or "unknown").strip()
    confidence = str(triage.get("confidence", "unknown") or "unknown").strip()
    start = raw.get("start") if isinstance(raw.get("start"), dict) else {}
    end = raw.get("end") if isinstance(raw.get("end"), dict) else {}

    return {
        "check_id": str(raw.get("check_id", "semgrep.unknown") or "semgrep.unknown"),
        "file": str(raw.get("path", "") or ""),
        "line": start.get("line"),
        "end_line": end.get("line"),
        "message": str(extra.get("message", "") or ""),
        "category": category,
        "confidence": confidence,
        "extra": {
            "context": {"access": access},
            "metadata": metadata,
        },
        # Keep the original result for JSON reporting and later investigation.
        "semgrep": raw,
    }


def _run_semgrep_scan(
    semgrep_path: str,
    rules_path: Path,
    target_dir: str,
    timeout: int,
    mem_mb: int,
) -> tuple[list[dict], str]:
    """Run local Semgrep without a shell and return normalized candidate findings."""
    del mem_mb  # Semgrep CE has no portable per-process memory flag.
    target = Path(target_dir)
    if target.is_symlink() or not target.is_dir():
        return [], "INVALID_TARGET"
    for current, dirnames, filenames in os.walk(target, followlinks=False):
        if any((Path(current) / name).is_symlink() for name in (*dirnames, *filenames)):
            return [], "SYMLINK_TARGET"
    if rules_path.is_symlink() or not rules_path.is_file():
        return [], "INVALID_RULES"

    cmd = [
        semgrep_path,
        "--disable-version-check",
        "--quiet",
        "--no-rewrite-rule-ids",
        "--config", str(rules_path),
        "--json",
        "--no-git-ignore",
        str(target),
    ]
    try:
        with tempfile.TemporaryDirectory(prefix="wp-hunter-semgrep-state-") as state_dir, \
                tempfile.TemporaryFile(mode="w+b") as stdout_file, \
                tempfile.TemporaryFile(mode="w+b") as stderr_file:
            proc = subprocess.run(
                cmd,
                timeout=max(1, timeout),
                stdout=stdout_file,
                stderr=stderr_file,
                check=False,
                stdin=subprocess.DEVNULL,
                shell=False,
                env=_semgrep_runtime_environment(state_dir),
            )
            stdout_file.seek(0, os.SEEK_END)
            output_size = stdout_file.tell()
            stdout_file.seek(0)
            stdout = stdout_file.read(MAX_SEMGREP_JSON_BYTES + 1)
            stderr_file.seek(0)
            stderr = stderr_file.read(4096)
    except subprocess.TimeoutExpired:
        return [], "TIMEOUT"
    except FileNotFoundError:
        return [], "BINARY_NOT_FOUND"
    except Exception as exc:
        return [], f"SCAN_ERR:{_decode_process_output(exc, 200)}"

    # Exit 1 is the normal Semgrep result for findings; all other non-zero
    # codes are errors and must preserve the plugin.
    if proc.returncode not in (0, 1):
        error_hint = _semgrep_error_detail(stdout, stderr, 300)
        suffix = f" — {error_hint}" if error_hint else ""
        return [], f"SCAN_ERR:{proc.returncode}{suffix}"

    if output_size > MAX_SEMGREP_JSON_BYTES:
        return [], "OUTPUT_TOO_LARGE"
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    if not isinstance(stdout, str) or not stdout.strip():
        return [], "INVALID_OUTPUT"
    try:
        data = json.loads(stdout)
    except (TypeError, json.JSONDecodeError):
        return [], "INVALID_OUTPUT"
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return [], "INVALID_OUTPUT"
    if isinstance(data.get("errors"), list) and data["errors"]:
        return [], "PARSE_ERROR"
    return [_normalize_semgrep_result(item) for item in data["results"]], "OK"


class SemgrepEngine:
    """Small adapter around the local Semgrep Community Edition CLI."""

    def __init__(self, executable: str, rules_path: str | Path):
        self.executable = executable
        self.rules_path = Path(rules_path).expanduser().absolute()

    def scan(self, target_dir: str, timeout: int, mem_mb: int) -> tuple[list[dict], str]:
        return _run_semgrep_scan(
            self.executable, self.rules_path, target_dir, timeout, mem_mb
        )


def _classify(results: list) -> tuple[dict, dict, int]:
    tier_counts: dict[str, int] = {}
    check_counts: dict[str, int] = {}
    in_scope = 0
    for r in results:
        if not isinstance(r, dict):
            in_scope += 1  # Unknown scanner output must never trigger deletion.
            continue
        extra = r.get("extra") if isinstance(r.get("extra"), dict) else {}
        context = extra.get("context") if isinstance(extra.get("context"), dict) else {}
        access = context.get("access", "") or ""
        access = str(access).lower().strip()
        check = str(r.get("check_id", "?"))
        tier_counts[access] = tier_counts.get(access, 0) + 1
        check_counts[check] = check_counts.get(check, 0) + 1
        # Treat unknown/ambiguous labels as potentially in-scope. This is
        # intentionally fail-closed: a new scanner label must not cause a
        # plugin to be deleted silently.
        if access in _IN_SCOPE_TIERS or access not in _KNOWN_OUT_OF_SCOPE_TIERS:
            in_scope += 1
    return tier_counts, check_counts, in_scope


def _plugin_last_updated_year(plugin_dir: str) -> int | None:
    """
    Read last_updated from plugin_info.json in the plugin folder.
    Returns the year as int, or None if not available.
    wp.org format: "2024-03-15 10:30am GMT"
    """
    meta = Path(plugin_dir) / "plugin_info.json"
    if meta.is_symlink() or not meta.is_file():
        return None
    try:
        if meta.stat().st_size > 4 * 1024 * 1024:
            return None
        with open(meta, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        last_updated = data.get("last_updated", "")
        if last_updated and len(last_updated) >= 4:
            return int(last_updated[:4])
    except Exception:
        pass
    return None


def _triage_one(plugin_dir: str, engine: SemgrepEngine, timeout: int, mem_mb: int,
                max_age_years: int = 0) -> dict:
    name = os.path.basename(plugin_dir.rstrip("\\/"))
    res = dict(
        name=name, dir=plugin_dir, status="OK", total=0, in_scope=0,
        tiers={}, checks={}, findings=[], keep=False, extracted_dir=None,
        cleanup_status="not_needed", deletion="retained",
    )
    res["dir_identity"] = _directory_identity(plugin_dir)
    if res["dir_identity"] is None:
        res["status"] = "INVALID_DIRECTORY"
        res["keep"] = True
        return res
    existing_extracted = Path(plugin_dir) / "extracted"
    if existing_extracted.is_dir() and not existing_extracted.is_symlink():
        res["extracted_dir"] = str(existing_extracted)

    # Date filter: skip plugin that hasn't been updated within max_age_years.
    if max_age_years > 0:
        year = _plugin_last_updated_year(plugin_dir)
        cutoff = datetime.now().year - max_age_years
        if year is not None and year < cutoff:
            res["status"] = f"OUTDATED ({year})"
            res["keep"] = True
            return res
        # If no metadata at all, fall through and let the scan decide.

    try:
        target, extracted_dir = _ensure_extracted(plugin_dir)
        res["extracted_dir"] = extracted_dir
    except Exception as exc:
        res["status"] = f"EXTRACT_ERROR:{exc}"
        res["keep"] = True
        return res
    if not target:
        # No source found — mark explicitly so the deletion reason is clear in report.
        res["status"] = "NO_SOURCE"
        res["keep"] = True
        return res

    try:
        results, status = engine.scan(target, timeout, mem_mb)
    except Exception as exc:
        results, status = [], f"SCAN_ERR:{exc}"
    res["status"] = status
    # Conservative: keep on any scan failure so we never silently lose a target.
    if status != "OK":
        res["keep"] = True
        return res

    tiers, checks, in_scope = _classify(results)
    res.update(
        total=len(results), in_scope=in_scope, tiers=tiers,
        checks=checks, findings=results,
    )
    # Any finding is a manual-review candidate. Access metadata only affects
    # prioritisation; it must never make a matched plugin deletion-eligible.
    res["keep"] = len(results) > 0
    return res


def _fmt_triage_summary(res: dict) -> str:
    tier_str = " ".join(
        f"{_display_text(t or 'empty')}={c}"
        for t, c in sorted(res["tiers"].items(), key=lambda kv: -_TIER_WEIGHT.get(kv[0], 100))
    )
    top = sorted(res["checks"].items(), key=lambda kv: -kv[1])[:4]
    check_str = ", ".join(f"{_display_text(c)}({n})" for c, n in top)
    return (
        f"{_display_text(res['name'])} | total={res['total']} in_scope={res['in_scope']}"
        + (f" | tiers: {tier_str}" if tier_str else "")
        + (f" | {check_str}" if check_str else "")
    )


def _fmt_finding(finding: dict) -> str:
    """Render one normalized candidate finding for the human report."""
    file_name = _display_text(finding.get("file", "?"), 180) or "?"
    line = _display_text(finding.get("line", "?"), 20) or "?"
    rule = _display_text(finding.get("check_id", "?"), 120) or "?"
    category = _display_text(finding.get("category", "unknown"), 60) or "unknown"
    confidence = _display_text(finding.get("confidence", "unknown"), 30) or "unknown"
    access = "unknown"
    extra = finding.get("extra") if isinstance(finding.get("extra"), dict) else {}
    context = extra.get("context") if isinstance(extra.get("context"), dict) else {}
    if context.get("access"):
        access = _display_text(context["access"], 40)
    message = _display_text(finding.get("message", ""), 240)
    detail = (
        f"    - {file_name}:{line} | rule={rule} | category={category} | "
        f"confidence={confidence} | access={access}"
    )
    return detail + (f" | {message}" if message else "")


def run_triage(
    output_dir: str, semgrep_path: str, semgrep_rules: str | Path,
    workers: int = 4, timeout: int = 120, mem_mb: int = 2048,
    dry_run: bool = True, keep_extracted: bool = False,
    max_age_years: int = 2, allow_unmarked: bool = False,
) -> None:
    workers = max(1, workers)
    timeout = max(1, timeout)
    mem_mb = max(1, mem_mb)
    try:
        root = _validate_triage_root(output_dir, allow_unmarked=allow_unmarked)
    except ValueError as exc:
        print(f"  [ERROR] {exc}", file=sys.stderr)
        return
    initial_marker_state = _root_marker_state(root / ROOT_MARKER_FILE)
    root_is_marked = initial_marker_state == "valid"
    if not dry_run and not root_is_marked:
        print(
            "  [ERROR] Live deletion requires an adopted, marked hunter root.",
            file=sys.stderr,
        )
        return
    if not root_is_marked and not keep_extracted:
        keep_extracted = True
        print(
            "  [WARN] Unmarked-root preview will preserve every extracted directory.",
            file=sys.stderr,
        )
    output_dir = str(root)
    root_identity = _directory_identity(root)
    if root_identity is None:
        print("  [ERROR] Could not establish triage-root identity.", file=sys.stderr)
        return
    engine = SemgrepEngine(semgrep_path, semgrep_rules)
    ts_fmt = datetime.now().strftime("%H:%M:%S")
    print(f"\n{'='*60}")
    print(f"  Vulnerability Triage  [{ts_fmt}]")
    print(f"  Folder   : {output_dir}")
    print(f"  Engine   : Semgrep ({engine.executable})")
    print(f"  Rules    : {engine.rules_path}")
    print(f"  Workers  : {workers}  |  Timeout: {timeout}s/plugin")
    cutoff_label = (
        f"  Filter   : skip plugins last updated before "
        f"{datetime.now().year - max_age_years} ({max_age_years}yr cutoff)"
    )
    print(cutoff_label if max_age_years > 0 else "  Filter   : no date filter (scanning all)")
    triage_mode_label = (
        "DRY RUN — no plugin folders will be deleted"
        if dry_run else "LIVE — no-candidate folders will be deleted"
    )
    print(f"  Mode     : {triage_mode_label}")
    print(f"{'='*60}")

    plugin_dirs = sorted(
        str(p)
        for p in root.iterdir()
        if _looks_like_plugin_dir(p)
    )
    total = len(plugin_dirs)
    if total == 0:
        print("  No plugin folders found.\n")
        return
    print(f"  Plugins  : {total}\n")

    results: list[dict] = []
    bar = ProgressBar(total=total, label="Scanning ")
    bar.start()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        fut_map = {
            executor.submit(_triage_one, d, engine, timeout, mem_mb, max_age_years): d
            for d in plugin_dirs
        }
        for fut in as_completed(fut_map):
            try:
                r = fut.result()
            except Exception as exc:
                d = fut_map[fut]
                r = dict(name=os.path.basename(d), dir=d, status=f"CRASH:{exc}",
                         total=0, in_scope=0, tiers={}, checks={}, findings=[], keep=True,
                         extracted_dir=None, cleanup_status="not_needed",
                         deletion="retained", dir_identity=_directory_identity(d))
            results.append(r)
            flag = "KEEP" if r["keep"] else "DEL "
            status_code = str(r["status"]).split(" —", 1)[0]
            status_note = (
                f" [{status_code}]" if status_code not in ("OK", "NO_SOURCE") else ""
            )
            bar.update(message=f"[{flag}] {r['name']} ({r['in_scope']}/{r['total']}){status_note}")

    bar.finish("Scan complete")

    if (
        _directory_identity(root) != root_identity
        or _root_marker_state(root / ROOT_MARKER_FILE) != initial_marker_state
    ):
        print(
            "  [ERROR] Triage root or marker changed during scanning; "
            "no cleanup or deletion performed.",
            file=sys.stderr,
        )
        return

    keep = [r for r in results if r["keep"]]
    # Only successfully scanned plugins with no Semgrep candidate are eligible
    # for deletion.
    delete = sorted(
        [r for r in results if r["status"] == "OK" and r["total"] == 0],
        key=lambda r: r["name"],
    )
    vuln = sorted(
        [r for r in results if r["status"] == "OK" and r["total"] > 0],
        key=lambda r: (
            -r["in_scope"],
            -max((_TIER_WEIGHT.get(t, 100) for t in r["tiers"]), default=0),
            -r["total"],
            r["name"],
        ),
    )
    no_source = sorted(
        [r for r in results if r["status"] == "NO_SOURCE"], key=lambda r: r["name"]
    )
    outdated = sorted(
        [r for r in results if r["status"].startswith("OUTDATED")],
        key=lambda r: r["name"],
    )
    scan_fail = sorted(
        [
            r for r in keep
            if r["in_scope"] == 0
            and r["status"] != "OK"
            and r["status"] != "NO_SOURCE"
            and not r["status"].startswith("OUTDATED")
        ],
        key=lambda r: r["name"],
    )

    # ---- Confirmation prompt before live deletions ----
    if not dry_run and delete:
        print(f"\n  About to delete {len(delete)} folders:")
        print(f"    {len(delete)} with no Semgrep candidate matched after a successful scan")
        for r in delete[:8]:
            print(f"    - {r['name']} (no Semgrep candidate matched)")
        if len(delete) > 8:
            print(f"    … and {len(delete) - 8} more")
        print()
        if _ask_choice("Commit these deletions?", ["no", "yes"], "no") != "yes":
            print("  Aborted — no folders were deleted.")
            print(f"  Tip: re-run with --triage-dry-run to preview without confirming.\n")
            dry_run = True

    # ---- Perform deletions ----
    deleted_names: list[str] = []
    would_delete_names: list[str] = []
    deletion_failures: list[dict] = []
    for r in delete:
        if dry_run:
            r["deletion"] = "would_delete"
            would_delete_names.append(r["name"])
            continue
        try:
            if not _is_direct_child(root, r["dir"]):
                raise ValueError("deletion target is not a safe direct child")
            if _directory_identity(r["dir"]) != tuple(r["dir_identity"]):
                raise ValueError("deletion target changed after scanning")
            shutil.rmtree(r["dir"])
            r["deletion"] = "deleted"
            deleted_names.append(r["name"])
        except Exception as exc:
            r["deletion"] = f"failed:{exc}"
            r["keep"] = True
            deletion_failures.append(r)
            print(f"  [WARN] Could not delete {r['name']}: {exc}", file=sys.stderr)

    # Extraction is disposable scan state, so remove it after both dry and
    # live runs unless the user explicitly asks to keep it.
    if not keep_extracted:
        for r in results:
            extracted_value = r.get("extracted_dir")
            if not extracted_value:
                continue
            plugin_path = Path(r["dir"])
            extracted_path = Path(str(extracted_value))
            if not plugin_path.exists():
                r["cleanup_status"] = "plugin_deleted"
                continue
            try:
                if (
                    not _is_direct_child(root, plugin_path)
                    or _directory_identity(plugin_path) != tuple(r["dir_identity"])
                    or extracted_path != plugin_path / "extracted"
                    or extracted_path.is_symlink()
                    or not extracted_path.is_dir()
                ):
                    raise ValueError("unsafe extracted directory")
                shutil.rmtree(extracted_path)
                r["cleanup_status"] = "removed"
            except Exception as exc:
                r["cleanup_status"] = f"failed:{exc}"
                print(
                    f"  [WARN] Could not clean extracted source for {r['name']}: {exc}",
                    file=sys.stderr,
                )

    # ---- Write reports after actions so counts and per-folder state are exact ----
    report_path = root / "vuln_report.txt"
    names_path = root / "vuln_plugins.txt"
    deleted_path = root / "deleted_plugins.txt"
    json_path = root / "triage_results.json"
    generated = datetime.now().isoformat(timespec="seconds")
    action_names = would_delete_names if dry_run else deleted_names
    action_label = "Would delete" if dry_run else "Deleted"

    _atomic_write_json(
        json_path,
        {
            "engine": "semgrep",
            "rules": str(engine.rules_path),
            "generated": generated,
            "dry_run": dry_run,
            "candidate_count": len(vuln),
            "deletion_candidate_count": len(delete),
            "deleted_count": len(deleted_names),
            "deletion_failure_count": len(deletion_failures),
            "results": sorted(results, key=lambda item: item.get("name", "")),
        },
    )

    with _atomic_text_file(report_path) as fh:
        fh.write("WP Plugin Semgrep Triage Report\n")
        fh.write(f"Generated : {generated}\n")
        fh.write(f"Folder    : {output_dir}\n")
        fh.write("Engine    : Semgrep\n")
        fh.write(f"Rules     : {engine.rules_path}\n")
        if max_age_years > 0:
            fh.write(
                f"Date filter: plugins updated before "
                f"{datetime.now().year - max_age_years} are skipped\n"
            )
        review_needed = (
            len(vuln) + len(scan_fail) + len(no_source) + len(outdated)
            + len(deletion_failures)
        )
        fh.write(
            f"Scanned   : {total}  |  Candidates: {len(vuln)}  |  "
            f"Outdated (skipped): {len(outdated)}  |  "
            f"Review-needed: {review_needed}  |  {action_label}: {len(action_names)}  |  "
            f"Deletion failures: {len(deletion_failures)}\n"
        )
        fh.write(
            "Deletion basis: no Semgrep candidate matched after a successful scan; "
            "zero Semgrep matches only "
            f"({len(delete)} folder candidate(s))\n"
        )
        fh.write("=" * 70 + "\n\n")

        if vuln:
            fh.write("PLUGINS WITH SEMGREP CANDIDATE FINDINGS (manual review required):\n")
            fh.write("-" * 70 + "\n")
            for r in vuln:
                fh.write(_fmt_triage_summary(r) + "\n")
                for finding in r.get("findings", []):
                    if isinstance(finding, dict):
                        fh.write(_fmt_finding(finding) + "\n")
            fh.write("\n")

        if outdated:
            fh.write(
                f"SKIPPED — OUTDATED (last_updated older than {max_age_years} years):\n"
            )
            fh.write("-" * 70 + "\n")
            for r in outdated:
                fh.write(f"  {r['name']}  ({r['status']})\n")
            fh.write("\n")

        if scan_fail:
            fh.write("KEPT FOR MANUAL REVIEW (scan failed or timed out):\n")
            fh.write("-" * 70 + "\n")
            for r in scan_fail:
                fh.write(f"  {r['name']}  status={r['status']}\n")
            fh.write("\n")

        if no_source:
            fh.write("KEPT FOR REVIEW — NO PHP/JAVASCRIPT SOURCE FILES FOUND:\n")
            fh.write("-" * 70 + "\n")
            for r in no_source:
                fh.write(f"  {r['name']}\n")
            fh.write("\n")

        if deletion_failures:
            fh.write("KEPT FOR REVIEW — DELETION FAILED:\n")
            fh.write("-" * 70 + "\n")
            for r in deletion_failures:
                fh.write(f"  {r['name']}  status={r['deletion']}\n")
            fh.write("\n")

    _atomic_write_text(
        names_path,
        "".join(f"{r['name']}\n" for r in vuln),
    )
    marker = "DRY RUN — NOT DELETED" if dry_run else "DELETED"
    _atomic_write_text(
        deleted_path,
        f"# {marker} — {generated}\n" + "".join(f"{name}\n" for name in sorted(action_names)),
    )

    # ---- Final summary ----
    print(f"\n{'='*60}")
    print("  Triage complete")
    print(f"    Semgrep candidates: {len(vuln)}")
    review_count = len(scan_fail) + len(no_source) + len(outdated)
    print(f"    Kept for review  : {review_count}  (outdated, no source, or scan failed)")
    if len(outdated):
        print(f"    Outdated/skipped : {len(outdated)}  (updated before {datetime.now().year - max_age_years})")
    print(f"    {action_label:<18}: {len(action_names)}")
    if deletion_failures:
        print(f"    Deletion failures : {len(deletion_failures)}")
    print(f"    Report           : {report_path}")
    print(f"    Candidate list   : {names_path}")
    print(f"    JSON results     : {json_path}")
    if dry_run:
        print(f"\n  This was a DRY RUN. Re-run with --confirm-delete to commit deletions.")
    if vuln:
        print(f"\n  Top Semgrep candidates:")
        for r in vuln[:5]:
            print(f"    {_fmt_triage_summary(r)}")
    print(f"{'='*60}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    # No args → interactive wizard
    if len(sys.argv) == 1:
        args = interactive_wizard()
    else:
        parser = argparse.ArgumentParser(
            description="WordPress Plugin Hunter — Download & triage by active installs",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Quick examples:
  %(prog)s                                  # interactive wizard
  %(prog)s --check                          # verify setup
  %(prog)s --installs 10K                   # download the exact 10K tier
  %(prog)s --min-installs 10K               # download plugins with >=10K installs
  %(prog)s --installs 10K --auto-triage     # download + scan + preview no-candidate folders
  %(prog)s --installs 10K --auto-triage --confirm-delete  # commit no-candidate deletion
  %(prog)s --installs 10K --auto-triage --triage-dry-run   # preview deletions
  %(prog)s --triage-only ./wp_plugins_10K   # triage existing folder

Tip: run without arguments to enter the interactive setup wizard.
            """,
        )

        install_group = parser.add_mutually_exclusive_group()
        install_group.add_argument(
            "--installs", type=str, default=None,
            help="Active installs tier: 1K, 5K, 10K, 50K, 100K, 1M "
                 "(exact match — use --min-installs for threshold mode)",
        )
        install_group.add_argument(
            "--min-installs", type=str, default=None,
            help="Active installs threshold: 1K, 5K, 10K … Matches plugins "
                 "with installs >= this value instead of an exact tier. "
                 "Recommended when combining with --tag/--search, since a "
                 "niche tag rarely has plugins at an EXACT install count.",
        )
        install_group.add_argument(
            "--patchstack", action="store_true",
            help="Source plugins from the Patchstack VDP directory "
                 "(vendor opt-in targets, often with bounty boost)",
        )
        parser.add_argument("--min-boost", type=_nonnegative_cli_int, default=0,
                            help="Patchstack: only plugins with bounty boost >= N%% (e.g. 25)")
        parser.add_argument("--include-themes", action="store_true",
                            help="Patchstack: include themes too (default: plugins only)")
        parser.add_argument("--browse", type=str, default="popular",
                            choices=["popular", "new", "updated", "top-rated"])
        parser.add_argument("--pages", type=_positive_cli_int, default=50,
                            help="Max API pages (100 plugins/page, default: 50)")
        parser.add_argument("--api-workers", type=_positive_cli_int, default=API_PARALLEL_WORKERS,
                            help=f"Parallel API fetchers (default: {API_PARALLEL_WORKERS})")
        parser.add_argument("--search", type=str, default=None)
        parser.add_argument("--tag", type=str, default=None)
        parser.add_argument("--output", type=str, default=None,
                            help="Output folder (default: ./wp_plugins_<tier>/)")
        parser.add_argument(
            "--adopt-output-root", action="store_true",
            help="Adopt a non-empty legacy output folder after exact-path confirmation",
        )
        parser.add_argument("--no-download", action="store_true",
                            help="Skip download — collect and export list only")
        parser.add_argument("--workers", type=_positive_cli_int, default=3,
                            help="Download threads (default: 3, max: 5)")
        parser.add_argument("--max-download-mb", type=_positive_cli_int, default=MAX_DOWNLOAD_BYTES // (1024 * 1024),
                            help="Maximum size of one downloaded archive (default: 512 MB)")
        parser.add_argument("--limit", type=_nonnegative_cli_int, default=None)
        parser.add_argument("--preview", action="store_true",
                            help="Show download plan (what would be fetched) without downloading")
        parser.add_argument("--force", action="store_true",
                            help="Re-download even if file already exists on disk")
        parser.add_argument("--no-global-dedup", action="store_true",
                            help="Disable cross-folder deduplication (by default, slugs "
                                 "already downloaded in marked sibling hunter folders are skipped)")
        parser.add_argument("--update-check", action="store_true",
                            help="Re-download if a newer version is available on wp.org")
        parser.add_argument("--dry-run-count", action="store_true",
                            help=argparse.SUPPRESS)  # kept for back-compat, alias of --preview
        parser.add_argument("--reset-manifest", action="store_true",
                            help="Clear download cache (re-downloads all on next run)")
        parser.add_argument("--auto-triage", action="store_true",
                            help="After download: scan and preview folders with no Semgrep candidate")
        parser.add_argument("--confirm-delete", action="store_true",
                            help="Allow live deletion after triage confirmation")
        parser.add_argument("--triage-only", type=str, default=None, metavar="DIR",
                            help="Skip download; run triage on an existing folder")
        parser.add_argument("--allow-unmarked-triage", action="store_true",
                            help="Allow a dry-run preview of a legacy/unmarked folder; "
                                 "live mode requires exact-path adoption")
        parser.add_argument("--triage-workers", type=_positive_cli_int, default=2,
                            help="Parallel scan workers (default: 2; increase carefully, "
                                 "each worker can use 1-3 GB RAM)")
        parser.add_argument("--triage-timeout", type=_positive_cli_int, default=120,
                            help="Per-plugin scan timeout seconds (default: 120)")
        parser.add_argument("--triage-mem-mb", type=_positive_cli_int, default=1024,
                            help="Memory budget used to size Semgrep workers (default: 1024 MB)")
        parser.add_argument("--triage-dry-run", action="store_true",
                            help="Triage: show what would be deleted without deleting")
        parser.add_argument("--min-updated-years", type=_nonnegative_cli_int, default=2,
                            help="Only include plugins updated within last N years "
                                 "(applies to both download and triage). Default: 2. Set 0 to disable.")
        parser.add_argument("--since", type=_date_cli_value, default=None,
                            help="Only include plugins updated on/after this date "
                                 "(YYYY-MM-DD, or YYYY-MM, or YYYY). Overrides --min-updated-years "
                                 "when both are given. Example: --since 2025-01-01")
        parser.add_argument("--keep-extracted", action="store_true",
                            help="Keep extracted/ subfolders after triage")
        parser.add_argument("--semgrep", type=str, default=None,
                            help="Path to Semgrep executable (auto-detected if omitted)")
        parser.add_argument("--semgrep-rules", type=str, default=None,
                            help="Path to Semgrep rules (default: rules/wordpress-triage.yml)")
        parser.add_argument("--check", action="store_true",
                            help="Verify dependencies and Semgrep setup, then exit")
        parser.add_argument("--quiet", action="store_true",
                            help="Suppress plugin list table; show only progress + summary")

        args = parser.parse_args()

        if not args.patchstack and (args.include_themes or args.min_boost):
            parser.error("--include-themes and --min-boost require --patchstack")
        if args.confirm_delete and not (args.auto_triage or args.triage_only):
            parser.error("--confirm-delete requires --auto-triage or --triage-only")
        if args.allow_unmarked_triage and not args.triage_only:
            parser.error("--allow-unmarked-triage requires --triage-only")

        # Back-compat alias
        if args.dry_run_count:
            args.preview = True

    # ---- --check ----
    if getattr(args, "check", False):
        cmd_check(
            getattr(args, "semgrep", None),
            getattr(args, "semgrep_rules", None),
        )
        return

    # ---- --triage-only ----
    if getattr(args, "triage_only", None):
        semgrep_path, semgrep_rules = _semgrep_or_exit(
            getattr(args, "semgrep", None),
            getattr(args, "semgrep_rules", None),
            validate_rules=not getattr(args, "semgrep_prevalidated", False),
        )
        try:
            triage_root = _validate_triage_root(
                args.triage_only,
                allow_unmarked=getattr(args, "allow_unmarked_triage", False),
            )
        except ValueError as exc:
            print(f"  [ERROR] {exc}", file=sys.stderr)
            sys.exit(2)
        live_requested = (
            getattr(args, "confirm_delete", False)
            and not getattr(args, "triage_dry_run", False)
        )
        if live_requested and _root_marker_state(triage_root / ROOT_MARKER_FILE) != "valid":
            if not _confirm_exact_path(triage_root, "adopt this root and allow live deletion"):
                print("  Cancelled — exact path did not match.", file=sys.stderr)
                sys.exit(2)
            try:
                triage_root = _ensure_hunter_root(triage_root, adopt_existing=True)
            except (OSError, ValueError) as exc:
                print(f"  [ERROR] Could not adopt triage root: {exc}", file=sys.stderr)
                sys.exit(2)
        req_workers = getattr(args, "triage_workers", 2)
        mem_mb = getattr(args, "triage_mem_mb", 1024)
        safe_w, warn = _safe_triage_workers(req_workers, mem_mb)
        if warn:
            print(f"  [WARN] {warn}", file=sys.stderr)
        run_triage(
            output_dir=str(triage_root),
            semgrep_path=semgrep_path,
            semgrep_rules=semgrep_rules,
            workers=safe_w,
            timeout=getattr(args, "triage_timeout", 120),
            mem_mb=mem_mb,
            dry_run=(getattr(args, "triage_dry_run", False)
                     or not getattr(args, "confirm_delete", False)),
            keep_extracted=getattr(args, "keep_extracted", False),
            max_age_years=getattr(args, "min_updated_years", 2),
            allow_unmarked=getattr(args, "allow_unmarked_triage", False),
        )
        print("  [DONE] Happy hunting!\n")
        return

    semgrep_path: str | None = None
    semgrep_rules: Path | None = None
    use_patchstack = getattr(args, "patchstack", False)
    target_installs = 0  # only meaningful for wp.org tier mode
    installs_mode = "exact"

    if use_patchstack:
        # ---- Patchstack VDP source ----
        output_dir = getattr(args, "output", None) or "./wp_plugins_patchstack"
    else:
        # ---- --installs (exact) or --min-installs (threshold) required ----
        installs_arg = getattr(args, "installs", None)
        min_installs_arg = getattr(args, "min_installs", None)

        if not installs_arg and not min_installs_arg:
            print("  [ERROR] --installs or --min-installs is required (e.g. --installs 10K),\n"
                  "  or use --patchstack to source from the Patchstack VDP directory.\n"
                  "  Run without arguments for the interactive wizard.", file=sys.stderr)
            sys.exit(1)

        if min_installs_arg:
            installs_mode = "min"
            raw_value = min_installs_arg
        else:
            installs_mode = "exact"
            raw_value = installs_arg

        try:
            target_installs = parse_installs_input(raw_value)
        except ValueError:
            flag = "--min-installs" if installs_mode == "min" else "--installs"
            print(f"  [ERROR] Invalid {flag} value: {raw_value!r}\n"
                  "  Use: 1K, 5K, 10K, 100K, 1M (or numeric like 10000)", file=sys.stderr)
            sys.exit(1)
        if target_installs < 1:
            print("  [ERROR] Install threshold must be greater than zero.", file=sys.stderr)
            sys.exit(2)

        # Tier-snapping only makes sense for exact-match mode (wp.org tiers are
        # discrete buckets). In "min" mode any positive threshold is valid.
        if installs_mode == "exact" and target_installs not in VALID_TIERS:
            closest = min(VALID_TIERS, key=lambda x: abs(x - target_installs))
            print(f"  [INFO] {target_installs:,} is not a standard wp.org tier — "
                  f"using closest match: {format_installs(closest)} ({closest:,})")
            target_installs = closest

        folder_tag = format_installs(target_installs).replace("+", "")
        if installs_mode == "min":
            folder_tag = f"min{folder_tag}"
        output_dir = getattr(args, "output", None) or f"./wp_plugins_{folder_tag}"

    # Validate Semgrep before collection/download, but only for a run that will
    # actually reach auto-triage.
    if (
        getattr(args, "auto_triage", False)
        and not getattr(args, "preview", False)
        and not getattr(args, "no_download", False)
    ):
        semgrep_path, semgrep_rules = _semgrep_or_exit(
            getattr(args, "semgrep", None),
            getattr(args, "semgrep_rules", None),
            validate_rules=not getattr(args, "semgrep_prevalidated", False),
        )

    max_workers = min(getattr(args, "workers", 3), 5)
    if getattr(args, "workers", 3) > 5:
        print("  [INFO] --workers capped at 5 (to be respectful to WordPress.org)")
    api_workers = min(getattr(args, "api_workers", API_PARALLEL_WORKERS), MAX_API_WORKERS)
    if getattr(args, "api_workers", API_PARALLEL_WORKERS) > MAX_API_WORKERS:
        print(f"  [INFO] --api-workers capped at {MAX_API_WORKERS}")
    max_download_bytes = getattr(args, "max_download_mb", MAX_DOWNLOAD_BYTES) * 1024 * 1024

    adopt_output_root = getattr(args, "adopt_output_root", False)
    if _requires_exact_adoption_confirmation(
        output_dir,
        adopt_output_root,
        getattr(args, "interactive_approval", False),
    ) and not _confirm_exact_path(
        output_dir, "adopt this non-empty folder as a hunter root"
    ):
        print("  Cancelled — exact path did not match.", file=sys.stderr)
        sys.exit(2)
    try:
        output_dir = str(
            _ensure_hunter_root(output_dir, adopt_existing=adopt_output_root)
        )
    except (OSError, ValueError) as exc:
        print(f"  [ERROR] Invalid output root: {exc}", file=sys.stderr)
        sys.exit(2)

    # ---- Reset manifest ----
    if getattr(args, "reset_manifest", False):
        mp = Path(output_dir) / MANIFEST_FILE
        if mp.is_symlink() or (mp.exists() and not mp.is_file()):
            print(f"  [ERROR] Refusing unsafe manifest path: {mp}", file=sys.stderr)
            sys.exit(2)
        if mp.exists():
            if not getattr(args, "force", False):
                print(f"  Reset manifest at {mp}?")
                print("  This means all plugins will be re-downloaded on the next run.")
                if _ask_choice("Reset manifest?", ["no", "yes"], "no") != "yes":
                    print("  Cancelled.")
                    sys.exit(0)
            mp.unlink()
            print(f"  Manifest cleared: {mp}")
        else:
            print(f"  No manifest found at: {mp}")

    # ---- Collect ----
    if use_patchstack:
        plugins = collect_patchstack_plugins(
            min_boost=getattr(args, "min_boost", 0),
            min_updated_years=getattr(args, "min_updated_years", 2),
            since=getattr(args, "since", None),
            include_themes=getattr(args, "include_themes", False),
            api_workers=api_workers,
            max_entries=getattr(args, "limit", None),
        )
    else:
        plugins = collect_plugins(
            target_installs=target_installs,
            browse=getattr(args, "browse", "popular"),
            max_pages=getattr(args, "pages", 50),
            search=getattr(args, "search", None),
            tag=getattr(args, "tag", None),
            api_workers=api_workers,
            min_updated_years=getattr(args, "min_updated_years", 2),
            since=getattr(args, "since", None),
            installs_mode=installs_mode,
        )

    if not plugins:
        if use_patchstack:
            print("  [!] No Patchstack VDP plugins matched.\n"
                  "  Try: lower --min-boost, or --include-themes\n", file=sys.stderr)
        else:
            print("  [!] No plugins found.\n"
                  "  Try: --browse popular  |  --pages 200  |  a different --installs tier\n",
                  file=sys.stderr)
        sys.exit(0)

    print_summary_table(plugins, quiet=getattr(args, "quiet", False))

    limit = getattr(args, "limit", None)
    if limit and limit < len(plugins):
        print(f"\n  Limit active: processing {limit} of {len(plugins)} plugins")
        plugins = plugins[:limit]

    print()
    if use_patchstack:
        export_patchstack_results(plugins, output_dir)
    else:
        export_results(plugins, output_dir, target_installs)

    # ---- Download ----
    preview = getattr(args, "preview", False)
    no_download = getattr(args, "no_download", False)

    if not no_download:
        if preview:
            manifest = DownloadManifest(Path(output_dir))
            nd = sum(1 for p in plugins if not manifest.is_downloaded(p["slug"]))
            ns = len(plugins) - nd
            print(f"\n  Preview (--preview): {nd} to download, {ns} already cached\n")
        else:
            # Build global slug index unless explicitly disabled.
            no_dedup = getattr(args, "no_global_dedup", False)
            global_slugs: set[str] | None = None
            if not no_dedup and not getattr(args, "force", False):
                parent = str(Path(output_dir).parent)
                global_slugs = build_global_slug_index(parent)
                # Remove slugs already in THIS output_dir (those are manifest hits, not cross-folder)
                this_dir = Path(output_dir)
                if this_dir.is_dir():
                    for d in this_dir.iterdir():
                        if d.is_dir() and not d.is_symlink():
                            global_slugs.discard(d.name)
                if global_slugs:
                    print(
                        f"  [INFO] Global dedup active — {len(global_slugs)} slugs "
                        "already in sibling folders will be skipped."
                    )
            download_all(
                plugins=plugins,
                output_dir=output_dir,
                max_workers=max_workers,
                skip_existing=not getattr(args, "force", False),
                update_check=getattr(args, "update_check", False),
                global_slugs=global_slugs,
                max_bytes=max_download_bytes,
            )
            # Hint about next steps
            if not getattr(args, "auto_triage", False):
                print(
                    f"  Next steps:\n"
                    f"    • Run triage:  python {Path(__file__).name}"
                    f" --triage-only {output_dir}\n"
                    f"    • Commit no-candidate deletion: add --confirm-delete\n"
                )
    else:
        print("  Download skipped (--no-download)")

    # ---- Auto-triage ----
    if getattr(args, "auto_triage", False) and not preview and not no_download:
        req_workers = getattr(args, "triage_workers", 2)
        mem_mb = getattr(args, "triage_mem_mb", 1024)
        safe_w, warn = _safe_triage_workers(req_workers, mem_mb)
        if warn:
            print(f"  [WARN] {warn}", file=sys.stderr)
        run_triage(
            output_dir=output_dir,
            semgrep_path=semgrep_path,
            semgrep_rules=semgrep_rules or SEMGREP_RULES_DEFAULT,
            workers=safe_w,
            timeout=getattr(args, "triage_timeout", 120),
            mem_mb=mem_mb,
            dry_run=(getattr(args, "triage_dry_run", False)
                     or not getattr(args, "confirm_delete", False)),
            keep_extracted=getattr(args, "keep_extracted", False),
            max_age_years=getattr(args, "min_updated_years", 2),
        )

    print("  [DONE] Happy hunting!\n")


if __name__ == "__main__":
    main()
