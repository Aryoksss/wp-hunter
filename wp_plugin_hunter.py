"""
WordPress Plugin Hunter - Auto Download by Active Installs
===========================================================
Script untuk bug bounty researcher yang ingin download plugin WordPress
berdasarkan jumlah active installations.

Quick start (no flags needed — interactive mode):
  python wp_plugin_hunter.py

One-liner download + triage:
  python wp_plugin_hunter.py --installs 10K --auto-triage

Common workflows:
  # Download only
  python wp_plugin_hunter.py --installs 10K --pages 50

  # Preview what would be downloaded (no actual download)
  python wp_plugin_hunter.py --installs 10K --preview

  # Download + auto triage (preview deletions first)
  python wp_plugin_hunter.py --installs 10K --auto-triage --triage-dry-run

  # Download + auto triage (commit deletions)
  python wp_plugin_hunter.py --installs 10K --auto-triage

  # Triage only an existing folder
  python wp_plugin_hunter.py --triage-only "Z:\\Pentest\\Plugin\\wp_plugins_10K"

  # Search + download
  python wp_plugin_hunter.py --installs 5K --search "file manager"

  # Check setup (dependencies + taint-scan path)
  python wp_plugin_hunter.py --check

All flags:
  --installs VALUE        Active installs tier: 1K, 5K, 10K, 100K, 1M …
  --browse MODE           Sort: popular | new | updated | top-rated (default: popular)
  --pages N               Max API pages (100 plugins/page, default: 50)
  --api-workers N         Parallel API fetchers (default: 5)
  --search KEYWORD        Search by keyword (overrides --browse)
  --tag TAG               Filter by tag
  --output DIR            Output folder (default: ./wp_plugins_<tier>/)
  --workers N             Download threads (default: 3, max: 5)
  --limit N               Cap number of plugins downloaded
  --preview               Show what would download without downloading
  --no-download           Skip download entirely (collect + export list only)
  --update-check          Re-download if a newer version exists on wp.org
  --force                 Re-download even if file already exists on disk
  --reset-manifest        Forget all downloaded plugins (re-downloads on next run)
  --auto-triage           After download: scan & delete folders with no vuln findings
  --triage-only DIR       Triage an existing folder without downloading anything
  --triage-workers N      Parallel scan workers (default: 4)
  --triage-timeout N      Per-plugin scan timeout seconds (default: 120)
  --triage-dry-run        Triage: show what would be deleted, don't actually delete
  --keep-extracted        Keep extracted/ folders after triage (default: clean up)
  --taint-scan PATH       Path to taint-scan.exe (auto-detected if omitted)
  --check                 Verify setup (dependencies, taint-scan path) then exit
  --quiet                 Suppress plugin list table, show only progress + summary
"""

import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path

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
MANIFEST_FILE = "downloaded_slugs.json"

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
    Each taint-scan process can burst to 2-3× mem_mb_per_worker on mega-plugins.
    We use a 2.5× burst factor as a conservative estimate.
    """
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

_TAINT_SCAN_CANDIDATES = [
    Path(__file__).parent / "wp-taint-scan" / "bin" / "taint-scan.exe",
    Path(__file__).parent / "wp-taint-scan" / "taint-scan.exe",
]


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
            line += f"  {message[:avail]}"
        if self._is_tty:
            sys.stdout.write(f"\r{line}")
            sys.stdout.flush()
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
        if self._path.exists():
            try:
                with open(self._path, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2, ensure_ascii=False)
            os.replace(tmp, self._path)
        except OSError:
            tmp.unlink(missing_ok=True)
            raise

    def is_downloaded(self, slug: str) -> bool:
        return slug in self._data

    def get_version(self, slug: str) -> str:
        return self._data.get(slug, {}).get("version", "")

    def mark_downloaded(self, slug: str, filename: str, size_kb: int, version: str) -> None:
        with self._lock:
            self._data[slug] = {
                "filename": filename,
                "size_kb": size_kb,
                "version": version,
                "downloaded_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self._save()

    def remove(self, slug: str) -> None:
        with self._lock:
            if slug in self._data:
                del self._data[slug]
                self._save()

    def count(self) -> int:
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
    value = value.strip().upper().replace("+", "").replace(",", "")
    if value.endswith("M"):
        return int(float(value[:-1]) * 1_000_000)
    if value.endswith("K"):
        return int(float(value[:-1]) * 1_000)
    return int(value)


# ---------------------------------------------------------------------------
# Setup check
# ---------------------------------------------------------------------------

def cmd_check(taint_scan_path: str | None = None) -> None:
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
        print(f"  ✓ requests {_r.__version__}")
    except ImportError:
        print("  ✗ requests — not installed. Fix: pip install requests")
        all_ok = False

    # 3. taint-scan (optional — only needed for --auto-triage / --triage-only)
    ts = _find_taint_scan(taint_scan_path)
    if ts:
        print(f"  ✓ taint-scan  →  {ts}")
    else:
        print(
            "  ⚠ taint-scan — not found (optional — only needed for --auto-triage)\n"
            "    Build it:\n"
            "      git clone https://github.com/dimasma0305/wp-taint-scan\n"
            "      cd wp-taint-scan\n"
            "      go build -o bin/taint-scan ./cmd/taint-scan"
        )

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


# Aliases accepted as canonical choice values.
_CHOICE_ALIASES: dict[str, str] = {
    "y": "yes", "n": "no", "d": "dry-run", "dr": "dry-run",
    "p": "patchstack", "w": "wp.org",
}


def _ask_choice(prompt: str, choices: list[str], default: str) -> str:
    """Prompt with labelled choices. Enter accepts default; y/n/d are aliases."""
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
    ts = _find_taint_scan(None)
    ts_ok = _green("taint-scan ✓") if ts else _yellow("taint-scan ⚠ (optional)")
    return f"  {_dim('Setup:')}  python {sys.version.split()[0]}  |  {ts_ok}"


def interactive_wizard() -> "argparse.Namespace":
    """Full interactive wizard — runs when script is called with no flags."""
    import argparse

    _print_header()
    print(_check_status_line())
    print(_dim("\n  Press Enter to accept [defaults].  Ctrl-C to cancel.\n"))

    # ── Step 1: Source ────────────────────────────────────────────────────
    _print_section("Step 1 of 5  –  Choose plugin source")
    print(f"  {_bold('wp.org')}       Download by active installs tier  {_dim('(e.g. all 10K+ plugins)')}")
    print(f"  {_bold('patchstack')}   Download from Patchstack VDP directory  {_dim('(vendor opt-in, bounty bonuses)')}")
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

        # Patchstack defaults
        tier_str = "0"
        installs = 0
        pages = 1
        default_out = "./wp_plugins_patchstack"
    else:
        print(f"  {_dim('Tiers: 500  1K  2K  3K  5K  10K  50K  100K  1M')}")
        tier_str = _ask("Active installs tier", "10K")
        try:
            installs = parse_installs_input(tier_str)
        except ValueError:
            print(f"  {_yellow('Invalid — using 10K')}")
            tier_str, installs = "10K", 10000
        if installs not in VALID_TIERS:
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
        default_out = f"./wp_plugins_{format_installs(installs).replace('+', '')}"

    # ── Step 3: Output folder ────────────────────────────────────────────
    _print_section("Step 3 of 5  –  Output folder")
    output_dir = _ask("Save plugins to", default_out)

    # ── Step 4: Download options ─────────────────────────────────────────
    _print_section("Step 4 of 5  –  Download")
    do_download = _ask_choice("Download plugins?", ["yes", "no"], "yes") == "yes"

    # ── Step 5: Auto-triage ──────────────────────────────────────────────
    do_triage = False
    triage_dry = False
    if do_download:
        _print_section("Step 5 of 5  –  Auto-triage")
        print(f"  After downloading, scan each plugin with taint-scan and delete")
        print(f"  folders that have {_bold('zero in-scope findings')}.")
        print()
        print(f"  {_bold('yes')}       scan + delete clean folders  {_dim('(saves disk, irreversible)')}")
        print(f"  {_bold('dry-run')}   scan + report what would be deleted, nothing deleted")
        print(f"  {_bold('no')}        skip triage, download only  {_dim('(default — triage later anytime)')}")
        print()

        triage_ans = _ask_choice("Auto-triage", ["yes", "dry-run", "no"], "no")
        if triage_ans in ("yes", "dry-run"):
            do_triage = True
            triage_dry = triage_ans == "dry-run"
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
    else:
        est = pages * 100
        print(f"  Source     :  wp.org  tier {_bold(format_installs(installs))}  (~{est} plugins scanned)")

    if min_updated_years:
        print(f"  Date filter:  updated in last {min_updated_years} year(s)  (older plugins skipped)")
    else:
        print(f"  Date filter:  none  (all plugins included)")

    if limit:
        print(f"  Limit      :  {limit} plugins max")

    print(f"  Output     :  {output_dir}")
    print(f"  Download   :  {'yes' if do_download else 'no'}")

    if do_triage:
        if triage_dry:
            print(f"  Triage     :  {_yellow('dry-run')}  (scan only, no deletions)")
        else:
            print(f"  Triage     :  {_green('yes')}  (clean folders will be deleted)")
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
        installs=tier_str if not use_patchstack else None,
        patchstack=use_patchstack,
        min_boost=min_boost,
        include_themes=False,
        browse="popular",
        pages=pages,
        api_workers=API_PARALLEL_WORKERS,
        search=None,
        tag=None,
        output=output_dir,
        no_download=not do_download,
        workers=3,
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
        taint_scan=None,
        quiet=False,
        min_updated_years=min_updated_years,
        since=None,
        no_global_dedup=False,
        check=False,
    )
    return ns


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

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
            resp = requests.get(API_URL, params=params, timeout=30)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as exc:
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


def _fetch_wporg_plugin_info(slug: str) -> dict | None:
    """Fetch single-plugin metadata from wp.org (download_link, version, last_updated)."""
    params = {
        "action": "plugin_information",
        "request[slug]": slug,
        "request[fields][active_installs]": "true",
        "request[fields][last_updated]": "true",
        "request[fields][downloaded]": "true",
    }
    try:
        resp = requests.get(WP_PLUGIN_INFO_API, params=params, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        # wp.org returns {"error": "..."} for unknown/closed plugins
        if not isinstance(data, dict) or data.get("error") or not data.get("slug"):
            return None
        return data
    except requests.exceptions.RequestException:
        return None


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
        if slug and slug not in seen:
            seen.add(slug)
            entries.append(item)

    pag = (first.get("recentlyAdded", {}) or {}).get("pagination", {}) or {}
    last_page = int(pag.get("last_page", 1) or 1)
    for item in (first.get("recentlyAdded", {}) or {}).get("results", []):
        slug = item.get("slug", "")
        if slug and slug not in seen:
            seen.add(slug)
            entries.append(item)

    print(f"  VDP programs: {first.get('total', '?')} total ({last_page} pages)")
    bar = ProgressBar(total=last_page, label="VDP pages")
    bar.start()
    bar.update(message="page 1")

    for pg in range(2, last_page + 1):
        data = _patchstack_page(pg)
        if data:
            for item in (data.get("recentlyAdded", {}) or {}).get("results", []):
                slug = item.get("slug", "")
                if slug and slug not in seen:
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
    boost_dist = _Counter(int(e.get("boost", 0) or 0) for e in plugin_entries)
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
        if not include_themes and kind and kind != "plugin":
            continue
        if min_boost and int(e.get("boost", 0) or 0) < min_boost:
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
        info = _fetch_wporg_plugin_info(slug)
        if not info:
            return {"_offwporg": True, "slug": slug}
        last_updated = info.get("last_updated", "") or ""
        rec = _parse_plugin_record(info)
        # attach Patchstack bounty metadata
        rec["patchstack_boost"] = entry.get("boost", 0)
        rec["patchstack_max_bounty"] = entry.get("maxBounty", "")
        rec["patchstack_vendor"] = entry.get("vendor_contact", "")
        rec["last_updated"] = last_updated
        return rec

    with ThreadPoolExecutor(max_workers=api_workers) as ex:
        futs = {ex.submit(enrich, e): e for e in filtered}
        for fut in as_completed(futs):
            r = fut.result()
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
    results.sort(key=lambda r: (-int(r.get("patchstack_boost", 0) or 0),
                                -int(r.get("active_installs", 0) or 0)))

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
            return resp.json()
        except requests.exceptions.RequestException as exc:
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
        "active_installs": plugin.get("active_installs", 0),
        "downloaded": plugin.get("downloaded", 0),
        "last_updated": plugin.get("last_updated", ""),
        "author": extract_author_text(plugin.get("author", "")),
        "requires": plugin.get("requires", ""),
        "requires_php": plugin.get("requires_php", ""),
        "tested": plugin.get("tested", ""),
        "download_link": plugin.get("download_link", ""),
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
        return datetime.now().replace(year=datetime.now().year - min_updated_years)
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
    cutoff_dt = _resolve_cutoff_date(min_updated_years, since)
    is_min_mode = installs_mode == "min"

    print(f"\n{'='*60}")
    print("  Collecting plugins from WordPress.org")
    installs_label = f">= {format_installs(target_installs)}" if is_min_mode else format_installs(target_installs)
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
    total_pages = max(info.get("pages", 1), 1)
    total_results = info.get("results", 0)
    actual_pages = min(max_pages, total_pages)

    print(f"  Directory total : {total_results:,} plugins ({total_pages} pages)")
    print(f"  Will fetch      : up to {actual_pages} pages using {api_workers} workers\n")

    pages_data: dict[int, list] = {1: first.get("plugins", [])}

    # Early-exit heuristic only applies to exact-tier mode without tag/search,
    # where results are sorted by popularity (installs descending). In "min"
    # mode or with tag/search, we always scan every requested page instead.
    if not search and not tag and not is_min_mode:
        p1_max = max((p.get("active_installs", 0) for p in pages_data[1]), default=0)
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
            if not search and not tag and not is_min_mode and pl:
                pg_max = max((p.get("active_installs", 0) for p in pl), default=0)
                if pg_max < target_installs:
                    early_exit.set()
            return pg, pl

        with ThreadPoolExecutor(max_workers=api_workers) as executor:
            fut_map: dict[Future, int] = {
                executor.submit(fetch_page, pg): pg for pg in pages_to_fetch
            }
            for fut in as_completed(fut_map):
                pg, result = fut.result()
                with lock:
                    if result is not None:
                        pages_data[pg] = result
                bar.update(message=f"page {pg} ✓")

        if early_exit.is_set():
            last_useful = max(
                (pg for pg, pl in pages_data.items()
                 if any(p.get("active_installs", 0) >= target_installs for p in pl)),
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
            installs = plugin.get("active_installs", 0)
            matches = (installs >= target_installs) if is_min_mode else (installs == target_installs)
            if not matches:
                continue
            slug = plugin.get("slug", "")
            if not slug or slug in seen_slugs:
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


# ---------------------------------------------------------------------------
# Single-plugin download
# ---------------------------------------------------------------------------

def build_global_slug_index(base_dir: str | None) -> set[str]:
    """
    Scan all wp_plugins_* sibling folders and return the set of slugs already
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
        if not folder.is_dir() or not folder.name.startswith("wp_plugins_"):
            continue
        for p in folder.iterdir():
            if p.is_dir() and not p.name.startswith(("_", ".")):
                seen.add(p.name)
    return seen


def download_plugin(
    plugin: dict, output_dir: str,
    skip_existing: bool = True,
    manifest: DownloadManifest | None = None,
    update_check: bool = False,
    global_slugs: set[str] | None = None,
) -> tuple[bool, str, str]:
    slug = plugin["slug"]
    download_url = plugin.get("download_link", "")
    if not download_url:
        return False, slug, "No download link"

    # Global dedup: skip if already present in any other wp_plugins_* folder.
    if skip_existing and global_slugs and slug in global_slugs:
        # Still record in manifest so future runs skip it too.
        if manifest and not manifest.is_downloaded(slug):
            filename = download_url.rstrip("/").split("/")[-1]
            manifest.mark_downloaded(slug, filename, 0, plugin.get("version", ""))
        return True, slug, "Already in another folder (dedup)"

    if skip_existing and manifest and manifest.is_downloaded(slug):
        if update_check:
            local_ver = manifest.get_version(slug)
            remote_ver = plugin.get("version", "")
            if not version_is_newer(remote_ver, local_ver):
                return True, slug, f"Up to date (v{local_ver})"
        else:
            return True, slug, "Already downloaded"

    plugin_dir = Path(output_dir) / slug
    plugin_dir.mkdir(parents=True, exist_ok=True)
    filename = download_url.rstrip("/").split("/")[-1]
    filepath = plugin_dir / filename

    if skip_existing and filepath.exists() and filepath.stat().st_size > 0:
        if manifest:
            manifest.mark_downloaded(slug, filename, filepath.stat().st_size // 1024, plugin.get("version", ""))
        return True, slug, "Already on disk"

    last_exc: Exception | None = None
    for attempt in range(1, DOWNLOAD_MAX_RETRIES + 1):
        try:
            resp = requests.get(download_url, timeout=60, stream=True)
            resp.raise_for_status()
            tmp_path = filepath.with_suffix(".part")
            with open(tmp_path, "wb") as fh:
                for chunk in resp.iter_content(chunk_size=8192):
                    fh.write(chunk)
            tmp_path.replace(filepath)
            last_exc = None
            break
        except Exception as exc:
            last_exc = exc
            if attempt < DOWNLOAD_MAX_RETRIES:
                time.sleep(2 ** attempt)

    if last_exc:
        return False, slug, f"Failed after {DOWNLOAD_MAX_RETRIES} attempts: {last_exc}"

    size_kb = filepath.stat().st_size // 1024
    expected_md5 = plugin.get("md5") or ""
    if expected_md5:
        actual_md5 = _md5_of_file(filepath)
        if actual_md5.lower() != expected_md5.lower():
            filepath.unlink(missing_ok=True)
            return False, slug, "MD5 mismatch — file deleted (corrupted download)"

    meta_file = plugin_dir / "plugin_info.json"
    with open(meta_file, "w", encoding="utf-8") as fh:
        json.dump(plugin, fh, indent=2, ensure_ascii=False)
    if manifest:
        manifest.mark_downloaded(slug, filename, size_kb, plugin.get("version", ""))

    md5_note = " ✓md5" if expected_md5 else ""
    return True, slug, f"OK ({size_kb} KB) v{plugin.get('version', '')}{md5_note}"


# ---------------------------------------------------------------------------
# Batch download
# ---------------------------------------------------------------------------

def download_all(
    plugins: list[dict], output_dir: str,
    max_workers: int = 3, skip_existing: bool = True, update_check: bool = False,
    global_slugs: set[str] | None = None,
) -> None:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    manifest = DownloadManifest(Path(output_dir))

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
            executor.submit(download_plugin, p, output_dir, skip_existing, manifest, update_check, global_slugs): p
            for p in plugins
        }
        for future in as_completed(futures):
            ok, slug, msg = future.result()
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
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(plugins, fh, indent=2, ensure_ascii=False)

    csv_path = Path(output_dir) / f"{base_name}.csv"
    fieldnames = ["name", "slug", "version", "active_installs", "downloaded",
                  "last_updated", "author", "requires", "requires_php", "tested",
                  "download_link", "homepage", "tags"]
    if plugins:
        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for p in plugins:
                row = dict(p)
                row["tags"] = "|".join(p.get("tags") or [])
                writer.writerow(row)

    print(f"  Exported: {json_path.name}  +  {csv_path.name}")
    return json_path, csv_path


def export_patchstack_results(plugins: list[dict], output_dir: str) -> tuple[Path, Path]:
    """Export Patchstack VDP targets with boost/bounty columns, sorted by value."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    json_path = Path(output_dir) / "patchstack_targets.json"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(plugins, fh, indent=2, ensure_ascii=False)

    csv_path = Path(output_dir) / "patchstack_targets.csv"
    fields = ["patchstack_boost", "patchstack_max_bounty", "slug", "name",
              "version", "active_installs", "last_updated", "patchstack_vendor",
              "download_link"]
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for p in plugins:
            writer.writerow(p)

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
        print(f"  {i:<4} {p['name'][:41]:<42} {p['slug'][:29]:<30} "
              f"{p['version'][:7]:<8} {(p['last_updated'] or 'N/A')[:10]:<12}")
    if len(plugins) > 50:
        print(f"  … and {len(plugins) - 50} more  (full list in exported JSON/CSV)")


# ---------------------------------------------------------------------------
# taint-scan helpers
# ---------------------------------------------------------------------------

def _find_taint_scan(explicit: str | None) -> str | None:
    if explicit:
        if os.path.isfile(explicit):
            return explicit
        print(f"  [ERROR] taint-scan not found at: {explicit}", file=sys.stderr)
        return None
    for p in _TAINT_SCAN_CANDIDATES:
        if p.exists():
            return str(p)
    found = shutil.which("taint-scan") or shutil.which("taint-scan.exe")
    return found


def _taint_scan_or_exit(explicit: str | None) -> str:
    """Return taint-scan path or print a helpful error and exit."""
    ts = _find_taint_scan(explicit)
    if ts:
        return ts
    print(
        "\n  [ERROR] taint-scan.exe not found.\n"
        "  Build it with:\n"
        "    git clone https://github.com/dimasma0305/wp-taint-scan\n"
        "    cd wp-taint-scan\n"
        "    go build -o bin/taint-scan.exe ./cmd/taint-scan\n"
        "  Or pass: --taint-scan <path>\n",
        file=sys.stderr,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Triage logic (inline — no dependency on vuln_triage.py)
# ---------------------------------------------------------------------------

_IN_SCOPE_TIERS = {
    "unauthenticated", "nonce_only", "permission_callback",
    "authenticated", "unknown", "",
}
_TIER_WEIGHT = {
    "unauthenticated": 1000, "permission_callback": 700, "nonce_only": 600,
    "authenticated": 400, "unknown": 300, "": 300, "capability_checked": 50,
}


def _ensure_extracted(plugin_dir: str) -> str | None:
    ext_dir = os.path.join(plugin_dir, "extracted")
    if os.path.isdir(ext_dir) and os.listdir(ext_dir):
        return ext_dir
    # Find the best zip: prefer the one whose name most closely matches the folder name.
    zips = [
        os.path.join(plugin_dir, f)
        for f in os.listdir(plugin_dir)
        if f.lower().endswith(".zip")
    ]
    if not zips:
        php_here = any(f.lower().endswith(".php") for f in os.listdir(plugin_dir))
        return plugin_dir if php_here else None
    if len(zips) > 1:
        folder_name = os.path.basename(plugin_dir).lower()
        # Prefer zip whose stem matches the folder name, fall back to largest.
        named_match = next(
            (z for z in zips if Path(z).stem.lower().startswith(folder_name[:8])), None
        )
        zip_path = named_match or max(zips, key=os.path.getsize)
    else:
        zip_path = zips[0]
    try:
        os.makedirs(ext_dir, exist_ok=True)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(ext_dir)
        return ext_dir
    except Exception as e:
        print(f"  [WARN] Extract failed for {os.path.basename(plugin_dir)}: {e}", file=sys.stderr)
        return None


def _run_taint_scan(taint_scan: str, target_dir: str, timeout: int, mem_mb: int) -> tuple[list, str]:
    out_dir = tempfile.mkdtemp(prefix="tsc_")
    try:
        cmd = [taint_scan, "-target", target_dir, "-output-dir", out_dir,
               "-mem-limit-mb", str(mem_mb)]
        try:
            proc = subprocess.run(
                cmd, timeout=timeout, capture_output=True, check=False,
            )
            if proc.returncode not in (0, 1):  # 1 = findings found (normal)
                stderr_hint = proc.stderr.decode("utf-8", errors="replace")[:200].strip()
                return [], f"SCAN_ERR:{proc.returncode}" + (f" — {stderr_hint}" if stderr_hint else "")
        except subprocess.TimeoutExpired:
            return [], "TIMEOUT"
        except Exception as exc:
            return [], f"SCAN_ERR:{exc}"

        json_path = os.path.join(out_dir, "taint-results.json")
        if not os.path.isfile(json_path):
            return [], "NO_OUTPUT"
        with open(json_path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        return data.get("results", []) or [], "OK"
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def _classify(results: list) -> tuple[dict, dict, int]:
    tier_counts: dict[str, int] = {}
    check_counts: dict[str, int] = {}
    in_scope = 0
    for r in results:
        access = (r.get("extra", {}).get("context", {}) or {}).get("access", "") or ""
        check = r.get("check_id", "?")
        tier_counts[access] = tier_counts.get(access, 0) + 1
        check_counts[check] = check_counts.get(check, 0) + 1
        if access in _IN_SCOPE_TIERS:
            in_scope += 1
    return tier_counts, check_counts, in_scope


def _plugin_last_updated_year(plugin_dir: str) -> int | None:
    """
    Read last_updated from plugin_info.json in the plugin folder.
    Returns the year as int, or None if not available.
    wp.org format: "2024-03-15 10:30am GMT"
    """
    meta = os.path.join(plugin_dir, "plugin_info.json")
    if not os.path.isfile(meta):
        return None
    try:
        with open(meta, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        last_updated = data.get("last_updated", "")
        if last_updated and len(last_updated) >= 4:
            return int(last_updated[:4])
    except Exception:
        pass
    return None


def _triage_one(plugin_dir: str, taint_scan: str, timeout: int, mem_mb: int,
                max_age_years: int = 0) -> dict:
    name = os.path.basename(plugin_dir.rstrip("\\/"))
    res = dict(name=name, dir=plugin_dir, status="OK",
               total=0, in_scope=0, tiers={}, checks={}, keep=False)

    # Date filter: skip plugin that hasn't been updated within max_age_years.
    if max_age_years > 0:
        year = _plugin_last_updated_year(plugin_dir)
        cutoff = datetime.now().year - max_age_years
        if year is not None and year < cutoff:
            res["status"] = f"OUTDATED ({year})"
            res["keep"] = False
            return res
        # If no metadata at all, fall through and let the scan decide.

    target = _ensure_extracted(plugin_dir)
    if not target:
        # No source found — mark explicitly so the deletion reason is clear in report.
        res["status"] = "NO_SOURCE"
        res["keep"] = False
        return res

    results, status = _run_taint_scan(taint_scan, target, timeout, mem_mb)
    res["status"] = status
    # Conservative: keep on any scan failure so we never silently lose a target.
    if status != "OK":
        res["keep"] = True
        return res

    tiers, checks, in_scope = _classify(results)
    res.update(total=len(results), in_scope=in_scope, tiers=tiers, checks=checks)
    res["keep"] = in_scope > 0
    return res


def _fmt_triage_summary(res: dict) -> str:
    tier_str = " ".join(
        f"{t or 'empty'}={c}"
        for t, c in sorted(res["tiers"].items(), key=lambda kv: -_TIER_WEIGHT.get(kv[0], 100))
    )
    top = sorted(res["checks"].items(), key=lambda kv: -kv[1])[:4]
    check_str = ", ".join(f"{c}({n})" for c, n in top)
    return (
        f"{res['name']} | total={res['total']} in_scope={res['in_scope']}"
        + (f" | tiers: {tier_str}" if tier_str else "")
        + (f" | {check_str}" if check_str else "")
    )


def run_triage(
    output_dir: str, taint_scan: str,
    workers: int = 4, timeout: int = 120, mem_mb: int = 2048,
    dry_run: bool = False, keep_extracted: bool = False,
    max_age_years: int = 2,
) -> None:
    ts_fmt = datetime.now().strftime("%H:%M:%S")
    print(f"\n{'='*60}")
    print(f"  Vulnerability Triage  [{ts_fmt}]")
    print(f"  Folder   : {output_dir}")
    print(f"  Workers  : {workers}  |  Timeout: {timeout}s/plugin")
    cutoff_label = f"  Filter   : skip plugins last updated before {datetime.now().year - max_age_years} ({max_age_years}yr cutoff)"
    print(cutoff_label if max_age_years > 0 else "  Filter   : no date filter (scanning all)")
    print(f"  Mode     : {'DRY RUN — nothing will be deleted' if dry_run else 'LIVE — clean folders will be deleted'}")
    print(f"{'='*60}")

    plugin_dirs = sorted(
        os.path.join(output_dir, d)
        for d in os.listdir(output_dir)
        if os.path.isdir(os.path.join(output_dir, d)) and not d.startswith("_")
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
            executor.submit(_triage_one, d, taint_scan, timeout, mem_mb, max_age_years): d
            for d in plugin_dirs
        }
        for fut in as_completed(fut_map):
            try:
                r = fut.result()
            except Exception as exc:
                d = fut_map[fut]
                r = dict(name=os.path.basename(d), dir=d, status=f"CRASH:{exc}",
                         total=0, in_scope=0, tiers={}, checks={}, keep=True)
            results.append(r)
            flag = "KEEP" if r["keep"] else "DEL "
            status_note = f" [{r['status']}]" if r["status"] not in ("OK", "NO_SOURCE") else ""
            bar.update(message=f"[{flag}] {r['name']} ({r['in_scope']}/{r['total']}){status_note}")

    bar.finish("Scan complete")

    keep = [r for r in results if r["keep"]]
    delete = [r for r in results if not r["keep"]]
    vuln = sorted(
        [r for r in keep if r["in_scope"] > 0],
        key=lambda r: (
            -r["in_scope"],
            -max((_TIER_WEIGHT.get(t, 100) for t in r["tiers"]), default=0),
            -r["total"],
        ),
    )
    no_source  = [r for r in delete if r["status"] == "NO_SOURCE"]
    outdated   = [r for r in delete if r["status"].startswith("OUTDATED")]
    scan_fail  = [r for r in keep if r["in_scope"] == 0 and r["status"] != "OK"]

    # ---- Confirmation prompt before live deletions ----
    if not dry_run and delete:
        outdated_count = len(outdated)
        clean_count = len(delete) - len(no_source) - outdated_count
        print(f"\n  About to delete {len(delete)} folders:")
        if outdated_count:
            print(f"    {outdated_count} outdated (last_updated older than {max_age_years} years)")
        if len(no_source):
            print(f"    {len(no_source)} with no source files")
        if clean_count:
            print(f"    {clean_count} with 0 in-scope findings after scan")
        for r in delete[:8]:
            if r["status"].startswith("OUTDATED"):
                reason = f"({r['status']})"
            elif r["status"] == "NO_SOURCE":
                reason = "(no source files)"
            else:
                reason = "(0 in-scope findings)"
            print(f"    - {r['name']} {reason}")
        if len(delete) > 8:
            print(f"    … and {len(delete) - 8} more")
        print()
        try:
            ans = input("  Press Enter to confirm deletions, or type 'no' to abort: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            ans = "no"
        if ans in ("no", "n"):
            print("  Aborted — no folders were deleted.")
            print(f"  Tip: re-run with --triage-dry-run to preview without confirming.\n")
            dry_run = True

    # ---- Write report ----
    report_path = os.path.join(output_dir, "vuln_report.txt")
    names_path = os.path.join(output_dir, "vuln_plugins.txt")
    deleted_path = os.path.join(output_dir, "deleted_plugins.txt")

    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write("WP Plugin Vulnerability Triage Report\n")
        fh.write(f"Generated : {datetime.now().isoformat(timespec='seconds')}\n")
        fh.write(f"Folder    : {output_dir}\n")
        if max_age_years > 0:
            fh.write(f"Date filter: plugins updated before {datetime.now().year - max_age_years} are skipped\n")
        fh.write(f"Scanned   : {total}  |  Vuln: {len(vuln)}  |  "
                 f"Outdated (skipped): {len(outdated)}  |  "
                 f"Scan-fail/timeout: {len(scan_fail)}  |  "
                 f"{'Would delete' if dry_run else 'Deleted'}: {len(delete)}\n")
        fh.write("=" * 70 + "\n\n")

        if vuln:
            fh.write("PLUGINS WITH POTENTIAL VULNERABILITIES (priority order):\n")
            fh.write("-" * 70 + "\n")
            for r in vuln:
                fh.write(_fmt_triage_summary(r) + "\n")
            fh.write("\n")

        if outdated:
            fh.write(f"SKIPPED — OUTDATED (last_updated older than {max_age_years} years):\n")
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
            fh.write("DELETED — NO SOURCE FILES FOUND (zip missing or empty):\n")
            fh.write("-" * 70 + "\n")
            for r in no_source:
                fh.write(f"  {r['name']}\n")
            fh.write("\n")

    with open(names_path, "w", encoding="utf-8") as fh:
        for r in vuln:
            fh.write(r["name"] + "\n")

    # ---- Perform deletions ----
    deleted_names: list[str] = []
    for r in delete:
        if dry_run:
            deleted_names.append(r["name"])
            continue
        try:
            shutil.rmtree(r["dir"])
            deleted_names.append(r["name"])
        except Exception as exc:
            print(f"  [WARN] Could not delete {r['name']}: {exc}", file=sys.stderr)

    if not dry_run and not keep_extracted:
        for r in keep:
            ext = os.path.join(r["dir"], "extracted")
            if os.path.isdir(ext):
                shutil.rmtree(ext, ignore_errors=True)

    marker = "DRY RUN — NOT DELETED" if dry_run else "DELETED"
    with open(deleted_path, "w", encoding="utf-8") as fh:
        fh.write(f"# {marker} — {datetime.now().isoformat(timespec='seconds')}\n")
        for n in sorted(deleted_names):
            fh.write(n + "\n")

    # ---- Final summary ----
    print(f"\n{'='*60}")
    print("  Triage complete")
    print(f"    Potential vulns  : {len(vuln)}")
    print(f"    Kept for review  : {len(scan_fail)}  (scan failed/timed out)")
    if len(outdated):
        print(f"    Outdated/skipped : {len(outdated)}  (updated before {datetime.now().year - max_age_years})")
    print(f"    {'Would delete' if dry_run else 'Deleted'}     : {len(deleted_names)}")
    print(f"    Report           : {report_path}")
    print(f"    Vuln names list  : {names_path}")
    if dry_run:
        print(f"\n  This was a DRY RUN. Re-run without --triage-dry-run to commit deletions.")
    if vuln:
        print(f"\n  Top findings:")
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
  %(prog)s --installs 10K                   # download 10K+ plugins
  %(prog)s --installs 10K --auto-triage     # download + scan + delete clean
  %(prog)s --installs 10K --auto-triage --triage-dry-run   # preview deletions
  %(prog)s --triage-only ./wp_plugins_10K   # triage existing folder

Tip: run without --installs to enter the interactive setup wizard.
            """,
        )

        parser.add_argument("--installs", type=str, default=None,
                            help="Active installs tier: 1K, 5K, 10K, 50K, 100K, 1M "
                                 "(exact match — use --min-installs for threshold mode)")
        parser.add_argument("--min-installs", type=str, default=None,
                            help="Active installs threshold: 1K, 5K, 10K … Matches plugins "
                                 "with installs >= this value instead of an exact tier. "
                                 "Recommended when combining with --tag/--search, since a "
                                 "niche tag rarely has plugins at an EXACT install count.")
        parser.add_argument("--patchstack", action="store_true",
                            help="Source plugins from the Patchstack VDP directory "
                                 "(vendor opt-in targets, often with bounty boost). "
                                 "Ignores --installs/--browse.")
        parser.add_argument("--min-boost", type=int, default=0,
                            help="Patchstack: only plugins with bounty boost >= N%% (e.g. 25)")
        parser.add_argument("--include-themes", action="store_true",
                            help="Patchstack: include themes too (default: plugins only)")
        parser.add_argument("--browse", type=str, default="popular",
                            choices=["popular", "new", "updated", "top-rated"])
        parser.add_argument("--pages", type=int, default=50,
                            help="Max API pages (100 plugins/page, default: 50)")
        parser.add_argument("--api-workers", type=int, default=API_PARALLEL_WORKERS,
                            help=f"Parallel API fetchers (default: {API_PARALLEL_WORKERS})")
        parser.add_argument("--search", type=str, default=None)
        parser.add_argument("--tag", type=str, default=None)
        parser.add_argument("--output", type=str, default=None,
                            help="Output folder (default: ./wp_plugins_<tier>/)")
        parser.add_argument("--no-download", action="store_true",
                            help="Skip download — collect and export list only")
        parser.add_argument("--workers", type=int, default=3,
                            help="Download threads (default: 3, max: 5)")
        parser.add_argument("--limit", type=int, default=None)
        parser.add_argument("--preview", action="store_true",
                            help="Show download plan (what would be fetched) without downloading")
        parser.add_argument("--force", action="store_true",
                            help="Re-download even if file already exists on disk")
        parser.add_argument("--no-global-dedup", action="store_true",
                            help="Disable cross-folder deduplication (by default, slugs "
                                 "already downloaded in any wp_plugins_* sibling folder are skipped)")
        parser.add_argument("--update-check", action="store_true",
                            help="Re-download if a newer version is available on wp.org")
        parser.add_argument("--dry-run-count", action="store_true",
                            help=argparse.SUPPRESS)  # kept for back-compat, alias of --preview
        parser.add_argument("--reset-manifest", action="store_true",
                            help="Clear download cache (re-downloads all on next run)")
        parser.add_argument("--auto-triage", action="store_true",
                            help="After download: scan & delete folders with no vuln findings")
        parser.add_argument("--triage-only", type=str, default=None, metavar="DIR",
                            help="Skip download; run triage on an existing folder")
        parser.add_argument("--triage-workers", type=int, default=2,
                            help="Parallel scan workers (default: 2, increase carefully — each worker can use 1-3 GB RAM)")
        parser.add_argument("--triage-timeout", type=int, default=120,
                            help="Per-plugin scan timeout seconds (default: 120)")
        parser.add_argument("--triage-mem-mb", type=int, default=1024,
                            help="Soft heap limit per taint-scan process MB (default: 1024)")
        parser.add_argument("--triage-dry-run", action="store_true",
                            help="Triage: show what would be deleted without deleting")
        parser.add_argument("--min-updated-years", type=int, default=2,
                            help="Only include plugins updated within last N years "
                                 "(applies to both download and triage). Default: 2. Set 0 to disable.")
        parser.add_argument("--since", type=str, default=None,
                            help="Only include plugins updated on/after this date "
                                 "(YYYY-MM-DD, or YYYY-MM, or YYYY). Overrides --min-updated-years "
                                 "when both are given. Example: --since 2025-01-01")
        parser.add_argument("--keep-extracted", action="store_true",
                            help="Keep extracted/ subfolders after triage")
        parser.add_argument("--taint-scan", type=str, default=None,
                            help="Path to taint-scan.exe (auto-detected if omitted)")
        parser.add_argument("--check", action="store_true",
                            help="Verify all dependencies and taint-scan path, then exit")
        parser.add_argument("--quiet", action="store_true",
                            help="Suppress plugin list table; show only progress + summary")

        args = parser.parse_args()

        # Back-compat alias
        if args.dry_run_count:
            args.preview = True

    # ---- --check ----
    if getattr(args, "check", False):
        cmd_check(getattr(args, "taint_scan", None))
        return

    # ---- --triage-only ----
    if getattr(args, "triage_only", None):
        ts = _taint_scan_or_exit(getattr(args, "taint_scan", None))
        req_workers = getattr(args, "triage_workers", 2)
        mem_mb = getattr(args, "triage_mem_mb", 1024)
        safe_w, warn = _safe_triage_workers(req_workers, mem_mb)
        if warn:
            print(f"  [WARN] {warn}", file=sys.stderr)
        run_triage(
            output_dir=args.triage_only,
            taint_scan=ts,
            workers=safe_w,
            timeout=getattr(args, "triage_timeout", 120),
            mem_mb=mem_mb,
            dry_run=getattr(args, "triage_dry_run", False),
            keep_extracted=getattr(args, "keep_extracted", False),
            max_age_years=getattr(args, "min_updated_years", 2),
        )
        print("  [DONE] Happy hunting!\n")
        return

    # ---- Validate taint-scan early when --auto-triage is requested ----
    taint_scan_path: str | None = None
    if getattr(args, "auto_triage", False):
        taint_scan_path = _taint_scan_or_exit(getattr(args, "taint_scan", None))

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

    max_workers = min(getattr(args, "workers", 3), 5)
    if getattr(args, "workers", 3) > 5:
        print("  [INFO] --workers capped at 5 (to be respectful to WordPress.org)")

    # ---- Reset manifest ----
    if getattr(args, "reset_manifest", False):
        mp = Path(output_dir) / MANIFEST_FILE
        if mp.exists():
            if not getattr(args, "force", False):
                try:
                    ans = input(
                        f"  Reset manifest at {mp}?\n"
                        "  This means all plugins will be re-downloaded on the next run.\n"
                        "  Type 'yes' or press Enter to confirm: "
                    ).strip().lower()
                except (KeyboardInterrupt, EOFError):
                    ans = ""
                if ans not in ("yes", "y", ""):
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
            api_workers=getattr(args, "api_workers", API_PARALLEL_WORKERS),
            max_entries=getattr(args, "limit", None),
        )
    else:
        plugins = collect_plugins(
            target_installs=target_installs,
            browse=getattr(args, "browse", "popular"),
            max_pages=getattr(args, "pages", 50),
            search=getattr(args, "search", None),
            tag=getattr(args, "tag", None),
            api_workers=getattr(args, "api_workers", API_PARALLEL_WORKERS),
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
                        if d.is_dir():
                            global_slugs.discard(d.name)
                if global_slugs:
                    print(f"  [INFO] Global dedup active — {len(global_slugs)} slugs already in sibling folders will be skipped.")
            download_all(
                plugins=plugins,
                output_dir=output_dir,
                max_workers=max_workers,
                skip_existing=not getattr(args, "force", False),
                update_check=getattr(args, "update_check", False),
                global_slugs=global_slugs,
            )
            # Hint about next steps
            if not getattr(args, "auto_triage", False):
                print(
                    f"  Next steps:\n"
                    f"    • Run triage:  python {Path(__file__).name}"
                    f" --triage-only {output_dir}\n"
                    f"    • Preview:     add --triage-dry-run first\n"
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
            taint_scan=taint_scan_path,
            workers=safe_w,
            timeout=getattr(args, "triage_timeout", 120),
            mem_mb=mem_mb,
            dry_run=getattr(args, "triage_dry_run", False),
            keep_extracted=getattr(args, "keep_extracted", False),
            max_age_years=getattr(args, "min_updated_years", 2),
        )

    print("  [DONE] Happy hunting!\n")


if __name__ == "__main__":
    main()
