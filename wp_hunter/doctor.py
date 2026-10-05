from __future__ import annotations

import shutil
import sys
from pathlib import Path

from .constants import REQUESTS_MIN_VERSION, SEMGREP_RULES_DEFAULT
from .semgrep_adapter import validate_semgrep_config as _validate_semgrep_config
from .semgrep_locate import (
    find_semgrep,
    indent_lines,
    semgrep_install_hint,
)
from .validation import numeric_version_tuple


def safe_triage_workers(requested: int, mem_mb_per_worker: int) -> tuple[int, str]:
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

        requests_ok = numeric_version_tuple(_r.__version__) >= REQUESTS_MIN_VERSION
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
    sg = find_semgrep(semgrep_path)
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
            print(indent_lines(semgrep_install_hint(), "    "))
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
