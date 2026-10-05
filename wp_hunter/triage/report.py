from __future__ import annotations

from datetime import datetime
from pathlib import Path

from ..core import _display_text
from ..fsutil import atomic_text_file as _atomic_text_file
from ..fsutil import atomic_write_json as _atomic_write_json
from ..fsutil import atomic_write_text as _atomic_write_text
from ..mappings import as_dict
from ..triage_schema import (
    CANDIDATES_FILE,
    DELETED_FILE,
    REPORT_FILE,
    RESULTS_FILE,
    TRIAGE_SCHEMA_VERSION,
)
from .engine import TIER_WEIGHT


def fmt_triage_summary(res: dict) -> str:
    tier_str = " ".join(
        f"{_display_text(t or 'empty')}={c}"
        for t, c in sorted(res["tiers"].items(), key=lambda kv: -TIER_WEIGHT.get(kv[0], 100))
    )
    top = sorted(res["checks"].items(), key=lambda kv: -kv[1])[:4]
    check_str = ", ".join(f"{_display_text(c)}({n})" for c, n in top)
    return (
        f"{_display_text(res['name'])} | total={res['total']} in_scope={res['in_scope']}"
        + (f" | tiers: {tier_str}" if tier_str else "")
        + (f" | {check_str}" if check_str else "")
    )


def fmt_finding(finding: dict) -> str:
    file_name = _display_text(finding.get("file", "?"), 180) or "?"
    line = _display_text(finding.get("line", "?"), 20) or "?"
    rule = _display_text(finding.get("check_id", "?"), 120) or "?"
    category = _display_text(finding.get("category", "unknown"), 60) or "unknown"
    confidence = _display_text(finding.get("confidence", "unknown"), 30) or "unknown"
    access = "unknown"
    extra = as_dict(finding.get("extra"))
    context = as_dict(extra.get("context"))
    if context.get("access"):
        access = _display_text(context["access"], 40)
    message = _display_text(finding.get("message", ""), 240)
    detail = (
        f"    - {file_name}:{line} | rule={rule} | category={category} | "
        f"confidence={confidence} | access={access}"
    )
    return detail + (f" | {message}" if message else "")


def build_results_payload(
    *,
    language: str,
    rules_path: str,
    generated: str,
    dry_run: bool,
    workers: int,
    timeout: int,
    mem_mb: int,
    max_age_years: int,
    since: str | None,
    summary: dict,
    results: list[dict],
) -> dict:
    return {
        "schema_version": TRIAGE_SCHEMA_VERSION,
        "language": language,
        "engine": "semgrep",
        "rules": str(rules_path),
        "generated_at": generated,
        "dry_run": dry_run,
        "scan": {
            "workers": workers,
            "timeout": timeout,
            "memory_mb": mem_mb,
            "max_age_years": max_age_years,
            "since": since,
        },
        "summary": summary,
        "results": sorted(results, key=lambda item: item.get("name", "")),
    }


def write_results_json(root: Path, payload: dict) -> Path:
    json_path = root / RESULTS_FILE
    _atomic_write_json(json_path, payload)
    return json_path


def write_report(
    *,
    root: Path,
    output_dir: str,
    rules_path: str,
    generated: str,
    cutoff_dt: datetime | None,
    language: str,
    dry_run: bool,
    total: int,
    vuln: list[dict],
    delete: list[dict],
    scan_fail: list[dict],
    no_source: list[dict],
    outdated: list[dict],
    unknown_date: list[dict],
    deletion_failures: list[dict],
    action_names: list[str],
) -> Path:
    indonesian = language == "id"

    def local(english: str, indonesia: str) -> str:
        return indonesia if indonesian else english

    report_path = root / REPORT_FILE
    action_label = "Would delete" if dry_run else "Deleted"
    with _atomic_text_file(report_path) as fh:
        fh.write(
            local("WP Plugin Semgrep Triage Report\n", "Laporan Triage Semgrep Plugin WordPress\n")
        )
        fh.write(f"{local('Generated', 'Dibuat'):<10}: {generated}\n")
        fh.write(f"{local('Folder', 'Folder'):<10}: {output_dir}\n")
        fh.write(f"{local('Engine', 'Mesin'):<10}: Semgrep\n")
        fh.write(f"{local('Rules', 'Aturan'):<10}: {rules_path}\n")
        if cutoff_dt:
            fh.write(
                local(
                    f"Date filter: plugins updated before {cutoff_dt.date()} are skipped\n",
                    f"Filter tanggal: plugin yang diperbarui sebelum {cutoff_dt.date()} dilewati\n",
                )
            )
        review_needed = (
            len(vuln)
            + len(scan_fail)
            + len(no_source)
            + len(outdated)
            + len(unknown_date)
            + len(deletion_failures)
        )
        if indonesian:
            fh.write(
                f"Dipindai: {total}  |  Kandidat: {len(vuln)}  |  "
                f"Usang (dilewati): {len(outdated)}  |  Perlu ditinjau: {review_needed}  |  "
                f"{'Akan dihapus' if dry_run else 'Dihapus'}: {len(action_names)}  |  "
                f"Kegagalan penghapusan: {len(deletion_failures)}\n"
            )
            fh.write(
                "Dasar penghapusan: tidak ada kandidat Semgrep setelah scan berhasil; "
                f"hanya hasil Semgrep nol ({len(delete)} kandidat folder)\n"
            )
        else:
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
            fh.write(
                local(
                    "PLUGINS WITH SEMGREP CANDIDATE FINDINGS (manual review required):\n",
                    "PLUGIN DENGAN TEMUAN KANDIDAT SEMGREP (perlu tinjauan manual):\n",
                )
            )
            fh.write("-" * 70 + "\n")
            for r in vuln:
                fh.write(fmt_triage_summary(r) + "\n")
                for finding in r.get("findings", []):
                    if isinstance(finding, dict):
                        fh.write(fmt_finding(finding) + "\n")
            fh.write("\n")

        if outdated:
            cutoff_label = cutoff_dt.date() if cutoff_dt else "N/A"
            fh.write(
                local(
                    f"SKIPPED — OUTDATED (last_updated before {cutoff_label}):\n",
                    f"DILEWATI — USANG (last_updated sebelum {cutoff_label}):\n",
                )
            )
            fh.write("-" * 70 + "\n")
            for r in outdated:
                fh.write(f"  {r['name']}  ({r['status']})\n")
            fh.write("\n")

        if unknown_date:
            fh.write(
                local(
                    "KEPT FOR REVIEW — LAST_UPDATED IS MISSING OR INVALID:\n",
                    "DISIMPAN UNTUK DITINJAU — LAST_UPDATED HILANG ATAU TIDAK VALID:\n",
                )
            )
            fh.write("-" * 70 + "\n")
            for r in unknown_date:
                fh.write(f"  {r['name']}\n")
            fh.write("\n")

        if scan_fail:
            fh.write(
                local(
                    "KEPT FOR MANUAL REVIEW (scan failed or timed out):\n",
                    "DISIMPAN UNTUK TINJAUAN MANUAL (scan gagal atau timeout):\n",
                )
            )
            fh.write("-" * 70 + "\n")
            for r in scan_fail:
                fh.write(f"  {r['name']}  status={r['status']}\n")
            fh.write("\n")

        if no_source:
            fh.write(
                local(
                    "KEPT FOR REVIEW — NO PHP/JAVASCRIPT SOURCE FILES FOUND:\n",
                    "DISIMPAN UNTUK DITINJAU — SUMBER PHP/JAVASCRIPT TIDAK DITEMUKAN:\n",
                )
            )
            fh.write("-" * 70 + "\n")
            for r in no_source:
                fh.write(f"  {r['name']}\n")
            fh.write("\n")

        if deletion_failures:
            fh.write(
                local(
                    "KEPT FOR REVIEW — DELETION FAILED:\n",
                    "DISIMPAN UNTUK DITINJAU — PENGHAPUSAN GAGAL:\n",
                )
            )
            fh.write("-" * 70 + "\n")
            for r in deletion_failures:
                fh.write(f"  {r['name']}  status={r['deletion']}\n")
            fh.write("\n")
    return report_path


def write_candidate_list(root: Path, vuln: list[dict]) -> Path:
    names_path = root / CANDIDATES_FILE
    _atomic_write_text(
        names_path,
        "".join(f"{r['name']}\n" for r in vuln),
    )
    return names_path


def write_deleted_list(root: Path, generated: str, dry_run: bool, action_names: list[str]) -> Path:
    deleted_path = root / DELETED_FILE
    marker = "DRY RUN — NOT DELETED" if dry_run else "DELETED"
    _atomic_write_text(
        deleted_path,
        f"# {marker} — {generated}\n" + "".join(f"{name}\n" for name in sorted(action_names)),
    )
    return deleted_path
