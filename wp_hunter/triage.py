from __future__ import annotations

import json
import os
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from .archive import ensure_extracted as _ensure_extracted
from .archive import looks_like_plugin_dir as _looks_like_plugin_dir
from .core import (
    ROOT_MARKER_FILE,
    ProgressBar,
    _ask_choice,
    _atomic_text_file,
    _atomic_write_json,
    _atomic_write_text,
    _directory_identity,
    _display_text,
    _is_direct_child,
    _root_marker_state,
    _validate_triage_root,
)
from .dates import plugin_last_updated as _plugin_last_updated_dt
from .dates import resolve_cutoff_date as _resolve_cutoff_date
from .semgrep_adapter import SemgrepEngine
from .state import ReviewLedger

_IN_SCOPE_TIERS = {
    "unauthenticated",
    "subscriber",
    "contributor",
    "author",
    "low_privilege",
    "nonce_only",
    "permission_callback",
}
_KNOWN_OUT_OF_SCOPE_TIERS = {
    "admin",
    "administrator",
    "editor",
    "super_admin",
    "capability_checked",
}
_TIER_WEIGHT = {
    "unauthenticated": 1000,
    "permission_callback": 700,
    "nonce_only": 600,
    "subscriber": 550,
    "contributor": 500,
    "author": 450,
    "low_privilege": 500,
    "authenticated": 400,
    "unknown": 300,
    "": 300,
    "capability_checked": 50,
}


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


def _plugin_last_updated_datetime(plugin_dir: str) -> datetime | None:
    meta = Path(plugin_dir) / "plugin_info.json"
    if meta.is_symlink() or not meta.is_file():
        return None
    try:
        if meta.stat().st_size > 4 * 1024 * 1024:
            return None
        with open(meta, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return None
        return _plugin_last_updated_dt(str(data.get("last_updated", "") or ""))
    except Exception:
        pass
    return None


def _plugin_review_identity(plugin_dir: str | Path) -> tuple[str, str]:
    meta = Path(plugin_dir) / "plugin_info.json"
    if meta.is_symlink() or not meta.is_file():
        return "", ""
    try:
        if meta.stat().st_size > 4 * 1024 * 1024:
            return "", ""
        with open(meta, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return "", ""
        return (
            str(data.get("version", "") or ""),
            str(data.get("downloaded_sha256", "") or ""),
        )
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return "", ""


def _triage_one(
    plugin_dir: str,
    engine: SemgrepEngine,
    timeout: int,
    mem_mb: int,
    cutoff_dt: datetime | None = None,
) -> dict:
    name = os.path.basename(plugin_dir.rstrip("\\/"))
    res = dict(
        name=name,
        dir=plugin_dir,
        status="OK",
        total=0,
        in_scope=0,
        tiers={},
        checks={},
        findings=[],
        keep=False,
        extracted_dir=None,
        cleanup_status="not_needed",
        deletion="retained",
    )
    res["dir_identity"] = _directory_identity(plugin_dir)
    if res["dir_identity"] is None:
        res["status"] = "INVALID_DIRECTORY"
        res["keep"] = True
        return res
    existing_extracted = Path(plugin_dir) / "extracted"
    if existing_extracted.is_dir() and not existing_extracted.is_symlink():
        res["extracted_dir"] = str(existing_extracted)

    # Date filter is exact. Unknown metadata stays retained for manual review.
    if cutoff_dt is not None:
        last_updated = _plugin_last_updated_datetime(plugin_dir)
        if last_updated is None:
            res["status"] = "UNKNOWN_DATE"
            res["keep"] = True
            return res
        if last_updated < cutoff_dt:
            res["status"] = f"OUTDATED ({last_updated.date().isoformat()})"
            res["keep"] = True
            return res

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
        total=len(results),
        in_scope=in_scope,
        tiers=tiers,
        checks=checks,
        findings=results,
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
    output_dir: str,
    semgrep_path: str,
    semgrep_rules: str | Path,
    workers: int = 4,
    timeout: int = 120,
    mem_mb: int = 2048,
    dry_run: bool = True,
    keep_extracted: bool = False,
    max_age_years: int = 2,
    since: str | None = None,
    allow_unmarked: bool = False,
    review_ledger: ReviewLedger | None = None,
    language: str = "en",
) -> None:
    indonesian = language == "id"

    def local(english: str, indonesia: str) -> str:
        return indonesia if indonesian else english

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
    cutoff_dt = _resolve_cutoff_date(max_age_years, since)
    ts_fmt = datetime.now().strftime("%H:%M:%S")
    print(f"\n{'=' * 60}")
    print(f"  Vulnerability Triage  [{ts_fmt}]")
    print(f"  Folder   : {output_dir}")
    print(f"  Engine   : Semgrep ({engine.executable})")
    print(f"  Rules    : {engine.rules_path}")
    print(f"  Workers  : {workers}  |  Timeout: {timeout}s/plugin")
    if cutoff_dt:
        print(f"  Filter   : skip plugins last updated before {cutoff_dt.date()}")
    else:
        print("  Filter   : no date filter (scanning all)")
    triage_mode_label = (
        "DRY RUN — no plugin folders will be deleted"
        if dry_run
        else "LIVE — no-candidate folders will be deleted"
    )
    print(f"  Mode     : {triage_mode_label}")
    print(f"{'=' * 60}")

    plugin_dirs = sorted(str(p) for p in root.iterdir() if _looks_like_plugin_dir(p))
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
            executor.submit(_triage_one, d, engine, timeout, mem_mb, cutoff_dt): d
            for d in plugin_dirs
        }
        for fut in as_completed(fut_map):
            try:
                r = fut.result()
            except Exception as exc:
                d = fut_map[fut]
                r = dict(
                    name=os.path.basename(d),
                    dir=d,
                    status=f"CRASH:{exc}",
                    total=0,
                    in_scope=0,
                    tiers={},
                    checks={},
                    findings=[],
                    keep=True,
                    extracted_dir=None,
                    cleanup_status="not_needed",
                    deletion="retained",
                    dir_identity=_directory_identity(d),
                )
            results.append(r)
            flag = "KEEP" if r["keep"] else "DEL "
            status_code = str(r["status"]).split(" —", 1)[0]
            status_note = f" [{status_code}]" if status_code not in ("OK", "NO_SOURCE") else ""
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
    no_source = sorted([r for r in results if r["status"] == "NO_SOURCE"], key=lambda r: r["name"])
    outdated = sorted(
        [r for r in results if r["status"].startswith("OUTDATED")],
        key=lambda r: r["name"],
    )
    unknown_date = sorted(
        [r for r in results if r["status"] == "UNKNOWN_DATE"],
        key=lambda r: r["name"],
    )
    scan_fail = sorted(
        [
            r
            for r in keep
            if r["in_scope"] == 0
            and r["status"] != "OK"
            and r["status"] != "NO_SOURCE"
            and r["status"] != "UNKNOWN_DATE"
            and not r["status"].startswith("OUTDATED")
        ],
        key=lambda r: r["name"],
    )
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
            print("  Tip: re-run the scan without --delete-no-findings for report-only mode.\n")
            dry_run = True
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
            reviewed_version, reviewed_sha256 = _plugin_review_identity(r["dir"])
            shutil.rmtree(r["dir"])
            r["deletion"] = "deleted"
            deleted_names.append(r["name"])
            if review_ledger is not None:
                try:
                    review_ledger.mark(
                        r["name"],
                        reviewed_version,
                        "no_semgrep_candidate",
                        reviewed_sha256,
                    )
                except (OSError, TypeError, ValueError) as history_exc:
                    r["review_history"] = f"failed:{history_exc}"
                    print(
                        f"  [WARN] Deleted {r['name']} but could not update review history: "
                        f"{history_exc}",
                        file=sys.stderr,
                    )
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
            "schema_version": 2,
            "language": language,
            "engine": "semgrep",
            "rules": str(engine.rules_path),
            "generated_at": generated,
            "dry_run": dry_run,
            "scan": {
                "workers": workers,
                "timeout": timeout,
                "memory_mb": mem_mb,
                "max_age_years": max_age_years,
                "since": since,
            },
            "summary": {
                "plugin_count": total,
                "candidate_count": len(vuln),
                "deletion_candidate_count": len(delete),
                "deleted_count": len(deleted_names),
                "deletion_failure_count": len(deletion_failures),
                "scan_error_count": len(scan_fail),
                "no_source_count": len(no_source),
                "outdated_count": len(outdated),
                "unknown_date_count": len(unknown_date),
            },
            "results": sorted(results, key=lambda item: item.get("name", "")),
        },
    )

    with _atomic_text_file(report_path) as fh:
        fh.write(
            local("WP Plugin Semgrep Triage Report\n", "Laporan Triage Semgrep Plugin WordPress\n")
        )
        fh.write(f"{local('Generated', 'Dibuat'):<10}: {generated}\n")
        fh.write(f"{local('Folder', 'Folder'):<10}: {output_dir}\n")
        fh.write(f"{local('Engine', 'Mesin'):<10}: Semgrep\n")
        fh.write(f"{local('Rules', 'Aturan'):<10}: {engine.rules_path}\n")
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
                fh.write(_fmt_triage_summary(r) + "\n")
                for finding in r.get("findings", []):
                    if isinstance(finding, dict):
                        fh.write(_fmt_finding(finding) + "\n")
            fh.write("\n")

        if outdated:
            fh.write(
                local(
                    f"SKIPPED — OUTDATED (last_updated before {cutoff_dt.date()}):\n",
                    f"DILEWATI — USANG (last_updated sebelum {cutoff_dt.date()}):\n",
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

    _atomic_write_text(
        names_path,
        "".join(f"{r['name']}\n" for r in vuln),
    )
    marker = "DRY RUN — NOT DELETED" if dry_run else "DELETED"
    _atomic_write_text(
        deleted_path,
        f"# {marker} — {generated}\n" + "".join(f"{name}\n" for name in sorted(action_names)),
    )
    print(f"\n{'=' * 60}")
    print("  Triage complete")
    print(f"    Semgrep candidates: {len(vuln)}")
    review_count = len(scan_fail) + len(no_source) + len(outdated) + len(unknown_date)
    print(
        f"    Kept for review  : {review_count}  "
        "(outdated, unknown date, no source, or scan failed)"
    )
    if len(outdated):
        print(f"    Outdated/skipped : {len(outdated)}  (updated before {cutoff_dt.date()})")
    print(f"    {action_label:<18}: {len(action_names)}")
    if deletion_failures:
        print(f"    Deletion failures : {len(deletion_failures)}")
    print(f"    Report           : {report_path}")
    print(f"    Candidate list   : {names_path}")
    print(f"    JSON results     : {json_path}")
    if dry_run:
        print("\n  This was report-only. Re-run with --delete-no-findings to allow deletion.")
    if vuln:
        print("\n  Top Semgrep candidates:")
        for r in vuln[:5]:
            print(f"    {_fmt_triage_summary(r)}")
    print(f"{'=' * 60}\n")
