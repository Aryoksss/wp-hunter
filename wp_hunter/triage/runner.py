from __future__ import annotations

import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from ..archive import looks_like_plugin_dir as _looks_like_plugin_dir
from ..constants import ROOT_MARKER_FILE
from ..core import _ask_choice
from ..dates import resolve_cutoff_date as _resolve_cutoff_date
from ..paths import (
    directory_identity as _directory_identity,
)
from ..paths import (
    is_direct_child as _is_direct_child,
)
from ..paths import (
    remove_directory as _remove_directory,
)
from ..paths import (
    root_marker_state as _root_marker_state,
)
from ..paths import (
    validate_triage_root as _validate_triage_root,
)
from ..progress import ProgressBar
from ..semgrep_adapter import SemgrepEngine
from ..state import ReviewLedger
from .engine import TIER_WEIGHT, plugin_review_identity, triage_one
from .report import (
    build_results_payload,
    fmt_triage_summary,
    write_candidate_list,
    write_deleted_list,
    write_report,
    write_results_json,
)


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
            executor.submit(triage_one, d, engine, timeout, mem_mb, cutoff_dt): d
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
            -max((TIER_WEIGHT.get(t, 100) for t in r["tiers"]), default=0),
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
            reviewed_version, reviewed_sha256 = plugin_review_identity(r["dir"])
            _remove_directory(r["dir"], root, tuple(r["dir_identity"]))
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
                extracted_identity = _directory_identity(extracted_path)
                if (
                    not _is_direct_child(root, plugin_path)
                    or _directory_identity(plugin_path) != tuple(r["dir_identity"])
                    or extracted_path != plugin_path / "extracted"
                    or extracted_path.is_symlink()
                    or extracted_identity is None
                ):
                    raise ValueError("unsafe extracted directory")
                _remove_directory(extracted_path, plugin_path, extracted_identity)
                r["cleanup_status"] = "removed"
            except Exception as exc:
                r["cleanup_status"] = f"failed:{exc}"
                print(
                    f"  [WARN] Could not clean extracted source for {r['name']}: {exc}",
                    file=sys.stderr,
                )
    generated = datetime.now().isoformat(timespec="seconds")
    action_names = would_delete_names if dry_run else deleted_names
    action_label = "Would delete" if dry_run else "Deleted"

    payload = build_results_payload(
        language=language,
        rules_path=str(engine.rules_path),
        generated=generated,
        dry_run=dry_run,
        workers=workers,
        timeout=timeout,
        mem_mb=mem_mb,
        max_age_years=max_age_years,
        since=since,
        summary={
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
        results=results,
    )
    json_path = write_results_json(root, payload)

    report_path = write_report(
        root=root,
        output_dir=output_dir,
        rules_path=str(engine.rules_path),
        generated=generated,
        cutoff_dt=cutoff_dt,
        language=language,
        dry_run=dry_run,
        total=total,
        vuln=vuln,
        delete=delete,
        scan_fail=scan_fail,
        no_source=no_source,
        outdated=outdated,
        unknown_date=unknown_date,
        deletion_failures=deletion_failures,
        action_names=action_names,
    )

    names_path = write_candidate_list(root, vuln)
    write_deleted_list(root, generated, dry_run, action_names)

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
            print(f"    {fmt_triage_summary(r)}")
    print(f"{'=' * 60}\n")
