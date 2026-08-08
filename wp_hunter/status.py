from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .migration import migrate_triage_result
from .state import DownloadManifest, ReviewLedger


@dataclass(slots=True)
class RootStatus:
    root: Path
    downloaded: int
    present: int
    removed: int
    reviewed: int
    scan_candidates: int
    scan_errors: int
    last_scan: str


def inspect_root(value: str | Path) -> RootStatus:
    root = Path(value).expanduser().resolve()
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"Output root is missing or unsafe: {root}")
    migrate_triage_result(root)
    manifest = DownloadManifest(root)
    ledger = ReviewLedger(root)
    entries = manifest.snapshot()
    present = sum(
        1 for slug in entries if (root / slug).is_dir() and not (root / slug).is_symlink()
    )
    candidates = errors = 0
    last_scan = ""
    triage_path = root / "triage_results.json"
    if triage_path.exists():
        if triage_path.is_symlink() or not triage_path.is_file():
            raise ValueError(f"Triage result is unsafe: {triage_path}")
        try:
            triage = json.loads(triage_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Triage result contains invalid JSON: {triage_path}") from exc
        if isinstance(triage, dict):
            summary = triage.get("summary") if isinstance(triage.get("summary"), dict) else triage
            candidates = int(summary.get("candidate_count", 0) or 0)
            errors = int(
                summary.get("scan_error_count", summary.get("deletion_failure_count", 0)) or 0
            )
            last_scan = str(triage.get("generated_at", triage.get("generated", "")) or "")
    return RootStatus(
        root=root,
        downloaded=len(entries),
        present=present,
        removed=max(0, len(entries) - present),
        reviewed=ledger.count(),
        scan_candidates=candidates,
        scan_errors=errors,
        last_scan=last_scan,
    )
