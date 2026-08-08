from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path


def migrate_triage_result(root: str | Path) -> bool:
    path = Path(root) / "triage_results.json"
    if not path.exists():
        return False
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError(f"Triage result is not a safe file: {path}")
    try:
        old = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Triage result contains invalid JSON: {path}") from exc
    if not isinstance(old, dict):
        raise ValueError(f"Triage result must be a JSON object: {path}")
    if old.get("schema_version") == 2:
        return False
    if "schema_version" in old:
        raise ValueError(f"Unsupported triage result schema: {old.get('schema_version')!r}")
    results = old.get("results")
    if not isinstance(results, list):
        raise ValueError(f"Legacy triage result has invalid entries: {path}")
    scan_errors = sum(
        1
        for item in results
        if isinstance(item, dict)
        and str(item.get("status", "")) not in {"OK", "NO_SOURCE", "UNKNOWN_DATE"}
        and not str(item.get("status", "")).startswith("OUTDATED")
    )
    payload = {
        "schema_version": 2,
        "engine": str(old.get("engine", "semgrep") or "semgrep"),
        "rules": str(old.get("rules", "") or ""),
        "generated_at": str(old.get("generated", "") or ""),
        "dry_run": bool(old.get("dry_run", True)),
        "scan": {},
        "summary": {
            "plugin_count": len(results),
            "candidate_count": int(old.get("candidate_count", 0) or 0),
            "deletion_candidate_count": int(old.get("deletion_candidate_count", 0) or 0),
            "deleted_count": int(old.get("deleted_count", 0) or 0),
            "deletion_failure_count": int(old.get("deletion_failure_count", 0) or 0),
            "scan_error_count": scan_errors,
        },
        "results": results,
    }
    fd, temporary_name = tempfile.mkstemp(
        prefix=".triage_results.", suffix=".tmp", dir=str(path.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)
    return True
