from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from ..archive import ensure_extracted as _ensure_extracted
from ..core import _directory_identity
from ..dates import plugin_last_updated as _plugin_last_updated_dt
from ..semgrep_adapter import SemgrepEngine

IN_SCOPE_TIERS = {
    "unauthenticated",
    "subscriber",
    "contributor",
    "author",
    "low_privilege",
    "nonce_only",
    "permission_callback",
}
KNOWN_OUT_OF_SCOPE_TIERS = {
    "admin",
    "administrator",
    "editor",
    "super_admin",
    "capability_checked",
}
TIER_WEIGHT = {
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

_METADATA_MAX_BYTES = 4 * 1024 * 1024


def classify(results: list) -> tuple[dict, dict, int]:
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
        if access in IN_SCOPE_TIERS or access not in KNOWN_OUT_OF_SCOPE_TIERS:
            in_scope += 1
    return tier_counts, check_counts, in_scope


def _read_plugin_metadata(plugin_dir: str) -> dict | None:
    meta = Path(plugin_dir) / "plugin_info.json"
    if meta.is_symlink() or not meta.is_file():
        return None
    try:
        if meta.stat().st_size > _METADATA_MAX_BYTES:
            return None
        with open(meta, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def plugin_last_updated_datetime(plugin_dir: str) -> datetime | None:
    data = _read_plugin_metadata(plugin_dir)
    if data is None:
        return None
    return _plugin_last_updated_dt(str(data.get("last_updated", "") or ""))


def plugin_review_identity(plugin_dir: str | Path) -> tuple[str, str]:
    data = _read_plugin_metadata(str(plugin_dir))
    if data is None:
        return "", ""
    return (
        str(data.get("version", "") or ""),
        str(data.get("downloaded_sha256", "") or ""),
    )


def triage_one(
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
        last_updated = plugin_last_updated_datetime(plugin_dir)
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

    tiers, checks, in_scope = classify(results)
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


__all__ = [
    "IN_SCOPE_TIERS",
    "KNOWN_OUT_OF_SCOPE_TIERS",
    "TIER_WEIGHT",
    "classify",
    "plugin_last_updated_datetime",
    "plugin_review_identity",
    "triage_one",
]
