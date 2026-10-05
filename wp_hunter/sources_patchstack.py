from __future__ import annotations

import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import http
from .core import (
    API_PARALLEL_WORKERS,
    MAX_API_WORKERS,
    MAX_PATCHSTACK_PAGES,
    ProgressBar,
    _display_text,
    _remote_nonnegative_int,
)
from .dates import plugin_last_updated as _plugin_last_updated_dt
from .dates import resolve_cutoff_date as _resolve_cutoff_date
from .models import PluginRecord
from .safe_names import is_safe_slug as _is_safe_slug
from .sources_wporg import _parse_plugin_record


def collect_patchstack_plugins(
    min_boost: int = 0,
    min_updated_years: int = 0,
    since: str | None = None,
    include_themes: bool = False,
    api_workers: int = API_PARALLEL_WORKERS,
    max_entries: int | None = None,
) -> list[PluginRecord]:
    api_workers = max(1, min(api_workers, MAX_API_WORKERS))
    cutoff_dt = _resolve_cutoff_date(min_updated_years, since)

    print(f"\n{'=' * 60}")
    print("  Collecting from Patchstack VDP directory")
    print(f"  Source : {http.PATCHSTACK_VDP_API}")
    date_desc = f", updated since {cutoff_dt.date()}" if cutoff_dt else ""
    print(
        f"  Filter : kind={'plugin+theme' if include_themes else 'plugin only'}"
        + (f", boost>={min_boost}%" if min_boost else "")
        + date_desc
    )
    print(f"{'=' * 60}\n")
    entries: list[dict] = []
    seen: set[str] = set()

    first = http._patchstack_page(1)
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
        _remote_nonnegative_int(pag.get("last_page", 1), default=1, maximum=MAX_PATCHSTACK_PAGES),
    )
    for item in (first.get("recentlyAdded", {}) or {}).get("results", []):
        slug = item.get("slug", "")
        if _is_safe_slug(slug) and slug not in seen:
            seen.add(slug)
            entries.append(item)

    print(f"  VDP programs: {_display_text(first.get('total', '?'), 30)} total ({last_page} pages)")
    bar = ProgressBar(total=last_page, label="VDP pages")
    bar.start()
    bar.update(message="page 1")

    for pg in range(2, last_page + 1):
        data = http._patchstack_page(pg)
        if data:
            for item in (data.get("recentlyAdded", {}) or {}).get("results", []):
                slug = item.get("slug", "")
                if _is_safe_slug(slug) and slug not in seen:
                    seen.add(slug)
                    entries.append(item)
        bar.update(message=f"page {pg}")
        time.sleep(0.25)  # be polite to Patchstack
    bar.finish(f"{len(entries)} programs collected")
    # Show the boost-tier breakdown so the threshold behaviour is transparent.
    # The Patchstack API only exposes a few discrete boost values (commonly
    # 0/25/35/100); the "+15%" shown on the website is a base bonus not present
    # in this field, so e.g. --min-boost 15 and --min-boost 25 behave the same.
    from collections import Counter as _Counter

    plugin_entries = [
        e for e in entries if include_themes or (e.get("kind") or "").lower() in ("", "plugin")
    ]
    boost_dist = _Counter(_remote_nonnegative_int(e.get("boost", 0)) for e in plugin_entries)
    tiers = ", ".join(f"{b}%={n}" for b, n in sorted(boost_dist.items()))
    print(f"\n  Boost tiers available (plugins): {tiers}")
    if min_boost:
        avail = sorted(b for b in boost_dist if b >= min_boost)
        if avail and avail[0] != min_boost:
            print(
                f"  Note: no entries at exactly {min_boost}% — selecting boost >= {avail[0]}% "
                f"(nearest tier with data)."
            )

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
    results: list[dict] = []
    skipped_offwporg = 0
    skipped_outdated = 0
    skipped_unknown_date = 0

    bar2 = ProgressBar(total=len(filtered), label="Enriching ")
    bar2.start()

    def enrich(entry: dict) -> dict | None:
        slug = entry["slug"]
        asset_kind = (entry.get("kind") or "plugin").lower()
        info = (
            http._fetch_wporg_theme_info(slug)
            if asset_kind == "theme"
            else http._fetch_wporg_plugin_info(slug)
        )
        if not info:
            return {"_offwporg": True, "slug": slug}
        last_updated = info.get("last_updated", "") or ""
        rec = _parse_plugin_record(info)
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
                if last_dt is None:
                    skipped_unknown_date += 1
                    continue
                if last_dt < cutoff_dt:
                    skipped_outdated += 1
                    continue
            results.append(r)
    bar2.finish()
    results.sort(
        key=lambda r: (
            -_remote_nonnegative_int(r.get("patchstack_boost", 0)),
            -_remote_nonnegative_int(r.get("active_installs", 0)),
        )
    )

    print("\n  Patchstack collection done:")
    print(f"    Downloadable on wp.org : {len(results)}")
    print(f"    Skipped (not on wp.org): {skipped_offwporg}  (commercial/closed)")
    if cutoff_dt:
        print(f"    Skipped (outdated)     : {skipped_outdated}")
        print(f"    Skipped (unknown date) : {skipped_unknown_date}")
    print()
    return [PluginRecord.from_mapping(item) for item in results]
