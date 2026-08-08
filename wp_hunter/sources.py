from __future__ import annotations

import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed

import requests

from .core import (
    API_PARALLEL_WORKERS,
    API_RATE_LIMIT_SEC,
    API_URL,
    MAX_API_WORKERS,
    MAX_PATCHSTACK_PAGES,
    ProgressBar,
    _display_text,
    _is_safe_slug,
    _remote_nonnegative_int,
    extract_author_text,
    format_installs,
)
from .dates import plugin_last_updated as _plugin_last_updated_dt
from .dates import resolve_cutoff_date as _resolve_cutoff_date
from .models import PluginRecord

_WPORG_RATE_LOCK = threading.Lock()
_WPORG_LAST_REQUEST_AT = 0.0


def _wporg_get(url: str, **kwargs):
    global _WPORG_LAST_REQUEST_AT
    with _WPORG_RATE_LOCK:
        now = time.monotonic()
        wait = API_RATE_LIMIT_SEC - (now - _WPORG_LAST_REQUEST_AT)
        if wait > 0:
            time.sleep(wait)
        _WPORG_LAST_REQUEST_AT = time.monotonic()
    return requests.get(url, **kwargs)


def _build_api_params(
    browse: str,
    page: int,
    per_page: int = 100,
    search: str | None = None,
    tag: str | None = None,
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
    browse: str = "popular",
    page: int = 1,
    per_page: int = 100,
    search: str | None = None,
    tag: str | None = None,
    retries: int = 3,
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
                wait = 2**attempt
                print(
                    f"  [WARN] API page {page} attempt {attempt}/{retries} failed ({exc}). Retry in {wait}s …",
                    file=sys.stderr,
                )
                time.sleep(wait)
            else:
                print(f"  [ERROR] API page {page} failed: {exc}", file=sys.stderr)
    return None


PATCHSTACK_VDP_API = "https://vdp.patchstack.com/api/database/vdp"
WP_PLUGIN_INFO_API = "https://api.wordpress.org/plugins/info/1.2/"
WP_THEME_INFO_API = "https://api.wordpress.org/themes/info/1.2/"


def _fetch_wporg_asset_info(slug: str, asset_kind: str = "plugin") -> dict | None:
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
) -> list[PluginRecord]:
    api_workers = max(1, min(api_workers, MAX_API_WORKERS))
    cutoff_dt = _resolve_cutoff_date(min_updated_years, since)

    print(f"\n{'=' * 60}")
    print("  Collecting from Patchstack VDP directory")
    print(f"  Source : {PATCHSTACK_VDP_API}")
    date_desc = f", updated since {cutoff_dt.date()}" if cutoff_dt else ""
    print(
        f"  Filter : kind={'plugin+theme' if include_themes else 'plugin only'}"
        + (f", boost>={min_boost}%" if min_boost else "")
        + date_desc
    )
    print(f"{'=' * 60}\n")
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
            _fetch_wporg_theme_info(slug)
            if asset_kind == "theme"
            else _fetch_wporg_plugin_info(slug)
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
                time.sleep(2**attempt)
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


def collect_plugins(
    target_installs: int,
    browse: str = "popular",
    max_pages: int = 50,
    search: str | None = None,
    tag: str | None = None,
    api_workers: int = API_PARALLEL_WORKERS,
    min_updated_years: int = 0,
    since: str | None = None,
    installs_mode: str = "exact",
) -> list[PluginRecord]:
    api_workers = max(1, min(api_workers, MAX_API_WORKERS))
    max_pages = max(1, max_pages)
    cutoff_dt = _resolve_cutoff_date(min_updated_years, since)
    is_min_mode = installs_mode == "min"
    can_early_exit = browse == "popular" and not search and not tag

    print(f"\n{'=' * 60}")
    print("  Collecting plugins from WordPress.org")
    installs_label = (
        f">= {format_installs(target_installs).replace('+', '')}"
        if is_min_mode
        else format_installs(target_installs)
    )
    print(
        f"  Installs: {installs_label}  |  Browse: {browse if not search else f'search:{search!r}'}"
        + (f"  |  Tag: {tag}" if tag else "")
    )
    print(f"  Max pages: {max_pages} (~{max_pages * 100} plugins)  |  API workers: {api_workers}")
    if cutoff_dt:
        print(f"  Date filter: only plugins updated since {cutoff_dt.date()}")
    print(f"{'=' * 60}\n")

    first = query_plugins_page(browse=browse, page=1, search=search, tag=tag)
    if not first or "plugins" not in first:
        print("  [ERROR] No response from WordPress.org API on page 1.", file=sys.stderr)
        return []

    info = first.get("info", {})
    total_pages = max(1, _remote_nonnegative_int(info.get("pages", 1), default=1))
    total_results = _remote_nonnegative_int(info.get("results", 0))

    print(f"  Directory total : {total_results:,} plugins ({total_pages} pages)")
    page_cache: dict[int, list] = {1: first.get("plugins", [])}

    def load_page(page: int) -> list | None:
        if page in page_cache:
            return page_cache[page]
        data = query_plugins_page(browse=browse, page=page, search=search, tag=tag)
        if data is None:
            return None
        plugins = data.get("plugins", [])
        page_cache[page] = plugins
        return plugins

    def install_bounds(page: int) -> tuple[int, int] | None:
        plugins = load_page(page)
        if plugins is None:
            return None
        installs = [_remote_nonnegative_int(plugin.get("active_installs", 0)) for plugin in plugins]
        return (min(installs), max(installs)) if installs else (0, 0)

    # Early exit is safe only for unfiltered popular browsing, where active
    # install buckets are descending. Other browse/search/tag modes are not
    # assumed to have that ordering.
    if can_early_exit:
        p1_bounds = install_bounds(1) or (0, 0)
        p1_max = p1_bounds[1]
        if p1_max < target_installs:
            print(
                f"  [!] Page 1's highest install count ({p1_max:,}) is already below "
                f"target ({target_installs:,}).\n"
                f"  Try --browse popular or a lower --installs tier.",
                file=sys.stderr,
            )
            return []

    if can_early_exit and not is_min_mode:
        low, high = 1, total_pages
        while low < high:
            middle = (low + high) // 2
            bounds = install_bounds(middle)
            if bounds is None:
                print(f"  [ERROR] Could not locate install tier: page {middle} failed.")
                return []
            if bounds[0] <= target_installs:
                high = middle
            else:
                low = middle + 1
        first_tier_page = low
        first_tier_bounds = install_bounds(first_tier_page)
        if first_tier_bounds is None or first_tier_bounds[1] < target_installs:
            print(f"  [!] No plugins found in the exact {installs_label} tier.\n")
            return []

        low, high = first_tier_page, total_pages
        while low < high:
            middle = (low + high + 1) // 2
            bounds = install_bounds(middle)
            if bounds is None:
                print(f"  [ERROR] Could not locate install tier: page {middle} failed.")
                return []
            if bounds[1] >= target_installs:
                low = middle
            else:
                high = middle - 1
        last_tier_page = low
        selected_pages = list(
            range(first_tier_page, min(last_tier_page, first_tier_page + max_pages - 1) + 1)
        )
        print(
            f"  Tier pages      : {first_tier_page}-{last_tier_page} "
            f"({last_tier_page - first_tier_page + 1} pages)"
        )
    else:
        selected_pages = list(range(1, min(max_pages, total_pages) + 1))

    print(f"  Will fetch      : {len(selected_pages)} pages using {api_workers} workers\n")

    pages_data = {page: page_cache[page] for page in selected_pages if page in page_cache}
    pages_to_fetch = [page for page in selected_pages if page not in pages_data]

    if selected_pages:
        bar = ProgressBar(total=len(selected_pages), label="Fetching pages")
        bar.start()
        for page in pages_data:
            bar.update(message=f"page {page} cached")

        def fetch_page(pg: int) -> tuple[int, list | None]:
            data = query_plugins_page(browse=browse, page=pg, search=search, tag=tag)
            if data is None:
                return pg, None
            return pg, data.get("plugins", [])

        if pages_to_fetch:
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
                    if result is not None:
                        pages_data[pg] = result
                    bar.update(message=f"page {pg} ✓")

        bar.finish(f"{len(pages_data)} pages fetched")

    seen_slugs: set[str] = set()
    results: list[dict] = []
    for pg in sorted(pages_data.keys()):
        for plugin in pages_data.get(pg, []):
            installs = _remote_nonnegative_int(plugin.get("active_installs", 0))
            matches = (
                (installs >= target_installs) if is_min_mode else (installs == target_installs)
            )
            if not matches:
                continue
            slug = plugin.get("slug", "")
            if not _is_safe_slug(slug) or slug in seen_slugs:
                continue
            if cutoff_dt:
                last_dt = _plugin_last_updated_dt(plugin.get("last_updated", "") or "")
                if last_dt is None or last_dt < cutoff_dt:
                    continue
            seen_slugs.add(slug)
            results.append(_parse_plugin_record(plugin))

    print(f"\n  Found: {len(results)} plugins ({installs_label} installs)\n")
    return [PluginRecord.from_mapping(item) for item in results]
