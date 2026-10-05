from __future__ import annotations

import sys
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from html.parser import HTMLParser

from . import http
from .core import (
    API_PARALLEL_WORKERS,
    MAX_API_WORKERS,
    ProgressBar,
    _display_text,
    _remote_nonnegative_int,
)
from .dates import plugin_last_updated as _plugin_last_updated_dt
from .dates import resolve_cutoff_date as _resolve_cutoff_date
from .installs import format_installs
from .models import PluginRecord
from .safe_names import is_safe_slug as _is_safe_slug


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

    first = http.query_plugins_page(browse=browse, page=1, search=search, tag=tag)
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
        data = http.query_plugins_page(browse=browse, page=page, search=search, tag=tag)
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
            data = http.query_plugins_page(browse=browse, page=pg, search=search, tag=tag)
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
