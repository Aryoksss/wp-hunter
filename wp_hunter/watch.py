from __future__ import annotations

import html
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import http
from .notifiers import NotificationResult, TelegramNotifier
from .versioning import version_is_newer
from .watch_state import WatchState


@dataclass
class PluginUpdate:
    slug: str
    name: str
    old_version: str
    new_version: str
    last_updated: str
    active_installs: int


@dataclass
class WatchReport:
    checked: int = 0
    new_plugins: int = 0
    updated: list[PluginUpdate] = field(default_factory=list)
    failed_pages: int = 0

    @property
    def has_changes(self) -> bool:
        return bool(self.updated)


def _collect_popular(target_installs: int, max_pages: int) -> tuple[list[dict], int]:
    """Return (plugins, failed_pages) from WordPress.org popular listings."""
    plugins: list[dict] = []
    failed = 0
    seen_slugs: set[str] = set()
    for page in range(1, max_pages + 1):
        data = http.query_plugins_page(browse="popular", page=page)
        if not data or "plugins" not in data:
            failed += 1
            break
        batch = data.get("plugins") or []
        if not batch:
            break
        for raw in batch:
            slug = str(raw.get("slug") or "")
            if not slug or slug in seen_slugs:
                continue
            installs = _as_int(raw.get("active_installs"))
            if target_installs and installs < target_installs:
                return plugins, failed
            seen_slugs.add(slug)
            plugins.append(raw)
        info = data.get("info", {})
        total_pages = _as_int(info.get("pages")) if isinstance(info, dict) else 0
        if total_pages and page >= total_pages:
            break
    return plugins, failed


def _as_int(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default


def _safe_text(value: str) -> str:
    # WordPress.org returns HTML entities (e.g. &#8211;), so normalize before escaping.
    return html.escape(html.unescape(value))


def _headline(report: WatchReport, empty: bool) -> str:
    if empty:
        return ""
    title = f"WP Hunter — {len(report.updated)} plugin update(s)"
    lines = [f"<b>{html.escape(title)}</b>"]
    for update in report.updated[:40]:
        name = _safe_text(update.name or update.slug)
        lines.append(
            f"\n<b>{name}</b>\n"
            f"  {_safe_text(update.old_version)} → <b>{_safe_text(update.new_version)}</b>\n"
            f"  {update.active_installs:,} installs"
        )
    if len(report.updated) > 40:
        lines.append(f"\n…and {len(report.updated) - 40} more.")
    lines.append(f"\n<i>Checked {report.checked} plugins at {_timestamp()}</i>")
    return "".join(lines)


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def run_watch(
    target_installs: int = 0,
    max_pages: int = 5,
    dry_run: bool = False,
    notify: bool = True,
    notifier: TelegramNotifier | None = None,
    state: WatchState | None = None,
) -> tuple[WatchReport, NotificationResult | None]:
    store = state if state is not None else WatchState()
    plugins, failed_pages = _collect_popular(target_installs, max_pages)

    report = WatchReport(checked=len(plugins), failed_pages=failed_pages)
    seen: set[str] = set()
    for raw in plugins:
        slug = str(raw.get("slug") or "")
        seen.add(slug)
        new_version = str(raw.get("version") or "")
        if not new_version:
            continue
        old_version = store.get_version(slug)
        if old_version is None:
            report.new_plugins += 1
        elif version_is_newer(new_version, old_version):
            report.updated.append(
                PluginUpdate(
                    slug=slug,
                    name=str(raw.get("name") or slug),
                    old_version=old_version,
                    new_version=new_version,
                    last_updated=str(raw.get("last_updated") or ""),
                    active_installs=_as_int(raw.get("active_installs")),
                )
            )
        if not dry_run:
            store.record(slug, new_version, str(raw.get("last_updated") or ""))

    if report.updated:
        report.updated.sort(key=lambda item: item.active_installs, reverse=True)

    if not dry_run:
        store.remove_missing(seen)
        store.save()

    if not report.has_changes:
        return report, None

    message = _headline(report, empty=False)
    if not notify:
        print(message, file=sys.stderr)
        return report, None
    sender = notifier if notifier is not None else TelegramNotifier()
    return report, sender.send(message)
