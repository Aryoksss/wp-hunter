from __future__ import annotations

import html
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import http
from .notifiers import NotificationResult, TelegramNotifier
from .safe_names import is_safe_slug
from .versioning import version_is_newer
from .vulndb import ScanOutcome, Vulnerability, WpscanClient, warn_unconfigured
from .watch_state import WatchState

PLUGIN_PAGE_URL = "https://wordpress.org/plugins/{slug}/"
MAX_CONSECUTIVE_PAGE_FAILURES = 5


@dataclass
class PluginUpdate:
    slug: str
    name: str
    old_version: str
    new_version: str
    last_updated: str
    active_installs: int


@dataclass
class VulnerablePlugin:
    slug: str
    name: str
    version: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    @property
    def affected(self) -> list[Vulnerability]:
        return [v for v in self.vulnerabilities if v.affected]


@dataclass
class WatchReport:
    checked: int = 0
    new_plugins: int = 0
    updated: list[PluginUpdate] = field(default_factory=list)
    vulnerable: list[VulnerablePlugin] = field(default_factory=list)
    failed_pages: int = 0
    vuln_errors: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.updated or self.vulnerable)

    @property
    def complete(self) -> bool:
        """False when a listing page failed, so the run only saw part of the list."""
        return self.failed_pages == 0


def _collect_popular(target_installs: int, max_pages: int) -> tuple[list[dict], int]:
    """Return (plugins, failed_pages) from WordPress.org popular listings.

    A failed page no longer aborts the rest of the walk: one 503 in the middle
    of a 600-page sweep must not hide 40,000 plugins. Five failures in a row
    still stop the run, so an outage cannot turn into a retry storm.
    """
    plugins: list[dict] = []
    failed = 0
    consecutive_failures = 0
    seen_slugs: set[str] = set()
    for page in range(1, max_pages + 1):
        data = http.query_plugins_page(browse="popular", page=page)
        if not data or "plugins" not in data:
            failed += 1
            consecutive_failures += 1
            if consecutive_failures >= MAX_CONSECUTIVE_PAGE_FAILURES:
                break
            continue
        consecutive_failures = 0
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


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    word = singular if count == 1 else (plural or f"{singular}s")
    return f"{count} {word}"


def _plugin_link(name: str, slug: str) -> str:
    """Link a plugin name to its WordPress.org page when the slug is safe."""
    label = _safe_text(name or slug)
    if not is_safe_slug(slug):
        return label
    return f'<a href="{PLUGIN_PAGE_URL.format(slug=slug)}">{label}</a>'


def _short_date(value: str) -> str:
    return value.split(" ", 1)[0] if value else ""


def _compact_number(value: int) -> str:
    for size, suffix in ((1_000_000, "M"), (1_000, "K")):
        if value >= size:
            scaled = value / size
            text = f"{scaled:.0f}" if scaled >= 10 or scaled == int(scaled) else f"{scaled:.1f}"
            return f"{text}{suffix}"
    return str(value)


def _severity(score: float | None) -> str:
    if score is None:
        return "⚪"
    if score >= 9:
        return "🔴"
    if score >= 7:
        return "🟠"
    if score >= 4:
        return "🟡"
    return "⚪"


def _vulnerability_line(vuln: Vulnerability) -> str:
    score = f"{vuln.cvss_score:g} — " if vuln.cvss_score is not None else ""
    fixed = f" → fixed in {_safe_text(vuln.fixed_in)}" if vuln.fixed_in else ""
    return f"   {_severity(vuln.cvss_score)} {score}{_safe_text(vuln.title)}{fixed}"


def _headline(report: WatchReport, empty: bool) -> str:
    if empty:
        return ""
    summary = [_plural(len(report.updated), "update")]
    if report.vulnerable:
        summary.append(f"{len(report.vulnerable)} vulnerable")
    lines = [
        f"<b>🛡 WP Hunter — {' · '.join(summary)}</b>",
        f"\n<i>{report.checked:,} plugins checked · {_timestamp()}</i>",
    ]
    if report.vulnerable:
        lines.append("\n\n<b>⚠ Vulnerabilities</b>")
        for index, item in enumerate(report.vulnerable[:20], 1):
            affected = item.affected
            lines.append(
                f"\n\n{index}. <b>{_plugin_link(item.name, item.slug)}</b>"
                f" · <code>{_safe_text(item.slug)}</code>"
                f" · v{_safe_text(item.version)}"
            )
            for vuln in affected[:5]:
                lines.append("\n" + _vulnerability_line(vuln))
            if len(affected) > 5:
                lines.append(f"\n   …and {len(affected) - 5} more advisories")
        if len(report.vulnerable) > 20:
            lines.append(f"\n\n…and {len(report.vulnerable) - 20} more vulnerable plugins")
    if report.updated:
        lines.append("\n\n<b>⬆ Updates</b>")
        for index, update in enumerate(report.updated[:20], 1):
            detail = [
                f"{_safe_text(update.old_version)} → <b>{_safe_text(update.new_version)}</b>",
                f"{_compact_number(update.active_installs)} installs",
            ]
            updated_on = _short_date(update.last_updated)
            if updated_on:
                detail.append(_safe_text(updated_on))
            lines.append(
                f"\n\n{index}. <b>{_plugin_link(update.name, update.slug)}</b>"
                f" · <code>{_safe_text(update.slug)}</code>"
                f"\n   {' · '.join(detail)}"
            )
        if len(report.updated) > 20:
            lines.append(f"\n\n…and {len(report.updated) - 20} more updates")
    if not report.complete:
        lines.append(
            f"\n\n<i>⚠ Partial scan: {_plural(report.failed_pages, 'listing page')} failed</i>"
        )
    return "".join(lines)


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _collect_vulnerabilities(
    plugins: list[dict], client: WpscanClient
) -> tuple[list[VulnerablePlugin], list[str]]:
    vulnerable: list[VulnerablePlugin] = []
    errors: list[str] = []
    for raw in plugins:
        slug = str(raw.get("slug") or "")
        version = str(raw.get("version") or "")
        if not slug or not version:
            continue
        outcome: ScanOutcome = client.scan(slug, version)
        if outcome.error:
            errors.append(f"{slug}: {outcome.error}")
        if outcome.has_affected:
            vulnerable.append(
                VulnerablePlugin(
                    slug=slug,
                    name=str(raw.get("name") or slug),
                    version=version,
                    vulnerabilities=outcome.vulnerabilities,
                )
            )
        if outcome.remaining_quota == 0:
            errors.append("WPScan daily quota exhausted; stopping further checks")
            break
    return vulnerable, errors


def run_watch(
    target_installs: int = 0,
    max_pages: int = 5,
    dry_run: bool = False,
    notify: bool = True,
    check_vulnerabilities: bool = False,
    notifier: TelegramNotifier | None = None,
    state: WatchState | None = None,
    vuln_client: WpscanClient | None = None,
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

    if check_vulnerabilities:
        client = vuln_client if vuln_client is not None else WpscanClient()
        if client.configured:
            report.vulnerable, report.vuln_errors = _collect_vulnerabilities(plugins, client)
            report.vulnerable.sort(key=lambda item: item.name.lower())
        else:
            warn_unconfigured()

    if not dry_run:
        # A failed page means the rest of the listing was never seen. Pruning
        # then would drop live slugs and report them as "new" on the next run.
        if report.complete:
            store.remove_missing(seen)
        store.save()

    if not report.has_changes:
        return report, None

    message = _headline(report, empty=False)
    if dry_run or not notify:
        # --dry-run promises "without recording state or notifying", so it must
        # never send an external message either.
        print(message, file=sys.stderr)
        return report, None
    sender = notifier if notifier is not None else TelegramNotifier()
    return report, sender.send(message)
