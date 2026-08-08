from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import core, downloader, sources, triage
from .migration import migrate_triage_result
from .models import DownloadOptions, ScanOptions
from .state import MANIFEST_FILE, DownloadManifest, ReviewLedger


@dataclass(slots=True)
class DownloadResult:
    root: Path
    collected: int
    selected: int
    reviewed_skipped: int
    preview_downloads: int = 0
    preview_cached: int = 0


def default_output(options: DownloadOptions, output_parent: str | Path = ".") -> Path:
    parent = Path(output_parent).expanduser()
    if options.source == "patchstack":
        return parent / "wp_plugins_patchstack"
    installs = core.parse_installs_input(options.installs)
    label = core.format_installs(installs).replace("+", "")
    prefix = "min" if options.installs_mode == "minimum" else ""
    return parent / f"wp_plugins_{prefix}{label}"


def execute_download(options: DownloadOptions, output_parent: str | Path = ".") -> DownloadResult:
    output = (
        Path(options.output).expanduser()
        if options.output
        else default_output(options, output_parent)
    )
    root = core._ensure_hunter_root(output, adopt_existing=options.adopt_existing)
    migrate_triage_result(root)

    if options.reset_cache:
        manifest_path = root / MANIFEST_FILE
        if manifest_path.is_symlink() or (manifest_path.exists() and not manifest_path.is_file()):
            raise ValueError(f"Refusing unsafe manifest path: {manifest_path}")
        manifest_path.unlink(missing_ok=True)

    manifest = DownloadManifest(root)
    ledger = ReviewLedger(root)
    ledger.sync_removed_downloads(manifest)

    if options.source == "patchstack":
        plugins = sources.collect_patchstack_plugins(
            min_boost=options.min_boost,
            min_updated_years=options.max_age_years,
            since=options.since,
            include_themes=options.include_themes,
            api_workers=options.api_workers,
            max_entries=None,
        )
    else:
        installs = core.parse_installs_input(options.installs)
        if options.installs_mode == "exact" and installs not in core.VALID_TIERS:
            raise ValueError(f"{options.installs!r} is not an exact WordPress.org install tier")
        plugins = sources.collect_plugins(
            target_installs=installs,
            browse=options.browse,
            max_pages=options.pages,
            search=options.search,
            tag=options.tag,
            api_workers=options.api_workers,
            min_updated_years=options.max_age_years,
            since=options.since,
            installs_mode="min" if options.installs_mode == "minimum" else "exact",
        )

    collected = len(plugins)
    reviewed_skipped = 0
    if not options.revisit_reviewed and not options.force:
        remaining = [plugin for plugin in plugins if not ledger.covers(plugin)]
        reviewed_skipped = len(plugins) - len(remaining)
        plugins = remaining
    if options.limit is not None:
        plugins = plugins[: options.limit]

    if options.source == "patchstack":
        downloader.export_patchstack_results(plugins, str(root))
    else:
        downloader.export_results(plugins, str(root), core.parse_installs_input(options.installs))

    result = DownloadResult(
        root=root,
        collected=collected,
        selected=len(plugins),
        reviewed_skipped=reviewed_skipped,
    )
    if options.metadata_only or not plugins:
        return result

    if options.preview:
        result.preview_downloads = sum(
            1 for plugin in plugins if not manifest.is_downloaded(plugin["slug"])
        )
        result.preview_cached = len(plugins) - result.preview_downloads
        return result

    global_slugs: set[str] | None = None
    if options.global_dedup and not options.force:
        global_slugs = downloader.build_global_slug_index(str(root.parent))
        for child in root.iterdir():
            if child.is_dir() and not child.is_symlink():
                global_slugs.discard(child.name)
    downloader.download_all(
        plugins=plugins,
        output_dir=str(root),
        max_workers=options.workers,
        skip_existing=not options.force,
        update_check=options.update_check,
        global_slugs=global_slugs,
        max_bytes=options.max_download_mb * 1024 * 1024,
    )
    return result


def execute_scan(options: ScanOptions) -> Path:
    root = core._validate_triage_root(options.root, allow_unmarked=options.allow_unmarked)
    migrate_triage_result(root)
    marked = core._root_marker_state(root / core.ROOT_MARKER_FILE) == "valid"
    if options.delete_no_findings and not marked:
        raise ValueError("Live deletion requires a marked WP Hunter output root")
    semgrep, rules = core._semgrep_or_exit(options.semgrep, options.rules)
    ledger = ReviewLedger(root) if marked else None
    safe_workers, warning = core._safe_triage_workers(options.workers, options.mem_mb)
    if warning:
        print(f"  [WARN] {warning}")
    triage.run_triage(
        output_dir=str(root),
        semgrep_path=semgrep,
        semgrep_rules=rules,
        workers=safe_workers,
        timeout=options.timeout,
        mem_mb=options.mem_mb,
        dry_run=not options.delete_no_findings,
        keep_extracted=options.keep_extracted,
        max_age_years=options.max_age_years,
        since=options.since,
        allow_unmarked=options.allow_unmarked,
        review_ledger=ledger,
        language=options.language,
    )
    return root
