from __future__ import annotations

import typer

from .cli_context import (
    confirm_exact_path,
    print_error,
    save_and_remember,
    save_requested_preset,
    state,
)
from .i18n import tr
from .models import DownloadOptions
from .services import DownloadResult, execute_download
from .validation import as_browse_mode


def validate_date(value: str) -> str:
    from . import core

    try:
        return core._date_cli_value(value)
    except Exception as exc:
        raise typer.BadParameter("date must be YYYY, YYYY-MM, or YYYY-MM-DD") from exc


def run_download(ctx: typer.Context, options: DownloadOptions) -> DownloadResult:
    context = state(ctx)
    if options.adopt_existing and options.output and not confirm_exact_path(options.output):
        context.console.print(f"[yellow]{tr('common.cancelled')}[/yellow]")
        raise typer.Exit()
    if options.reset_cache:
        target = options.output or "the resolved output folder"
        if not typer.confirm(tr("download.reset_confirm", target=target), default=False):
            context.console.print(f"[yellow]{tr('common.cancelled')}[/yellow]")
            raise typer.Exit()
    try:
        save_requested_preset(context, options)
        defaults = context.config.get("defaults", {})
        result = execute_download(options, defaults.get("output_parent", "."))
        save_and_remember(context, result.root)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        print_error(context.console, exc)
        raise typer.Exit(2) from exc
    _report_result(context, result, options)
    return result


def _report_result(context, result: DownloadResult, options: DownloadOptions) -> None:
    if result.reviewed_skipped:
        context.console.print(
            f"[yellow]{tr('download.reviewed', count=result.reviewed_skipped)}[/yellow]"
        )
    if options.preview:
        context.console.print(
            tr(
                "download.preview",
                download=result.preview_downloads,
                cached=result.preview_cached,
            )
        )
    context.console.print(f"[green]{tr('download.complete', root=result.root)}[/green]")


def register(app: typer.Typer) -> None:
    download_app = typer.Typer(help="Download WordPress targets / Unduh target WordPress.")
    download_app.command("wporg")(download_wporg)
    download_app.command("patchstack")(download_patchstack)
    app.add_typer(download_app, name="download")


def download_wporg(
    ctx: typer.Context,
    installs: str = typer.Option("10K", help="Install tier or threshold."),
    minimum: bool = typer.Option(False, "--minimum", help="Use installs as a minimum threshold."),
    browse: str = typer.Option("popular", help="popular, new, updated, or top-rated."),
    pages: int = typer.Option(50, min=1, help="Maximum API pages, 100 plugins per page."),
    search: str | None = typer.Option(None, help="Search keyword."),
    tag: str | None = typer.Option(None, help="WordPress.org tag."),
    max_age_years: int = typer.Option(2, min=0, help="Maximum plugin age; 0 disables the filter."),
    since: str | None = typer.Option(None, help="Updated on or after YYYY-MM-DD."),
    limit: int | None = typer.Option(None, min=1, help="Maximum selected plugins."),
    output: str | None = typer.Option(None, help="Output folder."),
    workers: int = typer.Option(3, min=1, max=5, help="Parallel download workers."),
    api_workers: int = typer.Option(5, min=1, max=10, help="Parallel API workers."),
    max_download_mb: int = typer.Option(512, min=1, help="Maximum archive size."),
    preview: bool = typer.Option(False, help="Collect and show the plan without downloading."),
    metadata_only: bool = typer.Option(False, help="Export metadata without downloading."),
    force: bool = typer.Option(False, help="Ignore the download cache."),
    update_check: bool = typer.Option(False, help="Download newer releases."),
    revisit_reviewed: bool = typer.Option(False, help="Include unchanged reviewed releases."),
    no_global_dedup: bool = typer.Option(False, help="Disable sibling-folder deduplication."),
    reset_cache: bool = typer.Option(False, help="Clear this output root's download cache."),
    adopt_existing: bool = typer.Option(False, help="Adopt an existing non-empty output folder."),
    save_preset_name: str | None = typer.Option(
        None, "--save-preset", help="Save safe options as a preset."
    ),
    replace_preset: bool = typer.Option(False, help="Replace an existing user preset."),
) -> None:
    browse_mode = as_browse_mode(browse)
    if browse_mode is None:
        raise typer.BadParameter("--browse must be popular, new, updated, or top-rated")
    if since:
        validate_date(since)
    run_download(
        ctx,
        DownloadOptions(
            source="wporg",
            installs=installs,
            installs_mode="minimum" if minimum else "exact",
            browse=browse_mode,
            pages=pages,
            search=search,
            tag=tag,
            max_age_years=max_age_years,
            since=since,
            limit=limit,
            output=output,
            workers=workers,
            api_workers=api_workers,
            max_download_mb=max_download_mb,
            preview=preview,
            metadata_only=metadata_only,
            force=force,
            update_check=update_check,
            revisit_reviewed=revisit_reviewed,
            global_dedup=not no_global_dedup,
            reset_cache=reset_cache,
            adopt_existing=adopt_existing,
            save_preset=save_preset_name,
            replace_preset=replace_preset,
        ),
    )


def download_patchstack(
    ctx: typer.Context,
    min_boost: int = typer.Option(0, min=0, help="Minimum Patchstack bounty boost."),
    include_themes: bool = typer.Option(False, help="Include themes."),
    max_age_years: int = typer.Option(2, min=0, help="Maximum asset age; 0 disables the filter."),
    since: str | None = typer.Option(None, help="Updated on or after YYYY-MM-DD."),
    limit: int | None = typer.Option(None, min=1, help="Maximum selected assets."),
    output: str | None = typer.Option(None, help="Output folder."),
    workers: int = typer.Option(3, min=1, max=5, help="Parallel download workers."),
    api_workers: int = typer.Option(5, min=1, max=10, help="Parallel API workers."),
    max_download_mb: int = typer.Option(512, min=1, help="Maximum archive size."),
    preview: bool = typer.Option(False, help="Collect and show the plan without downloading."),
    metadata_only: bool = typer.Option(False, help="Export metadata without downloading."),
    force: bool = typer.Option(False, help="Ignore the download cache."),
    update_check: bool = typer.Option(False, help="Download newer releases."),
    revisit_reviewed: bool = typer.Option(False, help="Include unchanged reviewed releases."),
    no_global_dedup: bool = typer.Option(False, help="Disable sibling-folder deduplication."),
    reset_cache: bool = typer.Option(False, help="Clear this output root's download cache."),
    adopt_existing: bool = typer.Option(False, help="Adopt an existing non-empty output folder."),
    save_preset_name: str | None = typer.Option(
        None, "--save-preset", help="Save safe options as a preset."
    ),
    replace_preset: bool = typer.Option(False, help="Replace an existing user preset."),
) -> None:
    if since:
        validate_date(since)
    run_download(
        ctx,
        DownloadOptions(
            source="patchstack",
            min_boost=min_boost,
            include_themes=include_themes,
            max_age_years=max_age_years,
            since=since,
            limit=limit,
            output=output,
            workers=workers,
            api_workers=api_workers,
            max_download_mb=max_download_mb,
            preview=preview,
            metadata_only=metadata_only,
            force=force,
            update_check=update_check,
            revisit_reviewed=revisit_reviewed,
            global_dedup=not no_global_dedup,
            reset_cache=reset_cache,
            adopt_existing=adopt_existing,
            save_preset=save_preset_name,
            replace_preset=replace_preset,
        ),
    )
