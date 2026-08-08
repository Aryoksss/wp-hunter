from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import questionary
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__, core
from .config import (
    BUILTIN_PRESETS,
    all_presets,
    config_path,
    default_config,
    get_preset,
    load_config,
    remember_root,
    save_config,
    save_preset,
)
from .i18n import get_language, set_language, tr
from .models import DownloadOptions, ScanOptions
from .services import DownloadResult, execute_download, execute_scan
from .status import inspect_root

app = typer.Typer(
    name="wp-hunter",
    help="WordPress vulnerability research toolkit / Toolkit riset kerentanan WordPress.",
    no_args_is_help=False,
    rich_markup_mode="rich",
)
download_app = typer.Typer(help="Download WordPress targets / Unduh target WordPress.")
preset_app = typer.Typer(help="Manage workflow presets / Kelola preset workflow.")
config_app = typer.Typer(help="Manage user preferences / Kelola preferensi pengguna.")
app.add_typer(download_app, name="download")
app.add_typer(preset_app, name="preset")
app.add_typer(config_app, name="config")


@dataclass
class AppContext:
    config: dict
    console: Console


def _state(ctx: typer.Context) -> AppContext:
    state = ctx.find_root().obj
    if not isinstance(state, AppContext):
        raise RuntimeError("WP Hunter application context is unavailable")
    return state


def _print_error(console: Console, error: object) -> None:
    console.print(f"[bold red]{tr('common.error')}:[/bold red] {error}")


def _validate_date(value: str) -> str:
    try:
        return core._date_cli_value(value)
    except Exception as exc:
        raise typer.BadParameter("date must be YYYY, YYYY-MM, or YYYY-MM-DD") from exc


def _validate_nonnegative_input(value: str) -> bool | str:
    try:
        return int(value.strip() or "0") >= 0 or tr("prompt.nonnegative_integer")
    except ValueError:
        return tr("prompt.nonnegative_integer")


def _ask_download_limit(defaults: dict) -> int | None:
    value = questionary.text(
        tr("prompt.download_limit"),
        default=str(defaults.get("download_limit", 0)),
        validate=_validate_nonnegative_input,
    ).ask()
    if value is None:
        raise typer.Exit()
    limit = int(value.strip() or "0")
    return limit or None


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    lang: str | None = typer.Option(
        None, "--lang", help="Interface language / Bahasa antarmuka: en|id."
    ),
    no_color: bool = typer.Option(
        False, "--no-color", help="Disable colored output / Nonaktifkan warna."
    ),
    version: bool = typer.Option(
        False,
        "--version",
        is_eager=True,
        help="Show version and exit / Tampilkan versi lalu keluar.",
    ),
) -> None:
    if version:
        typer.echo(f"wp-hunter {__version__}")
        raise typer.Exit()
    try:
        config = load_config()
    except (OSError, ValueError) as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(2) from exc
    selected_language = lang or str(config.get("language", "en"))
    if selected_language not in {"en", "id"}:
        raise typer.BadParameter("--lang must be 'en' or 'id'")
    set_language(selected_language)
    ctx.obj = AppContext(config=config, console=Console(no_color=no_color))
    if ctx.invoked_subcommand is None:
        _interactive_menu(ctx)


def _confirm_exact_path(root: str | Path, prompt_key: str = "confirm.delete") -> bool:
    resolved = str(Path(root).expanduser().resolve())
    entered = typer.prompt(f"{tr(prompt_key)} ({resolved})", default="", show_default=False)
    return entered == resolved


def _save_and_remember(state: AppContext, root: Path) -> None:
    remember_root(state.config, root)
    save_config(state.config)


def _save_requested_preset(state: AppContext, options: DownloadOptions) -> None:
    if not options.save_preset:
        return
    existing = state.config.get("presets", {})
    if (
        options.replace_preset
        and options.save_preset in existing
        and not typer.confirm(tr("preset.replace_confirm", name=options.save_preset), default=False)
    ):
        state.console.print(f"[yellow]{tr('common.cancelled')}[/yellow]")
        raise typer.Exit()
    save_preset(
        state.config,
        options.save_preset,
        options.preset_values(),
        replace=options.replace_preset,
    )
    save_config(state.config)
    state.console.print(f"[green]{tr('preset.saved', name=options.save_preset)}[/green]")


def _run_download(ctx: typer.Context, options: DownloadOptions) -> DownloadResult:
    state = _state(ctx)
    if options.adopt_existing and options.output and not _confirm_exact_path(options.output):
        state.console.print(f"[yellow]{tr('common.cancelled')}[/yellow]")
        raise typer.Exit()
    if options.reset_cache:
        target = options.output or "the resolved output folder"
        if not typer.confirm(tr("download.reset_confirm", target=target), default=False):
            state.console.print(f"[yellow]{tr('common.cancelled')}[/yellow]")
            raise typer.Exit()
    try:
        _save_requested_preset(state, options)
        defaults = state.config.get("defaults", {})
        result = execute_download(options, defaults.get("output_parent", "."))
        _save_and_remember(state, result.root)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        _print_error(state.console, exc)
        raise typer.Exit(2) from exc
    if result.reviewed_skipped:
        state.console.print(
            f"[yellow]{tr('download.reviewed', count=result.reviewed_skipped)}[/yellow]"
        )
    if options.preview:
        state.console.print(
            tr(
                "download.preview",
                download=result.preview_downloads,
                cached=result.preview_cached,
            )
        )
    state.console.print(f"[green]{tr('download.complete', root=result.root)}[/green]")
    return result


@download_app.command("wporg")
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
    if browse not in {"popular", "new", "updated", "top-rated"}:
        raise typer.BadParameter("--browse must be popular, new, updated, or top-rated")
    if since:
        _validate_date(since)
    _run_download(
        ctx,
        DownloadOptions(
            source="wporg",
            installs=installs,
            installs_mode="minimum" if minimum else "exact",
            browse=browse,
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


@download_app.command("patchstack")
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
        _validate_date(since)
    _run_download(
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


@app.command("scan", help="Scan an output folder / Pindai folder output.")
def scan(
    ctx: typer.Context,
    root: str = typer.Argument(..., help="WP Hunter output folder."),
    delete_no_findings: bool = typer.Option(
        False, help="Delete folders only after a successful zero-finding scan."
    ),
    workers: int = typer.Option(2, min=1, help="Parallel Semgrep workers."),
    timeout: int = typer.Option(120, min=1, help="Timeout per plugin in seconds."),
    mem_mb: int = typer.Option(1024, min=1, help="Memory budget used for worker sizing."),
    max_age_years: int = typer.Option(2, min=0, help="Maximum plugin age; 0 scans all."),
    since: str | None = typer.Option(None, help="Scan plugins updated since YYYY-MM-DD."),
    keep_extracted: bool = typer.Option(False, help="Keep extracted source folders."),
    semgrep: str | None = typer.Option(None, help="Semgrep executable path."),
    rules: str | None = typer.Option(None, help="Semgrep rules file."),
    allow_unmarked: bool = typer.Option(
        False, help="Allow report-only scan of an unmarked legacy root."
    ),
) -> None:
    state = _state(ctx)
    if delete_no_findings and not _confirm_exact_path(root):
        state.console.print(f"[yellow]{tr('common.cancelled')}[/yellow]")
        raise typer.Exit()
    if since:
        _validate_date(since)
    try:
        resolved = execute_scan(
            ScanOptions(
                root=root,
                language=get_language(),
                delete_no_findings=delete_no_findings,
                workers=workers,
                timeout=timeout,
                mem_mb=mem_mb,
                max_age_years=max_age_years,
                since=since,
                keep_extracted=keep_extracted,
                semgrep=semgrep,
                rules=rules,
                allow_unmarked=allow_unmarked,
            )
        )
        _save_and_remember(state, resolved)
    except (OSError, TypeError, ValueError) as exc:
        _print_error(state.console, exc)
        raise typer.Exit(2) from exc
    state.console.print(f"[green]{tr('scan.complete', root=resolved)}[/green]")


@app.command("status", help="Show output status / Tampilkan status output.")
def status_command(
    ctx: typer.Context,
    root: str | None = typer.Argument(None, help="Output folder; defaults to the most recent."),
    all_roots: bool = typer.Option(False, "--all", help="Show all remembered output roots."),
) -> None:
    state = _state(ctx)
    roots = list(state.config.get("recent_roots", []))
    selected = roots if all_roots else ([root] if root else roots[:1])
    if not selected:
        state.console.print(f"[yellow]{tr('status.no_roots')}[/yellow]")
        return
    table = Table(title=tr("status.title"))
    for column in tr("status.columns").split("|"):
        table.add_column(column)
    for item in selected:
        try:
            status = inspect_root(item)
        except (OSError, TypeError, ValueError) as exc:
            _print_error(state.console, exc)
            continue
        table.add_row(
            str(status.root),
            str(status.downloaded),
            str(status.present),
            str(status.removed),
            str(status.reviewed),
            str(status.scan_candidates),
            str(status.scan_errors),
            status.last_scan or "-",
        )
    state.console.print(table)


@app.command("doctor", help="Check runtime setup / Periksa konfigurasi runtime.")
def doctor(ctx: typer.Context, semgrep: str | None = None, rules: str | None = None) -> None:
    state = _state(ctx)
    state.console.print(Panel(tr("doctor.title")))
    core.cmd_check(semgrep, rules, language=get_language())


@preset_app.command("list")
def preset_list(ctx: typer.Context) -> None:
    state = _state(ctx)
    table = Table(title="Presets")
    for column in tr("preset.columns").split("|"):
        table.add_column(column)
    for name, (values, builtin) in sorted(all_presets(state.config).items()):
        details = ", ".join(f"{key}={value}" for key, value in values.items() if key != "source")
        table.add_row(
            name,
            tr("preset.builtin") if builtin else tr("preset.user"),
            str(values["source"]),
            details,
        )
    state.console.print(table)


@preset_app.command("show")
def preset_show(ctx: typer.Context, name: str) -> None:
    state = _state(ctx)
    try:
        values, builtin = get_preset(state.config, name)
    except (KeyError, ValueError) as exc:
        _print_error(state.console, tr("preset.missing", name=name))
        raise typer.Exit(2) from exc
    state.console.print_json(json.dumps({"name": name, "built_in": builtin, "options": values}))


@preset_app.command("run")
def preset_run(
    ctx: typer.Context,
    name: str,
    preview: bool = typer.Option(False, help="Preview without downloading."),
    output: str | None = typer.Option(None, help="Override output folder."),
) -> None:
    state = _state(ctx)
    try:
        values, _builtin = get_preset(state.config, name)
        values["preview"] = preview
        if output:
            values["output"] = output
        options = DownloadOptions(**values)
    except (KeyError, TypeError, ValueError) as exc:
        _print_error(
            state.console, tr("preset.missing", name=name) if isinstance(exc, KeyError) else exc
        )
        raise typer.Exit(2) from exc
    _run_download(ctx, options)


@preset_app.command("delete")
def preset_delete(ctx: typer.Context, name: str, yes: bool = typer.Option(False, "--yes")) -> None:
    state = _state(ctx)
    if name in BUILTIN_PRESETS:
        _print_error(state.console, f"Built-in preset {name!r} is immutable")
        raise typer.Exit(2)
    presets = state.config.get("presets", {})
    if name not in presets:
        _print_error(state.console, tr("preset.missing", name=name))
        raise typer.Exit(2)
    if not yes and not typer.confirm(tr("preset.delete_confirm", name=name), default=False):
        state.console.print(f"[yellow]{tr('common.cancelled')}[/yellow]")
        return
    del presets[name]
    save_config(state.config)
    state.console.print(f"[green]{tr('preset.deleted', name=name)}[/green]")


@config_app.command("show")
def config_show(ctx: typer.Context) -> None:
    _state(ctx).console.print_json(json.dumps(_state(ctx).config))


@config_app.command("set")
def config_set(ctx: typer.Context, key: str, value: str) -> None:
    state = _state(ctx)
    if key == "language":
        if value not in {"en", "id"}:
            raise typer.BadParameter("language must be en or id")
        state.config["language"] = value
        set_language(value)
    elif key == "output_parent":
        state.config.setdefault("defaults", {})[key] = value
    elif key in {
        "download_workers",
        "api_workers",
        "scan_workers",
        "scan_timeout",
        "scan_mem_mb",
        "max_age_years",
        "download_limit",
    }:
        try:
            numeric = int(value)
        except ValueError as exc:
            raise typer.BadParameter(f"{key} must be an integer") from exc
        nonnegative = {"max_age_years", "download_limit"}
        if key not in nonnegative and numeric < 1:
            raise typer.BadParameter(f"{key} must be greater than zero")
        if key in nonnegative and numeric < 0:
            raise typer.BadParameter(f"{key} cannot be negative")
        state.config.setdefault("defaults", {})[key] = numeric
    else:
        raise typer.BadParameter("Unsupported key")
    path = save_config(state.config)
    state.console.print(f"[green]{tr('config.saved', path=path)}[/green]")


@config_app.command("reset")
def config_reset(ctx: typer.Context, yes: bool = typer.Option(False, "--yes")) -> None:
    state = _state(ctx)
    if not yes and not typer.confirm(tr("config.reset_confirm"), default=False):
        state.console.print(f"[yellow]{tr('common.cancelled')}[/yellow]")
        return
    state.config = default_config()
    save_config(state.config)
    set_language("en")
    state.console.print(f"[green]{tr('config.reset')}[/green]")


def _interactive_menu(ctx: typer.Context) -> None:
    state = _state(ctx)
    path = config_path()
    if not path.exists():
        language = questionary.select(
            "Language / Bahasa",
            choices=[
                questionary.Choice("English", "en"),
                questionary.Choice("Bahasa Indonesia", "id"),
            ],
            default="en",
        ).ask()
        if language is None:
            raise typer.Exit()
        state.config["language"] = language
        set_language(language)
        save_config(state.config)
    state.console.print(Panel.fit(f"[bold cyan]WP Hunter[/bold cyan]\n{tr('app.tagline')}"))
    choices = [
        questionary.Choice(tr("menu.wporg"), "wporg"),
        questionary.Choice(tr("menu.patchstack"), "patchstack"),
        questionary.Choice(tr("menu.scan"), "scan"),
        questionary.Choice(tr("menu.status"), "status"),
        questionary.Choice(tr("menu.doctor"), "doctor"),
        questionary.Choice(tr("menu.settings"), "settings"),
        questionary.Choice(tr("menu.exit"), "exit"),
    ]
    action = questionary.select(tr("menu.title"), choices=choices).ask()
    if action in {None, "exit"}:
        raise typer.Exit()
    defaults = state.config.get("defaults", {})
    if action == "wporg":
        installs = questionary.text(tr("prompt.install_tier"), default="10K").ask() or "10K"
        minimum = questionary.confirm(tr("prompt.minimum"), default=False).ask()
        limit = _ask_download_limit(defaults)
        preview = questionary.confirm(tr("prompt.preview"), default=False).ask()
        _run_download(
            ctx,
            DownloadOptions(
                source="wporg",
                installs=installs,
                installs_mode="minimum" if minimum else "exact",
                pages=int(defaults.get("pages", 50)),
                max_age_years=int(defaults.get("max_age_years", 2)),
                workers=int(defaults.get("download_workers", 3)),
                api_workers=int(defaults.get("api_workers", 5)),
                limit=limit,
                preview=bool(preview),
            ),
        )
    elif action == "patchstack":
        boost = questionary.text(tr("prompt.min_boost"), default="0").ask() or "0"
        limit = _ask_download_limit(defaults)
        preview = questionary.confirm(tr("prompt.preview"), default=False).ask()
        _run_download(
            ctx,
            DownloadOptions(
                source="patchstack",
                min_boost=max(0, int(boost)),
                max_age_years=int(defaults.get("max_age_years", 2)),
                workers=int(defaults.get("download_workers", 3)),
                api_workers=int(defaults.get("api_workers", 5)),
                limit=limit,
                preview=bool(preview),
            ),
        )
    elif action == "scan":
        root = questionary.path(tr("prompt.output_folder")).ask()
        if root:
            scan(
                ctx,
                root=root,
                delete_no_findings=False,
                workers=int(defaults.get("scan_workers", 2)),
                timeout=int(defaults.get("scan_timeout", 120)),
                mem_mb=int(defaults.get("scan_mem_mb", 1024)),
                max_age_years=int(defaults.get("max_age_years", 2)),
                since=None,
                keep_extracted=False,
                semgrep=None,
                rules=None,
                allow_unmarked=False,
            )
    elif action == "status":
        status_command(ctx, root=None, all_roots=False)
    elif action == "doctor":
        doctor(ctx, semgrep=None, rules=None)
    else:
        language = questionary.select(
            "Language / Bahasa",
            choices=[
                questionary.Choice("English", "en"),
                questionary.Choice("Bahasa Indonesia", "id"),
            ],
            default=str(state.config.get("language", "en")),
        ).ask()
        if language:
            state.config["language"] = language
            set_language(language)
            save_config(state.config)
            state.console.print(f"[green]{tr('common.language_saved')}[/green]")


def run() -> None:
    app()
