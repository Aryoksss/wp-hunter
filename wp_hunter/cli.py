from __future__ import annotations

import typer
from rich.console import Console

from . import (
    __version__,
    cli_bot,
    cli_commands,
    cli_config,
    cli_context,
    cli_download,
    cli_menu,
    cli_presets,
    cli_watch,
)
from .config import load_config
from .i18n import get_language, set_language, tr
from .models import ScanOptions
from .services import execute_scan

app = typer.Typer(
    name="wp-hunter",
    help="WordPress vulnerability research toolkit / Toolkit riset kerentanan WordPress.",
    no_args_is_help=False,
    rich_markup_mode="rich",
)
cli_watch.register(app)
cli_bot.register(app)
cli_commands.register(app)
cli_download.register(app)
cli_config.register(app)
cli_presets.register(app, cli_download.run_download)

AppContext = cli_context.AppContext
_state = cli_context.state
_print_error = cli_context.print_error
_confirm_exact_path = cli_context.confirm_exact_path


def _validate_date(value: str) -> str:
    return cli_download.validate_date(value)


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
        cli_context.save_and_remember(state, resolved)
    except (OSError, TypeError, ValueError) as exc:
        _print_error(state.console, exc)
        raise typer.Exit(2) from exc
    state.console.print(f"[green]{tr('scan.complete', root=resolved)}[/green]")


def _interactive_menu(ctx: typer.Context) -> None:
    cli_menu.interactive_menu(
        ctx,
        _state(ctx),
        run_download=cli_download.run_download,
        scan_command=scan,
        status_command=cli_commands.status_command,
        doctor_command=cli_commands.doctor,
    )


def run() -> None:
    app()
