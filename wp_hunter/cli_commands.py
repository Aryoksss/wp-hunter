from __future__ import annotations

import typer
from rich.panel import Panel
from rich.table import Table

from . import core
from .cli_context import print_error, state
from .i18n import get_language, tr
from .status import inspect_root


def register(app: typer.Typer) -> None:
    app.command("status", help="Show output status / Tampilkan status output.")(status_command)
    app.command("doctor", help="Check runtime setup / Periksa konfigurasi runtime.")(doctor)


def status_command(
    ctx: typer.Context,
    root: str | None = typer.Argument(None, help="Output folder; defaults to the most recent."),
    all_roots: bool = typer.Option(False, "--all", help="Show all remembered output roots."),
) -> None:
    context = state(ctx)
    roots = list(context.config.get("recent_roots", []))
    selected = roots if all_roots else ([root] if root else roots[:1])
    if not selected:
        context.console.print(f"[yellow]{tr('status.no_roots')}[/yellow]")
        return
    table = Table(title=tr("status.title"))
    for column in tr("status.columns").split("|"):
        table.add_column(column)
    for item in selected:
        try:
            status = inspect_root(item)
        except (OSError, TypeError, ValueError) as exc:
            print_error(context.console, exc)
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
    context.console.print(table)


def doctor(ctx: typer.Context, semgrep: str | None = None, rules: str | None = None) -> None:
    context = state(ctx)
    context.console.print(Panel(tr("doctor.title")))
    core.cmd_check(semgrep, rules, language=get_language())
