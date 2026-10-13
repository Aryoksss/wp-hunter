from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import typer
from rich.console import Console

from .config import remember_root, save_config
from .i18n import tr
from .models import DownloadOptions


@dataclass
class AppContext:
    config: dict
    console: Console


def state(ctx: typer.Context) -> AppContext:
    value = ctx.find_root().obj
    if not isinstance(value, AppContext):
        raise RuntimeError("WP Hunter application context is unavailable")
    return value


def print_error(console: Console, error: object) -> None:
    console.print(f"[bold red]{tr('common.error')}:[/bold red] {error}")


def confirm_exact_path(root: str | Path, prompt_key: str = "confirm.delete") -> bool:
    resolved = str(Path(root).expanduser().resolve())
    entered = typer.prompt(f"{tr(prompt_key)} ({resolved})", default="", show_default=False)
    return entered == resolved


def save_and_remember(context: AppContext, root: Path) -> None:
    remember_root(context.config, root)
    save_config(context.config)


def save_requested_preset(context: AppContext, options: DownloadOptions) -> None:
    if not options.save_preset:
        return
    existing = context.config.get("presets", {})
    if (
        options.replace_preset
        and options.save_preset in existing
        and not typer.confirm(tr("preset.replace_confirm", name=options.save_preset), default=False)
    ):
        context.console.print(f"[yellow]{tr('common.cancelled')}[/yellow]")
        raise typer.Exit()
    from .config import save_preset

    save_preset(
        context.config,
        options.save_preset,
        options.preset_values(),
        replace=options.replace_preset,
    )
    save_config(context.config)
    context.console.print(f"[green]{tr('preset.saved', name=options.save_preset)}[/green]")
