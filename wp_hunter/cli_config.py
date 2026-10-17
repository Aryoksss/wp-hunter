from __future__ import annotations

import json

import typer

from .cli_context import state
from .config import default_config, save_config
from .i18n import set_language, tr
from .schedule import format_duration, parse_duration


def register(app: typer.Typer) -> None:
    config_app = typer.Typer(help="Manage user preferences / Kelola preferensi pengguna.")
    config_app.command("show")(config_show)
    config_app.command("set")(config_set)
    config_app.command("reset")(config_reset)
    app.add_typer(config_app, name="config")


def config_show(ctx: typer.Context) -> None:
    context = state(ctx)
    context.console.print_json(json.dumps(context.config))


def config_set(ctx: typer.Context, key: str, value: str) -> None:
    context = state(ctx)
    if key == "language":
        if value not in {"en", "id"}:
            raise typer.BadParameter("language must be en or id")
        context.config["language"] = value
        set_language(value)
    elif key == "output_parent":
        context.config.setdefault("defaults", {})[key] = value
    elif key == "watch_every":
        try:
            seconds = parse_duration(value)
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
        context.config.setdefault("defaults", {})[key] = format_duration(seconds)
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
        context.config.setdefault("defaults", {})[key] = numeric
    else:
        raise typer.BadParameter("Unsupported key")
    path = save_config(context.config)
    context.console.print(f"[green]{tr('config.saved', path=path)}[/green]")


def config_reset(ctx: typer.Context, yes: bool = typer.Option(False, "--yes")) -> None:
    context = state(ctx)
    if not yes and not typer.confirm(tr("config.reset_confirm"), default=False):
        context.console.print(f"[yellow]{tr('common.cancelled')}[/yellow]")
        return
    context.config = default_config()
    save_config(context.config)
    set_language("en")
    context.console.print(f"[green]{tr('config.reset')}[/green]")
