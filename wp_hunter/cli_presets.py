from __future__ import annotations

import json

import typer
from rich.table import Table

from .cli_context import print_error, state
from .config import BUILTIN_PRESETS, all_presets, get_preset, save_config
from .i18n import tr
from .models import DownloadOptions


def register(app: typer.Typer, download_runner) -> typer.Typer:
    preset_app = typer.Typer(help="Manage workflow presets / Kelola preset workflow.")
    preset_app.command("list")(preset_list)
    preset_app.command("show")(preset_show)
    preset_app.command("run")(_make_run(download_runner))
    preset_app.command("delete")(preset_delete)
    app.add_typer(preset_app, name="preset")
    return preset_app


def preset_list(ctx: typer.Context) -> None:
    context = state(ctx)
    table = Table(title="Presets")
    for column in tr("preset.columns").split("|"):
        table.add_column(column)
    for name, (values, builtin) in sorted(all_presets(context.config).items()):
        details = ", ".join(f"{key}={value}" for key, value in values.items() if key != "source")
        table.add_row(
            name,
            tr("preset.builtin") if builtin else tr("preset.user"),
            str(values["source"]),
            details,
        )
    context.console.print(table)


def preset_show(ctx: typer.Context, name: str) -> None:
    context = state(ctx)
    try:
        values, builtin = get_preset(context.config, name)
    except (KeyError, ValueError) as exc:
        print_error(context.console, tr("preset.missing", name=name))
        raise typer.Exit(2) from exc
    context.console.print_json(json.dumps({"name": name, "built_in": builtin, "options": values}))


def _make_run(download_runner):
    def preset_run(
        ctx: typer.Context,
        name: str,
        preview: bool = typer.Option(False, help="Preview without downloading."),
        output: str | None = typer.Option(None, help="Override output folder."),
    ) -> None:
        context = state(ctx)
        try:
            values, _builtin = get_preset(context.config, name)
            values["preview"] = preview
            if output:
                values["output"] = output
            options = DownloadOptions(**values)
        except (KeyError, TypeError, ValueError) as exc:
            print_error(
                context.console,
                tr("preset.missing", name=name) if isinstance(exc, KeyError) else exc,
            )
            raise typer.Exit(2) from exc
        download_runner(ctx, options)

    return preset_run


def preset_delete(ctx: typer.Context, name: str, yes: bool = typer.Option(False, "--yes")) -> None:
    context = state(ctx)
    if name in BUILTIN_PRESETS:
        print_error(context.console, f"Built-in preset {name!r} is immutable")
        raise typer.Exit(2)
    presets = context.config.get("presets", {})
    if name not in presets:
        print_error(context.console, tr("preset.missing", name=name))
        raise typer.Exit(2)
    if not yes and not typer.confirm(tr("preset.delete_confirm", name=name), default=False):
        context.console.print(f"[yellow]{tr('common.cancelled')}[/yellow]")
        return
    del presets[name]
    save_config(context.config)
    context.console.print(f"[green]{tr('preset.deleted', name=name)}[/green]")
