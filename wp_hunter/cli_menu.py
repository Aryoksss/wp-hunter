from __future__ import annotations

from collections.abc import Callable

import questionary
import typer
from rich.console import Console
from rich.panel import Panel

from .config import config_path, save_config
from .i18n import set_language, tr
from .models import DownloadOptions

_LANGUAGES = ("en", "id")


def _ask_download_limit(defaults: dict, questionary_module) -> int | None:
    value = questionary_module.text(
        tr("prompt.download_limit"),
        default=str(defaults.get("download_limit", 0)),
        validate=_validate_nonnegative_input,
    ).ask()
    if value is None:
        raise typer.Exit()
    limit = int(value.strip() or "0")
    return limit or None


def _validate_nonnegative_input(value: str) -> bool | str:
    try:
        return int(value.strip() or "0") >= 0 or tr("prompt.nonnegative_integer")
    except ValueError:
        return tr("prompt.nonnegative_integer")


def _select_language(default: str) -> str | None:
    return questionary.select(
        "Language / Bahasa",
        choices=[
            questionary.Choice("English", "en"),
            questionary.Choice("Bahasa Indonesia", "id"),
        ],
        default=default,
    ).ask()


def interactive_menu(
    ctx: typer.Context,
    state,
    *,
    run_download: Callable[..., object],
    scan_command: Callable[..., None],
    status_command: Callable[..., None],
    doctor_command: Callable[..., None],
) -> None:
    console: Console = state.console
    path = config_path()
    if not path.exists():
        language = _select_language("en")
        if language is None:
            raise typer.Exit()
        state.config["language"] = language
        set_language(language)
        save_config(state.config)
    console.print(Panel.fit(f"[bold cyan]WP Hunter[/bold cyan]\n{tr('app.tagline')}"))
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
        limit = _ask_download_limit(defaults, questionary)
        preview = questionary.confirm(tr("prompt.preview"), default=False).ask()
        run_download(
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
        limit = _ask_download_limit(defaults, questionary)
        preview = questionary.confirm(tr("prompt.preview"), default=False).ask()
        run_download(
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
            scan_command(
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
        doctor_command(ctx, semgrep=None, rules=None)
    else:
        language = _select_language(str(state.config.get("language", "en")))
        if language:
            state.config["language"] = language
            set_language(language)
            save_config(state.config)
            console.print(f"[green]{tr('common.language_saved')}[/green]")
