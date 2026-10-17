from __future__ import annotations

import os

import typer

from . import schedule
from .bot import BotError, TelegramBot, install_signal_handlers
from .cli_context import print_error, state
from .i18n import tr
from .notifiers import TELEGRAM_CHAT_ID_ENV, TELEGRAM_TOKEN_ENV


def register(app: typer.Typer) -> None:
    app.command("bot", help="Telegram command bot / Bot perintah Telegram.")(bot)


def bot(
    ctx: typer.Context,
    once: bool = typer.Option(False, "--once", help="Process pending commands once and exit."),
    install_service: bool = typer.Option(
        False, "--install-service", help="Write and start the systemd unit (needs root)."
    ),
) -> None:
    context = state(ctx)

    if install_service:
        try:
            actions = schedule.install_bot_service()
        except (OSError, ValueError) as exc:
            print_error(context.console, exc)
            raise typer.Exit(2) from exc
        for action in actions:
            context.console.print(f"[green]{action}[/green]")
        context.console.print(tr("bot.service_installed"))
        raise typer.Exit(0)

    token = os.environ.get(TELEGRAM_TOKEN_ENV, "").strip()
    chat_id = os.environ.get(TELEGRAM_CHAT_ID_ENV, "").strip()
    if not token or not chat_id:
        print_error(
            context.console,
            f"set {TELEGRAM_TOKEN_ENV} and {TELEGRAM_CHAT_ID_ENV} before starting the bot",
        )
        raise typer.Exit(2)

    runner = TelegramBot(token, chat_id)
    if once:
        try:
            handled, offset = runner.poll_once(runner.load_offset())
        except BotError as exc:
            print_error(context.console, exc)
            raise typer.Exit(2) from exc
        context.console.print(tr("bot.once", handled=handled, offset=offset))
        return

    install_signal_handlers(runner)
    context.console.print(tr("bot.listening"))
    try:
        runner.run_forever()
    except BotError as exc:
        print_error(context.console, exc)
        raise typer.Exit(2) from exc
