from __future__ import annotations

import signal
import threading

import typer

from . import schedule
from . import watch as watch_module
from .cli_context import AppContext, print_error
from .i18n import tr
from .installs import parse_installs_input as parse_installs
from .lock import StateBusy, state_lock


def register(app: typer.Typer) -> None:
    app.command("watch", help="Watch popular plugins for updates / Pantau update plugin populer.")(
        watch
    )


def watch(
    ctx: typer.Context,
    installs: str | None = typer.Option(
        None, help="Minimum installs, e.g. 100K or 1M. Default: no minimum."
    ),
    limit: int = typer.Option(5, min=1, help="API pages to scan (~100 plugins each)."),
    every: str | None = typer.Option(
        None,
        "--every",
        help="Check interval: 30m, 2h, 1h30m. A bare number means minutes.",
    ),
    interval: int | None = typer.Option(
        None, min=60, help="Legacy: seconds between checks in --daemon mode."
    ),
    daemon: bool = typer.Option(False, help="Keep running and re-check every interval."),
    vuln: bool = typer.Option(
        False, help="Also check WPScan for known vulnerabilities (needs WPSCAN_API_TOKEN)."
    ),
    dry_run: bool = typer.Option(
        False, help="Report updates without recording state or notifying."
    ),
    no_notify: bool = typer.Option(
        False, "--no-notify", help="Print to stderr instead of Telegram."
    ),
    install_timer: bool = typer.Option(
        False,
        "--install-timer",
        help="Write and arm the systemd timer for this interval (needs root).",
    ),
) -> None:
    context: AppContext = ctx.find_root().obj
    try:
        target_installs = parse_installs(installs) if installs else 0
        interval_seconds = schedule.resolve_interval(
            every, interval, context.config.get("defaults", {})
        )
    except ValueError as exc:
        print_error(context.console, exc)
        raise typer.Exit(2) from exc

    if install_timer:
        try:
            actions = schedule.install_timer(interval_seconds, limit=limit)
        except (OSError, ValueError) as exc:
            print_error(context.console, exc)
            raise typer.Exit(2) from exc
        for action in actions:
            context.console.print(f"[green]{action}[/green]")
        context.console.print(
            tr("watch.timer_installed", every=schedule.format_duration(interval_seconds))
        )
        raise typer.Exit(0)

    def once() -> bool:
        try:
            with state_lock():
                report, result = watch_module.run_watch(
                    target_installs=target_installs,
                    max_pages=limit,
                    dry_run=dry_run,
                    notify=not no_notify,
                    check_vulnerabilities=vuln,
                )
        except StateBusy:
            # A manual /run from Telegram holds the lock; skipping this cycle is
            # normal and must not fail the timer.
            context.console.print(f"[dim]{tr('watch.busy')}[/dim]")
            return True
        if report.has_changes:
            context.console.print(
                f"[green]{tr('watch.changed', count=len(report.updated))}[/green]"
            )
        else:
            context.console.print(f"[dim]{tr('watch.unchanged', count=report.checked)}[/dim]")
        if report.vulnerable:
            context.console.print(
                f"[bold red]{tr('watch.vulnerable', count=len(report.vulnerable))}[/bold red]"
            )
        if not report.complete:
            context.console.print(
                f"[yellow]{tr('watch.partial', failed=report.failed_pages, checked=report.checked)}[/yellow]"
            )
        if result is not None:
            if result.skipped_reason:
                context.console.print(f"[yellow]{result.skipped_reason}[/yellow]")
            for error in result.errors:
                print_error(context.console, error)
            if result.delivered:
                context.console.print(
                    f"[green]{tr('watch.notified', count=result.delivered)}[/green]"
                )
            if not result.ok:
                return False
        # A partial listing is not a successful run: exit non-zero so cron and
        # systemd surface it instead of logging a green pass.
        return report.complete

    if not daemon:
        raise typer.Exit(0 if once() else 2)
    stop = threading.Event()

    def _request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    for signal_name in ("SIGINT", "SIGTERM"):
        handler = getattr(signal, signal_name, None)
        if handler is not None:
            signal.signal(handler, _request_stop)
    context.console.print(
        f"[dim]{tr('watch.interval', every=schedule.format_duration(interval_seconds))}[/dim]"
    )
    while not stop.is_set():
        once()
        stop.wait(interval_seconds)
    context.console.print(f"[yellow]{tr('common.cancelled')}[/yellow]")
    raise typer.Exit(0)
