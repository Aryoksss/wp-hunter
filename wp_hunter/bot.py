"""Telegram command bot: change the watch cadence from the chat itself.

The bot long-polls ``getUpdates`` with the same token the notifier uses and
answers only messages that arrive from the configured chat.  Commands are
deliberately small and non-destructive: they never scan plugins on disk and
never touch a WP Hunter output root.
"""

from __future__ import annotations

import html
import json
import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from . import httpclient, schedule
from .config import config_dir, load_config, save_config
from .i18n import tr
from .lock import StateBusy, state_lock
from .notifiers import TelegramNotifier
from .watch import WatchReport, _headline, run_watch
from .watch_state import WatchState

TELEGRAM_API = "https://api.telegram.org/bot{token}/{method}"
OFFSET_FILE = "bot_offset.json"
POLL_TIMEOUT_SECONDS = 25
ERROR_BACKOFF_SECONDS = 10
MAX_BACKOFF_SECONDS = 120
WATCH_ALL_PAGES_CAP = 600
PLUGINS_PER_PAGE = 100


class BotError(RuntimeError):
    """A Telegram API call failed in a way the caller should report."""


class Sender(Protocol):
    def send(self, text: str) -> Any: ...


def parse_command(text: str) -> tuple[str, list[str]]:
    parts = (text or "").strip().split()
    if not parts or not parts[0].startswith("/"):
        return "", []
    command = parts[0][1:].split("@", 1)[0].lower()
    return command, parts[1:]


def _redact(text: str, token: str) -> str:
    """Never let a token reach the journal through an HTTP error message."""
    return text.replace(token, "<token>") if token else text


def _systemctl(*args: str) -> str:
    try:
        result = subprocess.run(
            ["systemctl", *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode != 0:
        return ""
    return (result.stdout or "").strip()


def timer_state() -> tuple[str, str]:
    """Return (is-active, next elapse) for the watcher timer."""
    active = _systemctl("is-active", schedule.TIMER_UNIT) or "unknown"
    next_run = _systemctl("show", "-p", "NextElapseUSecRealtime", "--value", schedule.TIMER_UNIT)
    return active, next_run or "-"


def watcher_busy() -> bool:
    return _systemctl("is-active", schedule.SERVICE_UNIT) in {"active", "activating", "reloading"}


class TelegramBot:
    def __init__(
        self,
        token: str,
        chat_id: str,
        *,
        config_path: Path | None = None,
        state_path: Path | None = None,
        offset_path: Path | None = None,
        notifier: Sender | None = None,
        watch_runner: Callable[..., tuple[WatchReport, Any]] = run_watch,
        api_get: Callable[..., Any] = httpclient.get,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.token = token
        self.chat_id = str(chat_id)
        self.config_path = config_path
        self.state_path = state_path
        self.offset_path = offset_path or (config_dir() / OFFSET_FILE)
        self._notifier = notifier or TelegramNotifier(token=token, chat_id=self.chat_id)
        self._watch_runner = watch_runner
        self._api_get = api_get
        self._sleep = sleep
        self._stop = threading.Event()
        self._run_thread: threading.Thread | None = None
        self._lock_dir = state_path.parent if state_path is not None else config_dir()

    # -- transport ---------------------------------------------------------
    def api(self, method: str, **params: Any) -> dict:
        try:
            response = self._api_get(
                TELEGRAM_API.format(token=self.token, method=method),
                params=params,
                timeout=POLL_TIMEOUT_SECONDS + 15,
            )
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:  # network and HTTP errors are reported, never retried silently
            raise BotError(_redact(str(exc), self.token)) from exc
        if not isinstance(payload, dict) or not payload.get("ok"):
            description = payload.get("description") if isinstance(payload, dict) else None
            raise BotError(str(description or "Telegram API call failed"))
        return payload

    def send(self, text: str) -> None:
        result = self._notifier.send(text)
        if not result.ok:
            print(f"  [WARN] could not reply: {result.errors[0]}", file=sys.stderr)

    # -- state -------------------------------------------------------------
    def load_offset(self) -> int | None:
        try:
            payload = json.loads(self.offset_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        offset = payload.get("offset") if isinstance(payload, dict) else None
        return offset if isinstance(offset, int) and offset >= 0 else None

    def save_offset(self, offset: int) -> None:
        try:
            self.offset_path.parent.mkdir(parents=True, exist_ok=True)
            self.offset_path.write_text(json.dumps({"offset": offset}), encoding="utf-8")
        except OSError as exc:
            print(f"  [WARN] could not persist bot offset: {exc}", file=sys.stderr)

    # -- commands ----------------------------------------------------------
    def _config(self) -> dict:
        return load_config(self.config_path)

    def _interval(self) -> int:
        return schedule.resolve_interval(None, None, self._config().get("defaults", {}))

    def handle(self, text: str) -> str:
        command, args = parse_command(text)
        if command in {"start", "help"}:
            return tr("bot.help")
        if command == "time":
            return self._cmd_time(args)
        if command == "status":
            return self._cmd_status()
        if command == "run":
            return self._cmd_run(args)
        if not command:
            return ""
        return tr("bot.unknown")

    def _cmd_time(self, args: list[str]) -> str:
        if not args:
            return tr("bot.time_current", every=schedule.format_duration(self._interval()))
        try:
            seconds = schedule.parse_duration(args[0])
        except ValueError as exc:
            return tr("bot.time_invalid", error=html.escape(str(exc)))
        config = self._config()
        config.setdefault("defaults", {})["watch_every"] = schedule.format_duration(seconds)
        save_config(config, self.config_path)
        every = schedule.format_duration(seconds)
        if os.geteuid() != 0:
            return tr("bot.time_needs_root", every=every)
        try:
            # limit=None keeps the existing service ExecStart untouched.
            schedule.install_timer(seconds, limit=None)
        except (OSError, ValueError) as exc:
            return tr("bot.time_timer_failed", every=every, error=html.escape(str(exc)))
        return tr("bot.time_set", every=every)

    def _cmd_status(self) -> str:
        state = WatchState(self.state_path)
        entries = state.snapshot()["plugins"]
        checked = [
            entry.get("checked_at", "") for entry in entries.values() if entry.get("checked_at")
        ]
        active, next_run = timer_state()
        return tr(
            "bot.status",
            plugins=len(entries),
            last=html.escape(max(checked)[:16].replace("T", " ")) if checked else "-",
            every=schedule.format_duration(self._interval()),
            pages=self._run_pages([]),
            timer=f"{html.escape(active)} · next {html.escape(next_run)}",
        )

    def _run_pages(self, args: list[str]) -> int:
        """Pages to scan for /run: explicit argument, then config, then the service."""
        if args:
            if args[0].lower() in {"all", "semua"}:
                return WATCH_ALL_PAGES_CAP
            try:
                pages = int(args[0])
            except ValueError as exc:
                raise ValueError("pages must be a number or 'all'") from exc
            return max(1, min(WATCH_ALL_PAGES_CAP, pages))
        configured = self._config().get("defaults", {}).get("watch_pages")
        if isinstance(configured, int) and not isinstance(configured, bool) and configured > 0:
            return min(WATCH_ALL_PAGES_CAP, configured)
        return min(WATCH_ALL_PAGES_CAP, schedule.read_service_limit() or 50)

    def _cmd_run(self, args: list[str] | None = None) -> str:
        try:
            pages = self._run_pages(args or [])
        except ValueError as exc:
            return tr("bot.run_invalid", error=html.escape(str(exc)))
        if self._run_thread is not None and self._run_thread.is_alive():
            return tr("bot.run_already")
        if watcher_busy():
            return tr("bot.run_busy")
        # Run off the poll loop: a 600-page sweep must not block /status or /time.
        thread = threading.Thread(
            target=self._run_job,
            args=(pages,),
            name="wp-hunter-run",
            daemon=True,
        )
        self._run_thread = thread
        thread.start()
        return tr("bot.run_started", pages=pages, approx=f"{pages * PLUGINS_PER_PAGE:,}")

    def _run_job(self, pages: int) -> None:
        try:
            with state_lock(self._lock_dir):
                report, _ = self._watch_runner(max_pages=pages, notify=False)
        except StateBusy:
            self.send(tr("bot.run_busy"))
            return
        except Exception as exc:  # a failed scan must still answer the chat
            self.send(tr("bot.run_failed", error=html.escape(str(exc))))
            return
        if report.has_changes:
            self.send(_headline(report, empty=False))
        else:
            self.send(tr("bot.run_none", count=report.checked))

    def wait_for_run(self, timeout: float = 30.0) -> bool:
        thread = self._run_thread
        if thread is None:
            return True
        thread.join(timeout)
        return not thread.is_alive()

    # -- polling -----------------------------------------------------------
    def _authorized(self, message: dict) -> bool:
        chat = message.get("chat")
        if not isinstance(chat, dict):
            return False
        return str(chat.get("id")) == self.chat_id

    def get_updates(self, offset: int | None, timeout: int = POLL_TIMEOUT_SECONDS) -> list[dict]:
        params: dict[str, Any] = {"timeout": timeout, "limit": 20}
        if offset is not None:
            params["offset"] = offset
        payload = self.api("getUpdates", **params)
        updates = payload.get("result")
        if not isinstance(updates, list):
            return []
        return [update for update in updates if isinstance(update, dict)]

    def drain(self) -> int:
        """Skip updates queued before this process started, without running them."""
        payload = self.api("getUpdates", offset=-1, timeout=0, limit=1)
        updates = payload.get("result") or []
        offset = 0
        for update in updates:
            if isinstance(update, dict) and isinstance(update.get("update_id"), int):
                offset = update["update_id"] + 1
        self.save_offset(offset)
        return offset

    def poll_once(self, offset: int | None = None) -> tuple[int, int]:
        """Process one batch. Returns (handled, next_offset)."""
        handled = 0
        for update in self.get_updates(offset):
            update_id = update.get("update_id")
            if isinstance(update_id, int):
                offset = update_id + 1
                self.save_offset(offset)
            message = update.get("message")
            if not isinstance(message, dict) or not self._authorized(message):
                continue
            text = message.get("text")
            if not isinstance(text, str):
                continue
            reply = self.handle(text)
            if reply:
                self.send(reply)
            handled += 1
        return handled, offset or 0

    def run_forever(self) -> None:
        offset = self.load_offset()
        if offset is None:
            try:
                offset = self.drain()
            except BotError as exc:
                raise BotError(
                    f"could not read the update queue ({exc}). "
                    "If a webhook is set, delete it with deleteWebhook first."
                ) from exc
        backoff = ERROR_BACKOFF_SECONDS
        while not self._stop.is_set():
            try:
                handled, offset = self.poll_once(offset)
            except BotError as exc:
                print(f"  [WARN] polling failed: {exc}", file=sys.stderr)
                self._stop.wait(backoff)
                backoff = min(MAX_BACKOFF_SECONDS, backoff * 2)
                continue
            backoff = ERROR_BACKOFF_SECONDS
            if handled == 0:
                self._stop.wait(1)

    def stop(self) -> None:
        self._stop.set()


def install_signal_handlers(bot: TelegramBot) -> None:
    import signal

    for signal_name in ("SIGINT", "SIGTERM"):
        handler = getattr(signal, signal_name, None)
        if handler is not None:
            signal.signal(handler, lambda *_: bot.stop())
