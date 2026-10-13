from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field

from . import httpclient

TELEGRAM_API_TEMPLATE = "https://api.telegram.org/bot{token}/sendMessage"
TELEGRAM_TOKEN_ENV = "TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID_ENV = "TELEGRAM_CHAT_ID"
TELEGRAM_MAX_MESSAGE_CHARS = 4096


def _split_message(text: str, limit: int = TELEGRAM_MAX_MESSAGE_CHARS) -> list[str]:
    """Split on newlines so a long update digest fits Telegram's per-message cap."""
    if len(text) <= limit:
        return [text]
    chunks: list[str] = []
    current = ""
    for line in text.splitlines(keepends=True):
        if len(line) > limit:
            if current:
                chunks.append(current)
                current = ""
            for start in range(0, len(line), limit):
                chunks.append(line[start : start + limit])
            continue
        if len(current) + len(line) > limit:
            chunks.append(current)
            current = ""
        current += line
    if current:
        chunks.append(current)
    return chunks


@dataclass
class NotificationResult:
    delivered: int = 0
    skipped_reason: str | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


class TelegramNotifier:
    """Send updates to a Telegram chat using environment-provided credentials."""

    def __init__(
        self,
        token: str | None = None,
        chat_id: str | None = None,
        timeout: int = 20,
    ) -> None:
        self._token = token if token is not None else os.environ.get(TELEGRAM_TOKEN_ENV, "")
        self._chat_id = chat_id if chat_id is not None else os.environ.get(TELEGRAM_CHAT_ID_ENV, "")
        self._timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self._token and self._chat_id)

    def send(self, text: str) -> NotificationResult:
        if not self.configured:
            return NotificationResult(
                skipped_reason=(
                    f"Set {TELEGRAM_TOKEN_ENV} and {TELEGRAM_CHAT_ID_ENV} to enable "
                    "Telegram notifications."
                )
            )
        result = NotificationResult()
        for chunk in _split_message(text):
            payload = {
                "chat_id": self._chat_id,
                "text": chunk,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            }
            try:
                response = httpclient.post(
                    TELEGRAM_API_TEMPLATE.format(token=self._token),
                    json=payload,
                    timeout=self._timeout,
                )
            except Exception as exc:  # network errors must not crash the watch loop
                result.errors.append(str(exc))
                continue
            if response.status_code >= 400:
                result.errors.append(f"HTTP {response.status_code}: {_telegram_error(response)}")
                continue
            result.delivered += 1
        return result


def _telegram_error(response: object) -> str:
    try:
        body = response.json()  # type: ignore[attr-defined]
    except (ValueError, json.JSONDecodeError):
        return "unparseable response"
    if isinstance(body, dict):
        return str(body.get("description") or body)
    return "unexpected response"


def notify_console(text: str) -> None:
    print(text, file=sys.stderr)
