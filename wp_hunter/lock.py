"""Single-run lock shared by the CLI watcher and the Telegram bot.

Two processes writing ``watch_state.json`` at once can drop updates and send
duplicate digests, so every watch run takes this lock first.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from pathlib import Path

from .config import config_dir

try:  # Windows has no fcntl; the lock degrades to a no-op there.
    import fcntl
except ImportError:  # pragma: no cover - platform dependent
    fcntl = None  # type: ignore[assignment]

LOCK_FILE = "watch.lock"


class StateBusy(RuntimeError):
    """Another watch run already holds the lock."""


def lock_path(directory: Path | None = None) -> Path:
    return (directory or config_dir()) / LOCK_FILE


@contextlib.contextmanager
def state_lock(directory: Path | None = None) -> Iterator[None]:
    target = lock_path(directory)
    target.parent.mkdir(parents=True, exist_ok=True)
    if fcntl is None:  # pragma: no cover - platform dependent
        yield
        return
    with open(target, "a+", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise StateBusy(f"another WP Hunter watch run is in progress ({target})") from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
