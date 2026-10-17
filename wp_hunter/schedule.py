"""Notification interval parsing and systemd timer installation.

The interval is expressed the way a user thinks about it ("30m", "2h",
"1h30m"); bare numbers are minutes.  The same value drives the resident
``--daemon`` loop and the systemd timer written by ``--install-timer``.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from .fsutil import atomic_write_text

MIN_INTERVAL_SECONDS = 60
MAX_INTERVAL_SECONDS = 7 * 24 * 60 * 60
DEFAULT_INTERVAL = "1h"

SERVICE_UNIT = "wp-hunter-watch.service"
TIMER_UNIT = "wp-hunter-watch.timer"
UNIT_DIR = Path("/etc/systemd/system")
ENV_FILE = Path("/etc/wp-hunter/watch.env")

_UNIT_SECONDS = {"d": 86400, "h": 3600, "m": 60, "s": 1}
_DURATION_TOKEN = re.compile(r"(\d+)\s*([dhms])", re.IGNORECASE)

_ENV_TEMPLATE = (
    "# WP Hunter watcher credentials. Keep this file at mode 600.\n"
    "TELEGRAM_BOT_TOKEN=\n"
    "TELEGRAM_CHAT_ID=\n"
    "# Optional: add WPSCAN_API_TOKEN and --vuln to the service ExecStart.\n"
    "WPSCAN_API_TOKEN=\n"
)


def parse_duration(value: object) -> int:
    """Return seconds for '90', '90m', '2h', '1h30m' or '45s'."""
    if isinstance(value, bool):
        raise ValueError("interval must be a duration such as 30m or 2h")
    if isinstance(value, int):
        seconds = value * 60
    else:
        text = str(value or "").strip().lower()
        if not text:
            raise ValueError("interval is empty")
        if text.isdigit():
            seconds = int(text) * 60
        else:
            tokens = _DURATION_TOKEN.findall(text)
            if not tokens or _DURATION_TOKEN.sub("", text).strip():
                raise ValueError(f"invalid interval {value!r}; use e.g. 30m, 2h, or 1h30m")
            seconds = sum(int(number) * _UNIT_SECONDS[unit.lower()] for number, unit in tokens)
    if seconds < MIN_INTERVAL_SECONDS:
        raise ValueError(f"interval must be at least {MIN_INTERVAL_SECONDS} seconds")
    if seconds > MAX_INTERVAL_SECONDS:
        raise ValueError("interval must be at most 7 days")
    return seconds


def format_duration(seconds: int) -> str:
    remaining = max(0, int(seconds))
    parts: list[str] = []
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if remaining >= size:
            parts.append(f"{remaining // size}{unit}")
            remaining %= size
    if remaining or not parts:
        parts.append(f"{remaining}s")
    return "".join(parts)


def systemd_span(seconds: int) -> str:
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}min"
    return f"{seconds}s"


def resolve_interval(every: str | None, interval: int | None, defaults: dict) -> int:
    """--every wins over the legacy --interval (seconds), which wins over config."""
    if every is not None:
        return parse_duration(every)
    if interval is not None:
        seconds = int(interval)
        if seconds < MIN_INTERVAL_SECONDS:
            raise ValueError(f"interval must be at least {MIN_INTERVAL_SECONDS} seconds")
        if seconds > MAX_INTERVAL_SECONDS:
            raise ValueError("interval must be at most 7 days")
        return seconds
    return parse_duration(defaults.get("watch_every", DEFAULT_INTERVAL))


def render_service(
    limit: int = 10,
    exec_path: str | None = None,
    env_file: Path = ENV_FILE,
) -> str:
    binary = exec_path or shutil.which("wp-hunter") or "wp-hunter"
    return (
        "[Unit]\n"
        "Description=WP Hunter plugin update watcher (one pass)\n"
        "Documentation=https://github.com/Aryoksss/wp-hunter\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"EnvironmentFile={env_file}\n"
        f"ExecStart={binary} watch --limit {max(1, int(limit))}\n"
        "TimeoutStartSec=15min\n"
    )


def render_timer(seconds: int) -> str:
    return (
        "[Unit]\n"
        f"Description=Run WP Hunter plugin watcher every {format_duration(seconds)}\n"
        "\n"
        "[Timer]\n"
        "OnBootSec=2min\n"
        f"OnUnitActiveSec={systemd_span(seconds)}\n"
        "RandomizedDelaySec=30s\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


def ensure_env_file(path: Path = ENV_FILE) -> bool:
    """Create the credentials file at mode 600 when it is missing."""
    if path.is_symlink():
        raise ValueError(f"refusing symlinked env file: {path}")
    if path.exists():
        if not path.is_file():
            raise ValueError(f"env path is not a file: {path}")
        return False
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(_ENV_TEMPLATE)
    return True


def install_timer(
    seconds: int,
    limit: int = 10,
    unit_dir: Path = UNIT_DIR,
    env_file: Path = ENV_FILE,
    run=subprocess.run,
) -> list[str]:
    """Write the systemd units for this interval and (re)arm the timer."""
    if os.geteuid() != 0:
        raise ValueError("installing the systemd timer requires root; re-run with sudo")
    service_path = unit_dir / SERVICE_UNIT
    timer_path = unit_dir / TIMER_UNIT
    for path in (service_path, timer_path):
        if path.is_symlink():
            raise ValueError(f"refusing symlinked unit path: {path}")

    actions: list[str] = []
    if ensure_env_file(env_file):
        actions.append(f"created {env_file} (mode 600)")

    for path, text in (
        (service_path, render_service(limit, env_file=env_file)),
        (timer_path, render_timer(seconds)),
    ):
        if path.exists():
            if not path.is_file():
                raise ValueError(f"unit path is not a file: {path}")
            current = path.read_text(encoding="utf-8")
            if current == text:
                continue
            backup = path.with_name(path.name + ".bak")
            atomic_write_text(backup, current)
            actions.append(f"backed up {path} → {backup.name}")
        atomic_write_text(path, text)
        os.chmod(path, 0o644)
        actions.append(f"wrote {path}")

    for command in (
        ["systemctl", "daemon-reload"],
        ["systemctl", "enable", TIMER_UNIT],
        ["systemctl", "restart", TIMER_UNIT],
    ):
        result = run(command, check=False, capture_output=True, text=True)
        if getattr(result, "returncode", 0) != 0:
            detail = (getattr(result, "stderr", "") or "").strip()[:200]
            raise ValueError(f"{' '.join(command)} failed: {detail}")
        actions.append(f"ran {' '.join(command)}")
    return actions
