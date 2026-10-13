from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import config_dir
from .fsutil import atomic_write_json as _atomic_write_json

WATCH_STATE_FILE = "watch_state.json"
WATCH_STATE_SCHEMA_VERSION = 1
WATCH_STATE_MAX_BYTES = 32 * 1024 * 1024


def watch_state_path(path: Path | None = None) -> Path:
    if path is not None:
        return path
    return config_dir() / WATCH_STATE_FILE


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class WatchState:
    """Track the last-seen version of each watched plugin slug."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = watch_state_path(path)
        self._entries: dict[str, dict[str, str]] = {}
        self._loaded = False

    @property
    def path(self) -> Path:
        return self._path

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        path = self._path
        if path.is_symlink():
            raise ValueError(f"Refusing symlink watch state: {path}")
        if not path.exists():
            return
        if not path.is_file() or path.stat().st_size > WATCH_STATE_MAX_BYTES:
            raise ValueError(f"Watch state is not a safe file: {path}")
        try:
            with open(path, encoding="utf-8") as handle:
                payload = json.load(handle)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Watch state contains invalid JSON: {path}") from exc
        if not isinstance(payload, dict):
            raise ValueError(f"Watch state must be a JSON object: {path}")
        if payload.get("schema_version") != WATCH_STATE_SCHEMA_VERSION:
            raise ValueError(f"Unsupported watch state schema: {payload.get('schema_version')!r}")
        plugins = payload.get("plugins")
        if not isinstance(plugins, dict):
            raise ValueError(f"Watch state has no plugin table: {path}")
        for slug, entry in plugins.items():
            if not isinstance(slug, str) or not isinstance(entry, dict):
                raise ValueError(f"Watch state has an invalid entry: {slug!r}")
        self._entries = plugins

    def get_version(self, slug: str) -> str | None:
        self._load()
        entry = self._entries.get(slug)
        if not entry:
            return None
        version = entry.get("version")
        return version if isinstance(version, str) else None

    def record(self, slug: str, version: str, last_updated: str = "") -> None:
        self._load()
        self._entries[slug] = {
            "version": version,
            "last_updated": last_updated,
            "checked_at": _now(),
        }

    def remove_missing(self, seen_slugs: set[str]) -> int:
        self._load()
        stale = [slug for slug in self._entries if slug not in seen_slugs]
        for slug in stale:
            del self._entries[slug]
        return len(stale)

    def save(self) -> None:
        self._load()
        payload = {
            "schema_version": WATCH_STATE_SCHEMA_VERSION,
            "updated_at": _now(),
            "plugins": self._entries,
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if self._path.parent.is_symlink() or self._path.is_symlink():
            raise ValueError(f"Refusing unsafe watch state path: {self._path}")
        _atomic_write_json(self._path, payload)

    def snapshot(self) -> Mapping[str, Any]:
        self._load()
        return {"count": len(self._entries), "updated_at": _now(), "plugins": dict(self._entries)}

    def count(self) -> int:
        self._load()
        return len(self._entries)
