from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
import time
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .versioning import version_is_newer

MANIFEST_FILE = "downloaded_slugs.json"
REVIEWED_FILE = "reviewed_slugs.json"
STATE_SCHEMA_VERSION = 2
_SAFE_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")


def _is_safe_slug(value: object) -> bool:
    return isinstance(value, str) and bool(_SAFE_SLUG_RE.fullmatch(value))


def _is_safe_filename(value: object) -> bool:
    return isinstance(value, str) and bool(_SAFE_FILENAME_RE.fullmatch(value))


def _sha256_of_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


@contextmanager
def _atomic_text_file(path: Path) -> Iterator[object]:
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError(f"Unsafe state parent: {parent}")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fd = -1
            yield fh
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temporary, path)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)


def _atomic_write_json(path: Path, value: object) -> None:
    with _atomic_text_file(path) as fh:
        json.dump(value, fh, indent=2, ensure_ascii=False)


def _state_payload(plugins: dict) -> dict:
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "plugins": plugins,
    }


def _load_state(path: Path, label: str) -> tuple[dict, bool]:
    if path.is_symlink():
        raise ValueError(f"Refusing symlink {label}: {path}")
    if not path.exists():
        return {}, False
    if not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError(f"{label.capitalize()} is not a safe file: {path}")
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label.capitalize()} contains invalid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label.capitalize()} must be a JSON object: {path}")
    if "schema_version" not in payload:
        if not all(
            isinstance(slug, str) and isinstance(entry, dict) for slug, entry in payload.items()
        ):
            raise ValueError(f"Legacy {label} has invalid entries: {path}")
        return payload, True
    if payload.get("schema_version") != STATE_SCHEMA_VERSION:
        raise ValueError(f"Unsupported {label} schema: {payload.get('schema_version')!r}")
    plugins = payload.get("plugins")
    if not isinstance(plugins, dict) or not all(
        isinstance(slug, str) and isinstance(entry, dict) for slug, entry in plugins.items()
    ):
        raise ValueError(f"{label.capitalize()} v2 has invalid plugin entries: {path}")
    return plugins, False


class DownloadManifest:
    def __init__(self, output_dir: Path):
        self._path = Path(output_dir) / MANIFEST_FILE
        self._lock = threading.Lock()
        self._data, migrated = self._load()
        if migrated:
            self._save()

    @property
    def root(self) -> Path:
        return self._path.parent

    def _load(self) -> tuple[dict, bool]:
        return _load_state(self._path, "download manifest")

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_json(self._path, _state_payload(self._data))

    def is_downloaded(self, slug: str) -> bool:
        with self._lock:
            entry = self._data.get(slug)
            if not isinstance(entry, dict):
                return False
            filename = entry.get("filename", "")
        if not _is_safe_slug(slug) or not _is_safe_filename(filename):
            return False
        plugin_dir = self.root / slug
        if plugin_dir.is_symlink():
            return False
        local_file = plugin_dir / filename
        try:
            if (
                local_file.is_symlink()
                or not local_file.is_file()
                or local_file.stat().st_size <= 0
                or not zipfile.is_zipfile(local_file)
            ):
                return False
            expected = str(entry.get("sha256", "") or "").lower()
            return not expected or _sha256_of_file(local_file).lower() == expected
        except OSError:
            return False

    def get_version(self, slug: str) -> str:
        with self._lock:
            entry = self._data.get(slug, {})
            return str(entry.get("version", "") or "") if isinstance(entry, dict) else ""

    def get_filename(self, slug: str) -> str:
        with self._lock:
            entry = self._data.get(slug, {})
            filename = entry.get("filename", "") if isinstance(entry, dict) else ""
        return filename if _is_safe_filename(filename) else ""

    def mark_downloaded(
        self, slug: str, filename: str, size_kb: int, version: str, sha256: str = ""
    ) -> None:
        if not _is_safe_slug(slug) or not _is_safe_filename(filename):
            raise ValueError("Refusing to write an unsafe manifest entry")
        with self._lock:
            self._data[slug] = {
                "filename": filename,
                "size_kb": size_kb,
                "version": version,
                "sha256": sha256,
                "downloaded_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self._save()

    def remove(self, slug: str) -> None:
        with self._lock:
            if slug in self._data:
                del self._data[slug]
                self._save()

    def count(self) -> int:
        with self._lock:
            return len(self._data)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                slug: dict(entry) for slug, entry in self._data.items() if isinstance(entry, dict)
            }


class ReviewLedger:
    def __init__(self, output_dir: Path):
        self._path = Path(output_dir) / REVIEWED_FILE
        self._lock = threading.Lock()
        self._data, migrated = self._load()
        if migrated:
            self._save()

    def _load(self) -> tuple[dict, bool]:
        return _load_state(self._path, "review ledger")

    def _save(self) -> None:
        _atomic_write_json(self._path, _state_payload(self._data))

    def mark(self, slug: str, version: str, outcome: str, sha256: str = "") -> None:
        if not _is_safe_slug(slug):
            raise ValueError("Refusing unsafe review-history slug")
        safe_outcome = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(outcome or ""))[:80]
        with self._lock:
            self._data[slug] = {
                "version": str(version or ""),
                "sha256": str(sha256 or ""),
                "outcome": safe_outcome,
                "reviewed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self._save()

    def covers(self, plugin: dict) -> bool:
        slug = plugin.get("slug", "")
        if not _is_safe_slug(slug):
            return False
        with self._lock:
            entry = self._data.get(slug)
            if not isinstance(entry, dict):
                return False
            reviewed = str(entry.get("version", "") or "")
        remote = str(plugin.get("version", "") or "")
        if not reviewed:
            return not remote
        if not remote:
            return True
        return not version_is_newer(remote, reviewed)

    def sync_removed_downloads(self, manifest: DownloadManifest) -> int:
        migrated = 0
        for slug, entry in manifest.snapshot().items():
            plugin_dir = manifest.root / slug
            if not _is_safe_slug(slug) or plugin_dir.exists() or manifest.is_downloaded(slug):
                continue
            version = str(entry.get("version", "") or "")
            with self._lock:
                current = self._data.get(slug)
                current_version = (
                    str(current.get("version", "") or "") if isinstance(current, dict) else ""
                )
            if current_version and not version_is_newer(version, current_version):
                continue
            self.mark(
                slug,
                version,
                "removed_after_download",
                str(entry.get("sha256", "") or ""),
            )
            migrated += 1
        return migrated

    def count(self) -> int:
        with self._lock:
            return len(self._data)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                slug: dict(entry) for slug, entry in self._data.items() if isinstance(entry, dict)
            }
