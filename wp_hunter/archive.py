from __future__ import annotations

import os
import re
import shutil
import stat
import sys
import tempfile
import zipfile
from pathlib import Path

MAX_ARCHIVE_MEMBERS = 50_000
MAX_ARCHIVE_MEMBER_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_UNPACKED_BYTES = 1 * 1024 * 1024 * 1024
SOURCE_SUFFIXES = {".php", ".js", ".jsx", ".mjs", ".cjs"}
_SAFE_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def validate_zip_members(zf: zipfile.ZipFile) -> None:
    members = zf.infolist()
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise ValueError(f"archive has too many members ({len(members)})")
    total_size = 0
    seen: set[str] = set()
    for info in members:
        raw_name = info.filename.replace("\\", "/")
        if not raw_name or "\x00" in raw_name:
            raise ValueError("archive contains an invalid member name")
        if raw_name.startswith("/") or re.match(r"^[A-Za-z]:", raw_name):
            raise ValueError(f"absolute archive member: {info.filename!r}")
        normalized = raw_name.rstrip("/")
        parts = normalized.split("/")
        if not normalized or any(part in {"", ".", ".."} for part in parts):
            raise ValueError(f"traversal archive member: {info.filename!r}")
        canonical_name = "/".join(parts).casefold()
        if canonical_name in seen:
            raise ValueError(f"duplicate archive member: {info.filename!r}")
        seen.add(canonical_name)
        mode = (info.external_attr >> 16) & 0o170000
        if stat.S_ISLNK(mode):
            raise ValueError(f"symlink archive member: {info.filename!r}")
        if mode and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError(f"special archive member: {info.filename!r}")
        if info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
            raise ValueError(f"archive member exceeds size limit: {info.filename!r}")
        total_size += max(0, info.file_size)
        if total_size > MAX_ARCHIVE_UNPACKED_BYTES:
            raise ValueError("archive exceeds total unpacked size limit")


def contains_source_file(directory: Path) -> bool:
    for current, dirnames, filenames in os.walk(directory, followlinks=False):
        current_path = Path(current)
        dirnames[:] = [name for name in dirnames if not (current_path / name).is_symlink()]
        if any(Path(name).suffix.lower() in SOURCE_SUFFIXES for name in filenames):
            return True
    return False


def looks_like_plugin_dir(path: Path) -> bool:
    if (
        path.is_symlink()
        or not path.is_dir()
        or not _SAFE_SLUG_RE.fullmatch(path.name)
        or path.name.startswith(("_", "."))
    ):
        return False
    metadata = path / "plugin_info.json"
    if metadata.is_file() and not metadata.is_symlink():
        return True
    extracted = path / "extracted"
    if extracted.is_dir() and not extracted.is_symlink():
        return True
    try:
        if any(
            candidate.is_file() and not candidate.is_symlink() for candidate in path.glob("*.zip")
        ):
            return True
    except OSError:
        return False
    return contains_source_file(path)


def ensure_extracted(plugin_dir: str) -> tuple[str | None, str | None]:
    root = Path(plugin_dir)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("plugin directory is not a real directory")
    ext_dir = root / "extracted"
    if ext_dir.is_symlink():
        raise ValueError("extracted directory is a symlink")
    if ext_dir.is_dir() and any(ext_dir.iterdir()):
        return (
            (str(ext_dir), str(ext_dir)) if contains_source_file(ext_dir) else (None, str(ext_dir))
        )
    zips = [
        root / name
        for name in os.listdir(root)
        if name.lower().endswith(".zip")
        and (root / name).is_file()
        and not (root / name).is_symlink()
    ]
    if not zips:
        removable = str(ext_dir) if ext_dir.is_dir() else None
        if contains_source_file(root):
            return str(root), removable
        return None, removable
    if len(zips) > 1:
        folder_name = root.name.lower()
        named_match = next(
            (path for path in zips if path.stem.lower().startswith(folder_name[:8])),
            None,
        )
        zip_path = named_match or max(zips, key=lambda path: path.stat().st_size)
    else:
        zip_path = zips[0]

    temporary_dir: Path | None = None
    try:
        with zipfile.ZipFile(zip_path) as zf:
            validate_zip_members(zf)
            temporary_dir = Path(tempfile.mkdtemp(prefix=".extract-", dir=str(root)))
            zf.extractall(temporary_dir)
        if ext_dir.exists():
            if not ext_dir.is_dir() or ext_dir.is_symlink():
                raise ValueError("extracted path is not a safe directory")
            if any(ext_dir.iterdir()):
                shutil.rmtree(temporary_dir, ignore_errors=True)
                temporary_dir = None
                target = str(ext_dir) if contains_source_file(ext_dir) else None
                return target, str(ext_dir)
            ext_dir.rmdir()
        os.replace(temporary_dir, ext_dir)
        temporary_dir = None
        target = str(ext_dir) if contains_source_file(ext_dir) else None
        return target, str(ext_dir)
    except Exception as exc:
        print(f"  [WARN] Extract failed for {root.name}: {exc}", file=sys.stderr)
        raise
    finally:
        if temporary_dir is not None:
            shutil.rmtree(temporary_dir, ignore_errors=True)
