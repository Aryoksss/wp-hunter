from __future__ import annotations

import os
import re
import shutil
import stat
from pathlib import Path

from .constants import (
    LEGACY_ROOT_MARKER_CONTENT,
    ROOT_MARKER_CONTENT,
    ROOT_MARKER_FILE,
)
from .errors import UnsafePathError
from .state import MANIFEST_FILE, REVIEWED_FILE
from .triage_schema import ARTIFACT_FILES


def protected_output_roots() -> set[Path]:
    protected = {
        Path(__file__).resolve().parent,
        Path.home().resolve(),
        Path.cwd().resolve(),
    }
    anchor = Path(Path.cwd().anchor or os.sep).resolve()
    protected.add(anchor)
    return protected


def validate_root_location(root: Path) -> None:
    if root.parent == root or root in protected_output_roots():
        raise UnsafePathError(f"Refusing protected output/triage root: {root}")


def root_marker_state(marker: Path) -> str:
    if marker.is_symlink():
        return "invalid"
    try:
        if not marker.exists():
            return "missing"
        if not marker.is_file():
            return "invalid"
        if marker.stat().st_size > 128:
            return "invalid"
        content = marker.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return "invalid"
    if content in {ROOT_MARKER_CONTENT, LEGACY_ROOT_MARKER_CONTENT}:
        return "valid"
    return "invalid"


def create_root_marker(marker: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(marker, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fd = -1
            fh.write(ROOT_MARKER_CONTENT)
            fh.flush()
            os.fsync(fh.fileno())
    finally:
        if fd >= 0:
            os.close(fd)


def directory_needs_adoption(output_dir: str | Path) -> bool:
    raw = Path(output_dir).expanduser()
    if raw.is_symlink() or not raw.exists() or not raw.is_dir():
        return False
    marker_state = root_marker_state(raw / ROOT_MARKER_FILE)
    if marker_state == "valid":
        return False
    try:
        return any(raw.iterdir())
    except OSError:
        return True


def looks_like_legacy_hunter_root(output_dir: str | Path) -> bool:
    root = Path(output_dir).expanduser()
    if root.is_symlink() or not root.is_dir():
        return False

    normalized_name = root.name.lower().replace("-", "_")
    if normalized_name.startswith(("wp_plugins_", "wp_hunter_")):
        return True

    root_artifacts = {MANIFEST_FILE, REVIEWED_FILE, *ARTIFACT_FILES}
    try:
        for index, child in enumerate(root.iterdir()):
            # A bounded inspection keeps this prompt fast even for broad folders.
            if index >= 100:
                break
            if child.is_symlink():
                continue
            if child.is_file() and (
                child.name in root_artifacts
                or re.fullmatch(r"plugins_.+\.(?:json|csv)", child.name)
            ):
                return True
            if child.is_dir():
                metadata = child / "plugin_info.json"
                if metadata.is_file() and not metadata.is_symlink():
                    return True
    except OSError:
        return False
    return False


def ensure_hunter_root(
    output_dir: str | Path,
    adopt_existing: bool = False,
) -> Path:
    raw = Path(output_dir).expanduser()
    if raw.is_symlink():
        raise UnsafePathError(f"Refusing symlink output root: {raw}")
    if raw.exists() and not raw.is_dir():
        raise UnsafePathError(f"Output root is not a directory: {raw}")
    raw.mkdir(parents=True, exist_ok=True)
    root = raw.resolve()
    validate_root_location(root)
    marker = root / ROOT_MARKER_FILE
    marker_state = root_marker_state(marker)
    if marker_state == "invalid":
        raise UnsafePathError(f"Root marker is invalid or unsafe: {marker}")
    if marker_state == "valid":
        return root

    try:
        nonempty = any(root.iterdir())
    except OSError as exc:
        raise UnsafePathError(f"Cannot inspect output root: {root}") from exc
    if nonempty and not adopt_existing:
        raise UnsafePathError(
            f"Refusing to claim non-empty unmarked directory: {root}. "
            "Use --adopt-output-root and confirm the exact path."
        )
    if marker_state == "missing":
        try:
            create_root_marker(marker)
        except FileExistsError as exc:
            if root_marker_state(marker) != "valid":
                raise UnsafePathError(f"Root marker changed while validating: {marker}") from exc
    return root


def validate_triage_root(output_dir: str | Path, allow_unmarked: bool = False) -> Path:
    raw = Path(output_dir).expanduser()
    if raw.is_symlink() or not raw.is_dir():
        raise UnsafePathError(f"Triage root must be a real directory: {raw}")
    root = raw.resolve()
    validate_root_location(root)
    marker = root / ROOT_MARKER_FILE
    marker_state = root_marker_state(marker)
    if marker_state == "invalid":
        raise UnsafePathError(f"Triage root marker is invalid or unsafe: {marker}")
    if not allow_unmarked and marker_state != "valid":
        raise UnsafePathError(
            f"Refusing unmarked triage root: {root}. "
            f"Use --allow-unmarked-triage only after verifying the directory."
        )
    return root


def is_direct_child(root: Path, candidate: str | Path) -> bool:
    path = Path(candidate)
    if path.is_symlink():
        return False
    try:
        return path.resolve().parent == root.resolve()
    except OSError:
        return False


def directory_identity(path: str | Path) -> tuple[int, int] | None:
    try:
        details = os.stat(path, follow_symlinks=False)
    except OSError:
        return None
    if not stat.S_ISDIR(details.st_mode):
        return None
    return details.st_dev, details.st_ino


def remove_directory(
    path: str | Path,
    parent: Path,
    expected_identity: tuple[int, int],
) -> None:
    closed_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_fd = os.open(parent, closed_flags)
    try:
        name = Path(path).name
        try:
            details = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise UnsafePathError("deletion target disappeared before removal") from exc
        if (details.st_dev, details.st_ino) != expected_identity:
            raise UnsafePathError("deletion target changed before removal")
        shutil.rmtree(name, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
