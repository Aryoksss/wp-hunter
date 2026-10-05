from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TextIO

_CHUNK_SIZE = 65_536


@contextmanager
def atomic_text_file(path: str | Path, newline: str | None = None) -> Iterator[TextIO]:
    destination = Path(path)
    parent = destination.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError(f"Unsafe output parent: {parent}")
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=str(parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline=newline) as fh:
            fd = -1
            yield fh
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temporary, destination)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)


def atomic_write_json(path: str | Path, value: object) -> None:
    with atomic_text_file(path) as fh:
        json.dump(value, fh, indent=2, ensure_ascii=False)


def atomic_write_text(path: str | Path, value: str) -> None:
    with atomic_text_file(path) as fh:
        fh.write(value)


def _hash_of_file(path: str | Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_of_file(path: str | Path) -> str:
    return _hash_of_file(path, "sha256")


def md5_of_file(path: str | Path) -> str:
    return _hash_of_file(path, "md5")
