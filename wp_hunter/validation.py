from __future__ import annotations

import re
from pathlib import Path
from typing import Literal, cast
from urllib.parse import urlsplit

from .constants import ALLOWED_DOWNLOAD_HOST_SUFFIX
from .safe_names import is_safe_filename as _is_safe_filename

BROWSE_MODES: tuple[str, ...] = ("popular", "new", "updated", "top-rated")
BrowseMode = Literal["popular", "new", "updated", "top-rated"]


def as_browse_mode(value: str) -> BrowseMode | None:
    return cast(BrowseMode, value) if value in BROWSE_MODES else None


def remote_nonnegative_int(
    value: object,
    default: int = 0,
    maximum: int = 1_000_000_000,
) -> int:
    if not isinstance(value, (int, float, str, bytes)):
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    if parsed < 0:
        return default
    return min(parsed, maximum)


def numeric_version_tuple(value: object, width: int = 3) -> tuple[int, ...]:
    parts = [int(part) for part in re.findall(r"\d+", str(value))[:width]]
    return tuple((parts + [0] * width)[:width])


def safe_download_url(download_url: object) -> bool:
    if not isinstance(download_url, str):
        return False
    try:
        parsed = urlsplit(download_url)
        host = (parsed.hostname or "").lower().rstrip(".")
        has_credentials = parsed.username is not None or parsed.password is not None
        has_port = parsed.port is not None
    except ValueError:
        return False
    if parsed.scheme.lower() != "https" or not host:
        return False
    if has_credentials or has_port:
        return False
    return host == "wordpress.org" or host.endswith(ALLOWED_DOWNLOAD_HOST_SUFFIX)


def safe_download_filename(download_url: str, slug: str) -> str:
    try:
        candidate = Path((urlsplit(download_url).path or "").replace("\\", "/")).name
    except ValueError:
        candidate = ""
    if (
        not _is_safe_filename(candidate)
        or candidate in {".", ".."}
        or not candidate.lower().endswith(".zip")
    ):
        return f"{slug}.zip"
    return candidate
