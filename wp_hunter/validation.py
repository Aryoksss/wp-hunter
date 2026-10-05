from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from .constants import ALLOWED_DOWNLOAD_HOST_SUFFIX
from .safe_names import is_safe_filename as _is_safe_filename


def remote_nonnegative_int(
    value: object,
    default: int = 0,
    maximum: int = 1_000_000_000,
) -> int:
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
