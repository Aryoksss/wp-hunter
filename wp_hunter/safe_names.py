from __future__ import annotations

import re

SAFE_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")


def is_safe_slug(value: object) -> bool:
    return isinstance(value, str) and bool(SAFE_SLUG_RE.fullmatch(value))


def is_safe_filename(value: object) -> bool:
    return isinstance(value, str) and bool(SAFE_FILENAME_RE.fullmatch(value))
