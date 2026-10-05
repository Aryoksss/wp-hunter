from __future__ import annotations

import re

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f\x80-\x9f]")


def display_text(value: object, limit: int | None = None) -> str:
    text = _CONTROL_RE.sub(" ", str(value or ""))
    return text[:limit] if limit is not None else text
