from __future__ import annotations

from typing import Any

_MISSING: dict[str, Any] = {}


def as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else _MISSING


def nested_dict(source: object, *keys: str) -> dict[str, Any]:
    current = as_dict(source)
    for key in keys:
        current = as_dict(current.get(key))
    return current
