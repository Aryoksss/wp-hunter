from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files

SUPPORTED_LANGUAGES = {"en", "id"}
_language = "en"


@lru_cache(maxsize=2)
def _catalog(language: str) -> dict[str, str]:
    resource = files("wp_hunter.resources.locales").joinpath(f"{language}.json")
    return json.loads(resource.read_text(encoding="utf-8"))


def set_language(language: str) -> None:
    if language not in SUPPORTED_LANGUAGES:
        raise ValueError(f"Unsupported language: {language}")
    global _language
    _language = language


def get_language() -> str:
    return _language


def tr(key: str, **values: object) -> str:
    text = _catalog(_language).get(key) or _catalog("en").get(key) or key
    return text.format(**values)
