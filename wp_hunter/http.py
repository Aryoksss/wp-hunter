from __future__ import annotations

import sys
import threading
import time

import requests

from .constants import (
    API_RATE_LIMIT_SEC,
    API_URL,
)
from .safe_names import is_safe_slug as _is_safe_slug

PATCHSTACK_VDP_API = "https://vdp.patchstack.com/api/database/vdp"
WP_PLUGIN_INFO_API = "https://api.wordpress.org/plugins/info/1.2/"
WP_THEME_INFO_API = "https://api.wordpress.org/themes/info/1.2/"

_WPORG_RATE_LOCK = threading.Lock()
_WPORG_LAST_REQUEST_AT = 0.0


def _wporg_get(url: str, **kwargs):
    global _WPORG_LAST_REQUEST_AT
    with _WPORG_RATE_LOCK:
        now = time.monotonic()
        wait = API_RATE_LIMIT_SEC - (now - _WPORG_LAST_REQUEST_AT)
        if wait > 0:
            time.sleep(wait)
        _WPORG_LAST_REQUEST_AT = time.monotonic()
    return requests.get(url, **kwargs)


def _build_api_params(
    browse: str,
    page: int,
    per_page: int = 100,
    search: str | None = None,
    tag: str | None = None,
) -> dict:
    params = {
        "action": "query_plugins",
        "request[browse]": browse,
        "request[per_page]": str(per_page),
        "request[page]": str(page),
        "request[fields][active_installs]": "true",
        "request[fields][last_updated]": "true",
        "request[fields][downloaded]": "true",
        "request[fields][tags]": "true",
        "request[fields][requires]": "true",
        "request[fields][requires_php]": "true",
        "request[fields][tested]": "true",
        "request[fields][md5]": "true",
    }
    if search:
        params.pop("request[browse]", None)
        params["request[search]"] = search
    if tag:
        params.pop("request[browse]", None)
        params["request[tag]"] = tag
    return params


def query_plugins_page(
    browse: str = "popular",
    page: int = 1,
    per_page: int = 100,
    search: str | None = None,
    tag: str | None = None,
    retries: int = 3,
) -> dict | None:
    params = _build_api_params(browse, page, per_page, search, tag)
    for attempt in range(1, retries + 1):
        try:
            resp = _wporg_get(API_URL, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            return data if isinstance(data, dict) else None
        except (requests.exceptions.RequestException, ValueError) as exc:
            if attempt < retries:
                wait = 2**attempt
                print(
                    f"  [WARN] API page {page} attempt {attempt}/{retries} failed ({exc}). Retry in {wait}s …",
                    file=sys.stderr,
                )
                time.sleep(wait)
            else:
                print(f"  [ERROR] API page {page} failed: {exc}", file=sys.stderr)
    return None


def _fetch_wporg_asset_info(slug: str, asset_kind: str = "plugin") -> dict | None:
    if not _is_safe_slug(slug):
        return None
    is_theme = asset_kind.lower() == "theme"
    params = {
        "action": "theme_information" if is_theme else "plugin_information",
        "request[slug]": slug,
        "request[fields][active_installs]": "true",
        "request[fields][last_updated]": "true",
        "request[fields][downloaded]": "true",
        "request[fields][md5]": "true",
    }
    try:
        endpoint = WP_THEME_INFO_API if is_theme else WP_PLUGIN_INFO_API
        resp = _wporg_get(endpoint, params=params, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        # wp.org returns {"error": "..."} for unknown/closed plugins
        if not isinstance(data, dict) or data.get("error") or not data.get("slug"):
            return None
        return data
    except (requests.exceptions.RequestException, ValueError):
        return None


def _fetch_wporg_plugin_info(slug: str) -> dict | None:
    return _fetch_wporg_asset_info(slug, "plugin")


def _fetch_wporg_theme_info(slug: str) -> dict | None:
    return _fetch_wporg_asset_info(slug, "theme")


def _patchstack_page(page: int, retries: int = 3) -> dict | None:
    params = {"page": str(page)}
    headers = {"Accept": "application/json", "User-Agent": "Mozilla/5.0"}
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(PATCHSTACK_VDP_API, params=params, headers=headers, timeout=25)
            resp.raise_for_status()
            data = resp.json()
            return data if isinstance(data, dict) else None
        except (requests.exceptions.RequestException, ValueError) as exc:
            if attempt < retries:
                time.sleep(2**attempt)
            else:
                print(f"  [WARN] Patchstack page {page} failed: {exc}", file=sys.stderr)
    return None
