from __future__ import annotations

import threading

import requests

_LOCK = threading.Lock()
_SESSION: requests.Session | None = None


def session() -> requests.Session:
    global _SESSION
    if _SESSION is None:
        with _LOCK:
            if _SESSION is None:
                _SESSION = requests.Session()
    return _SESSION


def get(url: str, **kwargs):
    return session().get(url, **kwargs)
