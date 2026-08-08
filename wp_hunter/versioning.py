from __future__ import annotations

import re

_QUALIFIER_RANK = {
    "dev": -5,
    "alpha": -4,
    "a": -4,
    "beta": -3,
    "b": -3,
    "rc": -2,
    "pre": -2,
    "preview": -2,
    "": 0,
    "final": 0,
    "stable": 0,
    "pl": 1,
    "p": 1,
    "post": 1,
}


def _parse_version(value: str) -> tuple[list[int], tuple[int, int, str]]:
    normalized = value.strip().lstrip("vV")
    match = re.search(r"[A-Za-z]+", normalized)
    core_text = normalized[: match.start()] if match else normalized
    core = [int(part) for part in re.findall(r"\d+", core_text)] or [0]
    while len(core) > 1 and core[-1] == 0:
        core.pop()
    if not match:
        return core, (0, 0, "")
    qualifier = match.group(0).lower()
    suffix_match = re.search(r"\d+", normalized[match.end() :])
    suffix_number = int(suffix_match.group(0)) if suffix_match else 0
    return core, (
        _QUALIFIER_RANK.get(qualifier, -1),
        suffix_number,
        qualifier,
    )


def version_is_newer(remote: str, local: str) -> bool:
    if not remote or not local:
        return False
    try:
        remote_core, remote_qualifier = _parse_version(remote)
        local_core, local_qualifier = _parse_version(local)
        width = max(len(remote_core), len(local_core))
        remote_core += [0] * (width - len(remote_core))
        local_core += [0] * (width - len(local_core))
        if remote_core != local_core:
            return remote_core > local_core
        return remote_qualifier > local_qualifier
    except (IndexError, TypeError, ValueError):
        return str(remote).casefold() != str(local).casefold()
