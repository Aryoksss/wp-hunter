from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any

CONFIG_SCHEMA_VERSION = 1
PRESET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
BUILTIN_PRESETS: dict[str, dict[str, Any]] = {
    "wporg-10k": {
        "source": "wporg",
        "installs": "10K",
        "installs_mode": "exact",
        "browse": "popular",
        "pages": 50,
        "max_age_years": 2,
    },
    "patchstack-vdp": {
        "source": "patchstack",
        "min_boost": 0,
        "include_themes": False,
        "max_age_years": 2,
    },
}
ALLOWED_PRESET_KEYS = {
    "source",
    "installs",
    "installs_mode",
    "browse",
    "pages",
    "search",
    "tag",
    "min_boost",
    "include_themes",
    "max_age_years",
    "since",
    "limit",
    "output",
    "workers",
    "api_workers",
    "max_download_mb",
}


def default_config() -> dict[str, Any]:
    return {
        "schema_version": CONFIG_SCHEMA_VERSION,
        "language": "en",
        "defaults": {
            "output_parent": ".",
            "download_workers": 3,
            "api_workers": 5,
            "scan_workers": 2,
            "scan_timeout": 120,
            "scan_mem_mb": 1024,
            "max_age_years": 2,
        },
        "recent_roots": [],
        "presets": {},
    }


def config_dir() -> Path:
    override = os.environ.get("WP_HUNTER_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "wp-hunter"


def config_path() -> Path:
    return config_dir() / "config.json"


def _validate(data: object) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("Configuration must be a JSON object")
    if data.get("schema_version") != CONFIG_SCHEMA_VERSION:
        raise ValueError("Unsupported configuration schema")
    if data.get("language") not in {"en", "id"}:
        raise ValueError("Configuration language must be 'en' or 'id'")
    defaults = data.get("defaults")
    presets = data.get("presets")
    roots = data.get("recent_roots")
    if (
        not isinstance(defaults, dict)
        or not isinstance(presets, dict)
        or not isinstance(roots, list)
    ):
        raise ValueError("Configuration has invalid sections")
    for name, preset in presets.items():
        validate_preset(name, preset)
    return data


def load_config(path: Path | None = None) -> dict[str, Any]:
    target = path or config_path()
    if target.is_symlink():
        raise ValueError(f"Refusing symlink configuration: {target}")
    if not target.exists():
        return default_config()
    if not target.is_file() or target.stat().st_size > 2 * 1024 * 1024:
        raise ValueError(f"Configuration is not a safe file: {target}")
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Configuration contains invalid JSON: {target}") from exc
    return _validate(data)


def save_config(data: dict[str, Any], path: Path | None = None) -> Path:
    validated = _validate(deepcopy(data))
    target = path or config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.parent.is_symlink() or target.is_symlink():
        raise ValueError(f"Refusing unsafe configuration path: {target}")
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            json.dump(validated, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)
    return target


def validate_preset(name: object, values: object) -> dict[str, Any]:
    if not isinstance(name, str) or not PRESET_NAME_RE.fullmatch(name):
        raise ValueError("Preset name must use lowercase letters, numbers, '.', '_' or '-'")
    if not isinstance(values, dict):
        raise ValueError(f"Preset {name!r} must be an object")
    unknown = set(values) - ALLOWED_PRESET_KEYS
    if unknown:
        raise ValueError(
            f"Preset contains unsafe or unsupported options: {', '.join(sorted(unknown))}"
        )
    if values.get("source") not in {"wporg", "patchstack"}:
        raise ValueError("Preset source must be 'wporg' or 'patchstack'")
    return dict(values)


def save_preset(
    config: dict[str, Any], name: str, values: dict[str, Any], replace: bool = False
) -> None:
    if name in BUILTIN_PRESETS:
        raise ValueError(f"Built-in preset {name!r} is immutable")
    safe_values = validate_preset(name, values)
    presets = config.setdefault("presets", {})
    if name in presets and not replace:
        raise ValueError(f"Preset {name!r} already exists; use --replace")
    presets[name] = safe_values


def get_preset(config: dict[str, Any], name: str) -> tuple[dict[str, Any], bool]:
    if name in BUILTIN_PRESETS:
        return deepcopy(BUILTIN_PRESETS[name]), True
    preset = config.get("presets", {}).get(name)
    if preset is None:
        raise KeyError(name)
    return deepcopy(validate_preset(name, preset)), False


def all_presets(config: dict[str, Any]) -> dict[str, tuple[dict[str, Any], bool]]:
    combined = {name: (deepcopy(value), True) for name, value in BUILTIN_PRESETS.items()}
    combined.update(
        {
            name: (deepcopy(validate_preset(name, value)), False)
            for name, value in config.get("presets", {}).items()
        }
    )
    return combined


def remember_root(config: dict[str, Any], root: str | Path, maximum: int = 20) -> None:
    resolved = str(Path(root).expanduser().resolve())
    roots = [item for item in config.get("recent_roots", []) if item != resolved]
    config["recent_roots"] = [resolved, *roots][:maximum]
