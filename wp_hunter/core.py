"""Backward-compatible facade over the small, focused WP Hunter modules.

Historically this module held every helper; it is now split into
``constants``, ``validation``, ``installs``, ``paths``, ``progress``,
``doctor`` and ``semgrep_locate``.  Names remain re-exported here so existing
callers (and the CLI) keep importing from ``wp_hunter.core``.
"""

from __future__ import annotations

from datetime import datetime

from wp_hunter.constants import (
    ALLOWED_DOWNLOAD_HOST_SUFFIX,
    API_PARALLEL_WORKERS,
    API_RATE_LIMIT_SEC,
    API_URL,
    DOWNLOAD_MAX_RETRIES,
    LEGACY_ROOT_MARKER_CONTENT,
    MAX_API_WORKERS,
    MAX_DOWNLOAD_BYTES,
    MAX_DOWNLOAD_REDIRECTS,
    MAX_PATCHSTACK_PAGES,
    REQUESTS_MIN_VERSION,
    ROOT_MARKER_CONTENT,
    ROOT_MARKER_FILE,
    SEMGREP_RULES_DEFAULT,
)
from wp_hunter.doctor import cmd_check
from wp_hunter.doctor import safe_triage_workers as _safe_triage_workers
from wp_hunter.installs import VALID_TIERS, format_installs, parse_installs_input
from wp_hunter.paths import (
    create_root_marker as _create_root_marker,
)
from wp_hunter.paths import (
    directory_identity as _directory_identity,
)
from wp_hunter.paths import (
    directory_needs_adoption as _directory_needs_adoption,
)
from wp_hunter.paths import (
    ensure_hunter_root as _ensure_hunter_root,
)
from wp_hunter.paths import (
    is_direct_child as _is_direct_child,
)
from wp_hunter.paths import (
    looks_like_legacy_hunter_root as _looks_like_legacy_hunter_root,
)
from wp_hunter.paths import (
    protected_output_roots as _protected_output_roots,
)
from wp_hunter.paths import (
    root_marker_state as _root_marker_state,
)
from wp_hunter.paths import (
    validate_root_location as _validate_root_location,
)
from wp_hunter.paths import (
    validate_triage_root as _validate_triage_root,
)
from wp_hunter.progress import ProgressBar
from wp_hunter.semgrep_adapter import (
    validate_semgrep_config as _validate_semgrep_config,
)
from wp_hunter.semgrep_locate import (
    find_semgrep as _find_semgrep,
)
from wp_hunter.semgrep_locate import (
    indent_lines as _indent_lines,
)
from wp_hunter.semgrep_locate import (
    semgrep_install_hint as _semgrep_install_hint,
)
from wp_hunter.semgrep_locate import (
    semgrep_or_exit as _semgrep_or_exit,
)
from wp_hunter.state import (
    MANIFEST_FILE,
    REVIEWED_FILE,
)
from wp_hunter.text import display_text as _display_text
from wp_hunter.validation import (
    numeric_version_tuple as _numeric_version_tuple,
)
from wp_hunter.validation import (
    remote_nonnegative_int as _remote_nonnegative_int,
)
from wp_hunter.validation import (
    safe_download_filename as _safe_download_filename,
)
from wp_hunter.validation import (
    safe_download_url as _safe_download_url,
)


def _date_cli_value(value: str) -> str:
    for date_format in ("%Y-%m-%d", "%Y-%m", "%Y"):
        try:
            datetime.strptime(value, date_format)
            return value
        except ValueError:
            continue
    raise ValueError("must use YYYY-MM-DD, YYYY-MM, or YYYY")


def _ask_choice(prompt: str, choices: list[str], default: str) -> str:
    labels = " / ".join(f"[{choice}]" if choice == default else choice for choice in choices)
    while True:
        try:
            value = input(f"  {prompt} ({labels}): ").strip().lower() or default
        except (EOFError, KeyboardInterrupt):
            return default
        if value in choices:
            return value


__all__ = [
    "ALLOWED_DOWNLOAD_HOST_SUFFIX",
    "API_PARALLEL_WORKERS",
    "API_RATE_LIMIT_SEC",
    "API_URL",
    "DOWNLOAD_MAX_RETRIES",
    "LEGACY_ROOT_MARKER_CONTENT",
    "MANIFEST_FILE",
    "MAX_API_WORKERS",
    "MAX_DOWNLOAD_BYTES",
    "MAX_DOWNLOAD_REDIRECTS",
    "MAX_PATCHSTACK_PAGES",
    "ProgressBar",
    "REQUESTS_MIN_VERSION",
    "REVIEWED_FILE",
    "ROOT_MARKER_CONTENT",
    "ROOT_MARKER_FILE",
    "SEMGREP_RULES_DEFAULT",
    "VALID_TIERS",
    "_ask_choice",
    "_create_root_marker",
    "_date_cli_value",
    "_directory_identity",
    "_directory_needs_adoption",
    "_display_text",
    "_ensure_hunter_root",
    "_find_semgrep",
    "_indent_lines",
    "_is_direct_child",
    "_looks_like_legacy_hunter_root",
    "_numeric_version_tuple",
    "_protected_output_roots",
    "_remote_nonnegative_int",
    "_root_marker_state",
    "_safe_download_filename",
    "_safe_download_url",
    "_safe_triage_workers",
    "_semgrep_install_hint",
    "_semgrep_or_exit",
    "_validate_root_location",
    "_validate_semgrep_config",
    "_validate_triage_root",
    "cmd_check",
    "format_installs",
    "parse_installs_input",
]
