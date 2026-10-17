from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from .constants import SEMGREP_RULES_DEFAULT
from .semgrep_adapter import validate_semgrep_config as _validate_semgrep_config


def _interpreter_bin_dir() -> Path | None:
    """Directory holding the running interpreter's console scripts (venv/pipx)."""
    executable = Path(sys.executable)
    if executable.parent.name in {"bin", "Scripts"}:
        return executable.parent
    return None


def _semgrep_in(directory: Path | None) -> str | None:
    if directory is None:
        return None
    for name in ("semgrep", "semgrep.exe"):
        candidate = directory / name
        try:
            if candidate.is_file() and not candidate.is_symlink() and os.access(candidate, os.X_OK):
                return str(candidate)
        except OSError:
            continue
    return None


def find_semgrep(explicit: str | None) -> str | None:
    if explicit:
        if (
            os.path.isfile(explicit)
            and not os.path.islink(explicit)
            and os.access(explicit, os.X_OK)
        ):
            return explicit
        print(f"  [ERROR] Semgrep not found at: {explicit}", file=sys.stderr)
        return None
    # A semgrep installed next to wp-hunter (pipx inject, venv) is not on PATH,
    # so fall back to the interpreter's own bin directory.
    return (
        shutil.which("semgrep")
        or shutil.which("semgrep.exe")
        or _semgrep_in(_interpreter_bin_dir())
    )


def semgrep_install_hint() -> str:
    return (
        "Install Semgrep locally with one of:\n"
        "python -m pip install semgrep\n"
        "pipx install semgrep\n"
        "Then verify with: semgrep --version"
    )


def indent_lines(value: str, prefix: str) -> str:
    return "\n".join(prefix + line for line in value.splitlines())


def semgrep_or_exit(
    explicit: str | None,
    rules_path: str | None = None,
    validate_rules: bool = True,
) -> tuple[str, Path]:
    semgrep = find_semgrep(explicit)
    if not semgrep:
        hint = indent_lines(semgrep_install_hint(), "  ")
        print(f"\n  [ERROR] Semgrep was not found.\n{hint}\n", file=sys.stderr)
        sys.exit(1)
    rules = Path(rules_path).expanduser() if rules_path else SEMGREP_RULES_DEFAULT
    if rules.is_symlink() or not rules.is_file():
        print(f"\n  [ERROR] Semgrep rules not found: {rules}\n", file=sys.stderr)
        sys.exit(1)
    resolved_rules = rules.resolve()
    if validate_rules:
        valid, diagnostic = _validate_semgrep_config(semgrep, resolved_rules)
        if not valid:
            print("\n  [ERROR] Semgrep rule validation failed.", file=sys.stderr)
            if diagnostic:
                print(f"  {diagnostic}", file=sys.stderr)
            print("  No plugin scan or deletion was started.\n", file=sys.stderr)
            sys.exit(1)
    return semgrep, resolved_rules
