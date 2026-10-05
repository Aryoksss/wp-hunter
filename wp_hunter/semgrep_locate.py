from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from .constants import SEMGREP_RULES_DEFAULT
from .semgrep_adapter import validate_semgrep_config as _validate_semgrep_config


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
    return shutil.which("semgrep") or shutil.which("semgrep.exe")


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
