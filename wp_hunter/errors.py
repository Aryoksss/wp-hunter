from __future__ import annotations


class WpHunterError(Exception):
    """Base class for expected, user-facing WP Hunter failures."""


class UnsafePathError(WpHunterError, ValueError):
    """A path failed the safety model (symlink, broad root, traversal)."""


class InvalidStateError(WpHunterError, ValueError):
    """Persisted state or configuration is missing, corrupt, or unsupported."""


class ExternalToolError(WpHunterError):
    """A required external tool (Semgrep) is missing or misconfigured."""
