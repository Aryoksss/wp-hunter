from __future__ import annotations

import sys
from contextlib import suppress
from pathlib import Path

API_URL = "https://api.wordpress.org/plugins/info/1.2/"
REQUESTS_MIN_VERSION = (2, 34, 2)
ROOT_MARKER_FILE = ".wp-hunter-root"
ROOT_MARKER_CONTENT = "wp-hunter-root:v1\n"
LEGACY_ROOT_MARKER_CONTENT = "wp-hunter root\n"

# Resource and input safety limits.  Plugin archives are untrusted input: the
# limits prevent a malformed or malicious response from exhausting disk/RAM.
MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
MAX_API_WORKERS = 10
MAX_PATCHSTACK_PAGES = 2_000
MAX_DOWNLOAD_REDIRECTS = 5
ALLOWED_DOWNLOAD_HOST_SUFFIX = ".wordpress.org"

DOWNLOAD_MAX_RETRIES = 3
API_RATE_LIMIT_SEC = 0.3
API_PARALLEL_WORKERS = 5

SEMGREP_RULES_DEFAULT = Path(__file__).parent / "resources" / "wordpress-triage.yml"

# Make stdout/stderr tolerant of Unicode (progress bars, box chars, ✓) even when
# the console codepage is cp1252 or output is piped to a file.
for _stream in (sys.stdout, sys.stderr):
    with suppress(AttributeError, ValueError):
        if hasattr(_stream, "reconfigure"):
            _stream.reconfigure(encoding="utf-8", errors="replace")
