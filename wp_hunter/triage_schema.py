from __future__ import annotations

TRIAGE_SCHEMA_VERSION = 2

REPORT_FILE = "vuln_report.txt"
CANDIDATES_FILE = "vuln_plugins.txt"
DELETED_FILE = "deleted_plugins.txt"
RESULTS_FILE = "triage_results.json"

ARTIFACT_FILES = (
    RESULTS_FILE,
    REPORT_FILE,
    CANDIDATES_FILE,
    DELETED_FILE,
)
