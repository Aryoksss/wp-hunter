import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from wp_hunter import core, triage

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "wp_hunter" / "resources" / "wordpress-triage.yml"

REPORT_FILES = (
    "triage_results.json",
    "vuln_report.txt",
    "vuln_plugins.txt",
    "deleted_plugins.txt",
)

TRIAGE_TOP_LEVEL_KEYS = {
    "schema_version",
    "language",
    "engine",
    "rules",
    "generated_at",
    "dry_run",
    "scan",
    "summary",
    "results",
}

TRIAGE_SCAN_KEYS = {
    "workers",
    "timeout",
    "memory_mb",
    "max_age_years",
    "since",
}

TRIAGE_SUMMARY_KEYS = {
    "plugin_count",
    "candidate_count",
    "deletion_candidate_count",
    "deleted_count",
    "deletion_failure_count",
    "scan_error_count",
    "no_source_count",
    "outdated_count",
    "unknown_date_count",
}


def _run_triage_on(root: Path, findings_by_name: dict, **kwargs):
    engine = SimpleNamespace(executable="semgrep", rules_path=RULES)

    def scan(target, _timeout, _mem_mb):
        return findings_by_name.get(Path(target).name, ([], "OK"))

    engine.scan = scan
    arguments = {
        "workers": 1,
        "timeout": 5,
        "mem_mb": 128,
        "max_age_years": 0,
        "dry_run": True,
    }
    arguments.update(kwargs)
    with (
        patch.object(triage, "SemgrepEngine", return_value=engine),
        contextlib.redirect_stdout(io.StringIO()),
    ):
        triage.run_triage(str(root), "semgrep", RULES, **arguments)


class TriageArtifactContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = core._ensure_hunter_root(self.temp.name)
        for name in ("candidate-plugin", "clean-plugin"):
            directory = self.root / name
            directory.mkdir()
            (directory / "plugin.php").write_text("<?php", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_triage_writes_exactly_the_contract_artifact_names(self):
        _run_triage_on(self.root, {})
        for name in REPORT_FILES:
            self.assertTrue((self.root / name).is_file(), f"missing artifact: {name}")

    def test_triage_json_top_level_keys_are_stable(self):
        _run_triage_on(self.root, {})
        payload = json.loads((self.root / "triage_results.json").read_text(encoding="utf-8"))
        self.assertEqual(set(payload), TRIAGE_TOP_LEVEL_KEYS)
        self.assertEqual(payload["schema_version"], 2)
        self.assertEqual(payload["engine"], "semgrep")
        self.assertIs(payload["dry_run"], True)

    def test_triage_json_scan_and_summary_sections_are_stable(self):
        _run_triage_on(self.root, {})
        payload = json.loads((self.root / "triage_results.json").read_text(encoding="utf-8"))
        self.assertEqual(set(payload["scan"]), TRIAGE_SCAN_KEYS)
        self.assertEqual(set(payload["summary"]), TRIAGE_SUMMARY_KEYS)

    def test_triage_json_summary_counts_reflect_findings(self):
        findings = {
            "candidate-plugin": (
                [
                    {
                        "check_id": "wordpress.file_write",
                        "file": "plugin.php",
                        "line": 3,
                        "category": "file_write",
                        "confidence": "medium",
                        "message": "review",
                        "extra": {"context": {"access": "unknown"}},
                    }
                ],
                "OK",
            )
        }
        _run_triage_on(self.root, findings)
        payload = json.loads((self.root / "triage_results.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["summary"]["plugin_count"], 2)
        self.assertEqual(payload["summary"]["candidate_count"], 1)
        self.assertEqual(payload["summary"]["deletion_candidate_count"], 1)
        self.assertEqual(payload["summary"]["scan_error_count"], 0)

    def test_vuln_plugins_lists_candidate_slug_only(self):
        findings = {
            "candidate-plugin": (
                [
                    {
                        "check_id": "wordpress.file_write",
                        "file": "plugin.php",
                        "line": 1,
                        "category": "file_write",
                        "confidence": "medium",
                        "message": "review",
                        "extra": {"context": {"access": "unknown"}},
                    }
                ],
                "OK",
            )
        }
        _run_triage_on(self.root, findings)
        listed = (self.root / "vuln_plugins.txt").read_text(encoding="utf-8").splitlines()
        self.assertEqual(listed, ["candidate-plugin"])

    def test_deleted_plugins_header_marks_dry_run(self):
        _run_triage_on(self.root, {})
        header = (self.root / "deleted_plugins.txt").read_text(encoding="utf-8").splitlines()[0]
        self.assertIn("DRY RUN", header)


if __name__ == "__main__":
    unittest.main()
