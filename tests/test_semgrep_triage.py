import ast
import contextlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import wp_plugin_hunter as hunter  # noqa: E402


RULES = ROOT / "rules" / "wordpress-triage.yml"


def fake_process(returncode=0, stdout='{"results": []}', stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


class SemgrepAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.target = Path(self.temp.name) / "plugin"
        self.target.mkdir()
        (self.target / "plugin.php").write_text("<?php echo 'fixture';", encoding="utf-8")
        self.engine = hunter.SemgrepEngine("semgrep", RULES)

    def tearDown(self):
        self.temp.cleanup()

    def scan_with(self, process):
        with patch.object(hunter.subprocess, "run", return_value=process):
            return self.engine.scan(str(self.target), timeout=5, mem_mb=128)

    def test_exit_zero_without_findings_is_valid(self):
        results, status = self.scan_with(fake_process())
        self.assertEqual(status, "OK")
        self.assertEqual(results, [])

    def test_exit_one_with_findings_is_valid_and_normalized(self):
        payload = {
            "results": [{
                "check_id": "wordpress.file_write",
                "path": "plugin.php",
                "start": {"line": 12},
                "end": {"line": 12},
                "extra": {
                    "message": "review write",
                    "metadata": {
                        "triage": {
                            "category": "file_write",
                            "access": "unauthenticated",
                            "confidence": "medium",
                        }
                    },
                },
            }]
        }
        results, status = self.scan_with(fake_process(1, json.dumps(payload)))
        self.assertEqual(status, "OK")
        self.assertEqual(results[0]["check_id"], "wordpress.file_write")
        self.assertEqual(results[0]["file"], "plugin.php")
        self.assertEqual(results[0]["line"], 12)
        self.assertEqual(results[0]["extra"]["context"]["access"], "unauthenticated")
        self.assertEqual(results[0]["category"], "file_write")

    def test_nonzero_error_preserves_target(self):
        results, status = self.scan_with(fake_process(2, "{}", "rule parse error"))
        self.assertEqual(results, [])
        self.assertTrue(status.startswith("SCAN_ERR:2"))

    def test_invalid_json_is_error(self):
        results, status = self.scan_with(fake_process(0, "not-json"))
        self.assertEqual(results, [])
        self.assertEqual(status, "INVALID_OUTPUT")

    def test_timeout_is_error(self):
        with patch.object(
            hunter.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["semgrep"], 5),
        ):
            results, status = self.engine.scan(str(self.target), timeout=5, mem_mb=128)
        self.assertEqual(results, [])
        self.assertEqual(status, "TIMEOUT")

    def test_missing_binary_is_error(self):
        with patch.object(hunter.subprocess, "run", side_effect=FileNotFoundError()):
            results, status = self.engine.scan(str(self.target), timeout=5, mem_mb=128)
        self.assertEqual(results, [])
        self.assertEqual(status, "BINARY_NOT_FOUND")

    def test_unknown_access_is_candidate(self):
        payload = {
            "results": [{
                "check_id": "wordpress.custom",
                "path": "plugin.php",
                "start": {"line": 1},
                "extra": {"metadata": {"triage": {"category": "custom"}}},
            }]
        }
        results, status = self.scan_with(fake_process(1, json.dumps(payload)))
        self.assertEqual(status, "OK")
        _, _, in_scope = hunter._classify(results)
        self.assertEqual(in_scope, 1)
        self.assertEqual(results[0]["extra"]["context"]["access"], "unknown")

    def test_find_semgrep_does_not_install(self):
        with patch.object(hunter.shutil, "which", return_value=None):
            self.assertIsNone(hunter._find_semgrep(None))


class TriageSafetyTests(unittest.TestCase):
    def test_scan_error_is_retained_and_candidate_report_has_details(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            hunter._ensure_hunter_root(root)
            candidate = root / "candidate-plugin"
            clean = root / "clean-plugin"
            failed = root / "failed-plugin"
            for directory in (candidate, clean, failed):
                directory.mkdir()
                (directory / "plugin.php").write_text("<?php", encoding="utf-8")

            fake_engine = SimpleNamespace(
                executable="semgrep",
                rules_path=RULES.resolve(),
            )

            def scan(target, timeout, mem_mb):
                if Path(target).name == "candidate-plugin":
                    return [{
                        "check_id": "wordpress.file_write",
                        "file": "plugin.php",
                        "line": 3,
                        "category": "file_write",
                        "confidence": "medium",
                        "message": "review this candidate",
                        "extra": {"context": {"access": "unknown"}},
                    }], "OK"
                if Path(target).name == "failed-plugin":
                    return [], "TIMEOUT"
                return [], "OK"

            fake_engine.scan = scan
            output = io.StringIO()
            with patch.object(hunter, "SemgrepEngine", return_value=fake_engine), \
                    contextlib.redirect_stdout(output):
                hunter.run_triage(
                    str(root), "semgrep", RULES, workers=1, timeout=5,
                    mem_mb=128, max_age_years=0,
                )

            self.assertTrue(candidate.is_dir())
            self.assertTrue(clean.is_dir(), "dry-run must not delete clean folders")
            self.assertTrue(failed.is_dir(), "scan errors must never delete folders")
            report = (root / "vuln_report.txt").read_text(encoding="utf-8")
            self.assertIn("no semgrep candidate", report.lower())
            self.assertIn("plugin.php:3", report)
            self.assertIn("category=file_write", report)
            self.assertIn("confidence=medium", report)
            self.assertIn("review this candidate", report)
            triage_json = json.loads((root / "triage_results.json").read_text(encoding="utf-8"))
            self.assertEqual(triage_json["engine"], "semgrep")
            self.assertTrue((root / "vuln_plugins.txt").read_text(encoding="utf-8").strip())


class CliAndRuleTests(unittest.TestCase):
    def test_source_ast_and_legacy_name_are_clean(self):
        source = (ROOT / "wp_plugin_hunter.py").read_text(encoding="utf-8")
        ast.parse(source)
        old_engine_name = "".join(chr(value) for value in (
            119, 112, 45, 116, 97, 105, 110, 116, 45, 115, 99, 97, 110,
        ))
        self.assertNotIn(old_engine_name, source)

    def test_help_exposes_semgrep_and_not_legacy_flag(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "wp_plugin_hunter.py"), "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("--semgrep", result.stdout)
        self.assertIn("--semgrep-rules", result.stdout)
        self.assertIn("--confirm-delete", result.stdout)
        old_flag = "--" + "".join(chr(value) for value in (
            116, 97, 105, 110, 116, 45, 115, 99, 97, 110,
        ))
        self.assertNotIn(old_flag, result.stdout)

    def test_default_triage_is_dry_run(self):
        self.assertTrue(__import__("inspect").signature(hunter.run_triage).parameters["dry_run"].default)

    @unittest.skipUnless(shutil.which("semgrep"), "Semgrep is an optional local dependency")
    def test_repository_rules_match_php_and_javascript_fixtures(self):
        fixture_root = ROOT / "tests" / "fixtures" / "triage"
        result = subprocess.run(
            [
                shutil.which("semgrep"), "--config", str(RULES), "--json",
                "--no-git-ignore", str(fixture_root),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertIn(result.returncode, (0, 1))
        payload = json.loads(result.stdout)
        checks = {item.get("check_id") for item in payload.get("results", [])}
        self.assertIn("wordpress.file-write", checks)
        self.assertIn("wordpress.js-dom-xss", checks)


if __name__ == "__main__":
    unittest.main()
