import ast
import contextlib
import csv
import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from click import unstyle
from typer.testing import CliRunner

from wp_hunter import core as hunter
from wp_hunter import downloader, semgrep_adapter, sources, triage
from wp_hunter.cli import app
from wp_hunter.config import (
    BUILTIN_PRESETS,
    default_config,
    get_preset,
    load_config,
    save_config,
    save_preset,
)
from wp_hunter.migration import migrate_triage_result
from wp_hunter.models import DownloadOptions
from wp_hunter.services import default_output
from wp_hunter.state import DownloadManifest, ReviewLedger
from wp_hunter.versioning import version_is_newer

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "wp_hunter" / "resources" / "wordpress-triage.yml"


def fake_process(returncode=0, stdout='{"results": []}', stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def zip_payload(files=None):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, contents in (files or {"plugin/plugin.php": "<?php"}).items():
            archive.writestr(name, contents)
    return buffer.getvalue()


class FakeResponse:
    def __init__(self, body=b"", status_code=200, headers=None):
        self.body = body
        self.status_code = status_code
        self.headers = headers or {}
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def close(self):
        self.closed = True

    def raise_for_status(self):
        if self.status_code >= 400:
            raise downloader.requests.exceptions.HTTPError(str(self.status_code))

    def iter_content(self, chunk_size=8192):
        for offset in range(0, len(self.body), chunk_size):
            yield self.body[offset : offset + chunk_size]


class SemgrepAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.target = Path(self.temp.name) / "plugin"
        self.target.mkdir()
        (self.target / "plugin.php").write_text("<?php echo 'fixture';", encoding="utf-8")
        self.engine = semgrep_adapter.SemgrepEngine("semgrep", RULES)

    def tearDown(self):
        self.temp.cleanup()

    def scan_with(self, process):
        def run(*_args, **kwargs):
            kwargs["stdout"].write(process.stdout.encode("utf-8"))
            kwargs["stderr"].write(process.stderr.encode("utf-8"))
            return SimpleNamespace(returncode=process.returncode)

        with patch.object(semgrep_adapter.subprocess, "run", side_effect=run):
            return self.engine.scan(str(self.target), timeout=5, mem_mb=128)

    def validate_with(self, process):
        def run(*_args, **kwargs):
            kwargs["stdout"].write(process.stdout.encode("utf-8"))
            kwargs["stderr"].write(process.stderr.encode("utf-8"))
            return SimpleNamespace(returncode=process.returncode)

        with patch.object(semgrep_adapter.subprocess, "run", side_effect=run):
            return hunter._validate_semgrep_config("semgrep", RULES, timeout=5)

    def test_exit_zero_without_findings_is_valid(self):
        results, status = self.scan_with(fake_process())
        self.assertEqual(status, "OK")
        self.assertEqual(results, [])

    def test_exit_one_with_findings_is_valid_and_normalized(self):
        payload = {
            "results": [
                {
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
                }
            ]
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
        self.assertNotIn("\n", status)

    def test_rule_validation_accepts_valid_configuration(self):
        valid, diagnostic = self.validate_with(fake_process(0, '{"results": [], "errors": []}', ""))
        self.assertTrue(valid)
        self.assertEqual(diagnostic, "")

    def test_rule_validation_uses_offline_smoke_scan(self):
        observed = {}

        def run(cmd, **kwargs):
            observed["cmd"] = cmd
            kwargs["stdout"].write(b'{"results": [], "errors": []}')
            return SimpleNamespace(returncode=0)

        with patch.object(semgrep_adapter.subprocess, "run", side_effect=run):
            valid, diagnostic = hunter._validate_semgrep_config("semgrep", RULES, timeout=5)
        self.assertTrue(valid, diagnostic)
        self.assertNotIn("--validate", observed["cmd"])
        self.assertIn("--metrics", observed["cmd"])

    def test_rule_validation_reports_compact_json_error(self):
        payload = {
            "results": [],
            "errors": [
                {
                    "type": "Rule parse error",
                    "rule_id": "wordpress.php-html-output",
                    "message": "Invalid PHP pattern",
                }
            ],
        }
        valid, diagnostic = self.validate_with(fake_process(2, json.dumps(payload)))
        self.assertFalse(valid)
        self.assertIn("wordpress.php-html-output", diagnostic)
        self.assertIn("Invalid PHP pattern", diagnostic)
        self.assertNotIn("\n", diagnostic)

    def test_rule_validation_timeout_is_safe(self):
        with patch.object(
            semgrep_adapter.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["semgrep"], 5),
        ):
            valid, diagnostic = hunter._validate_semgrep_config("semgrep", RULES, timeout=5)
        self.assertFalse(valid)
        self.assertIn("timed out", diagnostic)

    def test_invalid_json_is_error(self):
        results, status = self.scan_with(fake_process(0, "not-json"))
        self.assertEqual(results, [])
        self.assertEqual(status, "INVALID_OUTPUT")

    def test_semgrep_parse_errors_are_fail_closed(self):
        payload = {"results": [], "errors": [{"message": "bad PHP"}]}
        results, status = self.scan_with(fake_process(0, json.dumps(payload)))
        self.assertEqual(results, [])
        self.assertEqual(status, "PARSE_ERROR")

    def test_oversized_semgrep_json_is_rejected(self):
        with patch.object(semgrep_adapter, "MAX_SEMGREP_JSON_BYTES", 10):
            results, status = self.scan_with(fake_process(0, '{"results": []}'))
        self.assertEqual(results, [])
        self.assertEqual(status, "OUTPUT_TOO_LARGE")

    def test_timeout_is_error(self):
        with patch.object(
            semgrep_adapter.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["semgrep"], 5),
        ):
            results, status = self.engine.scan(str(self.target), timeout=5, mem_mb=128)
        self.assertEqual(results, [])
        self.assertEqual(status, "TIMEOUT")

    def test_missing_binary_is_error(self):
        with patch.object(semgrep_adapter.subprocess, "run", side_effect=FileNotFoundError()):
            results, status = self.engine.scan(str(self.target), timeout=5, mem_mb=128)
        self.assertEqual(results, [])
        self.assertEqual(status, "BINARY_NOT_FOUND")

    def test_unknown_access_is_candidate(self):
        payload = {
            "results": [
                {
                    "check_id": "wordpress.custom",
                    "path": "plugin.php",
                    "start": {"line": 1},
                    "extra": {"metadata": {"triage": {"category": "custom"}}},
                }
            ]
        }
        results, status = self.scan_with(fake_process(1, json.dumps(payload)))
        self.assertEqual(status, "OK")
        _, _, in_scope = triage._classify(results)
        self.assertEqual(in_scope, 1)
        self.assertEqual(results[0]["extra"]["context"]["access"], "unknown")

    def test_find_semgrep_does_not_install(self):
        with patch.object(hunter.shutil, "which", return_value=None):
            self.assertIsNone(hunter._find_semgrep(None))


class TriageSafetyTests(unittest.TestCase):
    def test_indonesian_report_uses_localized_headings(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = hunter._ensure_hunter_root(temp_name)
            plugin = root / "fixture-plugin"
            plugin.mkdir()
            (plugin / "plugin.php").write_text("<?php", encoding="utf-8")
            engine = SimpleNamespace(
                executable="semgrep",
                rules_path=RULES,
                scan=lambda *_args: ([], "OK"),
            )
            with (
                patch.object(triage, "SemgrepEngine", return_value=engine),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                triage.run_triage(
                    str(root),
                    "semgrep",
                    RULES,
                    workers=1,
                    max_age_years=0,
                    language="id",
                )

            report = (root / "vuln_report.txt").read_text(encoding="utf-8")
            payload = json.loads((root / "triage_results.json").read_text(encoding="utf-8"))
            self.assertIn("Laporan Triage Semgrep Plugin WordPress", report)
            self.assertIn("Dasar penghapusan", report)
            self.assertEqual(payload["language"], "id")

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
                    return [
                        {
                            "check_id": "wordpress.file_write",
                            "file": "plugin.php",
                            "line": 3,
                            "category": "file_write",
                            "confidence": "medium",
                            "message": "review this candidate",
                            "extra": {"context": {"access": "unknown"}},
                        }
                    ], "OK"
                if Path(target).name == "failed-plugin":
                    return [], "TIMEOUT"
                return [], "OK"

            fake_engine.scan = scan
            output = io.StringIO()
            with (
                patch.object(triage, "SemgrepEngine", return_value=fake_engine),
                contextlib.redirect_stdout(output),
            ):
                triage.run_triage(
                    str(root),
                    "semgrep",
                    RULES,
                    workers=1,
                    timeout=5,
                    mem_mb=128,
                    max_age_years=0,
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

    def test_capability_checked_finding_is_never_deleted(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = hunter._ensure_hunter_root(temp_name)
            matched = root / "matched-plugin"
            empty = root / "empty-plugin"
            for directory in (matched, empty):
                directory.mkdir()
                (directory / "plugin.php").write_text("<?php", encoding="utf-8")

            engine = SimpleNamespace(executable="semgrep", rules_path=RULES)

            def scan(target, _timeout, _mem_mb):
                if Path(target).name == "matched-plugin":
                    return [
                        {
                            "check_id": "wordpress.admin-operation",
                            "file": "plugin.php",
                            "line": 1,
                            "category": "privilege",
                            "confidence": "medium",
                            "message": "review even when capability checked",
                            "extra": {"context": {"access": "capability_checked"}},
                        }
                    ], "OK"
                return [], "OK"

            engine.scan = scan
            with (
                patch.object(triage, "SemgrepEngine", return_value=engine),
                patch.object(triage, "_ask_choice", return_value="yes"),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                triage.run_triage(
                    str(root),
                    "semgrep",
                    RULES,
                    workers=1,
                    timeout=5,
                    mem_mb=128,
                    dry_run=False,
                    max_age_years=0,
                )

            self.assertTrue(matched.is_dir(), "every Semgrep match must be retained")
            self.assertFalse(empty.exists(), "only a successful zero-match scan may be deleted")
            payload = json.loads((root / "triage_results.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["candidate_count"], 1)
            self.assertEqual(payload["summary"]["deleted_count"], 1)
            matched_result = next(r for r in payload["results"] if r["name"] == matched.name)
            self.assertEqual(matched_result["in_scope"], 0)
            self.assertEqual(matched_result["deletion"], "retained")
            self.assertIn(matched.name, (root / "vuln_plugins.txt").read_text(encoding="utf-8"))

    def test_live_triage_records_deleted_release_in_review_history(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = hunter._ensure_hunter_root(temp_name)
            plugin = root / "reviewed-by-triage"
            plugin.mkdir()
            (plugin / "plugin.php").write_text("<?php", encoding="utf-8")
            (plugin / "plugin_info.json").write_text(
                json.dumps({"version": "1.4.0", "downloaded_sha256": "abc123"}),
                encoding="utf-8",
            )
            engine = SimpleNamespace(
                executable="semgrep",
                rules_path=RULES,
                scan=lambda *_args: ([], "OK"),
            )
            ledger = ReviewLedger(root)
            with (
                patch.object(triage, "SemgrepEngine", return_value=engine),
                patch.object(triage, "_ask_choice", return_value="yes"),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                triage.run_triage(
                    str(root),
                    "semgrep",
                    RULES,
                    workers=1,
                    timeout=5,
                    mem_mb=128,
                    dry_run=False,
                    max_age_years=0,
                    review_ledger=ledger,
                )
            self.assertFalse(plugin.exists())
            self.assertTrue(ledger.covers({"slug": plugin.name, "version": "1.4.0"}))
            self.assertFalse(ledger.covers({"slug": plugin.name, "version": "1.5.0"}))

    def test_dry_run_removes_disposable_extracted_source(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = hunter._ensure_hunter_root(temp_name)
            plugin = root / "archive-plugin"
            plugin.mkdir()
            (plugin / "archive-plugin.zip").write_bytes(zip_payload())
            engine = SimpleNamespace(
                executable="semgrep",
                rules_path=RULES,
                scan=lambda *_args: ([], "OK"),
            )
            with (
                patch.object(triage, "SemgrepEngine", return_value=engine),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                triage.run_triage(
                    str(root),
                    "semgrep",
                    RULES,
                    workers=1,
                    timeout=5,
                    mem_mb=128,
                    dry_run=True,
                    max_age_years=0,
                )
            self.assertTrue(plugin.is_dir())
            self.assertFalse((plugin / "extracted").exists())
            payload = json.loads((root / "triage_results.json").read_text(encoding="utf-8"))
            result = payload["results"][0]
            self.assertEqual(result["cleanup_status"], "removed")
            self.assertEqual(result["deletion"], "would_delete")

    def test_javascript_source_is_scanned_and_unrelated_folder_is_ignored(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = hunter._ensure_hunter_root(temp_name)
            plugin = root / "javascript-plugin"
            plugin.mkdir()
            (plugin / "index.js").write_text("document.write(location.hash)", encoding="utf-8")
            unrelated = root / "notes"
            unrelated.mkdir()
            (unrelated / "README.txt").write_text("not a plugin", encoding="utf-8")
            scanned = []
            engine = SimpleNamespace(executable="semgrep", rules_path=RULES)

            def scan(target, *_args):
                scanned.append(Path(target))
                return [], "TIMEOUT"

            engine.scan = scan
            with (
                patch.object(triage, "SemgrepEngine", return_value=engine),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                triage.run_triage(
                    str(root),
                    "semgrep",
                    RULES,
                    workers=1,
                    timeout=5,
                    mem_mb=128,
                    dry_run=True,
                    max_age_years=0,
                )
            self.assertEqual(scanned, [plugin])
            self.assertTrue(plugin.is_dir())
            self.assertTrue(unrelated.is_dir())

    def test_failed_deletion_is_reported_as_retained(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = hunter._ensure_hunter_root(temp_name)
            plugin = root / "clean-plugin"
            plugin.mkdir()
            (plugin / "plugin.php").write_text("<?php", encoding="utf-8")
            engine = SimpleNamespace(
                executable="semgrep",
                rules_path=RULES,
                scan=lambda *_args: ([], "OK"),
            )
            real_rmtree = shutil.rmtree

            def fail_target(path, *args, **kwargs):
                if Path(path) == plugin:
                    raise OSError("simulated failure")
                return real_rmtree(path, *args, **kwargs)

            with (
                patch.object(triage, "SemgrepEngine", return_value=engine),
                patch.object(triage, "_ask_choice", return_value="yes"),
                patch.object(hunter.shutil, "rmtree", side_effect=fail_target),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                triage.run_triage(
                    str(root),
                    "semgrep",
                    RULES,
                    workers=1,
                    timeout=5,
                    mem_mb=128,
                    dry_run=False,
                    max_age_years=0,
                )
            payload = json.loads((root / "triage_results.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["deleted_count"], 0)
            self.assertEqual(payload["summary"]["deletion_failure_count"], 1)
            self.assertTrue(plugin.is_dir())
            report = (root / "vuln_report.txt").read_text(encoding="utf-8")
            self.assertIn("DELETION FAILED", report)

    def test_replaced_directory_after_scan_is_never_deleted(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = hunter._ensure_hunter_root(temp_name)
            plugin = root / "race-plugin"
            moved = root / "race-plugin-original"
            plugin.mkdir()
            (plugin / "plugin.php").write_text("<?php", encoding="utf-8")
            engine = SimpleNamespace(executable="semgrep", rules_path=RULES)

            def replace_target(_target, *_args):
                plugin.rename(moved)
                plugin.mkdir()
                (plugin / "replacement.php").write_text("<?php", encoding="utf-8")
                return [], "OK"

            engine.scan = replace_target
            with (
                patch.object(triage, "SemgrepEngine", return_value=engine),
                patch.object(triage, "_ask_choice", return_value="yes"),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                triage.run_triage(
                    str(root),
                    "semgrep",
                    RULES,
                    workers=1,
                    timeout=5,
                    mem_mb=128,
                    dry_run=False,
                    max_age_years=0,
                )
            self.assertTrue(plugin.is_dir())
            self.assertTrue(moved.is_dir())
            payload = json.loads((root / "triage_results.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["deleted_count"], 0)
            self.assertEqual(payload["summary"]["deletion_failure_count"], 1)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_report_write_replaces_symlink_without_touching_target(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = hunter._ensure_hunter_root(temp_name)
            plugin = root / "fixture-plugin"
            plugin.mkdir()
            (plugin / "plugin.php").write_text("<?php", encoding="utf-8")
            outside = root / "outside.txt"
            outside.write_text("sentinel", encoding="utf-8")
            report = root / "vuln_report.txt"
            report.symlink_to(outside)
            engine = SimpleNamespace(
                executable="semgrep",
                rules_path=RULES,
                scan=lambda *_args: ([], "OK"),
            )
            with (
                patch.object(triage, "SemgrepEngine", return_value=engine),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                triage.run_triage(
                    str(root),
                    "semgrep",
                    RULES,
                    workers=1,
                    timeout=5,
                    mem_mb=128,
                    dry_run=True,
                    max_age_years=0,
                )
            self.assertEqual(outside.read_text(encoding="utf-8"), "sentinel")
            self.assertFalse(report.is_symlink())
            self.assertIn("Semgrep Triage Report", report.read_text(encoding="utf-8"))


class RootSafetyTests(unittest.TestCase):
    def test_nonempty_root_requires_explicit_adoption(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            (root / "existing.txt").write_text("owned by user", encoding="utf-8")
            with self.assertRaises(ValueError):
                hunter._ensure_hunter_root(root)
            adopted = hunter._ensure_hunter_root(root, adopt_existing=True)
            self.assertEqual(adopted, root.resolve())
            self.assertEqual(
                (root / hunter.ROOT_MARKER_FILE).read_text(encoding="utf-8"),
                hunter.ROOT_MARKER_CONTENT,
            )

    def test_invalid_marker_and_project_root_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            (root / hunter.ROOT_MARKER_FILE).write_text("not a marker", encoding="utf-8")
            with self.assertRaises(ValueError):
                hunter._ensure_hunter_root(root, adopt_existing=True)
        with self.assertRaises(ValueError):
            hunter._ensure_hunter_root(ROOT, adopt_existing=True)

    def test_legacy_hunter_root_is_recognized_from_name_or_artifacts(self):
        with tempfile.TemporaryDirectory() as temp_name:
            parent = Path(temp_name)
            named = parent / "wp_plugins_10K"
            named.mkdir()
            self.assertTrue(hunter._looks_like_legacy_hunter_root(named))

            artifact = parent / "custom-output"
            artifact.mkdir()
            (artifact / hunter.MANIFEST_FILE).write_text("{}", encoding="utf-8")
            self.assertTrue(hunter._looks_like_legacy_hunter_root(artifact))

            general = parent / "documents"
            general.mkdir()
            (general / "notes.txt").write_text("mine", encoding="utf-8")
            self.assertFalse(hunter._looks_like_legacy_hunter_root(general))

    def test_default_output_uses_a_dedicated_wp_hunter_folder(self):
        with tempfile.TemporaryDirectory() as temp_name:
            parent = Path(temp_name) / "documents"
            parent.mkdir()
            selected = default_output(DownloadOptions(source="wporg"), parent)
            self.assertEqual(selected, parent / "wp_plugins_10K")

    def test_presets_never_accept_destructive_options(self):
        with tempfile.TemporaryDirectory() as temp_name:
            config = default_config()
            with self.assertRaises(ValueError):
                save_preset(config, "unsafe", {"source": "wporg", "force": True})
            save_config(config, Path(temp_name) / "config.json")

    def test_built_in_presets_are_immutable(self):
        with tempfile.TemporaryDirectory() as temp_name:
            config = default_config()
            with self.assertRaises(ValueError):
                save_preset(config, "wporg-10k", {"source": "wporg"}, replace=True)
            self.assertIn("patchstack-vdp", BUILTIN_PRESETS)
            save_config(config, Path(temp_name) / "config.json")

    def test_unmarked_root_can_be_previewed_but_never_live_deleted(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            plugin = root / "fixture-plugin"
            plugin.mkdir()
            (plugin / "plugin.php").write_text("<?php", encoding="utf-8")
            engine = SimpleNamespace(
                executable="semgrep",
                rules_path=RULES,
                scan=lambda *_args: ([], "OK"),
            )
            with (
                patch.object(triage, "SemgrepEngine", return_value=engine),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                triage.run_triage(
                    str(root),
                    "semgrep",
                    RULES,
                    workers=1,
                    timeout=5,
                    mem_mb=128,
                    dry_run=False,
                    max_age_years=0,
                    allow_unmarked=True,
                )
            self.assertTrue(plugin.is_dir())

            extracted = plugin / "extracted"
            extracted.mkdir()
            (extracted / "plugin.php").write_text("<?php", encoding="utf-8")
            with (
                patch.object(triage, "SemgrepEngine", return_value=engine),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                triage.run_triage(
                    str(root),
                    "semgrep",
                    RULES,
                    workers=1,
                    timeout=5,
                    mem_mb=128,
                    dry_run=True,
                    max_age_years=0,
                    allow_unmarked=True,
                    keep_extracted=False,
                )
            self.assertTrue(extracted.is_dir())

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_symlink_marker_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            target = root / "target"
            target.write_text(hunter.ROOT_MARKER_CONTENT, encoding="utf-8")
            (root / hunter.ROOT_MARKER_FILE).symlink_to(target)
            with self.assertRaises(ValueError):
                hunter._validate_triage_root(root, allow_unmarked=True)


class CollectionTests(unittest.TestCase):
    @staticmethod
    def plugin(slug, installs):
        return {
            "slug": slug,
            "name": slug,
            "version": "1.0",
            "active_installs": installs,
            "downloaded": 1,
            "last_updated": "2026-01-01",
            "author": "author",
            "tags": {},
            "download_link": f"https://downloads.wordpress.org/plugin/{slug}.zip",
        }

    def test_nonpopular_browse_does_not_use_popularity_early_exit(self):
        pages = {
            1: {
                "info": {"pages": 2, "results": 2},
                "plugins": [self.plugin("below", 1000)],
            },
            2: {
                "info": {"pages": 2, "results": 2},
                "plugins": [self.plugin("match", 10000)],
            },
        }

        def query(**kwargs):
            return pages[kwargs["page"]]

        with (
            patch.object(sources, "query_plugins_page", side_effect=query),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            results = sources.collect_plugins(
                10000,
                browse="updated",
                max_pages=2,
                api_workers=1,
                min_updated_years=0,
            )
        self.assertEqual([item["slug"] for item in results], ["match"])

    def test_popular_browse_can_stop_when_first_page_is_below_tier(self):
        first = {
            "info": {"pages": 10, "results": 1000},
            "plugins": [self.plugin("below", 1000)],
        }
        with (
            patch.object(sources, "query_plugins_page", return_value=first) as query,
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            results = sources.collect_plugins(
                10000,
                browse="popular",
                max_pages=10,
                api_workers=1,
                min_updated_years=0,
            )
        self.assertEqual(results, [])
        self.assertEqual(query.call_count, 1)

    def test_patchstack_theme_uses_theme_information_api(self):
        first = {
            "total": 1,
            "featured": {"results": []},
            "recentlyAdded": {
                "pagination": {"last_page": 1},
                "results": [
                    {
                        "slug": "fixture-theme",
                        "kind": "theme",
                        "boost": 25,
                        "maxBounty": 500,
                        "vendor_contact": "vendor",
                    }
                ],
            },
        }
        theme_info = self.plugin("fixture-theme", 5000)
        with (
            patch.object(sources, "_patchstack_page", return_value=first),
            patch.object(sources, "_fetch_wporg_theme_info", return_value=theme_info) as themes,
            patch.object(sources, "_fetch_wporg_plugin_info") as plugins,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            results = sources.collect_patchstack_plugins(
                include_themes=True,
                api_workers=1,
                min_updated_years=0,
            )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["asset_kind"], "theme")
        themes.assert_called_once_with("fixture-theme")
        plugins.assert_not_called()

    def test_wordpress_api_requests_are_start_rate_limited(self):
        previous = sources._WPORG_LAST_REQUEST_AT
        sources._WPORG_LAST_REQUEST_AT = 10.0
        try:
            with (
                patch.object(sources.time, "monotonic", side_effect=[10.1, 10.4]),
                patch.object(sources.time, "sleep") as sleep,
                patch.object(sources.requests, "get", return_value="response") as get,
            ):
                response = sources._wporg_get("https://api.wordpress.org/example")
        finally:
            sources._WPORG_LAST_REQUEST_AT = previous
        self.assertEqual(response, "response")
        sleep.assert_called_once()
        self.assertAlmostEqual(sleep.call_args.args[0], 0.2)
        get.assert_called_once()


class DownloadAndExportTests(unittest.TestCase):
    @staticmethod
    def plugin(url, payload, slug="fixture-plugin"):
        return {
            "slug": slug,
            "name": slug,
            "version": "1.0",
            "download_link": url,
            "md5": hashlib.md5(payload).hexdigest(),
            "tags": [],
        }

    def test_download_validates_zip_checksum_and_uses_zip_filename(self):
        payload = zip_payload()
        plugin = self.plugin(
            "https://downloads.wordpress.org/plugin/not-an-archive.php?download=1",
            payload,
        )
        with tempfile.TemporaryDirectory() as temp_name:
            root = hunter._ensure_hunter_root(temp_name)
            response = FakeResponse(payload, headers={"Content-Length": str(len(payload))})
            with patch.object(downloader.requests, "get", return_value=response):
                ok, slug, message = downloader.download_plugin(plugin, str(root))
            archive = root / slug / f"{slug}.zip"
            self.assertTrue(ok, message)
            self.assertTrue(zipfile.is_zipfile(archive))
            metadata = json.loads((root / slug / "plugin_info.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["downloaded_sha256"], hashlib.sha256(payload).hexdigest())

    def test_existing_invalid_archive_is_repaired_atomically(self):
        old_payload = zip_payload({"old/plugin.php": "<?php echo 'old';"})
        new_payload = zip_payload({"new/plugin.php": "<?php echo 'new';"})
        url = "https://downloads.wordpress.org/plugin/fixture-plugin.zip"
        plugin = self.plugin(url, new_payload)
        with tempfile.TemporaryDirectory() as temp_name:
            root = hunter._ensure_hunter_root(temp_name)
            plugin_dir = root / plugin["slug"]
            plugin_dir.mkdir()
            archive = plugin_dir / "fixture-plugin.zip"
            archive.write_bytes(old_payload)
            with patch.object(downloader.requests, "get", return_value=FakeResponse(new_payload)):
                ok, _slug, message = downloader.download_plugin(plugin, str(root))
            self.assertTrue(ok, message)
            self.assertEqual(archive.read_bytes(), new_payload)
            self.assertFalse(list(plugin_dir.glob("*.part")))

    def test_redirect_to_untrusted_host_is_never_requested(self):
        payload = zip_payload()
        plugin = self.plugin("https://downloads.wordpress.org/plugin/fixture-plugin.zip", payload)

        def redirect(*_args, **_kwargs):
            return FakeResponse(
                status_code=302,
                headers={"Location": "https://example.invalid/payload.zip"},
            )

        with tempfile.TemporaryDirectory() as temp_name:
            root = hunter._ensure_hunter_root(temp_name)
            with (
                patch.object(downloader.requests, "get", side_effect=redirect) as get,
                patch.object(downloader.time, "sleep"),
            ):
                ok, _slug, message = downloader.download_plugin(plugin, str(root))
            self.assertFalse(ok)
            self.assertIn("non-WordPress", message)
            self.assertEqual(get.call_count, hunter.DOWNLOAD_MAX_RETRIES)
            self.assertTrue(
                all(call.args[0].endswith("fixture-plugin.zip") for call in get.call_args_list)
            )
            self.assertTrue(
                all(call.kwargs["allow_redirects"] is False for call in get.call_args_list)
            )

    def test_global_dedup_indexes_only_marked_roots_with_valid_archives(self):
        with tempfile.TemporaryDirectory() as temp_name:
            base = Path(temp_name)
            marked = hunter._ensure_hunter_root(base / "custom-hunter-root")
            valid_plugin = marked / "valid-plugin"
            valid_plugin.mkdir()
            (valid_plugin / "valid-plugin.zip").write_bytes(zip_payload())
            empty_plugin = marked / "empty-plugin"
            empty_plugin.mkdir()

            unmarked = base / "wp_plugins_unmarked"
            unmarked.mkdir()
            ignored_plugin = unmarked / "ignored-plugin"
            ignored_plugin.mkdir()
            (ignored_plugin / "ignored-plugin.zip").write_bytes(zip_payload())

            self.assertEqual(downloader.build_global_slug_index(str(base)), {"valid-plugin"})

    def test_csv_formula_prefix_with_whitespace_is_escaped(self):
        plugin = {
            "name": " \t=CMD()",
            "slug": "fixture",
            "version": "1",
            "active_installs": 1000,
            "downloaded": 0,
            "last_updated": "",
            "author": "\u00a0+author",
            "requires": "",
            "requires_php": "",
            "tested": "",
            "download_link": "",
            "homepage": "",
            "tags": [],
        }
        with tempfile.TemporaryDirectory() as temp_name, contextlib.redirect_stdout(io.StringIO()):
            _json_path, csv_path = downloader.export_results([plugin], temp_name, 1000)
            with open(csv_path, newline="", encoding="utf-8") as fh:
                row = next(csv.DictReader(fh))
        self.assertTrue(row["name"].startswith("'"))
        self.assertTrue(row["author"].startswith("'"))

    def test_unsafe_and_case_colliding_zip_members_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            traversal = root / "traversal.zip"
            with zipfile.ZipFile(traversal, "w") as archive:
                archive.writestr("../outside.php", "<?php")
            valid, reason = downloader._validate_download_archive(traversal)
            self.assertFalse(valid)
            self.assertIn("traversal", reason)

            collision = root / "collision.zip"
            with zipfile.ZipFile(collision, "w") as archive:
                archive.writestr("Plugin/file.php", "<?php")
                archive.writestr("plugin/FILE.php", "<?php")
            valid, reason = downloader._validate_download_archive(collision)
            self.assertFalse(valid)
            self.assertIn("duplicate", reason)

    def test_removed_download_is_skipped_until_remote_version_changes(self):
        payload = zip_payload()
        with tempfile.TemporaryDirectory() as temp_name:
            root = hunter._ensure_hunter_root(temp_name)
            slug = "reviewed-plugin"
            plugin_dir = root / slug
            plugin_dir.mkdir()
            archive = plugin_dir / f"{slug}.zip"
            archive.write_bytes(payload)
            manifest = DownloadManifest(root)
            manifest.mark_downloaded(
                slug,
                archive.name,
                len(payload) // 1024,
                "2.0.0-beta1",
                hashlib.sha256(payload).hexdigest(),
            )
            shutil.rmtree(plugin_dir)

            ledger = ReviewLedger(root)
            self.assertEqual(ledger.sync_removed_downloads(manifest), 1)
            self.assertTrue(ledger.covers({"slug": slug, "version": "2.0.0-beta1"}))
            self.assertFalse(ledger.covers({"slug": slug, "version": "2.0.0"}))
            self.assertEqual(ledger.sync_removed_downloads(manifest), 0)

    def test_version_comparison_understands_prereleases(self):
        self.assertTrue(version_is_newer("2.0.0", "2.0.0-beta1"))
        self.assertTrue(version_is_newer("2.0.0-beta2", "2.0.0-beta1"))
        self.assertFalse(version_is_newer("2.0.0-beta1", "2.0.0"))
        self.assertTrue(version_is_newer("1.10", "1.9"))


class CliAndRuleTests(unittest.TestCase):
    def test_installed_cli_exposes_version(self):
        result = CliRunner().invoke(app, ["--version"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("wp-hunter 2.0.0", result.output)

    def test_top_level_help_exposes_v2_commands(self):
        result = CliRunner().invoke(app, ["--help"])
        self.assertEqual(result.exit_code, 0)
        for command in ("download", "scan", "status", "doctor", "preset", "config"):
            self.assertIn(command, result.output)

    def test_scan_help_exposes_semgrep_and_safe_deletion(self):
        result = CliRunner().invoke(app, ["scan", "--help"], terminal_width=180)
        output = unstyle(result.output)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("--semgrep", output)
        self.assertIn("--rules", output)
        self.assertIn("--delete-no-find", output)
        self.assertNotIn("--confirm-delete", output)

    def test_indonesian_status_output(self):
        with tempfile.TemporaryDirectory() as temp_name:
            result = CliRunner().invoke(
                app,
                ["--lang", "id", "status"],
                env={"WP_HUNTER_CONFIG_DIR": temp_name},
            )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Belum ada folder output", result.output)

    def test_config_round_trip_is_atomic(self):
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "config.json"
            config = default_config()
            config["language"] = "id"
            save_config(config, path)
            loaded = load_config(path)
            self.assertFalse(any(Path(temp_name).glob("*.tmp")))
        self.assertEqual(loaded["language"], "id")

    def test_builtin_preset_has_expected_safe_defaults(self):
        values, builtin = get_preset(default_config(), "wporg-10k")
        self.assertTrue(builtin)
        self.assertEqual(values["installs"], "10K")
        self.assertEqual(values["max_age_years"], 2)
        self.assertNotIn("force", values)

    def test_user_preset_round_trip(self):
        config = default_config()
        save_preset(
            config,
            "fresh-targets",
            {
                "source": "wporg",
                "installs": "10K",
                "installs_mode": "minimum",
                "max_age_years": 1,
            },
        )
        values, builtin = get_preset(config, "fresh-targets")
        self.assertFalse(builtin)
        self.assertEqual(values["installs_mode"], "minimum")

    def test_legacy_triage_result_migrates_without_backup(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            path = root / "triage_results.json"
            path.write_text(
                json.dumps(
                    {
                        "engine": "semgrep",
                        "generated": "2026-01-01T00:00:00",
                        "candidate_count": 1,
                        "results": [],
                    }
                ),
                encoding="utf-8",
            )
            self.assertTrue(migrate_triage_result(root))
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], 2)
            self.assertEqual(payload["summary"]["candidate_count"], 1)
            self.assertFalse(any(root.glob("*.bak")))

    def test_package_sources_parse_and_legacy_entrypoint_is_removed(self):
        self.assertFalse((ROOT / "wp_plugin_hunter.py").exists())
        for source_path in (ROOT / "wp_hunter").glob("*.py"):
            ast.parse(source_path.read_text(encoding="utf-8"))

    def test_default_triage_is_dry_run(self):
        self.assertTrue(
            __import__("inspect").signature(triage.run_triage).parameters["dry_run"].default
        )

    def test_cli_rejects_invalid_browse_and_dates(self):
        runner = CliRunner()
        invalid_browse = runner.invoke(app, ["download", "wporg", "--browse", "invalid"])
        self.assertEqual(invalid_browse.exit_code, 2)
        invalid_date = runner.invoke(app, ["download", "wporg", "--since", "not-a-date"])
        self.assertEqual(invalid_date.exit_code, 2)

    @unittest.skipUnless(shutil.which("semgrep"), "Semgrep is an optional local dependency")
    def test_repository_rules_match_php_and_javascript_fixtures(self):
        with tempfile.TemporaryDirectory() as temp_name:
            fixture_root = Path(temp_name) / "wordpress-fixtures"
            shutil.copytree(ROOT / "tests" / "fixtures" / "triage", fixture_root)
            engine = semgrep_adapter.SemgrepEngine(shutil.which("semgrep"), RULES)
            results, status = engine.scan(str(fixture_root), timeout=60, mem_mb=256)
        self.assertEqual(status, "OK")
        checks = {item.get("check_id") for item in results}
        self.assertIn("wordpress.file-write", checks)
        self.assertIn("wordpress.sql-wpdb", checks)
        self.assertIn("wordpress.ajax-nopriv-entrypoint", checks)
        self.assertIn("wordpress.rest-route", checks)
        self.assertIn("wordpress.rest-permissive-route", checks)
        self.assertIn("wordpress.shortcode-entrypoint", checks)
        self.assertIn("wordpress.public-lifecycle-entrypoint", checks)
        self.assertIn("wordpress.nonce-check", checks)
        self.assertIn("wordpress.php-request-to-dynamic-load", checks)
        self.assertIn("wordpress.php-html-output", checks)
        self.assertIn("wordpress.user-update", checks)
        self.assertIn("wordpress.php-dangerous-execution", checks)
        self.assertIn("wordpress.js-dom-xss", checks)
        noisy_clean_matches = {
            item.get("check_id")
            for item in results
            if str(item.get("file", "")).endswith("clean.php")
        }
        self.assertNotIn("wordpress.php-dangerous-execution", noisy_clean_matches)


if __name__ == "__main__":
    unittest.main()
