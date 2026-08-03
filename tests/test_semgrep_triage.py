import ast
import contextlib
import csv
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import wp_plugin_hunter as hunter  # noqa: E402


RULES = ROOT / "rules" / "wordpress-triage.yml"


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
            raise hunter.requests.exceptions.HTTPError(str(self.status_code))

    def iter_content(self, chunk_size=8192):
        for offset in range(0, len(self.body), chunk_size):
            yield self.body[offset:offset + chunk_size]


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
        def run(*_args, **kwargs):
            kwargs["stdout"].write(process.stdout.encode("utf-8"))
            kwargs["stderr"].write(process.stderr.encode("utf-8"))
            return SimpleNamespace(returncode=process.returncode)

        with patch.object(hunter.subprocess, "run", side_effect=run):
            return self.engine.scan(str(self.target), timeout=5, mem_mb=128)

    def validate_with(self, process):
        def run(*_args, **kwargs):
            kwargs["stdout"].write(process.stdout.encode("utf-8"))
            kwargs["stderr"].write(process.stderr.encode("utf-8"))
            return SimpleNamespace(returncode=process.returncode)

        with patch.object(hunter.subprocess, "run", side_effect=run):
            return hunter._validate_semgrep_config("semgrep", RULES, timeout=5)

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
        self.assertNotIn("\n", status)

    def test_rule_validation_accepts_valid_configuration(self):
        valid, diagnostic = self.validate_with(fake_process(0, "", ""))
        self.assertTrue(valid)
        self.assertEqual(diagnostic, "")

    def test_rule_validation_reports_compact_json_error(self):
        payload = {
            "results": [],
            "errors": [{
                "type": "Rule parse error",
                "rule_id": "wordpress.php-html-output",
                "message": "Invalid PHP pattern",
            }],
        }
        valid, diagnostic = self.validate_with(fake_process(2, json.dumps(payload)))
        self.assertFalse(valid)
        self.assertIn("wordpress.php-html-output", diagnostic)
        self.assertIn("Invalid PHP pattern", diagnostic)
        self.assertNotIn("\n", diagnostic)

    def test_rule_validation_timeout_is_safe(self):
        with patch.object(
            hunter.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["semgrep"], 5),
        ):
            valid, diagnostic = hunter._validate_semgrep_config(
                "semgrep", RULES, timeout=5
            )
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
        with patch.object(hunter, "MAX_SEMGREP_JSON_BYTES", 10):
            results, status = self.scan_with(fake_process(0, '{"results": []}'))
        self.assertEqual(results, [])
        self.assertEqual(status, "OUTPUT_TOO_LARGE")

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
                    return [{
                        "check_id": "wordpress.admin-operation",
                        "file": "plugin.php",
                        "line": 1,
                        "category": "privilege",
                        "confidence": "medium",
                        "message": "review even when capability checked",
                        "extra": {"context": {"access": "capability_checked"}},
                    }], "OK"
                return [], "OK"

            engine.scan = scan
            with patch.object(hunter, "SemgrepEngine", return_value=engine), \
                    patch.object(hunter, "_ask_choice", return_value="yes"), \
                    contextlib.redirect_stdout(io.StringIO()):
                hunter.run_triage(
                    str(root), "semgrep", RULES, workers=1, timeout=5,
                    mem_mb=128, dry_run=False, max_age_years=0,
                )

            self.assertTrue(matched.is_dir(), "every Semgrep match must be retained")
            self.assertFalse(empty.exists(), "only a successful zero-match scan may be deleted")
            payload = json.loads((root / "triage_results.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["candidate_count"], 1)
            self.assertEqual(payload["deleted_count"], 1)
            matched_result = next(r for r in payload["results"] if r["name"] == matched.name)
            self.assertEqual(matched_result["in_scope"], 0)
            self.assertEqual(matched_result["deletion"], "retained")
            self.assertIn(matched.name, (root / "vuln_plugins.txt").read_text(encoding="utf-8"))

    def test_dry_run_removes_disposable_extracted_source(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = hunter._ensure_hunter_root(temp_name)
            plugin = root / "archive-plugin"
            plugin.mkdir()
            (plugin / "archive-plugin.zip").write_bytes(zip_payload())
            engine = SimpleNamespace(
                executable="semgrep", rules_path=RULES,
                scan=lambda *_args: ([], "OK"),
            )
            with patch.object(hunter, "SemgrepEngine", return_value=engine), \
                    contextlib.redirect_stdout(io.StringIO()):
                hunter.run_triage(
                    str(root), "semgrep", RULES, workers=1, timeout=5,
                    mem_mb=128, dry_run=True, max_age_years=0,
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
            with patch.object(hunter, "SemgrepEngine", return_value=engine), \
                    contextlib.redirect_stdout(io.StringIO()):
                hunter.run_triage(
                    str(root), "semgrep", RULES, workers=1, timeout=5,
                    mem_mb=128, dry_run=True, max_age_years=0,
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
                executable="semgrep", rules_path=RULES,
                scan=lambda *_args: ([], "OK"),
            )
            real_rmtree = shutil.rmtree

            def fail_target(path, *args, **kwargs):
                if Path(path) == plugin:
                    raise OSError("simulated failure")
                return real_rmtree(path, *args, **kwargs)

            with patch.object(hunter, "SemgrepEngine", return_value=engine), \
                    patch.object(hunter, "_ask_choice", return_value="yes"), \
                    patch.object(hunter.shutil, "rmtree", side_effect=fail_target), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                hunter.run_triage(
                    str(root), "semgrep", RULES, workers=1, timeout=5,
                    mem_mb=128, dry_run=False, max_age_years=0,
                )
            payload = json.loads((root / "triage_results.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["deleted_count"], 0)
            self.assertEqual(payload["deletion_failure_count"], 1)
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
            with patch.object(hunter, "SemgrepEngine", return_value=engine), \
                    patch.object(hunter, "_ask_choice", return_value="yes"), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                hunter.run_triage(
                    str(root), "semgrep", RULES, workers=1, timeout=5,
                    mem_mb=128, dry_run=False, max_age_years=0,
                )
            self.assertTrue(plugin.is_dir())
            self.assertTrue(moved.is_dir())
            payload = json.loads((root / "triage_results.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["deleted_count"], 0)
            self.assertEqual(payload["deletion_failure_count"], 1)

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
                executable="semgrep", rules_path=RULES,
                scan=lambda *_args: ([], "OK"),
            )
            with patch.object(hunter, "SemgrepEngine", return_value=engine), \
                    contextlib.redirect_stdout(io.StringIO()):
                hunter.run_triage(
                    str(root), "semgrep", RULES, workers=1, timeout=5,
                    mem_mb=128, dry_run=True, max_age_years=0,
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

    def test_interactive_legacy_root_defaults_to_reuse_without_typed_path(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name) / "wp_plugins_10K"
            root.mkdir()
            (root / "old-plugin.zip").write_bytes(b"legacy")
            with patch.object(hunter, "_ask", return_value=str(root)), \
                    patch.object(hunter, "_ask_choice", return_value="use-folder") as choice, \
                    contextlib.redirect_stdout(io.StringIO()):
                selected, adopt = hunter._interactive_output_folder("./wp_plugins_10K")
            self.assertEqual(Path(selected), root)
            self.assertTrue(adopt)
            self.assertEqual(choice.call_args.args[2], "use-folder")

    def test_interactive_general_folder_uses_dedicated_subfolder(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name) / "documents"
            root.mkdir()
            (root / "notes.txt").write_text("mine", encoding="utf-8")
            with patch.object(hunter, "_ask", return_value=str(root)), \
                    patch.object(hunter, "_ask_choice", return_value="new-subfolder") as choice, \
                    contextlib.redirect_stdout(io.StringIO()):
                selected, adopt = hunter._interactive_output_folder("./wp_plugins_10K")
            self.assertEqual(Path(selected), root / "wp_plugins_10K")
            self.assertFalse(adopt)
            self.assertEqual(choice.call_args.args[2], "new-subfolder")

    def test_interactive_adoption_does_not_require_duplicate_typed_confirmation(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            (root / "existing.txt").write_text("legacy", encoding="utf-8")
            self.assertFalse(
                hunter._requires_exact_adoption_confirmation(root, True, True)
            )
            self.assertTrue(
                hunter._requires_exact_adoption_confirmation(root, True, False)
            )

    def test_unmarked_root_can_be_previewed_but_never_live_deleted(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            plugin = root / "fixture-plugin"
            plugin.mkdir()
            (plugin / "plugin.php").write_text("<?php", encoding="utf-8")
            engine = SimpleNamespace(
                executable="semgrep", rules_path=RULES,
                scan=lambda *_args: ([], "OK"),
            )
            with patch.object(hunter, "SemgrepEngine", return_value=engine), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                hunter.run_triage(
                    str(root), "semgrep", RULES, workers=1, timeout=5,
                    mem_mb=128, dry_run=False, max_age_years=0,
                    allow_unmarked=True,
                )
            self.assertTrue(plugin.is_dir())

            extracted = plugin / "extracted"
            extracted.mkdir()
            (extracted / "plugin.php").write_text("<?php", encoding="utf-8")
            with patch.object(hunter, "SemgrepEngine", return_value=engine), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                hunter.run_triage(
                    str(root), "semgrep", RULES, workers=1, timeout=5,
                    mem_mb=128, dry_run=True, max_age_years=0,
                    allow_unmarked=True, keep_extracted=False,
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

        with patch.object(hunter, "query_plugins_page", side_effect=query), \
                contextlib.redirect_stdout(io.StringIO()):
            results = hunter.collect_plugins(
                10000, browse="updated", max_pages=2, api_workers=1,
                min_updated_years=0,
            )
        self.assertEqual([item["slug"] for item in results], ["match"])

    def test_popular_browse_can_stop_when_first_page_is_below_tier(self):
        first = {
            "info": {"pages": 10, "results": 1000},
            "plugins": [self.plugin("below", 1000)],
        }
        with patch.object(hunter, "query_plugins_page", return_value=first) as query, \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            results = hunter.collect_plugins(
                10000, browse="popular", max_pages=10, api_workers=1,
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
                "results": [{
                    "slug": "fixture-theme", "kind": "theme", "boost": 25,
                    "maxBounty": 500, "vendor_contact": "vendor",
                }],
            },
        }
        theme_info = self.plugin("fixture-theme", 5000)
        with patch.object(hunter, "_patchstack_page", return_value=first), \
                patch.object(hunter, "_fetch_wporg_theme_info", return_value=theme_info) as themes, \
                patch.object(hunter, "_fetch_wporg_plugin_info") as plugins, \
                contextlib.redirect_stdout(io.StringIO()):
            results = hunter.collect_patchstack_plugins(
                include_themes=True, api_workers=1, min_updated_years=0,
            )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["asset_kind"], "theme")
        themes.assert_called_once_with("fixture-theme")
        plugins.assert_not_called()

    def test_wordpress_api_requests_are_start_rate_limited(self):
        previous = hunter._WPORG_LAST_REQUEST_AT
        hunter._WPORG_LAST_REQUEST_AT = 10.0
        try:
            with patch.object(hunter.time, "monotonic", side_effect=[10.1, 10.4]), \
                    patch.object(hunter.time, "sleep") as sleep, \
                    patch.object(hunter.requests, "get", return_value="response") as get:
                response = hunter._wporg_get("https://api.wordpress.org/example")
        finally:
            hunter._WPORG_LAST_REQUEST_AT = previous
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
            with patch.object(hunter.requests, "get", return_value=response):
                ok, slug, message = hunter.download_plugin(plugin, str(root))
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
            with patch.object(hunter.requests, "get", return_value=FakeResponse(new_payload)):
                ok, _slug, message = hunter.download_plugin(plugin, str(root))
            self.assertTrue(ok, message)
            self.assertEqual(archive.read_bytes(), new_payload)
            self.assertFalse(list(plugin_dir.glob("*.part")))

    def test_redirect_to_untrusted_host_is_never_requested(self):
        payload = zip_payload()
        plugin = self.plugin(
            "https://downloads.wordpress.org/plugin/fixture-plugin.zip", payload
        )

        def redirect(*_args, **_kwargs):
            return FakeResponse(
                status_code=302,
                headers={"Location": "https://example.invalid/payload.zip"},
            )

        with tempfile.TemporaryDirectory() as temp_name:
            root = hunter._ensure_hunter_root(temp_name)
            with patch.object(hunter.requests, "get", side_effect=redirect) as get, \
                    patch.object(hunter.time, "sleep"):
                ok, _slug, message = hunter.download_plugin(plugin, str(root))
            self.assertFalse(ok)
            self.assertIn("non-WordPress", message)
            self.assertEqual(get.call_count, hunter.DOWNLOAD_MAX_RETRIES)
            self.assertTrue(all(call.args[0].endswith("fixture-plugin.zip") for call in get.call_args_list))
            self.assertTrue(all(call.kwargs["allow_redirects"] is False for call in get.call_args_list))

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

            self.assertEqual(hunter.build_global_slug_index(str(base)), {"valid-plugin"})

    def test_csv_formula_prefix_with_whitespace_is_escaped(self):
        plugin = {
            "name": " \t=CMD()", "slug": "fixture", "version": "1",
            "active_installs": 1000, "downloaded": 0, "last_updated": "",
            "author": "\u00a0+author", "requires": "", "requires_php": "",
            "tested": "", "download_link": "", "homepage": "", "tags": [],
        }
        with tempfile.TemporaryDirectory() as temp_name, \
                contextlib.redirect_stdout(io.StringIO()):
            _json_path, csv_path = hunter.export_results([plugin], temp_name, 1000)
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
            valid, reason = hunter._validate_download_archive(traversal)
            self.assertFalse(valid)
            self.assertIn("traversal", reason)

            collision = root / "collision.zip"
            with zipfile.ZipFile(collision, "w") as archive:
                archive.writestr("Plugin/file.php", "<?php")
                archive.writestr("plugin/FILE.php", "<?php")
            valid, reason = hunter._validate_download_archive(collision)
            self.assertFalse(valid)
            self.assertIn("duplicate", reason)


class CliAndRuleTests(unittest.TestCase):
    def test_semgrep_preflight_falls_back_to_download_only(self):
        with patch.object(hunter, "_find_semgrep", return_value=None), \
                patch.object(hunter, "_ask_choice", return_value="download-only") as choice, \
                contextlib.redirect_stdout(io.StringIO()):
            enabled, executable, rules = hunter._interactive_semgrep_preflight(True)
        self.assertFalse(enabled)
        self.assertIsNone(executable)
        self.assertEqual(Path(rules), hunter.SEMGREP_RULES_DEFAULT)
        self.assertEqual(choice.call_args.args[2], "download-only")

    def test_semgrep_preflight_uses_detected_defaults_without_more_questions(self):
        with patch.object(hunter, "_find_semgrep", return_value="/usr/bin/semgrep"), \
                patch.object(hunter, "_validate_semgrep_config", return_value=(True, "")), \
                patch.object(hunter, "_ask_choice") as choice, \
                patch.object(hunter, "_ask") as ask, \
                contextlib.redirect_stdout(io.StringIO()):
            enabled, executable, rules = hunter._interactive_semgrep_preflight(True)
        self.assertTrue(enabled)
        self.assertIsNone(executable)
        self.assertEqual(Path(rules), hunter.SEMGREP_RULES_DEFAULT.resolve())
        choice.assert_not_called()
        ask.assert_not_called()

    def test_semgrep_preflight_invalid_rules_can_continue_download_only(self):
        with patch.object(hunter, "_find_semgrep", return_value="/usr/bin/semgrep"), \
                patch.object(
                    hunter,
                    "_validate_semgrep_config",
                    return_value=(False, "Rule parse error in wordpress.broken"),
                ), patch.object(
                    hunter, "_ask_choice", return_value="download-only"
                ), contextlib.redirect_stdout(io.StringIO()):
            enabled, executable, rules = hunter._interactive_semgrep_preflight(True)
        self.assertFalse(enabled)
        self.assertIsNone(executable)
        self.assertEqual(Path(rules), hunter.SEMGREP_RULES_DEFAULT)

    def test_semgrep_preflight_accepts_a_custom_executable_path(self):
        with patch.object(
            hunter, "_find_semgrep", side_effect=[None, "/opt/semgrep"]
        ), patch.object(
            hunter, "_ask_choice", return_value="enter-path"
        ), patch.object(
            hunter, "_ask", return_value="/opt/semgrep"
        ), patch.object(
            hunter, "_validate_semgrep_config", return_value=(True, "")
        ), contextlib.redirect_stdout(io.StringIO()):
            enabled, executable, rules = hunter._interactive_semgrep_preflight(False)
        self.assertTrue(enabled)
        self.assertEqual(executable, "/opt/semgrep")
        self.assertEqual(Path(rules), hunter.SEMGREP_RULES_DEFAULT.resolve())

    def test_arrow_menu_selects_without_line_input(self):
        output = io.StringIO()
        with patch.object(hunter, "_menu_keys_supported", return_value=True), \
                patch.object(hunter, "_read_menu_key", side_effect=["down", "enter"]), \
                contextlib.redirect_stdout(output):
            selected = hunter._ask_choice("Action", ["download", "triage"], "download")
        self.assertEqual(selected, "triage")

    def test_arrow_menu_falls_back_when_raw_terminal_read_fails(self):
        with patch.object(hunter, "_menu_keys_supported", return_value=True), \
                patch.object(hunter, "_read_menu_key", return_value="fallback"), \
                patch.object(hunter, "_ask", return_value="triage"), \
                contextlib.redirect_stdout(io.StringIO()):
            selected = hunter._ask_choice("Action", ["download", "triage"], "download")
        self.assertEqual(selected, "triage")

    def test_destructive_choice_defaults_to_no_on_enter(self):
        with patch.object(hunter, "_menu_keys_supported", return_value=False), \
                patch("builtins.input", return_value=""), \
                contextlib.redirect_stdout(io.StringIO()):
            selected = hunter._ask_choice("Delete?", ["no", "yes"], "no")
        self.assertEqual(selected, "no")

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
        self.assertIn("--adopt-output-root", result.stdout)
        self.assertIn("--min-installs", result.stdout)
        old_flag = "--" + "".join(chr(value) for value in (
            116, 97, 105, 110, 116, 45, 115, 99, 97, 110,
        ))
        self.assertNotIn(old_flag, result.stdout)

    def test_default_triage_is_dry_run(self):
        self.assertTrue(__import__("inspect").signature(hunter.run_triage).parameters["dry_run"].default)

    def test_cli_rejects_conflicting_sources_and_invalid_dates(self):
        conflict = subprocess.run(
            [
                sys.executable, str(ROOT / "wp_plugin_hunter.py"),
                "--installs", "1K", "--min-installs", "10K",
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(conflict.returncode, 2)
        invalid_date = subprocess.run(
            [
                sys.executable, str(ROOT / "wp_plugin_hunter.py"),
                "--installs", "1K", "--since", "not-a-date",
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(invalid_date.returncode, 2)

    @unittest.skipUnless(shutil.which("semgrep"), "Semgrep is an optional local dependency")
    def test_repository_rules_match_php_and_javascript_fixtures(self):
        with tempfile.TemporaryDirectory() as temp_name:
            fixture_root = Path(temp_name) / "wordpress-fixtures"
            shutil.copytree(ROOT / "tests" / "fixtures" / "triage", fixture_root)
            engine = hunter.SemgrepEngine(shutil.which("semgrep"), RULES)
            results, status = engine.scan(str(fixture_root), timeout=60, mem_mb=256)
        self.assertEqual(status, "OK")
        checks = {item.get("check_id") for item in results}
        self.assertIn("wordpress.file-write", checks)
        self.assertIn("wordpress.sql-wpdb", checks)
        self.assertIn("wordpress.ajax-nopriv-entrypoint", checks)
        self.assertIn("wordpress.rest-route", checks)
        self.assertIn("wordpress.rest-permissive-route", checks)
        self.assertIn("wordpress.user-update", checks)
        self.assertIn("wordpress.php-dangerous-execution", checks)
        self.assertIn("wordpress.js-dom-xss", checks)


if __name__ == "__main__":
    unittest.main()
