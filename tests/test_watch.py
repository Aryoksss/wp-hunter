import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wp_hunter.notifiers import (
    TELEGRAM_CHAT_ID_ENV,
    TELEGRAM_TOKEN_ENV,
    TelegramNotifier,
    _split_message,
)
from wp_hunter.vulndb import ScanOutcome, Vulnerability, WpscanClient
from wp_hunter.watch import run_watch
from wp_hunter.watch_state import WatchState


class WatchStateTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "watch_state.json"

    def tearDown(self):
        self._tmp.cleanup()

    def test_missing_state_starts_empty(self):
        state = WatchState(self.path)
        self.assertIsNone(state.get_version("elementor"))
        self.assertEqual(state.count(), 0)

    def test_record_and_reload_round_trip(self):
        state = WatchState(self.path)
        state.record("elementor", "4.3.4", "2026-10-05 12:50pm GMT")
        state.save()

        reloaded = WatchState(self.path)
        self.assertEqual(reloaded.get_version("elementor"), "4.3.4")
        self.assertEqual(reloaded.count(), 1)

    def test_record_overwrites_previous_version(self):
        state = WatchState(self.path)
        state.record("elementor", "4.0.0")
        state.record("elementor", "4.3.4")
        self.assertEqual(state.get_version("elementor"), "4.3.4")

    def test_remove_missing_drops_unseen_slugs(self):
        state = WatchState(self.path)
        state.record("keep", "1.0")
        state.record("drop", "1.0")
        removed = state.remove_missing({"keep"})
        self.assertEqual(removed, 1)
        self.assertIsNone(state.get_version("drop"))
        self.assertEqual(state.get_version("keep"), "1.0")

    def test_save_creates_missing_parent_directory(self):
        nested = Path(self._tmp.name) / "a" / "b" / "watch_state.json"
        state = WatchState(nested)
        state.record("elementor", "4.3.4")
        state.save()
        self.assertTrue(nested.is_file())

    def test_symlink_state_is_rejected(self):
        target = Path(self._tmp.name) / "real.json"
        target.write_text("{}", encoding="utf-8")
        link = Path(self._tmp.name) / "link.json"
        link.symlink_to(target)
        state = WatchState(link)
        with self.assertRaises(ValueError):
            state.get_version("elementor")

    def test_invalid_json_is_rejected(self):
        self.path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(ValueError):
            WatchState(self.path).get_version("elementor")

    def test_unsupported_schema_is_rejected(self):
        self.path.write_text(json.dumps({"schema_version": 99, "plugins": {}}), encoding="utf-8")
        with self.assertRaises(ValueError):
            WatchState(self.path).get_version("elementor")


class TelegramNotifierTests(unittest.TestCase):
    def test_unconfigured_reports_skipped_reason(self):
        with patch.dict(os.environ, {}, clear=True):
            notifier = TelegramNotifier()
            result = notifier.send("hello")
        self.assertIsNotNone(result.skipped_reason)
        self.assertIn(TELEGRAM_TOKEN_ENV, result.skipped_reason)
        self.assertEqual(result.delivered, 0)

    def test_env_variables_configure_notifier(self):
        env = {TELEGRAM_TOKEN_ENV: "tok", TELEGRAM_CHAT_ID_ENV: "42"}
        with patch.dict(os.environ, env, clear=True):
            self.assertTrue(TelegramNotifier().configured)

    def test_send_posts_to_telegram(self):
        notifier = TelegramNotifier(token="tok", chat_id="42")
        with patch("wp_hunter.notifiers.httpclient.post") as post:
            post.return_value.status_code = 200
            result = notifier.send("update")
        self.assertTrue(result.ok)
        self.assertEqual(result.delivered, 1)
        _, kwargs = post.call_args
        self.assertEqual(kwargs["json"]["chat_id"], "42")

    def test_http_error_is_captured(self):
        notifier = TelegramNotifier(token="tok", chat_id="42")
        with patch("wp_hunter.notifiers.httpclient.post") as post:
            post.return_value.status_code = 401
            post.return_value.json.return_value = {"description": "Unauthorized"}
            result = notifier.send("update")
        self.assertFalse(result.ok)
        self.assertIn("401", result.errors[0])

    def test_network_error_does_not_raise(self):
        notifier = TelegramNotifier(token="tok", chat_id="42")
        with patch("wp_hunter.notifiers.httpclient.post", side_effect=OSError("boom")):
            result = notifier.send("update")
        self.assertFalse(result.ok)
        self.assertEqual(len(result.errors), 1)

    def test_long_message_is_split_under_limit(self):
        chunks = _split_message("x" * 9000)
        self.assertGreater(len(chunks), 1)
        for chunk in chunks:
            self.assertLessEqual(len(chunk), 4096)


class WatchRunnerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "state.json"
        self.page = {
            "info": {"pages": 1, "results": 2},
            "plugins": [
                {
                    "slug": "elementor",
                    "name": "Elementor",
                    "version": "4.3.4",
                    "active_installs": 10_000_000,
                    "last_updated": "2026-10-05",
                },
                {
                    "slug": "wordpress-seo",
                    "name": "Yoast",
                    "version": "28.7",
                    "active_installs": 5_000_000,
                    "last_updated": "2026-10-04",
                },
            ],
        }

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, **kwargs):
        with (
            patch("wp_hunter.watch.http.query_plugins_page", return_value=self.page),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            return run_watch(state=WatchState(self.path), notify=False, **kwargs)

    def test_first_run_records_without_reports(self):
        report, result = self._run(max_pages=1)
        self.assertEqual(report.checked, 2)
        self.assertEqual(report.new_plugins, 2)
        self.assertFalse(report.has_changes)
        self.assertIsNone(result)
        self.assertEqual(WatchState(self.path).get_version("elementor"), "4.3.4")

    def test_newer_version_is_reported(self):
        state = WatchState(self.path)
        state.record("elementor", "4.0.0")
        state.save()
        with contextlib.redirect_stderr(io.StringIO()):
            report, _ = self._run(max_pages=1)
        self.assertEqual(len(report.updated), 1)
        self.assertEqual(report.updated[0].slug, "elementor")
        self.assertEqual(report.updated[0].old_version, "4.0.0")
        self.assertEqual(report.updated[0].new_version, "4.3.4")

    def test_unchanged_version_is_not_reported(self):
        state = WatchState(self.path)
        state.record("elementor", "4.3.4")
        state.record("wordpress-seo", "28.7")
        state.save()
        report, _ = self._run(max_pages=1)
        self.assertFalse(report.has_changes)

    def test_dry_run_does_not_write_state(self):
        self._run(max_pages=1, dry_run=True)
        self.assertFalse(self.path.exists())

    def test_updates_sorted_by_installs(self):
        state = WatchState(self.path)
        state.record("elementor", "1.0.0")
        state.record("wordpress-seo", "1.0.0")
        state.save()
        with contextlib.redirect_stderr(io.StringIO()):
            report, _ = self._run(max_pages=1)
        self.assertEqual([u.slug for u in report.updated], ["elementor", "wordpress-seo"])

    def test_failed_page_is_counted(self):
        with patch("wp_hunter.watch.http.query_plugins_page", return_value=None):
            report, _ = run_watch(state=WatchState(self.path), max_pages=1, notify=False)
        self.assertEqual(report.failed_pages, 1)
        self.assertEqual(report.checked, 0)

    def test_html_entities_are_not_double_escaped(self):
        self.page["plugins"][0]["name"] = "Elementor &#8211; builder"
        state = WatchState(self.path)
        state.record("elementor", "1.0.0")
        state.save()
        notifier = TelegramNotifier(token="t", chat_id="1")
        with (
            patch("wp_hunter.watch.http.query_plugins_page", return_value=self.page),
            patch("wp_hunter.notifiers.httpclient.post") as post,
        ):
            post.return_value.status_code = 200
            with contextlib.redirect_stderr(io.StringIO()):
                run_watch(state=WatchState(self.path), max_pages=1, notifier=notifier)
        text = post.call_args.kwargs["json"]["text"]
        self.assertIn("–", text)
        self.assertNotIn("&amp;#8211;", text)


class WatchVulnerabilityTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "watch_state.json"
        self.page = {
            "plugins": [
                {
                    "slug": "elementor",
                    "name": "Elementor",
                    "version": "3.5.0",
                    "active_installs": 10_000_000,
                    "last_updated": "2026-10-01",
                }
            ],
            "info": {"pages": 1},
        }

    def tearDown(self):
        self._tmp.cleanup()

    def _client_with(self, outcome: ScanOutcome) -> WpscanClient:
        client = WpscanClient(token="tok")
        client.scan = lambda slug, version: outcome  # type: ignore[method-assign]
        return client

    def test_vulnerable_plugin_enters_report_and_message(self):
        outcome = ScanOutcome(
            slug="elementor",
            vulnerabilities=[
                Vulnerability("1", "Stored XSS", "XSS", "", 4.1, True),
            ],
        )
        notifier = TelegramNotifier(token="t", chat_id="1")
        with (
            patch("wp_hunter.watch.http.query_plugins_page", return_value=self.page),
            patch("wp_hunter.notifiers.httpclient.post") as post,
        ):
            post.return_value.status_code = 200
            with contextlib.redirect_stderr(io.StringIO()):
                report, _ = run_watch(
                    state=WatchState(self.path),
                    max_pages=1,
                    notifier=notifier,
                    check_vulnerabilities=True,
                    vuln_client=self._client_with(outcome),
                )
        self.assertEqual([v.slug for v in report.vulnerable], ["elementor"])
        self.assertTrue(report.has_changes)
        text = post.call_args.kwargs["json"]["text"]
        self.assertIn("Stored XSS", text)
        self.assertIn("CVSS 4.1", text)

    def test_vuln_errors_are_collected(self):
        outcome = ScanOutcome(slug="elementor", error="HTTP 500")
        with (
            patch("wp_hunter.watch.http.query_plugins_page", return_value=self.page),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            report, _ = run_watch(
                state=WatchState(self.path),
                max_pages=1,
                notify=False,
                check_vulnerabilities=True,
                vuln_client=self._client_with(outcome),
            )
        self.assertEqual(report.vuln_errors, ["elementor: HTTP 500"])
        self.assertEqual(report.vulnerable, [])

    def test_unconfigured_vuln_client_warns(self):
        with patch.dict("os.environ", {}, clear=True):
            client = WpscanClient()
        stderr = io.StringIO()
        with (
            patch("wp_hunter.watch.http.query_plugins_page", return_value=self.page),
            contextlib.redirect_stderr(stderr),
        ):
            run_watch(
                state=WatchState(self.path),
                max_pages=1,
                notify=False,
                check_vulnerabilities=True,
                vuln_client=client,
            )
        self.assertIn("WPSCAN_API_TOKEN", stderr.getvalue())


class WatchDaemonSignalTests(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("WP_HUNTER_NETWORK_TESTS") == "1", "set WP_HUNTER_NETWORK_TESTS=1"
    )
    def test_sigterm_stops_daemon_cleanly(self):
        import signal
        import subprocess
        import sys
        import time

        project_root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmp:
            env = {**os.environ, "WP_HUNTER_CONFIG_DIR": tmp, "PYTHONPATH": str(project_root)}
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "wp_hunter",
                    "watch",
                    "--limit",
                    "1",
                    "--no-notify",
                    "--daemon",
                    "--interval",
                    "300",
                ],
                cwd=str(project_root),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                time.sleep(45)
                if process.poll() is not None:
                    self.skipTest("daemon exited before signal delivery")
                process.send_signal(signal.SIGTERM)
                process.wait(timeout=15)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
        self.assertEqual(process.returncode, 0)


if __name__ == "__main__":
    unittest.main()
