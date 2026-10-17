import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wp_hunter import schedule


class ParseDurationTests(unittest.TestCase):
    def test_minutes_hours_and_combinations(self):
        cases = {
            "30m": 1800,
            "2h": 7200,
            "1h30m": 5400,
            "90": 5400,
            "90s": 90,
            " 2 H ": 7200,
            "1d": 86400,
            45: 2700,
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(schedule.parse_duration(value), expected)

    def test_invalid_values_are_rejected(self):
        for value in ("", "abc", "30x", "1.5h", "0", "30s", "8d", None, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                schedule.parse_duration(value)


class FormatDurationTests(unittest.TestCase):
    def test_shapes(self):
        cases = {
            3600: "1h",
            5400: "1h30m",
            90: "1m30s",
            86400: "1d",
            60: "1m",
            45: "45s",
            0: "0s",
        }
        for seconds, expected in cases.items():
            with self.subTest(seconds=seconds):
                self.assertEqual(schedule.format_duration(seconds), expected)


class ResolveIntervalTests(unittest.TestCase):
    def test_every_wins_over_interval_and_config(self):
        self.assertEqual(schedule.resolve_interval("2h", 300, {"watch_every": "5m"}), 7200)

    def test_legacy_seconds_used_when_every_is_absent(self):
        self.assertEqual(schedule.resolve_interval(None, 300, {"watch_every": "5m"}), 300)

    def test_config_default_is_used_last(self):
        self.assertEqual(schedule.resolve_interval(None, None, {"watch_every": "45m"}), 2700)

    def test_missing_config_falls_back_to_one_hour(self):
        self.assertEqual(schedule.resolve_interval(None, None, {}), 3600)

    def test_invalid_config_value_is_reported(self):
        with self.assertRaises(ValueError):
            schedule.resolve_interval(None, None, {"watch_every": "soon"})


class RenderTests(unittest.TestCase):
    def test_timer_uses_the_requested_interval(self):
        text = schedule.render_timer(5400)
        self.assertIn("OnUnitActiveSec=90min", text)
        self.assertIn("every 1h30m", text)
        self.assertIn("WantedBy=timers.target", text)

    def test_timer_uses_hours_when_it_divides_evenly(self):
        self.assertIn("OnUnitActiveSec=2h", schedule.render_timer(7200))

    def test_service_points_at_the_env_file_and_limit(self):
        text = schedule.render_service(
            25,
            exec_path="/usr/local/bin/wp-hunter",
            env_file=Path("/etc/wp-hunter/watch.env"),
        )
        self.assertIn("EnvironmentFile=/etc/wp-hunter/watch.env", text)
        self.assertIn("ExecStart=/usr/local/bin/wp-hunter watch --limit 25", text)

    def test_watcher_unit_is_hardened(self):
        text = schedule.render_service(10, exec_path="/usr/bin/wp-hunter")
        self.assertIn("NoNewPrivileges=true", text)
        self.assertIn("PrivateTmp=true", text)
        self.assertIn("ProtectSystem=strict", text)
        self.assertIn("ProtectHome=read-only", text)
        self.assertIn("ReadWritePaths=-", text)

    def test_bot_unit_keeps_unit_management_working(self):
        text = schedule.render_bot_service(exec_path="/usr/bin/wp-hunter")
        self.assertIn("NoNewPrivileges=true", text)
        # The bot rewrites /etc/systemd/system on /time, so no ProtectSystem here.
        self.assertNotIn("ProtectSystem=strict", text)


class InstallTimerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.units = self.base / "systemd"
        self.units.mkdir()
        self.env = self.base / "wp-hunter" / "watch.env"
        self.calls = []

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, command, **_kwargs):
        self.calls.append(command)
        return type("Result", (), {"returncode": 0, "stderr": ""})()

    def test_requires_root(self):
        with (
            patch.object(schedule.os, "geteuid", return_value=1000),
            self.assertRaises(ValueError),
        ):
            schedule.install_timer(3600, unit_dir=self.units, env_file=self.env, run=self._run)

    def test_writes_units_env_file_and_arms_timer(self):
        with patch.object(schedule.os, "geteuid", return_value=0):
            actions = schedule.install_timer(
                7200, limit=10, unit_dir=self.units, env_file=self.env, run=self._run
            )
        timer = (self.units / schedule.TIMER_UNIT).read_text(encoding="utf-8")
        service = (self.units / schedule.SERVICE_UNIT).read_text(encoding="utf-8")
        self.assertIn("OnUnitActiveSec=2h", timer)
        self.assertIn("--limit 10", service)
        self.assertTrue(self.env.exists())
        self.assertEqual(oct(self.env.stat().st_mode)[-3:], "600")
        self.assertEqual(
            self.calls,
            [
                ["systemctl", "daemon-reload"],
                ["systemctl", "enable", schedule.TIMER_UNIT],
                ["systemctl", "restart", schedule.TIMER_UNIT],
            ],
        )
        self.assertTrue(any("created" in action for action in actions))

    def test_reinstall_with_new_interval_backs_up_and_rewrites(self):
        with patch.object(schedule.os, "geteuid", return_value=0):
            schedule.install_timer(3600, unit_dir=self.units, env_file=self.env, run=self._run)
            actions = schedule.install_timer(
                7200, unit_dir=self.units, env_file=self.env, run=self._run
            )
        backup = self.units / (schedule.TIMER_UNIT + ".bak")
        self.assertTrue(backup.exists())
        self.assertIn("OnUnitActiveSec=1h", backup.read_text(encoding="utf-8"))
        self.assertIn(
            "OnUnitActiveSec=2h",
            (self.units / schedule.TIMER_UNIT).read_text(encoding="utf-8"),
        )
        self.assertTrue(any("backed up" in action for action in actions))

    def test_systemctl_failure_is_reported(self):
        def failing(_command, **_kwargs):
            return type("Result", (), {"returncode": 1, "stderr": "no systemd"})()

        with (
            patch.object(schedule.os, "geteuid", return_value=0),
            self.assertRaises(ValueError) as ctx,
        ):
            schedule.install_timer(3600, unit_dir=self.units, env_file=self.env, run=failing)
        self.assertIn("daemon-reload", str(ctx.exception))

    def test_existing_env_file_is_never_overwritten(self):
        self.env.parent.mkdir(parents=True)
        self.env.write_text("TELEGRAM_BOT_TOKEN=secret\n", encoding="utf-8")
        with patch.object(schedule.os, "geteuid", return_value=0):
            schedule.install_timer(3600, unit_dir=self.units, env_file=self.env, run=self._run)
        self.assertEqual(self.env.read_text(encoding="utf-8"), "TELEGRAM_BOT_TOKEN=secret\n")


if __name__ == "__main__":
    unittest.main()
