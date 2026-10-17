import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wp_hunter import schedule
from wp_hunter.bot import BotError, TelegramBot, parse_command
from wp_hunter.i18n import set_language
from wp_hunter.notifiers import NotificationResult
from wp_hunter.watch import PluginUpdate, WatchReport
from wp_hunter.watch_state import WatchState


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload
        self.status_code = 200

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class FakeNotifier:
    def __init__(self):
        self.sent = []

    def send(self, text):
        self.sent.append(text)
        return NotificationResult(delivered=1)


def make_update(update_id, chat_id, text):
    return {"update_id": update_id, "message": {"chat": {"id": chat_id}, "text": text}}


class ParseCommandTests(unittest.TestCase):
    def test_commands_and_mentions(self):
        self.assertEqual(parse_command("/time"), ("time", []))
        self.assertEqual(parse_command("/time 2h"), ("time", ["2h"]))
        self.assertEqual(parse_command("/time@igpotpot_bot 30m"), ("time", ["30m"]))
        self.assertEqual(parse_command("  /HELP "), ("help", []))

    def test_plain_text_is_not_a_command(self):
        self.assertEqual(parse_command("time 2h"), ("", []))
        self.assertEqual(parse_command(""), ("", []))


class BotTestCase(unittest.TestCase):
    def setUp(self):
        set_language("en")
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.config_path = base / "cfg" / "config.json"
        self.state_path = base / "watch_state.json"
        self.offset_path = base / "bot_offset.json"
        self.notifier = FakeNotifier()
        self.bot = TelegramBot(
            "token",
            "42",
            config_path=self.config_path,
            state_path=self.state_path,
            offset_path=self.offset_path,
            notifier=self.notifier,
        )

    def tearDown(self):
        self._tmp.cleanup()


class CommandTests(BotTestCase):
    def test_time_without_arguments_reports_the_current_interval(self):
        reply = self.bot.handle("/time")
        self.assertIn("Current interval: 1h", reply)

    def test_time_changes_the_config_and_rearms_the_timer(self):
        with (
            patch("wp_hunter.bot.os.geteuid", return_value=0),
            patch.object(schedule, "install_timer", return_value=[]) as install,
        ):
            reply = self.bot.handle("/time 2h")
        self.assertIn("2h", reply)
        install.assert_called_once_with(7200, limit=None)
        saved = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertEqual(saved["defaults"]["watch_every"], "2h")

    def test_time_without_root_only_saves_the_config(self):
        with (
            patch("wp_hunter.bot.os.geteuid", return_value=1000),
            patch.object(schedule, "install_timer") as install,
        ):
            reply = self.bot.handle("/time 45m")
        install.assert_not_called()
        self.assertIn("45m", reply)
        self.assertIn("sudo", reply)

    def test_time_rejects_invalid_values(self):
        reply = self.bot.handle("/time soon")
        self.assertIn("Invalid interval", reply)

    def test_status_reports_tracked_plugins_and_timer(self):
        state = WatchState(self.state_path)
        state.record("elementor", "4.3.4", "2026-10-17 09:00am GMT")
        state.record("wordpress-seo", "28.7")
        state.save()
        with patch("wp_hunter.bot.timer_state", return_value=("active", "Sat 17:19")):
            reply = self.bot.handle("/status")
        self.assertIn("Plugins tracked: 2", reply)
        self.assertIn("active", reply)
        self.assertIn("1h", reply)

    def test_run_returns_the_digest_with_links(self):
        report = WatchReport(
            checked=100,
            updated=[
                PluginUpdate(
                    slug="elementor",
                    name="Elementor",
                    old_version="4.3.3",
                    new_version="4.3.4",
                    last_updated="2026-10-15 11:40am GMT",
                    active_installs=10_000_000,
                )
            ],
        )
        bot = TelegramBot(
            "token",
            "42",
            config_path=self.config_path,
            state_path=self.state_path,
            offset_path=self.offset_path,
            notifier=self.notifier,
            watch_runner=lambda **_kwargs: (report, None),
        )
        with patch("wp_hunter.bot.watcher_busy", return_value=False):
            reply = bot.handle("/run")
        self.assertEqual(self.notifier.sent, ["Checking now…"])
        self.assertIn("https://wordpress.org/plugins/elementor/", reply)

    def test_run_refuses_while_a_scheduled_pass_is_running(self):
        with patch("wp_hunter.bot.watcher_busy", return_value=True):
            reply = self.bot.handle("/run")
        self.assertIn("scheduled check", reply)

    def test_help_and_unknown_commands(self):
        self.assertIn("/time", self.bot.handle("/help"))
        self.assertIn("Unknown command", self.bot.handle("/nope"))
        self.assertEqual(self.bot.handle("just text"), "")


class PollingTests(BotTestCase):
    def _bot_with_updates(self, updates):
        calls = []

        def fake_get(url, params=None, timeout=None):
            calls.append(params)
            return FakeResponse({"ok": True, "result": updates})

        bot = TelegramBot(
            "token",
            "42",
            config_path=self.config_path,
            state_path=self.state_path,
            offset_path=self.offset_path,
            notifier=self.notifier,
            api_get=fake_get,
        )
        return bot, calls

    def test_only_the_configured_chat_is_answered(self):
        updates = [
            make_update(10, 999, "/time"),
            make_update(11, 42, "/time"),
        ]
        bot, _calls = self._bot_with_updates(updates)
        handled, offset = bot.poll_once(None)
        self.assertEqual(handled, 1)
        self.assertEqual(offset, 12)
        self.assertEqual(len(self.notifier.sent), 1)
        self.assertIn("Current interval", self.notifier.sent[0])

    def test_offset_is_persisted_after_each_update(self):
        bot, _calls = self._bot_with_updates([make_update(7, 42, "/time")])
        bot.poll_once(None)
        self.assertEqual(json.loads(self.offset_path.read_text())["offset"], 8)

    def test_drain_skips_queued_commands(self):
        bot, _calls = self._bot_with_updates([make_update(3, 42, "/run")])
        offset = bot.drain()
        self.assertEqual(offset, 4)
        self.assertEqual(self.notifier.sent, [])

    def test_api_failure_is_reported(self):
        def failing(_url, params=None, timeout=None):
            raise OSError("no network")

        bot = TelegramBot(
            "token",
            "42",
            config_path=self.config_path,
            offset_path=self.offset_path,
            notifier=self.notifier,
            api_get=failing,
        )
        with self.assertRaises(BotError):
            bot.poll_once(None)

    def test_api_errors_never_echo_the_token(self):
        def failing(_url, params=None, timeout=None):
            raise OSError(
                "401 Client Error for url: "
                "https://api.telegram.org/botsuper-secret-token/getUpdates"
            )

        bot = TelegramBot(
            "super-secret-token",
            "42",
            config_path=self.config_path,
            offset_path=self.offset_path,
            notifier=self.notifier,
            api_get=failing,
        )
        with self.assertRaises(BotError) as ctx:
            bot.poll_once(None)
        self.assertNotIn("super-secret-token", str(ctx.exception))
        self.assertIn("<token>", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
