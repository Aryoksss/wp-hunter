import json
import os
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from typer.testing import CliRunner

from wp_hunter.cli import app
from wp_hunter.config import default_config, load_config, save_config
from wp_hunter.migration import migrate_triage_result
from wp_hunter.models import DownloadOptions
from wp_hunter.services import DownloadResult
from wp_hunter.state import DownloadManifest, ReviewLedger


class StateMigrationTests(unittest.TestCase):
    def test_manifest_v1_migrates_to_v2_without_backup(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            path = root / "downloaded_slugs.json"
            path.write_text(
                json.dumps({"fixture": {"filename": "fixture.zip", "version": "1.0"}}),
                encoding="utf-8",
            )
            manifest = DownloadManifest(root)
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(manifest.count(), 1)
            self.assertEqual(payload["schema_version"], 2)
            self.assertIn("fixture", payload["plugins"])
            self.assertFalse(any(root.glob("*.bak")))

    def test_review_ledger_v2_open_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            path = root / "reviewed_slugs.json"
            payload = {
                "schema_version": 2,
                "updated_at": "2026-01-01T00:00:00+00:00",
                "plugins": {"fixture": {"version": "1.0"}},
            }
            original = json.dumps(payload, indent=2)
            path.write_text(original, encoding="utf-8")
            ledger = ReviewLedger(root)
            self.assertEqual(ledger.count(), 1)
            self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_invalid_manifest_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            path = root / "downloaded_slugs.json"
            path.write_text("{invalid", encoding="utf-8")
            with self.assertRaises(ValueError):
                DownloadManifest(root)
            self.assertEqual(path.read_text(encoding="utf-8"), "{invalid")

    def test_failed_migration_replace_leaves_v1_intact(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            path = root / "downloaded_slugs.json"
            original = json.dumps({"fixture": {"version": "1.0"}})
            path.write_text(original, encoding="utf-8")
            with (
                patch("wp_hunter.state.os.replace", side_effect=OSError("blocked")),
                self.assertRaises(OSError),
            ):
                DownloadManifest(root)
            self.assertEqual(path.read_text(encoding="utf-8"), original)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_symlink_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            outside = root / "outside.json"
            outside.write_text("{}", encoding="utf-8")
            (root / "downloaded_slugs.json").symlink_to(outside)
            with self.assertRaises(ValueError):
                DownloadManifest(root)

    def test_corrupt_triage_result_is_not_rewritten(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            path = root / "triage_results.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(ValueError):
                migrate_triage_result(root)
            self.assertEqual(path.read_text(encoding="utf-8"), "[]")


class V2CliTests(unittest.TestCase):
    def test_interactive_wporg_menu_passes_download_limit(self):
        with tempfile.TemporaryDirectory() as temp_name:
            save_config(default_config(), Path(temp_name) / "config.json")
            selection = SimpleNamespace(ask=lambda: "wporg")
            install_tier = SimpleNamespace(ask=lambda: "1K")
            download_limit = SimpleNamespace(ask=lambda: "250")
            minimum = SimpleNamespace(ask=lambda: False)
            preview = SimpleNamespace(ask=lambda: True)
            with (
                patch("wp_hunter.cli.questionary.select", return_value=selection),
                patch(
                    "wp_hunter.cli.questionary.text",
                    side_effect=[install_tier, download_limit],
                ),
                patch(
                    "wp_hunter.cli.questionary.confirm",
                    side_effect=[minimum, preview],
                ),
                patch("wp_hunter.cli._run_download") as run_download,
            ):
                result = CliRunner().invoke(app, [], env={"WP_HUNTER_CONFIG_DIR": temp_name})

        self.assertEqual(result.exit_code, 0, result.output)
        options = run_download.call_args.args[1]
        self.assertEqual(options.limit, 250)
        self.assertTrue(options.preview)

    def test_config_can_persist_download_limit(self):
        with tempfile.TemporaryDirectory() as temp_name:
            result = CliRunner().invoke(
                app,
                ["config", "set", "download_limit", "500"],
                env={"WP_HUNTER_CONFIG_DIR": temp_name},
            )
            invalid = CliRunner().invoke(
                app,
                ["config", "set", "download_limit", "-1"],
                env={"WP_HUNTER_CONFIG_DIR": temp_name},
            )
            config = load_config(Path(temp_name) / "config.json")

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(config["defaults"]["download_limit"], 500)
        self.assertEqual(invalid.exit_code, 2, invalid.output)

    def test_replacing_user_preset_requires_confirmation(self):
        with tempfile.TemporaryDirectory() as temp_name:
            config_file = Path(temp_name) / "config.json"
            config = default_config()
            config["presets"]["targets"] = {"source": "wporg", "installs": "10K"}
            save_config(config, config_file)
            root = Path(temp_name) / "output"
            download_result = DownloadResult(root=root, collected=0, selected=0, reviewed_skipped=0)
            arguments = [
                "download",
                "wporg",
                "--installs",
                "50K",
                "--preview",
                "--output",
                str(root),
                "--save-preset",
                "targets",
                "--replace-preset",
            ]
            with patch("wp_hunter.cli.execute_download", return_value=download_result):
                cancelled = CliRunner().invoke(
                    app,
                    arguments,
                    input="n\n",
                    env={"WP_HUNTER_CONFIG_DIR": temp_name},
                )
                accepted = CliRunner().invoke(
                    app,
                    arguments,
                    input="y\n",
                    env={"WP_HUNTER_CONFIG_DIR": temp_name},
                )

            preset = load_config(config_file)["presets"]["targets"]
        self.assertEqual(cancelled.exit_code, 0, cancelled.output)
        self.assertIn("Cancelled", cancelled.output)
        self.assertEqual(accepted.exit_code, 0, accepted.output)
        self.assertEqual(preset["installs"], "50K")

    def test_save_preset_option_persists_only_safe_fields(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name) / "output"
            result = DownloadResult(root=root, collected=0, selected=0, reviewed_skipped=0)
            with patch("wp_hunter.cli.execute_download", return_value=result):
                invocation = CliRunner().invoke(
                    app,
                    [
                        "download",
                        "wporg",
                        "--preview",
                        "--force",
                        "--save-preset",
                        "my-targets",
                        "--output",
                        str(root),
                    ],
                    env={"WP_HUNTER_CONFIG_DIR": temp_name},
                )
            self.assertEqual(invocation.exit_code, 0, invocation.output)
            preset = load_config(Path(temp_name) / "config.json")["presets"]["my-targets"]
            self.assertEqual(preset["source"], "wporg")
            self.assertNotIn("force", preset)
            self.assertNotIn("preview", preset)

    def test_no_argument_first_run_persists_language(self):
        first = SimpleNamespace(ask=lambda: "id")
        second = SimpleNamespace(ask=lambda: "exit")
        with (
            tempfile.TemporaryDirectory() as temp_name,
            patch("wp_hunter.cli.questionary.select", side_effect=[first, second]),
        ):
            result = CliRunner().invoke(app, [], env={"WP_HUNTER_CONFIG_DIR": temp_name})
            config = load_config(Path(temp_name) / "config.json")
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(config["language"], "id")
        self.assertIn("Toolkit riset", result.output)

    def test_global_language_override_does_not_mutate_config(self):
        with tempfile.TemporaryDirectory() as temp_name:
            CliRunner().invoke(
                app,
                ["config", "set", "language", "en"],
                env={"WP_HUNTER_CONFIG_DIR": temp_name},
            )
            result = CliRunner().invoke(
                app,
                ["--lang", "id", "status"],
                env={"WP_HUNTER_CONFIG_DIR": temp_name},
            )
            config = load_config(Path(temp_name) / "config.json")
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Belum ada", result.output)
        self.assertEqual(config["language"], "en")

    def test_preset_values_exclude_destructive_controls(self):
        values = DownloadOptions(
            source="wporg",
            force=True,
            reset_cache=True,
            adopt_existing=True,
            preview=True,
        ).preset_values()
        self.assertNotIn("force", values)
        self.assertNotIn("reset_cache", values)
        self.assertNotIn("adopt_existing", values)
        self.assertNotIn("preview", values)

    def test_packaged_resources_are_available(self):
        rules = files("wp_hunter.resources").joinpath("wordpress-triage.yml")
        english = files("wp_hunter.resources.locales").joinpath("en.json")
        indonesian = files("wp_hunter.resources.locales").joinpath("id.json")
        self.assertTrue(rules.is_file())
        self.assertTrue(english.is_file())
        self.assertTrue(indonesian.is_file())


if __name__ == "__main__":
    unittest.main()
