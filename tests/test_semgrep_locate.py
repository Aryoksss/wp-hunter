import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wp_hunter import semgrep_locate


class FindSemgrepTests(unittest.TestCase):
    def test_explicit_valid_executable_is_returned(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "semgrep"
            exe.write_text("#!/bin/sh\n")
            exe.chmod(0o755)
            self.assertEqual(semgrep_locate.find_semgrep(str(exe)), str(exe))

    def test_explicit_missing_prints_error_and_returns_none(self):
        with patch("sys.stderr") as stderr:
            result = semgrep_locate.find_semgrep("/no/such/semgrep")
        self.assertIsNone(result)
        self.assertTrue(stderr.write.called)

    def test_explicit_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "real"
            real.write_text("#!/bin/sh\n")
            real.chmod(0o755)
            link = Path(tmp) / "link"
            link.symlink_to(real)
            with patch("sys.stderr"):
                self.assertIsNone(semgrep_locate.find_semgrep(str(link)))

    def test_explicit_non_executable_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "semgrep"
            exe.write_text("data")
            exe.chmod(0o644)
            with patch("sys.stderr"):
                self.assertIsNone(semgrep_locate.find_semgrep(str(exe)))

    def test_falls_back_to_path_lookup(self):
        with patch.object(semgrep_locate.shutil, "which", side_effect=["/usr/bin/semgrep", None]):
            self.assertEqual(semgrep_locate.find_semgrep(None), "/usr/bin/semgrep")

    def test_returns_none_when_not_on_path(self):
        with patch.object(semgrep_locate.shutil, "which", return_value=None):
            self.assertIsNone(semgrep_locate.find_semgrep(None))


class TextHelperTests(unittest.TestCase):
    def test_indent_lines_prefixes_every_line(self):
        self.assertEqual(semgrep_locate.indent_lines("a\nb", "> "), "> a\n> b")

    def test_indent_lines_handles_empty(self):
        self.assertEqual(semgrep_locate.indent_lines("", "> "), "")

    def test_install_hint_mentions_pipx(self):
        self.assertIn("pipx install semgrep", semgrep_locate.semgrep_install_hint())


class SemgrepOrExitTests(unittest.TestCase):
    def test_missing_semgrep_exits_one(self):
        with (
            patch.object(semgrep_locate, "find_semgrep", return_value=None),
            patch("sys.stderr"),
            self.assertRaises(SystemExit) as ctx,
        ):
            semgrep_locate.semgrep_or_exit(None)
        self.assertEqual(ctx.exception.code, 1)

    def test_missing_rules_exits_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "nope.yml"
            with (
                patch.object(semgrep_locate, "find_semgrep", return_value="/usr/bin/semgrep"),
                patch("sys.stderr"),
                self.assertRaises(SystemExit) as ctx,
            ):
                semgrep_locate.semgrep_or_exit("/usr/bin/semgrep", str(missing))
        self.assertEqual(ctx.exception.code, 1)

    def test_symlinked_rules_exit_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "real.yml"
            real.write_text("rules: []")
            link = Path(tmp) / "link.yml"
            link.symlink_to(real)
            with (
                patch.object(semgrep_locate, "find_semgrep", return_value="/usr/bin/semgrep"),
                patch("sys.stderr"),
                self.assertRaises(SystemExit) as ctx,
            ):
                semgrep_locate.semgrep_or_exit("/usr/bin/semgrep", str(link))
        self.assertEqual(ctx.exception.code, 1)

    def test_invalid_rules_exit_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "rules.yml"
            rules.write_text("rules: []")
            with (
                patch.object(semgrep_locate, "find_semgrep", return_value="/usr/bin/semgrep"),
                patch.object(
                    semgrep_locate, "_validate_semgrep_config", return_value=(False, "bad config")
                ),
                patch("sys.stderr"),
                self.assertRaises(SystemExit) as ctx,
            ):
                semgrep_locate.semgrep_or_exit("/usr/bin/semgrep", str(rules))
        self.assertEqual(ctx.exception.code, 1)

    def test_success_returns_semgrep_and_resolved_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "rules.yml"
            rules.write_text("rules: []")
            with (
                patch.object(semgrep_locate, "find_semgrep", return_value="/usr/bin/semgrep"),
                patch.object(semgrep_locate, "_validate_semgrep_config", return_value=(True, "")),
            ):
                sg, resolved = semgrep_locate.semgrep_or_exit(
                    "/usr/bin/semgrep", str(rules), validate_rules=True
                )
        self.assertEqual(sg, "/usr/bin/semgrep")
        self.assertEqual(resolved, rules.resolve())

    def test_validation_is_skipped_when_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "rules.yml"
            rules.write_text("rules: []")
            with (
                patch.object(semgrep_locate, "find_semgrep", return_value="/usr/bin/semgrep"),
                patch.object(semgrep_locate, "_validate_semgrep_config") as validate,
            ):
                sg, _ = semgrep_locate.semgrep_or_exit(
                    "/usr/bin/semgrep", str(rules), validate_rules=False
                )
        validate.assert_not_called()
        self.assertEqual(sg, "/usr/bin/semgrep")


if __name__ == "__main__":
    unittest.main()
