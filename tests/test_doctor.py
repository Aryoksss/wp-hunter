import contextlib
import io
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from wp_hunter import doctor


class SafeTriageWorkersTests(unittest.TestCase):
    def _with_memory(self, available_mb: int):
        # psutil is an optional extra; inject a stub so the patch resolves
        # whether or not it is installed.
        memory = type("Mem", (), {"available": available_mb * 1024 * 1024})()
        stub = types.ModuleType("psutil")
        stub.virtual_memory = lambda: memory  # type: ignore[attr-defined]
        return patch.dict(sys.modules, {"psutil": stub})

    def test_request_below_limit_is_unchanged(self):
        with self._with_memory(64 * 1024):
            workers, warn = doctor.safe_triage_workers(2, 512)
        self.assertEqual(workers, 2)
        self.assertEqual(warn, "")

    def test_request_above_limit_is_capped_with_warning(self):
        with self._with_memory(4 * 1024):
            workers, warn = doctor.safe_triage_workers(32, 512)
        self.assertLess(workers, 32)
        self.assertGreaterEqual(workers, 1)
        self.assertIn("[MEM]", warn)
        self.assertIn("Reducing triage workers", warn)

    def test_zero_request_is_clamped_to_one(self):
        with self._with_memory(64 * 1024):
            workers, _ = doctor.safe_triage_workers(0, 512)
        self.assertEqual(workers, 1)

    def test_zero_mem_budget_is_clamped(self):
        with self._with_memory(64 * 1024):
            workers, _ = doctor.safe_triage_workers(1, 0)
        self.assertEqual(workers, 1)

    def test_psutil_missing_falls_back_to_cap(self):
        with patch.dict("sys.modules", {"psutil": None}):
            workers, warn = doctor.safe_triage_workers(100, 512)
        self.assertGreaterEqual(workers, 1)
        self.assertLess(workers, 100)
        self.assertIn("[MEM]", warn)


class CmdCheckTests(unittest.TestCase):
    def _run(self, **kwargs) -> tuple[str, int | None]:
        out = io.StringIO()
        code: int | None = None
        with contextlib.redirect_stdout(out):
            try:
                doctor.cmd_check(**kwargs)
            except SystemExit as exc:
                code = exc.code if isinstance(exc.code, int) else 0
        return out.getvalue(), code

    def test_all_ok_path_prints_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "rules.yml"
            rules.write_text("rules: []")
            with (
                patch.object(doctor, "find_semgrep", return_value="/usr/bin/semgrep"),
                patch.object(doctor, "_validate_semgrep_config", return_value=(True, "")),
            ):
                text, code = self._run(semgrep_rules=str(rules))
        self.assertIsNone(code)
        self.assertIn("All checks passed", text)
        self.assertIn("Semgrep", text)

    def test_missing_semgrep_warns_but_does_not_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "rules.yml"
            rules.write_text("rules: []")
            with patch.object(doctor, "find_semgrep", return_value=None):
                text, code = self._run(semgrep_rules=str(rules))
        self.assertIsNone(code)
        self.assertIn("not found", text)

    def test_invalid_rules_fails_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "rules.yml"
            rules.write_text("rules: []")
            with (
                patch.object(doctor, "find_semgrep", return_value="/usr/bin/semgrep"),
                patch.object(doctor, "_validate_semgrep_config", return_value=(False, "bad rules")),
                patch("sys.stderr"),
            ):
                text, code = self._run(semgrep_rules=str(rules))
        self.assertEqual(code, 1)
        self.assertIn("bad rules", text)
        self.assertIn("Fix critical issues", text)

    def test_missing_rules_warns(self):
        with (
            patch.object(doctor, "find_semgrep", return_value="/usr/bin/semgrep"),
            patch.object(doctor, "SEMGREP_RULES_DEFAULT", Path("/no/such/rules.yml")),
        ):
            text, code = self._run()
        self.assertIsNone(code)
        self.assertIn("missing or unsafe", text)

    def test_indonesian_language(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "rules.yml"
            rules.write_text("rules: []")
            with (
                patch.object(doctor, "find_semgrep", return_value="/usr/bin/semgrep"),
                patch.object(doctor, "_validate_semgrep_config", return_value=(True, "")),
            ):
                text, _ = self._run(semgrep_rules=str(rules), language="id")
        self.assertIn("Pemeriksaan Konfigurasi", text)

    def test_disk_usage_oserror_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "rules.yml"
            rules.write_text("rules: []")
            with (
                patch.object(doctor, "find_semgrep", return_value="/usr/bin/semgrep"),
                patch.object(doctor, "_validate_semgrep_config", return_value=(True, "")),
                patch.object(doctor.shutil, "disk_usage", side_effect=OSError("nope")),
            ):
                text, code = self._run(semgrep_rules=str(rules))
        self.assertIsNone(code)
        self.assertNotIn("Disk free", text)

    def test_low_disk_shows_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "rules.yml"
            rules.write_text("rules: []")
            usage = shutil._ntuple_diskusage(total=0, used=0, free=1024)  # type: ignore[attr-defined]
            with (
                patch.object(doctor, "find_semgrep", return_value="/usr/bin/semgrep"),
                patch.object(doctor, "_validate_semgrep_config", return_value=(True, "")),
                patch.object(doctor.shutil, "disk_usage", return_value=usage),
            ):
                text, _ = self._run(semgrep_rules=str(rules))
        self.assertIn("large batches may fail", text)


if __name__ == "__main__":
    unittest.main()
