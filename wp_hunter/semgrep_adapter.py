from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

MAX_SEMGREP_JSON_BYTES = 64 * 1024 * 1024


def _display_text(value: object) -> str:
    return re.sub(r"[\x00-\x1f\x7f\x80-\x9f]", " ", str(value or ""))


def decode_process_output(value: object, limit: int = 512) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    text = str(value or "")
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = re.sub(r"\s+", " ", _display_text(text)).strip()
    return text[:limit]


def _semgrep_error_detail(stdout: object, stderr: object, limit: int = 500) -> str:
    decoded_stdout = (
        stdout.decode("utf-8", errors="replace") if isinstance(stdout, bytes) else stdout
    )
    try:
        payload = json.loads(str(decoded_stdout or ""))
    except (TypeError, json.JSONDecodeError):
        payload = None
    if isinstance(payload, dict) and isinstance(payload.get("errors"), list):
        for error in payload["errors"]:
            if not isinstance(error, dict):
                continue
            error_type = decode_process_output(error.get("type"), 80)
            rule_id = decode_process_output(error.get("rule_id"), 120)
            message = decode_process_output(error.get("message"), limit)
            heading = error_type or "Semgrep error"
            if rule_id:
                heading += f" in {rule_id}"
            if message.lower().startswith(heading.lower()):
                return message[:limit]
            return f"{heading}: {message}"[:limit] if message else heading[:limit]
    return decode_process_output(stderr or stdout, limit)


def _semgrep_runtime_environment(state_dir: str | Path) -> dict[str, str]:
    state = Path(state_dir)
    cache = state / "cache"
    config = state / "config"
    cache.mkdir(parents=True, exist_ok=True)
    config.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.update(
        {
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
            "SEMGREP_SETTINGS_FILE": str(state / "settings.yml"),
            "SEMGREP_LOG_FILE": str(state / "semgrep.log"),
            "SEMGREP_VERSION_CACHE_PATH": str(cache / "version"),
            "XDG_CACHE_HOME": str(cache),
            "XDG_CONFIG_HOME": str(config),
        }
    )
    return environment


def validate_semgrep_config(
    semgrep_path: str,
    rules_path: str | Path,
    timeout: int = 30,
) -> tuple[bool, str]:
    rules = Path(rules_path).expanduser()
    if rules.is_symlink() or not rules.is_file():
        return False, f"Rules file is missing or unsafe: {rules}"
    cmd = [
        semgrep_path,
        "--disable-version-check",
        "--metrics",
        "off",
        "--quiet",
        "--no-rewrite-rule-ids",
        "--config",
        str(rules),
        "--json",
        "--no-git-ignore",
    ]
    try:
        with (
            tempfile.TemporaryDirectory(prefix="wp-hunter-semgrep-state-") as state_dir,
            tempfile.TemporaryDirectory(prefix="wp-hunter-rule-check-") as fixture_dir,
            tempfile.TemporaryFile(mode="w+b") as stdout_file,
            tempfile.TemporaryFile(mode="w+b") as stderr_file,
        ):
            fixture = Path(fixture_dir)
            (fixture / "fixture.php").write_text(
                "<?php echo $_GET['wp_hunter_rule_check'];\n", encoding="utf-8"
            )
            (fixture / "fixture.js").write_text(
                "document.write(window.location.hash);\n", encoding="utf-8"
            )
            proc = subprocess.run(
                [*cmd, str(fixture)],
                timeout=max(1, timeout),
                stdout=stdout_file,
                stderr=stderr_file,
                check=False,
                stdin=subprocess.DEVNULL,
                shell=False,
                env=_semgrep_runtime_environment(state_dir),
            )
            stdout_file.seek(0)
            stdout = stdout_file.read(64 * 1024)
            stderr_file.seek(0)
            stderr = stderr_file.read(64 * 1024)
    except subprocess.TimeoutExpired:
        return False, "Semgrep rule validation timed out"
    except FileNotFoundError:
        return False, "Semgrep executable was not found"
    except Exception as exc:
        return False, decode_process_output(exc, 500)
    try:
        payload = json.loads(stdout.decode("utf-8", errors="replace"))
    except (AttributeError, json.JSONDecodeError, UnicodeError):
        payload = None
    if proc.returncode in (0, 1) and isinstance(payload, dict):
        errors = payload.get("errors")
        if not isinstance(errors, list) or not errors:
            return True, ""
    detail = _semgrep_error_detail(stdout, stderr)
    return False, detail or f"Semgrep validation exited with code {proc.returncode}"


def _normalize_semgrep_result(raw: object) -> dict:
    if not isinstance(raw, dict):
        return {"check_id": "semgrep.unknown", "extra": {"context": {"access": "unknown"}}}
    extra = raw.get("extra") if isinstance(raw.get("extra"), dict) else {}
    metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
    triage = metadata.get("triage") if isinstance(metadata.get("triage"), dict) else {}
    access = str(triage.get("access", "unknown") or "unknown").lower().strip()
    category = str(triage.get("category", "unknown") or "unknown").strip()
    confidence = str(triage.get("confidence", "unknown") or "unknown").strip()
    start = raw.get("start") if isinstance(raw.get("start"), dict) else {}
    end = raw.get("end") if isinstance(raw.get("end"), dict) else {}
    return {
        "check_id": str(raw.get("check_id", "semgrep.unknown") or "semgrep.unknown"),
        "file": str(raw.get("path", "") or ""),
        "line": start.get("line"),
        "end_line": end.get("line"),
        "message": str(extra.get("message", "") or ""),
        "category": category,
        "confidence": confidence,
        "extra": {"context": {"access": access}, "metadata": metadata},
        "semgrep": raw,
    }


def run_semgrep_scan(
    semgrep_path: str,
    rules_path: Path,
    target_dir: str,
    timeout: int,
    mem_mb: int,
) -> tuple[list[dict], str]:
    del mem_mb
    target = Path(target_dir)
    if target.is_symlink() or not target.is_dir():
        return [], "INVALID_TARGET"
    for current, dirnames, filenames in os.walk(target, followlinks=False):
        if any((Path(current) / name).is_symlink() for name in (*dirnames, *filenames)):
            return [], "SYMLINK_TARGET"
    if rules_path.is_symlink() or not rules_path.is_file():
        return [], "INVALID_RULES"
    cmd = [
        semgrep_path,
        "--disable-version-check",
        "--metrics",
        "off",
        "--quiet",
        "--no-rewrite-rule-ids",
        "--config",
        str(rules_path),
        "--json",
        "--no-git-ignore",
        str(target),
    ]
    try:
        with (
            tempfile.TemporaryDirectory(prefix="wp-hunter-semgrep-state-") as state_dir,
            tempfile.TemporaryFile(mode="w+b") as stdout_file,
            tempfile.TemporaryFile(mode="w+b") as stderr_file,
        ):
            proc = subprocess.run(
                cmd,
                timeout=max(1, timeout),
                stdout=stdout_file,
                stderr=stderr_file,
                check=False,
                stdin=subprocess.DEVNULL,
                shell=False,
                env=_semgrep_runtime_environment(state_dir),
            )
            stdout_file.seek(0, os.SEEK_END)
            output_size = stdout_file.tell()
            stdout_file.seek(0)
            stdout = stdout_file.read(MAX_SEMGREP_JSON_BYTES + 1)
            stderr_file.seek(0)
            stderr = stderr_file.read(4096)
    except subprocess.TimeoutExpired:
        return [], "TIMEOUT"
    except FileNotFoundError:
        return [], "BINARY_NOT_FOUND"
    except Exception as exc:
        return [], f"SCAN_ERR:{decode_process_output(exc, 200)}"
    if proc.returncode not in (0, 1):
        error_hint = _semgrep_error_detail(stdout, stderr, 300)
        suffix = f" — {error_hint}" if error_hint else ""
        return [], f"SCAN_ERR:{proc.returncode}{suffix}"
    if output_size > MAX_SEMGREP_JSON_BYTES:
        return [], "OUTPUT_TOO_LARGE"
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    if not isinstance(stdout, str) or not stdout.strip():
        return [], "INVALID_OUTPUT"
    try:
        data = json.loads(stdout)
    except (TypeError, json.JSONDecodeError):
        return [], "INVALID_OUTPUT"
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return [], "INVALID_OUTPUT"
    if isinstance(data.get("errors"), list) and data["errors"]:
        return [], "PARSE_ERROR"
    return [_normalize_semgrep_result(item) for item in data["results"]], "OK"


class SemgrepEngine:
    def __init__(self, executable: str, rules_path: str | Path):
        self.executable = executable
        self.rules_path = Path(rules_path).expanduser().absolute()

    def scan(self, target_dir: str, timeout: int, mem_mb: int) -> tuple[list[dict], str]:
        return run_semgrep_scan(self.executable, self.rules_path, target_dir, timeout, mem_mb)
