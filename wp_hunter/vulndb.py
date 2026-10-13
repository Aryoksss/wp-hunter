from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import TextIO

from . import httpclient
from .versioning import version_is_newer

WPSCAN_PLUGIN_API = "https://wpscan.com/api/v3/plugins"
WPSCAN_TOKEN_ENV = "WPSCAN_API_TOKEN"


@dataclass(frozen=True)
class Vulnerability:
    id: str
    title: str
    vuln_type: str
    fixed_in: str
    cvss_score: float | None
    affected: bool


@dataclass
class ScanOutcome:
    slug: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    remaining_quota: int | None = None
    error: str | None = None

    @property
    def has_affected(self) -> bool:
        return any(v.affected for v in self.vulnerabilities)


class WpscanClient:
    def __init__(self, token: str | None = None) -> None:
        self.token = token if token is not None else os.environ.get(WPSCAN_TOKEN_ENV, "").strip()
        self._remaining: int | None = None

    @property
    def configured(self) -> bool:
        return bool(self.token)

    @property
    def remaining_quota(self) -> int | None:
        return self._remaining

    def scan(self, slug: str, current_version: str) -> ScanOutcome:
        outcome = ScanOutcome(slug=slug)
        if not self.configured:
            outcome.error = "WPSCAN_API_TOKEN is not set"
            return outcome
        if self._remaining is not None and self._remaining <= 0:
            outcome.error = "WPScan daily quota exhausted"
            outcome.remaining_quota = 0
            return outcome
        headers = {"Authorization": f"Token token={self.token}", "Accept": "application/json"}
        try:
            response = httpclient.get(f"{WPSCAN_PLUGIN_API}/{slug}", headers=headers, timeout=20)
        except Exception as exc:
            outcome.error = str(exc)
            return outcome
        self._update_quota(response)
        outcome.remaining_quota = self._remaining
        if response.status_code == 404:
            return outcome
        if response.status_code == 429:
            self._remaining = 0
            outcome.remaining_quota = 0
            outcome.error = "WPScan rate limit reached"
            return outcome
        if response.status_code != 200:
            outcome.error = f"WPScan returned HTTP {response.status_code}"
            return outcome
        try:
            payload = response.json()
        except ValueError as exc:
            outcome.error = f"invalid WPScan JSON: {exc}"
            return outcome
        outcome.vulnerabilities = parse_plugin_response(payload, slug, current_version)
        return outcome

    def _update_quota(self, response: object) -> None:
        headers = getattr(response, "headers", {}) or {}
        raw = headers.get("x-ratelimit-remaining") if hasattr(headers, "get") else None
        if raw is None:
            return
        try:
            self._remaining = int(str(raw).strip())
        except ValueError:
            return


def parse_plugin_response(payload: object, slug: str, current_version: str) -> list[Vulnerability]:
    if not isinstance(payload, dict):
        return []
    entry = payload.get(slug)
    if not isinstance(entry, dict):
        return []
    raw_vulns = entry.get("vulnerabilities")
    if not isinstance(raw_vulns, list):
        return []
    results: list[Vulnerability] = []
    for raw in raw_vulns:
        if not isinstance(raw, dict):
            continue
        fixed_in = _as_text(raw.get("fixed_in"))
        results.append(
            Vulnerability(
                id=_as_text(raw.get("id")),
                title=_as_text(raw.get("title")) or "(untitled vulnerability)",
                vuln_type=_as_text(raw.get("vuln_type")),
                fixed_in=fixed_in,
                cvss_score=_cvss_score(raw.get("cvss")),
                affected=_affects(current_version, fixed_in),
            )
        )
    results.sort(key=lambda v: (not v.affected, v.fixed_in or "zzz", v.title))
    return results


def _affects(current_version: str, fixed_in: str) -> bool:
    if not current_version:
        return True
    if not fixed_in:
        # No fix published: the advisory covers every version.
        return True
    return not version_is_newer(fixed_in, current_version) and fixed_in != current_version


def _cvss_score(value: object) -> float | None:
    score = value.get("score") if isinstance(value, dict) else None
    if isinstance(score, bool):
        return None
    if isinstance(score, (int, float)):
        return float(score)
    if isinstance(score, str):
        try:
            return float(score.strip())
        except ValueError:
            return None
    return None


def _as_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def summarize(outcomes: list[ScanOutcome]) -> dict[str, int]:
    total = sum(len(o.vulnerabilities) for o in outcomes)
    affected = sum(1 for o in outcomes if o.has_affected)
    return {"checked": len(outcomes), "advisories": total, "affected_plugins": affected}


def warn_unconfigured(stream: TextIO | None = None) -> None:
    print(
        f"  [WARN] Vulnerability checks need {WPSCAN_TOKEN_ENV} "
        "(get a free token at https://wpscan.com/).",
        file=stream if stream is not None else sys.stderr,
    )
