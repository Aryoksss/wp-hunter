import unittest
from unittest.mock import patch

from wp_hunter import httpclient
from wp_hunter.vulndb import (
    WPSCAN_TOKEN_ENV,
    ScanOutcome,
    Vulnerability,
    WpscanClient,
    parse_plugin_response,
    summarize,
)

ELEMENTOR_PAYLOAD = {
    "elementor": {
        "latest_version": "3.5.0",
        "vulnerabilities": [
            {
                "id": "abc",
                "title": "Contributor+ SQL Injection",
                "vuln_type": "SQLI",
                "fixed_in": "3.6.3",
                "cvss": {"score": 6.4, "severity": "medium"},
            },
            {
                "id": "def",
                "title": "Stored XSS",
                "vuln_type": "XSS",
                "fixed_in": None,
                "cvss": {"score": 4.1},
            },
        ],
    }
}


class ResponseStub:
    def __init__(self, status_code=200, payload=None, headers=None):
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}

    def json(self):
        if self._payload is None:
            raise ValueError("no payload")
        return self._payload


class ParseResponseTests(unittest.TestCase):
    def test_parses_title_fixed_in_and_cvss(self):
        vulns = parse_plugin_response(ELEMENTOR_PAYLOAD, "elementor", "3.5.0")
        titles = {v.title for v in vulns}
        self.assertEqual(titles, {"Contributor+ SQL Injection", "Stored XSS"})

    def test_marks_fixed_in_above_current_version_as_not_affected(self):
        vulns = parse_plugin_response(ELEMENTOR_PAYLOAD, "elementor", "3.5.0")
        sqli = next(v for v in vulns if v.vuln_type == "SQLI")
        self.assertFalse(sqli.affected)
        self.assertEqual(sqli.fixed_in, "3.6.3")
        self.assertEqual(sqli.cvss_score, 6.4)

    def test_marks_unfixed_advisory_as_affected(self):
        vulns = parse_plugin_response(ELEMENTOR_PAYLOAD, "elementor", "3.5.0")
        xss = next(v for v in vulns if v.vuln_type == "XSS")
        self.assertTrue(xss.affected)
        self.assertEqual(xss.cvss_score, 4.1)

    def test_current_version_equal_to_fix_is_not_affected(self):
        vulns = parse_plugin_response(ELEMENTOR_PAYLOAD, "elementor", "3.6.3")
        sqli = next(v for v in vulns if v.vuln_type == "SQLI")
        self.assertFalse(sqli.affected)

    def test_affected_sorted_before_unaffected(self):
        vulns = parse_plugin_response(ELEMENTOR_PAYLOAD, "elementor", "3.5.0")
        self.assertTrue(vulns[0].affected)
        self.assertFalse(vulns[-1].affected)

    def test_missing_slug_returns_empty(self):
        self.assertEqual(parse_plugin_response(ELEMENTOR_PAYLOAD, "other", "1.0"), [])

    def test_non_dict_payload_returns_empty(self):
        self.assertEqual(parse_plugin_response(["oops"], "elementor", "1.0"), [])

    def test_malformed_entries_are_skipped(self):
        payload = {"x": {"vulnerabilities": ["nope", {"title": "Real"}]}}
        vulns = parse_plugin_response(payload, "x", "1.0")
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].title, "Real")

    def test_untitled_vulnerability_gets_placeholder(self):
        payload = {"x": {"vulnerabilities": [{"cvss": {"score": 5}}]}}
        vulns = parse_plugin_response(payload, "x", "1.0")
        self.assertEqual(vulns[0].title, "(untitled vulnerability)")

    def test_defensive_cvss_parsing(self):
        payload = {
            "x": {
                "vulnerabilities": [
                    {"title": "a", "cvss": {"score": True}},
                    {"title": "b", "cvss": {"score": "7.5"}},
                    {"title": "c", "cvss": {"score": "bad"}},
                    {"title": "d", "cvss": "notadict"},
                ]
            }
        }
        scores = {v.title: v.cvss_score for v in parse_plugin_response(payload, "x", "1.0")}
        self.assertIsNone(scores["a"])
        self.assertEqual(scores["b"], 7.5)
        self.assertIsNone(scores["c"])
        self.assertIsNone(scores["d"])


class WpscanClientTests(unittest.TestCase):
    def test_unconfigured_client_reports_error(self):
        with patch.dict("os.environ", {}, clear=True):
            client = WpscanClient()
        self.assertFalse(client.configured)
        outcome = client.scan("elementor", "3.5.0")
        self.assertIn("WPSCAN_API_TOKEN", outcome.error or "")

    def test_configured_scan_tracks_remaining_quota(self):
        client = WpscanClient(token="tok")
        stub = ResponseStub(payload=ELEMENTOR_PAYLOAD, headers={"x-ratelimit-remaining": "42"})
        with patch.object(httpclient, "get", return_value=stub) as get:
            outcome = client.scan("elementor", "3.5.0")
        self.assertEqual(outcome.remaining_quota, 42)
        self.assertTrue(outcome.has_affected)
        self.assertIn("Token token=tok", get.call_args.kwargs["headers"]["Authorization"])

    def test_404_is_not_an_error(self):
        client = WpscanClient(token="tok")
        stub = ResponseStub(status_code=404, payload={})
        with patch.object(httpclient, "get", return_value=stub):
            outcome = client.scan("unknown-slug", "1.0")
        self.assertIsNone(outcome.error)
        self.assertEqual(outcome.vulnerabilities, [])

    def test_429_sets_quota_zero_and_stops(self):
        client = WpscanClient(token="tok")
        with patch.object(
            httpclient, "get", return_value=ResponseStub(status_code=429, payload={})
        ):
            first = client.scan("a", "1.0")
            second = client.scan("b", "1.0")
        self.assertEqual(first.remaining_quota, 0)
        self.assertIn("rate limit", first.error or "")
        self.assertIn("quota exhausted", second.error or "")

    def test_500_reports_http_error(self):
        client = WpscanClient(token="tok")
        with patch.object(
            httpclient, "get", return_value=ResponseStub(status_code=503, payload={})
        ):
            outcome = client.scan("a", "1.0")
        self.assertIn("HTTP 503", outcome.error or "")

    def test_network_exception_is_captured(self):
        client = WpscanClient(token="tok")
        with patch.object(httpclient, "get", side_effect=RuntimeError("boom")):
            outcome = client.scan("a", "1.0")
        self.assertIn("boom", outcome.error or "")

    def test_invalid_json_reports_error(self):
        client = WpscanClient(token="tok")
        with patch.object(httpclient, "get", return_value=ResponseStub(payload=None)):
            outcome = client.scan("a", "1.0")
        self.assertIn("invalid WPScan JSON", outcome.error or "")

    def test_explicit_token_overrides_environment(self):
        with patch.dict("os.environ", {WPSCAN_TOKEN_ENV: "env-token"}):
            self.assertEqual(WpscanClient("explicit").token, "explicit")
            self.assertEqual(WpscanClient().token, "env-token")


class SummarizeTests(unittest.TestCase):
    def test_summary_counts(self):
        outcomes = [
            ScanOutcome(slug="a", vulnerabilities=[Vulnerability("1", "t", "XSS", "", 5.0, True)]),
            ScanOutcome(slug="b", vulnerabilities=[]),
        ]
        summary = summarize(outcomes)
        self.assertEqual(summary["checked"], 2)
        self.assertEqual(summary["advisories"], 1)
        self.assertEqual(summary["affected_plugins"], 1)


if __name__ == "__main__":
    unittest.main()
