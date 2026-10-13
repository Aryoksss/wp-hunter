import unittest
from unittest.mock import MagicMock, patch

import requests

from wp_hunter import http


class BuildApiParamsTests(unittest.TestCase):
    def test_browse_mode_sets_browse_key(self):
        params = http._build_api_params("popular", 1)
        self.assertEqual(params["request[browse]"], "popular")
        self.assertEqual(params["request[page]"], "1")
        self.assertEqual(params["request[per_page]"], "100")

    def test_search_drops_browse(self):
        params = http._build_api_params("popular", 1, search="elementor")
        self.assertNotIn("request[browse]", params)
        self.assertEqual(params["request[search]"], "elementor")

    def test_tag_drops_browse(self):
        params = http._build_api_params("popular", 1, tag="security")
        self.assertNotIn("request[browse]", params)
        self.assertEqual(params["request[tag]"], "security")

    def test_fields_requested(self):
        params = http._build_api_params("popular", 2)
        self.assertEqual(params["request[fields][active_installs]"], "true")
        self.assertEqual(params["request[fields][md5]"], "true")


class WporgGetTests(unittest.TestCase):
    def test_rate_limit_sleeps_when_needed(self):
        http._WPORG_LAST_REQUEST_AT = 0.0
        with (
            patch.object(http.time, "monotonic", side_effect=[0.0, 0.0, 0.0]),
            patch.object(http.time, "sleep") as sleep,
            patch.object(http, "_get", return_value="ok"),
        ):
            http._wporg_get("https://example.test")
        sleep.assert_called_once()
        self.assertGreater(sleep.call_args.args[0], 0)

    def test_no_sleep_when_interval_elapsed(self):
        http._WPORG_LAST_REQUEST_AT = 0.0
        with (
            patch.object(http.time, "monotonic", side_effect=[100.0, 100.0]),
            patch.object(http.time, "sleep") as sleep,
            patch.object(http, "_get", return_value="ok"),
        ):
            http._wporg_get("https://example.test")
        sleep.assert_not_called()


class QueryPluginsPageTests(unittest.TestCase):
    def _response(self, payload, status=200):
        resp = MagicMock()
        resp.json.return_value = payload
        resp.raise_for_status.return_value = None
        resp.status_code = status
        return resp

    def test_returns_dict_on_success(self):
        with patch.object(http, "_wporg_get", return_value=self._response({"plugins": []})):
            self.assertEqual(http.query_plugins_page(page=1), {"plugins": []})

    def test_non_dict_payload_returns_none(self):
        with patch.object(http, "_wporg_get", return_value=self._response(["not", "dict"])):
            self.assertIsNone(http.query_plugins_page(page=1))

    def test_retries_then_succeeds(self):
        good = self._response({"plugins": []})
        with (
            patch.object(
                http,
                "_wporg_get",
                side_effect=[requests.exceptions.Timeout("slow"), good],
            ),
            patch.object(http.time, "sleep"),
            patch("sys.stderr"),
        ):
            self.assertEqual(http.query_plugins_page(page=1), {"plugins": []})

    def test_exhausted_retries_returns_none(self):
        with (
            patch.object(
                http, "_wporg_get", side_effect=requests.exceptions.ConnectionError("down")
            ),
            patch.object(http.time, "sleep"),
            patch("sys.stderr"),
        ):
            self.assertIsNone(http.query_plugins_page(page=1))


class FetchAssetInfoTests(unittest.TestCase):
    def _ok(self, payload):
        resp = MagicMock()
        resp.json.return_value = payload
        resp.raise_for_status.return_value = None
        return resp

    def test_rejects_unsafe_slug_without_request(self):
        with patch.object(http, "_wporg_get") as get:
            self.assertIsNone(http._fetch_wporg_plugin_info("../etc/passwd"))
        get.assert_not_called()

    def test_returns_data_for_valid_plugin(self):
        payload = {"slug": "elementor", "version": "3.5.0"}
        with patch.object(http, "_wporg_get", return_value=self._ok(payload)):
            self.assertEqual(http._fetch_wporg_plugin_info("elementor"), payload)

    def test_error_payload_returns_none(self):
        with patch.object(http, "_wporg_get", return_value=self._ok({"error": "closed"})):
            self.assertIsNone(http._fetch_wporg_plugin_info("elementor"))

    def test_network_error_returns_none(self):
        with patch.object(
            http, "_wporg_get", side_effect=requests.exceptions.RequestException("boom")
        ):
            self.assertIsNone(http._fetch_wporg_theme_info("twentytwenty"))

    def test_missing_slug_field_returns_none(self):
        with patch.object(http, "_wporg_get", return_value=self._ok({"version": "1.0"})):
            self.assertIsNone(http._fetch_wporg_plugin_info("elementor"))


class PatchstackPageTests(unittest.TestCase):
    def test_returns_dict_on_success(self):
        resp = MagicMock()
        resp.json.return_value = {"total": 5}
        resp.raise_for_status.return_value = None
        with patch.object(http, "_get", return_value=resp):
            self.assertEqual(http._patchstack_page(1), {"total": 5})

    def test_non_dict_returns_none(self):
        resp = MagicMock()
        resp.json.return_value = []
        resp.raise_for_status.return_value = None
        with patch.object(http, "_get", return_value=resp):
            self.assertIsNone(http._patchstack_page(1))

    def test_failure_after_retries_returns_none(self):
        with (
            patch.object(http, "_get", side_effect=requests.exceptions.ConnectionError("x")),
            patch.object(http.time, "sleep"),
            patch("sys.stderr"),
        ):
            self.assertIsNone(http._patchstack_page(1))


if __name__ == "__main__":
    unittest.main()
