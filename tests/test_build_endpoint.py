"""Tests for GET /api/v1/build (sidecar-build-identity-spec.md).

Covers the proxy dashboard endpoint:
  - shape (documented fields)
  - build_id stability across calls
  - auth (401 when password is set)
  - plugin aggregation from ExtensionRegistry.loaded_plugin_build_infos()

Direct-handler tests cover the plugin-aggregation matrix without a
live HTTP server.
"""

from __future__ import annotations

import http.client
import json
import shutil
import tempfile
import types
import unittest

from lumen_argus.dashboard.api_config import handle_build
from lumen_argus.extensions import ExtensionRegistry
from lumen_argus_core.build_info import BUILD_ID_UNKNOWN, UNKNOWN, compute_build_id
from tests.helpers import make_store, start_dashboard_server, stop_dashboard_server


def _get(port, path, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path, headers=headers or {})
    resp = conn.getresponse()
    status = resp.status
    body = resp.read().decode("utf-8", errors="replace")
    conn.close()
    return status, body


class TestBuildEndpointHTTP(unittest.TestCase):
    """End-to-end checks through the real aiohttp server."""

    def setUp(self):
        compute_build_id.cache_clear()
        self.tmpdir = tempfile.mkdtemp()
        self.store, _ = make_store(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_shape(self):
        server, port, loop, sse = start_dashboard_server(store=self.store)
        try:
            status, body = _get(port, "/api/v1/build")
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual(data["service"], "lumen-argus")
            for field in ("version", "git_commit", "build_id", "built_at", "plugins"):
                self.assertIn(field, data)
            self.assertTrue(data["build_id"].startswith("sha256:"))
            self.assertIsInstance(data["plugins"], list)
        finally:
            stop_dashboard_server(server, loop, sse)

    def test_build_id_stable(self):
        server, port, loop, sse = start_dashboard_server(store=self.store)
        try:
            _, b1 = _get(port, "/api/v1/build")
            _, b2 = _get(port, "/api/v1/build")
            self.assertEqual(json.loads(b1)["build_id"], json.loads(b2)["build_id"])
        finally:
            stop_dashboard_server(server, loop, sse)

    def test_auth_required_when_password_set(self):
        server, port, loop, sse = start_dashboard_server(password="hunter2", store=self.store)
        try:
            status, body = _get(port, "/api/v1/build")
            self.assertEqual(status, 401)
            self.assertEqual(json.loads(body)["error"], "authentication_required")
        finally:
            stop_dashboard_server(server, loop, sse)


class TestHandleBuildDirect(unittest.TestCase):
    """Direct calls to handle_build() — cheaper than spinning up a server."""

    def setUp(self):
        compute_build_id.cache_clear()

    def test_no_extensions(self):
        status, body = handle_build(None)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["plugins"], [])
        self.assertEqual(data["service"], "lumen-argus")

    def test_no_plugins_loaded(self):
        ext = ExtensionRegistry()
        status, body = handle_build(ext)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["plugins"], [])

    def test_plugin_without_build_info_uses_fallbacks(self):
        """A plugin loaded via the registry that hasn't shipped __build_info__
        still appears — with git_commit / build_id defaulted to sentinels."""
        ext = ExtensionRegistry()
        # Simulate a loaded plugin that lacks __build_info__.
        mod = types.ModuleType("test_plugin_a")
        ext._loaded_plugins.append(("test-plugin-a", "0.0.1"))
        ext._loaded_plugin_modules["test-plugin-a"] = mod

        status, body = handle_build(ext)
        data = json.loads(body)
        self.assertEqual(status, 200)
        plugins = {p["name"]: p for p in data["plugins"]}
        self.assertEqual(plugins["test-plugin-a"]["version"], "0.0.1")
        self.assertEqual(plugins["test-plugin-a"]["git_commit"], UNKNOWN)
        self.assertEqual(plugins["test-plugin-a"]["build_id"], BUILD_ID_UNKNOWN)

    def test_plugin_with_build_info(self):
        ext = ExtensionRegistry()
        mod = types.ModuleType("test_plugin_b")
        mod.__build_info__ = {
            "name": "test-plugin-b",
            "version": "2.3.4",
            "git_commit": "cafef00d" * 5,
            "build_id": "sha256:" + "ab" * 32,
        }
        ext._loaded_plugins.append(("test-plugin-b", "2.3.4"))
        ext._loaded_plugin_modules["test-plugin-b"] = mod

        status, body = handle_build(ext)
        data = json.loads(body)
        self.assertEqual(status, 200)
        plugins = {p["name"]: p for p in data["plugins"]}
        self.assertEqual(plugins["test-plugin-b"]["git_commit"], "cafef00d" * 5)
        self.assertEqual(plugins["test-plugin-b"]["build_id"], "sha256:" + "ab" * 32)

    def test_plugin_with_malformed_build_info(self):
        """Non-dict __build_info__ is logged and treated as missing."""
        ext = ExtensionRegistry()
        mod = types.ModuleType("test_plugin_c")
        mod.__build_info__ = "not-a-dict"
        ext._loaded_plugins.append(("test-plugin-c", "1.0"))
        ext._loaded_plugin_modules["test-plugin-c"] = mod

        status, body = handle_build(ext)
        data = json.loads(body)
        self.assertEqual(status, 200)
        plugins = {p["name"]: p for p in data["plugins"]}
        self.assertEqual(plugins["test-plugin-c"]["git_commit"], UNKNOWN)

    def test_multiple_plugins(self):
        ext = ExtensionRegistry()
        ma = types.ModuleType("a")
        mb = types.ModuleType("b")
        mb.__build_info__ = {"git_commit": "bb" * 20}
        ext._loaded_plugins.extend([("plug-a", "0.1"), ("plug-b", "0.2")])
        ext._loaded_plugin_modules["plug-a"] = ma
        ext._loaded_plugin_modules["plug-b"] = mb

        _status, body = handle_build(ext)
        data = json.loads(body)
        self.assertEqual(len(data["plugins"]), 2)
        names = [p["name"] for p in data["plugins"]]
        self.assertEqual(names, ["plug-a", "plug-b"])


if __name__ == "__main__":
    unittest.main()
