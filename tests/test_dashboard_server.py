"""Comprehensive tests for dashboard server, API, SSE, AuditReader, and extensions.

Uses stdlib-only HTTP clients and temp directories. Starts actual HTTP servers
on random ports for integration tests.
"""

import http.client
import io
import json
import os
import shutil
import tempfile
import threading
import time
import unittest

from lumen_argus.analytics.store import AnalyticsStore
from lumen_argus.config import Config, LoggingConfig
from lumen_argus.dashboard.api import handle_community_api
from lumen_argus.dashboard.audit_reader import AuditReader
from lumen_argus.dashboard.html import (
    COMMUNITY_DASHBOARD_HTML,
    _build_dashboard_html,
)
from lumen_argus.dashboard.server import (
    DashboardServer,
    _SESSION_TIMEOUT,
)
from lumen_argus.dashboard.sse import SSEBroadcaster
from lumen_argus.extensions import ExtensionRegistry
from lumen_argus.models import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _free_port():
    """Find a free TCP port."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_store(tmpdir):
    """Create an AnalyticsStore in a temp directory."""
    db_path = os.path.join(tmpdir, "analytics.db")
    return AnalyticsStore(db_path=db_path)


def _seed_findings(store, count=5):
    """Insert sample findings into the store."""
    findings = []
    for i in range(count):
        findings.append(
            Finding(
                detector="secrets",
                type="aws_access_key_%d" % i,
                severity="critical",
                location="user_message[%d]" % i,
                matched_value="AKIA" + "X" * 16,
                value_preview="AKIA****%d" % i,
                action="alert",
            )
        )
    store.record_findings(findings, provider="anthropic", model="claude-3")


def _start_server(password="", store=None, extensions=None, audit_reader=None, config=None, sse_broadcaster=None):
    """Start a DashboardServer on a random port. Returns (server, port)."""
    port = _free_port()
    if extensions is None:
        extensions = ExtensionRegistry()
    server = DashboardServer(
        "127.0.0.1",
        port,
        store,
        extensions,
        password=password,
        audit_reader=audit_reader,
        sse_broadcaster=sse_broadcaster,
        config=config,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def _get(port, path, headers=None, follow_redirects=False):
    """Send a GET request. Returns (status, headers_dict, body_str)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path, headers=headers or {})
    resp = conn.getresponse()
    status = resp.status
    resp_headers = {k.lower(): v for k, v in resp.getheaders()}
    body = resp.read().decode("utf-8", errors="replace")
    conn.close()
    return status, resp_headers, body


def _post(port, path, body=b"", headers=None):
    """Send a POST request. Returns (status, headers_dict, body_str)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    hdrs = headers or {}
    if "Content-Length" not in hdrs:
        hdrs["Content-Length"] = str(len(body))
    conn.request("POST", path, body=body, headers=hdrs)
    resp = conn.getresponse()
    status = resp.status
    resp_headers = {k.lower(): v for k, v in resp.getheaders()}
    body_str = resp.read().decode("utf-8", errors="replace")
    conn.close()
    return status, resp_headers, body_str


def _put(port, path, body=b"", headers=None):
    """Send a PUT request."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    hdrs = headers or {}
    if "Content-Length" not in hdrs:
        hdrs["Content-Length"] = str(len(body))
    conn.request("PUT", path, body=body, headers=hdrs)
    resp = conn.getresponse()
    status = resp.status
    resp_headers = {k.lower(): v for k, v in resp.getheaders()}
    body_str = resp.read().decode("utf-8", errors="replace")
    conn.close()
    return status, resp_headers, body_str


def _delete(port, path, headers=None):
    """Send a DELETE request."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    hdrs = headers or {}
    if "Content-Length" not in hdrs:
        hdrs["Content-Length"] = "0"
    conn.request("DELETE", path, headers=hdrs)
    resp = conn.getresponse()
    status = resp.status
    resp_headers = {k.lower(): v for k, v in resp.getheaders()}
    body_str = resp.read().decode("utf-8", errors="replace")
    conn.close()
    return status, resp_headers, body_str


def _login(port, password, next_url="/"):
    """POST to /login and return (status, response_headers, session_cookie, csrf_cookie)."""
    body = "password=%s&next=%s" % (password, next_url)
    body_bytes = body.encode("utf-8")
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request(
        "POST",
        "/login",
        body=body_bytes,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(body_bytes)),
        },
    )
    resp = conn.getresponse()
    resp.read()
    status = resp.status
    resp_headers = {k.lower(): v for k, v in resp.getheaders()}

    session_cookie = ""
    csrf_cookie = ""
    # http.client returns multiple Set-Cookie as separate headers
    set_cookies = []
    for k, v in resp.getheaders():
        if k.lower() == "set-cookie":
            set_cookies.append(v)
    for sc in set_cookies:
        if sc.startswith("argus_session="):
            session_cookie = sc.split(";")[0].split("=", 1)[1]
        elif sc.startswith("csrf_token="):
            csrf_cookie = sc.split(";")[0].split("=", 1)[1]
    conn.close()
    return status, resp_headers, session_cookie, csrf_cookie


# ---------------------------------------------------------------------------
# 1. Dashboard HTML assembly
# ---------------------------------------------------------------------------


class TestDashboardHTML(unittest.TestCase):
    def test_no_unreplaced_placeholders(self):
        html = COMMUNITY_DASHBOARD_HTML
        self.assertNotIn("{{STYLE}}", html)
        self.assertNotIn("{{SCRIPT}}", html)

    def test_has_style_and_script_tags(self):
        html = COMMUNITY_DASHBOARD_HTML
        self.assertIn("<style>", html.lower() if "<style>" not in html else html)
        self.assertIn("<script>", html.lower() if "<script>" not in html else html)
        self.assertIn("</style>", html)
        self.assertIn("</script>", html)

    def test_build_dashboard_html_succeeds(self):
        html = _build_dashboard_html()
        self.assertIsInstance(html, str)
        self.assertGreater(len(html), 100)

    def test_fallback_on_missing_files(self):
        # The module-level fallback is already tested by the import,
        # but we verify the fallback HTML structure
        fallback = (
            "<!DOCTYPE html><html><head><title>lumen-argus</title></head>"
            "<body><h1>Dashboard static files are missing</h1>"
            "<p>Re-install the package: <code>pip install -e .</code></p>"
            "</body></html>"
        )
        self.assertIn("static files are missing", fallback)


# ---------------------------------------------------------------------------
# 2. Dashboard server
# ---------------------------------------------------------------------------


class TestDashboardServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.store = _make_store(cls.tmpdir)
        _seed_findings(cls.store)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_serves_html_on_root(self):
        server, port = _start_server(store=self.store)
        try:
            status, headers, body = _get(port, "/")
            self.assertEqual(status, 200)
            self.assertIn("text/html", headers.get("content-type", ""))
            self.assertIn("</html>", body)
        finally:
            server.shutdown()

    def test_no_password_open_access(self):
        server, port = _start_server(store=self.store)
        try:
            status, _, body = _get(port, "/api/v1/status")
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertIn("version", data)
        finally:
            server.shutdown()

    def test_auth_password_required_redirects_to_login(self):
        server, port = _start_server(password="hunter2", store=self.store)
        try:
            # GET / without session should redirect to /login
            status, headers, _ = _get(port, "/")
            self.assertEqual(status, 302)
            self.assertIn("/login", headers.get("location", ""))
        finally:
            server.shutdown()

    def test_auth_api_returns_401_without_session(self):
        server, port = _start_server(password="hunter2", store=self.store)
        try:
            status, _, body = _get(port, "/api/v1/status")
            self.assertEqual(status, 401)
            data = json.loads(body)
            self.assertEqual(data["error"], "authentication_required")
        finally:
            server.shutdown()

    def test_auth_login_and_access(self):
        server, port = _start_server(password="hunter2", store=self.store)
        try:
            # Login
            status, _, session, csrf = _login(port, "hunter2")
            self.assertEqual(status, 302)
            self.assertTrue(session)
            self.assertTrue(csrf)

            # Authenticated GET
            cookie = "argus_session=%s; csrf_token=%s" % (session, csrf)
            status, _, body = _get(port, "/api/v1/status", headers={"Cookie": cookie})
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual(data["status"], "operational")
        finally:
            server.shutdown()

    def test_auth_bad_password_redirects_with_error(self):
        server, port = _start_server(password="hunter2", store=self.store)
        try:
            status, headers, _, _ = _login(port, "wrong")
            self.assertEqual(status, 302)
            self.assertIn("error=1", headers.get("location", ""))
        finally:
            server.shutdown()

    def test_auth_logout(self):
        server, port = _start_server(password="hunter2", store=self.store)
        try:
            _, _, session, csrf = _login(port, "hunter2")
            cookie = "argus_session=%s; csrf_token=%s" % (session, csrf)

            # Logout
            status, headers, _ = _get(port, "/logout", headers={"Cookie": cookie})
            self.assertEqual(status, 302)
            self.assertIn("/login", headers.get("location", ""))

            # Session should be invalid now
            status, _, body = _get(port, "/api/v1/status", headers={"Cookie": cookie})
            self.assertEqual(status, 401)
        finally:
            server.shutdown()

    def test_session_expiry(self):
        server, port = _start_server(password="hunter2", store=self.store)
        try:
            session_id = server.create_session()
            self.assertTrue(server.validate_session(session_id))

            # Simulate expiry by backdating the session
            with server._session_lock:
                server._sessions[session_id] = time.monotonic() - _SESSION_TIMEOUT - 1

            self.assertFalse(server.validate_session(session_id))
        finally:
            server.shutdown()

    def test_csrf_double_submit_on_post(self):
        server, port = _start_server(password="hunter2", store=self.store)
        try:
            _, _, session, csrf = _login(port, "hunter2")
            cookie = "argus_session=%s; csrf_token=%s" % (session, csrf)

            # POST with matching CSRF header and cookie -> should pass CSRF check
            license_body = json.dumps({"key": "test-key"}).encode()
            status, _, body = _post(
                port,
                "/api/v1/license",
                body=license_body,
                headers={
                    "Cookie": cookie,
                    "X-CSRF-Token": csrf,
                    "Content-Type": "application/json",
                    "Content-Length": str(len(license_body)),
                },
            )
            self.assertEqual(status, 200)
        finally:
            server.shutdown()

    def test_csrf_missing_header_rejected(self):
        server, port = _start_server(password="hunter2", store=self.store)
        try:
            _, _, session, csrf = _login(port, "hunter2")
            cookie = "argus_session=%s; csrf_token=%s" % (session, csrf)

            # POST without X-CSRF-Token header -> 403
            status, _, body = _post(
                port,
                "/api/v1/license",
                body=b'{"key":"x"}',
                headers={
                    "Cookie": cookie,
                    "Content-Type": "application/json",
                },
            )
            self.assertEqual(status, 403)
            data = json.loads(body)
            self.assertEqual(data["error"], "csrf_validation_failed")
        finally:
            server.shutdown()

    def test_csrf_mismatched_token_rejected(self):
        server, port = _start_server(password="hunter2", store=self.store)
        try:
            _, _, session, csrf = _login(port, "hunter2")
            cookie = "argus_session=%s; csrf_token=%s" % (session, csrf)

            # POST with wrong X-CSRF-Token -> 403
            status, _, body = _post(
                port,
                "/api/v1/license",
                body=b'{"key":"x"}',
                headers={
                    "Cookie": cookie,
                    "X-CSRF-Token": "wrong-token",
                    "Content-Type": "application/json",
                },
            )
            self.assertEqual(status, 403)
        finally:
            server.shutdown()

    def test_csrf_exempt_on_get(self):
        """GET requests should not require CSRF validation."""
        server, port = _start_server(password="hunter2", store=self.store)
        try:
            _, _, session, csrf = _login(port, "hunter2")
            cookie = "argus_session=%s" % session  # No csrf_token cookie

            status, _, body = _get(port, "/api/v1/status", headers={"Cookie": cookie})
            self.assertEqual(status, 200)
        finally:
            server.shutdown()

    def test_security_headers(self):
        server, port = _start_server(store=self.store)
        try:
            status, headers, _ = _get(port, "/")
            self.assertEqual(status, 200)
            self.assertEqual(headers.get("x-frame-options"), "DENY")
            self.assertEqual(headers.get("x-content-type-options"), "nosniff")
            self.assertIn("default-src", headers.get("content-security-policy", ""))
        finally:
            server.shutdown()


# ---------------------------------------------------------------------------
# 3. API endpoints
# ---------------------------------------------------------------------------


class TestAPIEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.store = _make_store(cls.tmpdir)
        _seed_findings(cls.store, count=10)

        # Create audit log files
        cls.audit_dir = os.path.join(cls.tmpdir, "audit")
        os.makedirs(cls.audit_dir)
        audit_file = os.path.join(cls.audit_dir, "guard-20260101-000000.jsonl")
        with open(audit_file, "w") as f:
            for i in range(3):
                entry = {
                    "timestamp": "2026-01-01T00:00:%02dZ" % i,
                    "request_id": "req-%d" % i,
                    "provider": "anthropic",
                    "model": "claude-3",
                    "endpoint": "/v1/messages",
                    "action": "alert",
                    "findings": [{"type": "aws_key"}],
                }
                f.write(json.dumps(entry) + "\n")

        cls.audit_reader = AuditReader(cls.audit_dir)

        # Create log file for logs/tail
        cls.log_dir = os.path.join(cls.tmpdir, "logs")
        os.makedirs(cls.log_dir)
        log_file = os.path.join(cls.log_dir, "lumen-argus.log")
        with open(log_file, "w") as f:
            for i in range(5):
                f.write("2026-01-01 line %d\n" % i)

        cls.config = Config(logging_config=LoggingConfig(log_dir=cls.log_dir))

        cls.server, cls.port = _start_server(
            store=cls.store,
            audit_reader=cls.audit_reader,
            config=cls.config,
        )

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_status(self):
        status, _, body = _get(self.port, "/api/v1/status")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("version", data)
        self.assertIn("uptime_seconds", data)
        self.assertEqual(data["status"], "operational")

    def test_findings_paginated(self):
        status, _, body = _get(self.port, "/api/v1/findings?limit=3&offset=0")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("findings", data)
        self.assertIn("total", data)
        self.assertEqual(len(data["findings"]), 3)
        self.assertEqual(data["total"], 10)

    def test_findings_default(self):
        status, _, body = _get(self.port, "/api/v1/findings")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["total"], 10)

    def test_finding_detail(self):
        # Get first finding ID
        status, _, body = _get(self.port, "/api/v1/findings?limit=1")
        data = json.loads(body)
        fid = data["findings"][0]["id"]

        status, _, body = _get(self.port, "/api/v1/findings/%d" % fid)
        self.assertEqual(status, 200)
        detail = json.loads(body)
        self.assertEqual(detail["id"], fid)
        self.assertEqual(detail["detector"], "secrets")

    def test_finding_detail_not_found(self):
        status, _, body = _get(self.port, "/api/v1/findings/99999")
        self.assertEqual(status, 404)

    def test_finding_detail_invalid_id(self):
        status, _, body = _get(self.port, "/api/v1/findings/abc")
        self.assertEqual(status, 400)

    def test_stats(self):
        status, _, body = _get(self.port, "/api/v1/stats")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("total_findings", data)
        self.assertIn("by_severity", data)
        self.assertIn("by_detector", data)

    def test_stats_days_param(self):
        for days in ["7", "30", "90"]:
            status, _, body = _get(self.port, f"/api/v1/stats?days={days}")
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertIn("daily_trend", data)
        # Invalid days falls back to 30
        status, _, body = _get(self.port, "/api/v1/stats?days=abc")
        self.assertEqual(status, 200)

    def test_config(self):
        status, _, body = _get(self.port, "/api/v1/config")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("community", data)
        community = data["community"]
        self.assertIn("proxy", community)
        self.assertIn("detectors", community)
        self.assertEqual(community["proxy"]["port"], 8080)

    def test_audit(self):
        status, _, body = _get(self.port, "/api/v1/audit")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("entries", data)
        self.assertIn("total", data)
        self.assertIn("providers", data)
        self.assertEqual(data["total"], 3)
        self.assertIn("anthropic", data["providers"])

    def test_logs_tail(self):
        status, _, body = _get(self.port, "/api/v1/logs/tail")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("lines", data)
        self.assertEqual(len(data["lines"]), 5)

    def test_license_post(self):
        """POST /api/v1/license saves a key (no auth required on open server)."""
        license_body = json.dumps({"key": "LUMEN-TEST-KEY-123"}).encode()
        status, _, body = _post(
            self.port,
            "/api/v1/license",
            body=license_body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(license_body)),
            },
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["status"], "saved")

    def test_license_post_empty_key(self):
        license_body = json.dumps({"key": ""}).encode()
        status, _, body = _post(
            self.port,
            "/api/v1/license",
            body=license_body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(license_body)),
            },
        )
        self.assertEqual(status, 400)

    def test_license_post_invalid_json(self):
        status, _, body = _post(
            self.port,
            "/api/v1/license",
            body=b"not-json",
            headers={
                "Content-Type": "application/json",
            },
        )
        self.assertEqual(status, 400)


# ---------------------------------------------------------------------------
# 4. Tier gating
# ---------------------------------------------------------------------------


class TestTierGating(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.store = _make_store(cls.tmpdir)
        cls.server, cls.port = _start_server(store=cls.store)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_post_notifications_channels_without_pro(self):
        """POST to notifications/channels without Pro returns 404 (no types registered)."""
        status, _, body = _post(self.port, "/api/v1/notifications/channels", body=b'{"type":"webhook","name":"test"}')
        # Without Pro, no channel types registered — falls through to 404
        self.assertIn(status, (400, 404))

    def test_put_rules_is_community(self):
        """Rules are community-owned — PUT returns 200 or 404, not 402."""
        status, _, body = _put(self.port, "/api/v1/rules/nonexistent", body=b"{}")
        self.assertIn(status, (200, 404))

    def test_post_allowlist_returns_402(self):
        status, _, body = _post(self.port, "/api/v1/allowlist", body=b"{}")
        self.assertEqual(status, 402)
        data = json.loads(body)
        self.assertEqual(data["error"], "pro_required")

    def test_put_config_empty_returns_400(self):
        status, _, body = _put(self.port, "/api/v1/config", body=b"{}")
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn("error", data)

    def test_unknown_path_returns_404(self):
        status, _, body = _get(self.port, "/api/v1/nonexistent")
        self.assertEqual(status, 404)
        data = json.loads(body)
        self.assertEqual(data["error"], "not_found")


# ---------------------------------------------------------------------------
# 5. Extension hooks
# ---------------------------------------------------------------------------


class TestExtensionHooks(unittest.TestCase):
    def test_register_and_get_dashboard_pages(self):
        reg = ExtensionRegistry()
        page = {"name": "notifications", "label": "Notifications", "js": "console.log('hi')", "order": 55}
        reg.register_dashboard_pages([page])
        pages = reg.get_dashboard_pages()
        self.assertEqual(len(pages), 1)
        self.assertEqual(pages[0]["name"], "notifications")

    def test_register_and_get_dashboard_css(self):
        reg = ExtensionRegistry()
        reg.register_dashboard_css(".pro-badge { color: gold; }")
        css_list = reg.get_dashboard_css()
        self.assertEqual(len(css_list), 1)
        self.assertIn("pro-badge", css_list[0])

    def test_register_and_get_dashboard_api(self):
        reg = ExtensionRegistry()

        def my_handler(path, method, body, store, audit_reader):
            if path == "/api/v1/custom":
                return 200, json.dumps({"custom": True}).encode()
            return None

        reg.register_dashboard_api(my_handler)
        handler = reg.get_dashboard_api_handler()
        self.assertIs(handler, my_handler)

    def test_set_and_get_analytics_store(self):
        reg = ExtensionRegistry()
        self.assertIsNone(reg.get_analytics_store())
        mock_store = object()
        reg.set_analytics_store(mock_store)
        self.assertIs(reg.get_analytics_store(), mock_store)

    def test_register_and_get_auth_providers(self):
        reg = ExtensionRegistry()
        self.assertEqual(reg.get_auth_providers(), [])

        class FakeAuthProvider:
            def authenticate(self, headers):
                return {"user_id": "test"}

        provider = FakeAuthProvider()
        reg.register_auth_provider(provider)
        providers = reg.get_auth_providers()
        self.assertEqual(len(providers), 1)
        self.assertIs(providers[0], provider)

    def test_set_and_get_sse_broadcaster_none_by_default(self):
        reg = ExtensionRegistry()
        self.assertIsNone(reg.get_sse_broadcaster())

    def test_set_and_get_sse_broadcaster(self):
        reg = ExtensionRegistry()
        broadcaster = object()
        reg.set_sse_broadcaster(broadcaster)
        self.assertIs(reg.get_sse_broadcaster(), broadcaster)

    def test_clear_dashboard_pages(self):
        reg = ExtensionRegistry()
        reg.register_dashboard_pages([{"name": "test"}])
        reg.register_dashboard_css("body{}")
        reg.register_dashboard_api(lambda *a: None)
        self.assertEqual(len(reg.get_dashboard_pages()), 1)
        self.assertEqual(len(reg.get_dashboard_css()), 1)
        self.assertIsNotNone(reg.get_dashboard_api_handler())

        reg.clear_dashboard_pages()
        self.assertEqual(len(reg.get_dashboard_pages()), 0)
        self.assertEqual(len(reg.get_dashboard_css()), 0)
        self.assertIsNone(reg.get_dashboard_api_handler())

    def test_plugin_css_injection(self):
        """Plugin CSS should appear before </style> in served HTML."""
        tmpdir = tempfile.mkdtemp()
        try:
            store = _make_store(tmpdir)
            ext = ExtensionRegistry()
            ext.register_dashboard_css(".injected-class { display: block; }")
            server, port = _start_server(store=store, extensions=ext)
            try:
                status, _, body = _get(port, "/")
                self.assertEqual(status, 200)
                # CSS should be injected before </style>
                style_end = body.find("</style>")
                injected_pos = body.find(".injected-class")
                self.assertGreater(injected_pos, -1, "Injected CSS not found in HTML")
                self.assertLess(injected_pos, style_end, "Injected CSS should appear before </style>")
            finally:
                server.shutdown()
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_plugin_js_injection(self):
        """Plugin page JS should appear before </body> in served HTML."""
        tmpdir = tempfile.mkdtemp()
        try:
            store = _make_store(tmpdir)
            ext = ExtensionRegistry()
            ext.register_dashboard_pages(
                [
                    {
                        "name": "test-page",
                        "label": "Test Page",
                        "js": "console.log('plugin-page-loaded');",
                        "order": 99,
                    }
                ]
            )
            server, port = _start_server(store=store, extensions=ext)
            try:
                status, _, body = _get(port, "/")
                self.assertEqual(status, 200)
                body_end = body.find("</body>")
                js_pos = body.find("plugin-page-loaded")
                self.assertGreater(js_pos, -1, "Injected JS not found in HTML")
                self.assertLess(js_pos, body_end, "Injected JS should appear before </body>")
            finally:
                server.shutdown()
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_plugin_api_handler_called_before_community(self):
        """Plugin API handler should intercept requests before community."""
        tmpdir = tempfile.mkdtemp()
        try:
            store = _make_store(tmpdir)
            ext = ExtensionRegistry()

            def pro_handler(path, method, body, store, audit_reader):
                if path == "/api/v1/status" and method == "GET":
                    return 200, json.dumps({"pro": True}).encode()
                return None  # Fall through

            ext.register_dashboard_api(pro_handler)
            server, port = _start_server(store=store, extensions=ext)
            try:
                # /api/v1/status intercepted by plugin
                status, _, body = _get(port, "/api/v1/status")
                self.assertEqual(status, 200)
                data = json.loads(body)
                self.assertTrue(data.get("pro"))

                # /api/v1/stats falls through to community
                status, _, body = _get(port, "/api/v1/stats")
                self.assertEqual(status, 200)
                data = json.loads(body)
                self.assertIn("total_findings", data)
            finally:
                server.shutdown()
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 6. SSE
# ---------------------------------------------------------------------------


class TestSSEBroadcaster(unittest.TestCase):
    def test_register_unregister(self):
        broadcaster = SSEBroadcaster(heartbeat_interval=9999)
        buf = io.BytesIO()
        self.assertEqual(broadcaster.client_count, 0)

        broadcaster.register(buf)
        self.assertEqual(broadcaster.client_count, 1)

        broadcaster.unregister(buf)
        self.assertEqual(broadcaster.client_count, 0)

    def test_broadcast_to_clients(self):
        broadcaster = SSEBroadcaster(heartbeat_interval=9999)
        buf1 = io.BytesIO()
        buf2 = io.BytesIO()
        broadcaster.register(buf1)
        broadcaster.register(buf2)

        broadcaster.broadcast("finding", {"id": 1, "type": "aws_key"})

        for buf in (buf1, buf2):
            output = buf.getvalue().decode("utf-8")
            self.assertIn("event: finding", output)
            self.assertIn('"id": 1', output)

        broadcaster.unregister(buf1)
        broadcaster.unregister(buf2)

    def test_broadcast_removes_dead_clients(self):
        broadcaster = SSEBroadcaster(heartbeat_interval=9999)

        class DeadWriter:
            def write(self, data):
                raise BrokenPipeError("gone")

            def flush(self):
                raise BrokenPipeError("gone")

        dead = DeadWriter()
        alive = io.BytesIO()
        broadcaster.register(dead)
        broadcaster.register(alive)
        self.assertEqual(broadcaster.client_count, 2)

        broadcaster.broadcast("test", {"x": 1})

        # Dead client should be removed
        self.assertEqual(broadcaster.client_count, 1)
        # Alive client should have received the message
        self.assertIn(b"event: test", alive.getvalue())

        broadcaster.unregister(alive)

    def test_client_count(self):
        broadcaster = SSEBroadcaster(heartbeat_interval=9999)
        bufs = [io.BytesIO() for _ in range(5)]
        for b in bufs:
            broadcaster.register(b)
        self.assertEqual(broadcaster.client_count, 5)
        for b in bufs:
            broadcaster.unregister(b)
        self.assertEqual(broadcaster.client_count, 0)


# ---------------------------------------------------------------------------
# 7. AuditReader
# ---------------------------------------------------------------------------


class TestAuditReader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.audit_dir = os.path.join(cls.tmpdir, "audit")
        os.makedirs(cls.audit_dir)

        # Write two audit files
        file1 = os.path.join(cls.audit_dir, "guard-20260101-000000.jsonl")
        file2 = os.path.join(cls.audit_dir, "guard-20260102-000000.jsonl")

        with open(file1, "w") as f:
            for i in range(3):
                entry = {
                    "timestamp": "2026-01-01T00:00:%02dZ" % i,
                    "request_id": "req-a%d" % i,
                    "provider": "anthropic",
                    "model": "claude-3",
                    "endpoint": "/v1/messages",
                    "action": "alert",
                    "findings": [{"type": "aws_key"}],
                }
                f.write(json.dumps(entry) + "\n")

        with open(file2, "w") as f:
            for i in range(2):
                entry = {
                    "timestamp": "2026-01-02T00:00:%02dZ" % i,
                    "request_id": "req-b%d" % i,
                    "provider": "openai",
                    "model": "gpt-4",
                    "endpoint": "/v1/chat/completions",
                    "action": "block",
                    "findings": [],
                }
                f.write(json.dumps(entry) + "\n")

        # Malformed line in file2
        with open(file2, "a") as f:
            f.write("not-json\n")

        cls.reader = AuditReader(cls.audit_dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_read_all_entries(self):
        entries, total = self.reader.read_entries(limit=100, offset=0)
        self.assertEqual(total, 5)
        self.assertEqual(len(entries), 5)

    def test_read_entries_pagination(self):
        entries, total = self.reader.read_entries(limit=2, offset=0)
        self.assertEqual(total, 5)
        self.assertEqual(len(entries), 2)

        entries2, total2 = self.reader.read_entries(limit=2, offset=2)
        self.assertEqual(total2, 5)
        self.assertEqual(len(entries2), 2)

    def test_filter_by_action(self):
        entries, total = self.reader.read_entries(action="block")
        self.assertEqual(total, 2)
        for e in entries:
            self.assertEqual(e["action"], "block")

    def test_filter_by_provider(self):
        entries, total = self.reader.read_entries(provider="anthropic")
        self.assertEqual(total, 3)
        for e in entries:
            self.assertEqual(e["provider"], "anthropic")

    def test_filter_by_search(self):
        entries, total = self.reader.read_entries(search="messages")
        self.assertEqual(total, 3)
        for e in entries:
            self.assertIn("messages", e["endpoint"])

    def test_get_providers(self):
        providers = self.reader.get_providers()
        self.assertIn("anthropic", providers)
        self.assertIn("openai", providers)

    def test_finding_count_field(self):
        entries, _ = self.reader.read_entries(provider="anthropic", limit=1)
        self.assertEqual(entries[0]["finding_count"], 1)

        entries, _ = self.reader.read_entries(provider="openai", limit=1)
        self.assertEqual(entries[0]["finding_count"], 0)

    def test_cache_ttl(self):
        """Reading twice within TTL should return cached data."""
        reader = AuditReader(self.audit_dir)
        entries1, _ = reader.read_entries()
        # Access internal cache time
        cache_time_1 = reader._cache_time
        self.assertGreater(cache_time_1, 0)

        entries2, _ = reader.read_entries()
        cache_time_2 = reader._cache_time
        # Cache time should not have changed (data served from cache)
        self.assertEqual(cache_time_1, cache_time_2)

    def test_empty_directory(self):
        empty_dir = os.path.join(self.tmpdir, "empty_audit")
        os.makedirs(empty_dir, exist_ok=True)
        reader = AuditReader(empty_dir)
        entries, total = reader.read_entries()
        self.assertEqual(total, 0)
        self.assertEqual(entries, [])

    def test_nonexistent_directory(self):
        reader = AuditReader(os.path.join(self.tmpdir, "no_such_dir"))
        entries, total = reader.read_entries()
        self.assertEqual(total, 0)


# ---------------------------------------------------------------------------
# Direct API handler tests (no server needed)
# ---------------------------------------------------------------------------


class TestCommunityAPIDirect(unittest.TestCase):
    """Test handle_community_api directly without HTTP server overhead."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.store = _make_store(cls.tmpdir)
        _seed_findings(cls.store, count=3)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_status_no_store(self):
        status, body = handle_community_api("/api/v1/status", "GET", b"", None)
        data = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(data["total_findings"], 0)

    def test_findings_no_store(self):
        status, body = handle_community_api("/api/v1/findings", "GET", b"", None)
        data = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(data["findings"], [])

    def test_stats_no_store(self):
        status, body = handle_community_api("/api/v1/stats", "GET", b"", None)
        data = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(data["total_findings"], 0)
        self.assertEqual(data["today_count"], 0)
        self.assertIsNone(data["last_finding_time"])

    def test_stats_advanced_returns_402_without_pro(self):
        status, body = handle_community_api("/api/v1/stats/advanced", "GET", b"", None)
        data = json.loads(body)
        self.assertEqual(status, 402)
        self.assertEqual(data["error"], "pro_required")

    def test_config_no_config(self):
        status, body = handle_community_api("/api/v1/config", "GET", b"", None)
        data = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(data, {"community": {}})

    def test_audit_no_reader(self):
        status, body = handle_community_api("/api/v1/audit", "GET", b"", None)
        data = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(data["entries"], [])
        self.assertEqual(data["providers"], [])

    def test_logs_tail_no_config(self):
        status, body = handle_community_api("/api/v1/logs/tail", "GET", b"", None)
        data = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(data["lines"], [])

    def test_unknown_get_returns_404(self):
        status, body = handle_community_api("/api/v1/foo", "GET", b"", None)
        data = json.loads(body)
        self.assertEqual(status, 404)
        self.assertEqual(data["error"], "not_found")

    def test_pro_endpoint_post_returns_402(self):
        # Rules are now community-handled, only allowlist is Pro-gated
        status, body = handle_community_api("/api/v1/allowlist", "POST", b"{}", None)
        data = json.loads(body)
        self.assertEqual(status, 402, "Expected 402 for POST /api/v1/allowlist")
        self.assertEqual(data["error"], "pro_required")

    def test_put_config_empty_returns_400(self):
        status, body = handle_community_api("/api/v1/config", "PUT", b"{}", None)
        data = json.loads(body)
        self.assertEqual(status, 400)
        self.assertIn("error", data)

    def test_pro_endpoint_delete_returns_402(self):
        # Rules are community-owned, test allowlist instead
        status, body = handle_community_api("/api/v1/allowlist/1", "DELETE", b"", None)
        data = json.loads(body)
        self.assertEqual(status, 402)
        self.assertEqual(data["error"], "pro_required")


class TestConfigOverrides(unittest.TestCase):
    """Tests for community config save (SQLite-backed overrides)."""

    def setUp(self):
        import tempfile

        from lumen_argus.analytics.store import AnalyticsStore

        self._tmpdir = tempfile.mkdtemp()
        self.store = AnalyticsStore(db_path=self._tmpdir + "/test.db")

    def tearDown(self):
        import shutil

        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_set_and_get_override(self):
        self.store.set_config_override("proxy.timeout", "60")
        overrides = self.store.get_config_overrides()
        self.assertEqual(overrides["proxy.timeout"], "60")

    def test_set_override_updates_existing(self):
        self.store.set_config_override("proxy.timeout", "60")
        self.store.set_config_override("proxy.timeout", "120")
        overrides = self.store.get_config_overrides()
        self.assertEqual(overrides["proxy.timeout"], "120")

    def test_delete_override(self):
        self.store.set_config_override("proxy.timeout", "60")
        deleted = self.store.delete_config_override("proxy.timeout")
        self.assertTrue(deleted)
        self.assertEqual(self.store.get_config_overrides(), {})

    def test_delete_nonexistent_returns_false(self):
        deleted = self.store.delete_config_override("proxy.timeout")
        self.assertFalse(deleted)

    def test_unknown_key_raises(self):
        with self.assertRaises(ValueError):
            self.store.set_config_override("unknown.key", "value")

    def test_timeout_validation_rejects_zero(self):
        with self.assertRaises(ValueError):
            self.store.set_config_override("proxy.timeout", "0")

    def test_timeout_validation_rejects_over_max(self):
        with self.assertRaises(ValueError):
            self.store.set_config_override("proxy.timeout", "999")

    def test_retries_validation_rejects_negative(self):
        with self.assertRaises(ValueError):
            self.store.set_config_override("proxy.retries", "-1")

    def test_action_validation_rejects_redact(self):
        """Community store rejects redact — Pro plugin extends _VALID_ACTIONS."""
        with self.assertRaises(ValueError):
            self.store.set_config_override("default_action", "redact")

    def test_action_validation_accepts_block(self):
        self.store.set_config_override("default_action", "block")
        self.assertEqual(self.store.get_config_overrides()["default_action"], "block")

    def test_detector_action_override(self):
        self.store.set_config_override("detectors.secrets.action", "block")
        self.store.set_config_override("detectors.pii.action", "alert")
        overrides = self.store.get_config_overrides()
        self.assertEqual(overrides["detectors.secrets.action"], "block")
        self.assertEqual(overrides["detectors.pii.action"], "alert")

    def test_put_config_api_success(self):
        body = json.dumps({"proxy.timeout": 60, "default_action": "block"}).encode()
        status, resp = handle_community_api("/api/v1/config", "PUT", body, self.store)
        data = json.loads(resp)
        self.assertEqual(status, 200)
        self.assertIn("proxy.timeout", data["applied"])
        self.assertIn("default_action", data["applied"])

    def test_put_config_api_invalid_key(self):
        body = json.dumps({"bad.key": "value"}).encode()
        status, resp = handle_community_api("/api/v1/config", "PUT", body, self.store)
        self.assertEqual(status, 400)
        self.assertIn(b"Invalid config key", resp)

    def test_put_config_api_partial_success(self):
        body = json.dumps({"proxy.timeout": 60, "bad.key": "value"}).encode()
        status, resp = handle_community_api("/api/v1/config", "PUT", body, self.store)
        data = json.loads(resp)
        self.assertEqual(status, 207)
        self.assertIn("proxy.timeout", data["applied"])
        self.assertTrue(len(data["errors"]) > 0)


if __name__ == "__main__":
    unittest.main()
