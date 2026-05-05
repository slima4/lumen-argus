"""Tests for mitmproxy addon (host filtering, header injection, routing)."""

import unittest
from unittest import mock

from lumen_argus_agent.mitm_addon import SCAN_HOSTS, LumenArgusAddon


class TestScanHosts(unittest.TestCase):
    """Test the default scan host set."""

    def test_copilot_hosts_included(self):
        self.assertIn("api.individual.githubcopilot.com", SCAN_HOSTS)
        self.assertIn("api.business.githubcopilot.com", SCAN_HOSTS)

    def test_standard_providers_included(self):
        self.assertIn("api.anthropic.com", SCAN_HOSTS)
        self.assertIn("api.openai.com", SCAN_HOSTS)
        self.assertIn("generativelanguage.googleapis.com", SCAN_HOSTS)

    def test_warp_included(self):
        self.assertIn("app.warp.dev", SCAN_HOSTS)


class TestHostFiltering(unittest.TestCase):
    """Test addon host filtering logic."""

    def setUp(self):
        self.addon = LumenArgusAddon(upstream_proxy="http://localhost:8080")

    def test_intercept_copilot(self):
        self.assertTrue(self.addon._should_intercept("api.individual.githubcopilot.com"))

    def test_intercept_anthropic(self):
        self.assertTrue(self.addon._should_intercept("api.anthropic.com"))

    def test_skip_github_api(self):
        self.assertFalse(self.addon._should_intercept("api.github.com"))

    def test_skip_npm(self):
        self.assertFalse(self.addon._should_intercept("registry.npmjs.org"))

    def test_skip_google(self):
        self.assertFalse(self.addon._should_intercept("www.google.com"))

    def test_extra_scan_hosts(self):
        addon = LumenArgusAddon(
            upstream_proxy="http://localhost:8080",
            extra_scan_hosts=frozenset({"custom-ai.example.com"}),
        )
        self.assertTrue(addon._should_intercept("custom-ai.example.com"))
        self.assertTrue(addon._should_intercept("api.anthropic.com"))


class TestAddonConfig(unittest.TestCase):
    """Test addon initialization."""

    def test_default_proxy(self):
        addon = LumenArgusAddon()
        self.assertEqual(addon._proxy_host, "localhost")
        self.assertEqual(addon._proxy_port, 8080)
        self.assertEqual(addon._proxy_scheme, "http")

    def test_custom_proxy(self):
        addon = LumenArgusAddon(upstream_proxy="https://proxy.example.com:9090")
        self.assertEqual(addon._proxy_host, "proxy.example.com")
        self.assertEqual(addon._proxy_port, 9090)
        self.assertEqual(addon._proxy_scheme, "https")

    def test_agent_credentials(self):
        addon = LumenArgusAddon(
            agent_token="tok_123",
            agent_id="agent_abc",
            machine_id="machine_xyz",
        )
        self.assertEqual(addon._agent_token, "tok_123")
        self.assertEqual(addon._agent_id, "agent_abc")
        self.assertEqual(addon._machine_id, "machine_xyz")


class TestRequestInterception(unittest.TestCase):
    """Test addon request handler."""

    def setUp(self):
        self.addon = LumenArgusAddon(
            upstream_proxy="http://localhost:8080",
            agent_token="tok_test",
            agent_id="agent_test",
        )

    def _make_flow(self, host, port=443, scheme="https", path="/v1/responses", method="POST"):
        """Create a mock mitmproxy flow."""
        flow = mock.MagicMock()
        flow.request.pretty_host = host
        flow.request.port = port
        flow.request.scheme = scheme
        flow.request.path = path
        flow.request.method = method
        flow.request.headers = {}
        flow.client_conn = mock.MagicMock()
        flow.client_conn.peername = ("127.0.0.1", 54321)
        return flow

    @mock.patch("lumen_argus_agent.context.resolve_context")
    def test_intercepts_copilot(self, mock_resolve):
        mock_resolve.return_value = mock.MagicMock(
            working_directory="/Users/test/project",
            git_branch="main",
            os_platform="darwin",
            hostname="test-mac",
            username="testuser",
            client_pid=1234,
        )

        flow = self._make_flow("api.individual.githubcopilot.com")
        self.addon.request(flow)

        # Should re-route to proxy
        self.assertEqual(flow.request.host, "localhost")
        self.assertEqual(flow.request.port, 8080)
        self.assertEqual(flow.request.scheme, "http")
        self.assertTrue(flow.request.path.startswith("/_forward"))

        # Should set forward headers
        self.assertEqual(flow.request.headers["x-lumen-forward-host"], "api.individual.githubcopilot.com")
        self.assertEqual(flow.request.headers["x-lumen-forward-scheme"], "https")

        # Should set identity headers
        self.assertEqual(flow.request.headers["x-lumen-argus-working-dir"], "/Users/test/project")
        self.assertEqual(flow.request.headers["x-lumen-argus-hostname"], "test-mac")
        self.assertEqual(flow.request.headers["x-lumen-argus-username"], "testuser")
        self.assertEqual(flow.request.headers["x-lumen-argus-agent-token"], "tok_test")
        self.assertEqual(flow.request.headers["x-lumen-argus-agent-id"], "agent_test")

    def test_skips_non_ai_host(self):
        flow = self._make_flow("api.github.com")
        original_host = flow.request.host
        self.addon.request(flow)

        # Should NOT modify the request
        self.assertEqual(flow.request.host, original_host)

    @mock.patch("lumen_argus_agent.context.resolve_context")
    def test_preserves_path(self, mock_resolve):
        mock_resolve.return_value = mock.MagicMock(
            working_directory="",
            git_branch="",
            os_platform="",
            hostname="",
            username="",
            client_pid=0,
        )
        flow = self._make_flow("api.anthropic.com", path="/v1/messages")
        self.addon.request(flow)
        self.assertEqual(flow.request.path, "/_forward/v1/messages")

    @mock.patch("lumen_argus_agent.context.resolve_context")
    def test_non_standard_port_included(self, mock_resolve):
        mock_resolve.return_value = mock.MagicMock(
            working_directory="",
            git_branch="",
            os_platform="",
            hostname="",
            username="",
            client_pid=0,
        )
        flow = self._make_flow("api.openai.com", port=8443)
        self.addon.request(flow)
        self.assertEqual(flow.request.headers["x-lumen-forward-port"], "8443")

    @mock.patch("lumen_argus_agent.context.resolve_context")
    def test_standard_port_not_included(self, mock_resolve):
        mock_resolve.return_value = mock.MagicMock(
            working_directory="",
            git_branch="",
            os_platform="",
            hostname="",
            username="",
            client_pid=0,
        )
        flow = self._make_flow("api.openai.com", port=443)
        self.addon.request(flow)
        self.assertNotIn("x-lumen-forward-port", flow.request.headers)


class TestGitHubAccountExtraction(unittest.TestCase):
    """Test GitHub account_id extraction from /copilot_internal/user."""

    def test_extracts_login_from_response(self):
        import json

        addon = LumenArgusAddon()
        flow = mock.MagicMock()
        flow.request.pretty_host = "api.github.com"
        flow.request.path = "/copilot_internal/user"
        flow.response.status_code = 200
        flow.response.content = json.dumps({"login": "testuser", "copilot_plan": "individual"}).encode()
        flow.response.headers = {}

        addon.response(flow)
        self.assertEqual(addon._github_login, "testuser")

    def test_skips_non_github_host(self):
        addon = LumenArgusAddon()
        flow = mock.MagicMock()
        flow.request.pretty_host = "api.openai.com"
        flow.request.path = "/copilot_internal/user"
        flow.response.status_code = 200
        flow.response.content = b'{"login": "testuser"}'
        flow.response.headers = {}

        addon.response(flow)
        self.assertEqual(addon._github_login, "")

    def test_skips_non_200(self):
        addon = LumenArgusAddon()
        flow = mock.MagicMock()
        flow.request.pretty_host = "api.github.com"
        flow.request.path = "/copilot_internal/user"
        flow.response.status_code = 401
        flow.response.content = b'{"message": "unauthorized"}'
        flow.response.headers = {}

        addon.response(flow)
        self.assertEqual(addon._github_login, "")

    def test_cached_login_not_overwritten(self):
        addon = LumenArgusAddon()
        addon._github_login = "existing_user"
        flow = mock.MagicMock()
        flow.request.pretty_host = "api.github.com"
        flow.request.path = "/copilot_internal/user"
        flow.response.status_code = 200
        flow.response.content = b'{"login": "new_user"}'
        flow.response.headers = {}

        addon.response(flow)
        self.assertEqual(addon._github_login, "existing_user")

    @mock.patch("lumen_argus_agent.context.resolve_context")
    def test_login_injected_into_request(self, mock_resolve):
        mock_resolve.return_value = mock.MagicMock(
            working_directory="",
            git_branch="",
            os_platform="",
            hostname="",
            username="",
            client_pid=0,
        )
        addon = LumenArgusAddon(upstream_proxy="http://localhost:8080")
        addon._github_login = "slima4"
        flow = mock.MagicMock()
        flow.request.pretty_host = "api.individual.githubcopilot.com"
        flow.request.port = 443
        flow.request.scheme = "https"
        flow.request.path = "/responses"
        flow.request.method = "POST"
        flow.request.headers = {}
        flow.client_conn = mock.MagicMock()
        flow.client_conn.peername = ("127.0.0.1", 54321)

        addon.request(flow)
        self.assertEqual(flow.request.headers["x-lumen-argus-account-id"], "slima4")


class TestRequestSpoofingDefence(unittest.TestCase):
    """Regression tests for issue #76 — caller-supplied x-lumen-argus-* spoofing.

    A local process speaking HTTPS through the forward proxy must not be able
    to attribute its activity to a different identity by pre-setting any
    x-lumen-argus-* header. mitmproxy's ``Headers`` is case-insensitive on
    __setitem__, but the inject pass must also drop fields the agent
    *chooses not to set* (empty ctx, privacy flags off, no GitHub login).
    """

    def setUp(self):
        from mitmproxy.http import Headers

        self.Headers = Headers
        self.addon = LumenArgusAddon(
            upstream_proxy="http://localhost:8080",
            agent_token="tok_test",
            agent_id="agent_test",
        )

    def _make_flow(self, headers, host="api.individual.githubcopilot.com"):
        flow = mock.MagicMock()
        flow.request.pretty_host = host
        flow.request.port = 443
        flow.request.scheme = "https"
        flow.request.path = "/v1/responses"
        flow.request.method = "POST"
        flow.request.headers = headers
        flow.client_conn = mock.MagicMock()
        flow.client_conn.peername = ("127.0.0.1", 54321)
        return flow

    @mock.patch("lumen_argus_agent.context.resolve_context")
    def test_strips_caller_lumen_headers_when_agent_sets_field(self, mock_resolve):
        mock_resolve.return_value = mock.MagicMock(
            working_directory="/genuine/path",
            git_branch="main",
            os_platform="darwin",
            hostname="genuine-host",
            username="genuine-user",
            client_pid=4242,
        )
        headers = self.Headers(
            [
                (b"x-lumen-argus-working-dir", b"SPOOF"),
                (b"X-LUMEN-ARGUS-USERNAME", b"SPOOF"),
                (b"X-Lumen-Argus-Hostname", b"SPOOF"),
            ]
        )
        flow = self._make_flow(headers)

        self.addon.request(flow)

        self.assertEqual(flow.request.headers["x-lumen-argus-working-dir"], "/genuine/path")
        self.assertEqual(flow.request.headers["x-lumen-argus-username"], "genuine-user")
        self.assertEqual(flow.request.headers["x-lumen-argus-hostname"], "genuine-host")
        self.assertNotIn("SPOOF", list(flow.request.headers.values()))

    @mock.patch("lumen_argus_agent.context.resolve_context")
    def test_strips_caller_lumen_headers_when_agent_skips_field(self, mock_resolve):
        """Empty ctx + no GitHub login + agent-token/id absent — caller's spoofs must still die."""
        mock_resolve.return_value = mock.MagicMock(
            working_directory="",
            git_branch="",
            os_platform="",
            hostname="",
            username="",
            client_pid=0,
        )
        addon = LumenArgusAddon(upstream_proxy="http://localhost:8080")  # no agent_token, no agent_id
        headers = self.Headers(
            [
                (b"x-lumen-argus-working-dir", b"SPOOF-cwd"),
                (b"X-Lumen-Argus-Hostname", b"SPOOF-host"),
                (b"x-lumen-argus-account-id", b"SPOOF-acct"),
                (b"x-lumen-argus-bogus-field", b"SPOOF"),
                (b"x-lumen-argus-agent-token", b"SPOOF-tok"),
            ]
        )
        flow = self._make_flow(headers)

        addon.request(flow)

        for key in flow.request.headers.keys():
            self.assertFalse(
                key.lower().startswith("x-lumen-argus-"),
                f"caller-supplied lumen header survived inject: {key!r}",
            )

    @mock.patch("lumen_argus_agent.context.resolve_context")
    def test_caller_account_id_replaced_by_cached_github_login(self, mock_resolve):
        """Spoofed x-lumen-argus-account-id must be overwritten by cached _github_login.

        ``_github_login`` is resolved server-side from the Copilot
        ``/copilot_internal/user`` response and cached on the addon
        instance. Once cached, it is injected on every subsequent request.
        A local process pre-setting ``x-lumen-argus-account-id: SPOOF``
        must not survive the strip + write.
        """
        mock_resolve.return_value = mock.MagicMock(
            working_directory="",
            git_branch="",
            os_platform="darwin",
            hostname="",
            username="",
            client_pid=0,
        )
        addon = LumenArgusAddon(upstream_proxy="http://localhost:8080", agent_id="agent_test")
        addon._github_login = "real_login"
        headers = self.Headers([(b"x-lumen-argus-account-id", b"SPOOF-acct")])
        flow = self._make_flow(headers)

        addon.request(flow)

        self.assertEqual(flow.request.headers["x-lumen-argus-account-id"], "real_login")
        self.assertEqual(flow.request.headers.get_all("x-lumen-argus-account-id"), ["real_login"])

    @mock.patch("lumen_argus_agent.context.resolve_context")
    def test_caller_account_id_dropped_when_no_github_login_resolved(self, mock_resolve):
        """Before _github_login is resolved, no caller-supplied account-id may survive.

        The strip must drop the spoofed account-id even though the addon
        does not write its own value (login not yet cached).
        """
        mock_resolve.return_value = mock.MagicMock(
            working_directory="",
            git_branch="",
            os_platform="",
            hostname="",
            username="",
            client_pid=0,
        )
        addon = LumenArgusAddon(upstream_proxy="http://localhost:8080")
        # _github_login left at default ""
        headers = self.Headers([(b"x-lumen-argus-account-id", b"SPOOF-acct")])
        flow = self._make_flow(headers)

        addon.request(flow)

        self.assertNotIn("x-lumen-argus-account-id", flow.request.headers)

    @mock.patch("lumen_argus_agent.context.resolve_context")
    def test_preserves_non_lumen_headers(self, mock_resolve):
        mock_resolve.return_value = mock.MagicMock(
            working_directory="",
            git_branch="",
            os_platform="darwin",
            hostname="",
            username="",
            client_pid=0,
        )
        headers = self.Headers(
            [
                (b"Authorization", b"Bearer real-token"),
                (b"User-Agent", b"copilot-cli/1.0"),
                (b"x-lumen-argus-working-dir", b"SPOOF"),
            ]
        )
        flow = self._make_flow(headers)

        self.addon.request(flow)

        self.assertEqual(flow.request.headers["Authorization"], "Bearer real-token")
        self.assertEqual(flow.request.headers["User-Agent"], "copilot-cli/1.0")
        self.assertNotIn("SPOOF", list(flow.request.headers.values()))


class TestResponseStripping(unittest.TestCase):
    """Test addon response handler."""

    def test_strips_lumen_headers(self):
        addon = LumenArgusAddon()
        flow = mock.MagicMock()
        flow.response.headers = {
            "Content-Type": "application/json",
            "x-lumen-argus-working-dir": "/tmp",
            "x-lumen-forward-host": "api.openai.com",
            "X-Request-Id": "abc123",
        }
        addon.response(flow)
        # Lumen headers should be removed
        self.assertNotIn("x-lumen-argus-working-dir", flow.response.headers)
        self.assertNotIn("x-lumen-forward-host", flow.response.headers)
        # Other headers preserved
        self.assertIn("Content-Type", flow.response.headers)
        self.assertIn("X-Request-Id", flow.response.headers)


if __name__ == "__main__":
    unittest.main()
