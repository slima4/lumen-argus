"""Tests for the agent relay forwarding proxy."""

import json
import os
import unittest

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop
from lumen_argus_agent.context import CallerContext
from lumen_argus_agent.relay import (
    _RELAY_KEY,
    AgentRelay,
    RelayConfig,
    _build_forward_headers,
    _inject_identity_headers,
    _resolve_direct_upstream,
)


class TestResolveDirectUpstream(unittest.TestCase):
    """Provider routing for direct (fail-open) forwarding."""

    def test_anthropic_messages(self):
        url, provider = _resolve_direct_upstream("/v1/messages", {"x-api-key": "sk-ant-123"})
        self.assertEqual(provider, "anthropic")
        self.assertIn("anthropic", url)

    def test_openai_chat(self):
        url, provider = _resolve_direct_upstream("/v1/chat/completions", {})
        self.assertEqual(provider, "openai")
        self.assertIn("openai", url)

    def test_openai_embeddings(self):
        _url, provider = _resolve_direct_upstream("/v1/embeddings", {})
        self.assertEqual(provider, "openai")

    def test_gemini_generate(self):
        _url, provider = _resolve_direct_upstream("/v1beta/models/gemini:generateContent", {})
        self.assertEqual(provider, "gemini")

    def test_header_detection_anthropic(self):
        _url, provider = _resolve_direct_upstream("/custom", {"x-api-key": "test"})
        self.assertEqual(provider, "anthropic")

    def test_header_detection_openai_bearer(self):
        _url, provider = _resolve_direct_upstream("/custom", {"authorization": "Bearer sk-proj-123"})
        self.assertEqual(provider, "openai")

    def test_default_anthropic(self):
        _url, provider = _resolve_direct_upstream("/unknown", {})
        self.assertEqual(provider, "anthropic")


class TestInjectIdentityHeaders(unittest.TestCase):
    """X-Lumen-* header injection."""

    def test_enrolled_agent(self):
        headers: dict[str, str] = {}
        config = RelayConfig(agent_id="agent_abc123", machine_id="mac_def456")
        ctx = CallerContext(
            working_directory="/Users/dev/proj",
            git_branch="main",
            os_platform="darwin",
            hostname="macbook",
            username="slim",
            client_pid=12345,
        )
        _inject_identity_headers(headers, config, ctx)

        self.assertEqual(headers["X-Lumen-Argus-Agent-Id"], "agent_abc123")
        self.assertEqual(headers["X-Lumen-Argus-Device-Id"], "mac_def456")
        self.assertEqual(headers["X-Lumen-Argus-Working-Dir"], "/Users/dev/proj")
        self.assertEqual(headers["X-Lumen-Argus-Git-Branch"], "main")
        self.assertEqual(headers["X-Lumen-Argus-OS-Platform"], "darwin")
        self.assertEqual(headers["X-Lumen-Argus-Hostname"], "macbook")
        self.assertEqual(headers["X-Lumen-Argus-Username"], "slim")
        self.assertEqual(headers["X-Lumen-Argus-Client-PID"], "12345")

    def test_not_enrolled_skips_agent_fields(self):
        headers: dict[str, str] = {}
        config = RelayConfig()  # no agent_id, no machine_id
        ctx = CallerContext(os_platform="linux", hostname="dev-box", username="user")
        _inject_identity_headers(headers, config, ctx)

        self.assertNotIn("X-Lumen-Argus-Agent-Id", headers)
        self.assertNotIn("X-Lumen-Argus-Device-Id", headers)
        self.assertEqual(headers["X-Lumen-Argus-OS-Platform"], "linux")
        self.assertEqual(headers["X-Lumen-Argus-Hostname"], "dev-box")
        self.assertEqual(headers["X-Lumen-Argus-Username"], "user")

    def test_empty_fields_not_injected(self):
        headers: dict[str, str] = {}
        config = RelayConfig()
        ctx = CallerContext()  # all empty
        _inject_identity_headers(headers, config, ctx)

        # No X-Lumen-* headers should be present
        lumen_headers = [k for k in headers if k.lower().startswith("x-lumen-argus-")]
        self.assertEqual(lumen_headers, [])

    def test_send_username_false_omits_header(self):
        headers: dict[str, str] = {}
        config = RelayConfig(send_username=False, send_hostname=True)
        ctx = CallerContext(hostname="macbook", username="slim")
        _inject_identity_headers(headers, config, ctx)

        self.assertNotIn("X-Lumen-Argus-Username", headers)
        self.assertEqual(headers["X-Lumen-Argus-Hostname"], "macbook")

    def test_root_cwd_not_injected(self):
        """Root '/' cwd is meaningless (e.g. Node.js process) — don't send it."""
        headers: dict[str, str] = {}
        config = RelayConfig()
        ctx = CallerContext(working_directory="/", os_platform="darwin")
        _inject_identity_headers(headers, config, ctx)

        self.assertNotIn("X-Lumen-Argus-Working-Dir", headers)
        self.assertEqual(headers["X-Lumen-Argus-OS-Platform"], "darwin")

    def test_send_hostname_false_omits_header(self):
        headers: dict[str, str] = {}
        config = RelayConfig(send_username=True, send_hostname=False)
        ctx = CallerContext(hostname="macbook", username="slim")
        _inject_identity_headers(headers, config, ctx)

        self.assertEqual(headers["X-Lumen-Argus-Username"], "slim")
        self.assertNotIn("X-Lumen-Argus-Hostname", headers)

    def test_both_privacy_flags_false(self):
        headers: dict[str, str] = {}
        config = RelayConfig(send_username=False, send_hostname=False)
        ctx = CallerContext(hostname="macbook", username="slim", os_platform="darwin")
        _inject_identity_headers(headers, config, ctx)

        self.assertNotIn("X-Lumen-Argus-Username", headers)
        self.assertNotIn("X-Lumen-Argus-Hostname", headers)
        # Other headers still injected
        self.assertEqual(headers["X-Lumen-Argus-OS-Platform"], "darwin")

    def test_does_not_overwrite_existing(self):
        headers = {"Authorization": "Bearer sk-ant-123", "x-api-key": "test"}
        config = RelayConfig(agent_id="agent_test")
        ctx = CallerContext(os_platform="darwin")
        _inject_identity_headers(headers, config, ctx)

        # Original headers preserved
        self.assertEqual(headers["Authorization"], "Bearer sk-ant-123")
        self.assertEqual(headers["x-api-key"], "test")
        # Identity headers added
        self.assertEqual(headers["X-Lumen-Argus-Agent-Id"], "agent_test")


class TestBuildForwardHeaders(unittest.TestCase):
    """Forward header construction."""

    def _make_request(self, headers: dict[str, str], body: bytes = b"{}") -> web.Request:
        """Create a minimal mock request for header testing."""
        from aiohttp.test_utils import make_mocked_request
        from multidict import CIMultiDict

        return make_mocked_request("POST", "/v1/messages", headers=CIMultiDict(headers))

    def test_strips_hop_by_hop(self):
        req = self._make_request({"Connection": "keep-alive", "x-api-key": "test"})
        fwd = _build_forward_headers(req, b"{}")
        self.assertNotIn("Connection", fwd)
        self.assertNotIn("connection", fwd)
        self.assertIn("x-api-key", fwd)

    def test_strips_host_and_accept_encoding(self):
        req = self._make_request({"Host": "localhost:8070", "Accept-Encoding": "gzip"})
        fwd = _build_forward_headers(req, b"{}")
        self.assertNotIn("Host", fwd)
        self.assertNotIn("Accept-Encoding", fwd)

    def test_recalculates_content_length(self):
        body = b'{"test": true}'
        req = self._make_request({"Content-Length": "999"}, body)
        fwd = _build_forward_headers(req, body)
        self.assertEqual(fwd["Content-Length"], str(len(body)))


class TestAgentRelayHealth(AioHTTPTestCase):
    """Test relay health endpoint."""

    async def get_application(self):
        config = RelayConfig(upstream_url="http://localhost:19999")
        relay = AgentRelay(config)
        app = web.Application()
        from lumen_argus_agent.relay import _RELAY_KEY, _handle_request

        app[_RELAY_KEY] = relay
        app.router.add_route("*", "/{path_info:.*}", _handle_request)
        return app

    @unittest_run_loop
    async def test_health_endpoint(self):
        resp = await self.client.get("/health")
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["upstream"], "unhealthy")
        self.assertEqual(data["fail_mode"], "open")
        self.assertFalse(data["enrolled"])
        self.assertIn("uptime", data)

    @unittest_run_loop
    async def test_health_enrolled(self):
        relay = self.app[_RELAY_KEY]
        relay.config.agent_id = "agent_test123"
        resp = await self.client.get("/health")
        data = await resp.json()
        self.assertTrue(data["enrolled"])
        self.assertEqual(data["agent_id"], "agent_test123")


class TestAgentRelayForwarding(AioHTTPTestCase):
    """Test relay forwarding to upstream proxy."""

    async def get_application(self):
        # Create a mock upstream that records requests
        self._upstream_requests: list[web.Request] = []
        self._upstream_bodies: list[bytes] = []
        self._upstream_headers: list[dict[str, str]] = []

        async def mock_upstream(request: web.Request) -> web.Response:
            body = await request.read()
            self._upstream_bodies.append(body)
            self._upstream_headers.append(dict(request.headers))
            return web.json_response({"response": "ok"})

        async def mock_upstream_sse(request: web.Request) -> web.StreamResponse:
            body = await request.read()
            self._upstream_bodies.append(body)
            self._upstream_headers.append(dict(request.headers))
            resp = web.StreamResponse(
                status=200,
                headers={"Content-Type": "text/event-stream"},
            )
            await resp.prepare(request)
            for chunk in [b"data: chunk1\n\n", b"data: chunk2\n\n", b"data: [DONE]\n\n"]:
                await resp.write(chunk)
            await resp.write_eof()
            return resp

        async def mock_health(request: web.Request) -> web.Response:
            return web.json_response({"status": "ok"})

        # Build upstream app
        upstream_app = web.Application()
        upstream_app.router.add_post("/v1/messages", mock_upstream)
        upstream_app.router.add_post("/v1/messages/stream", mock_upstream_sse)
        upstream_app.router.add_get("/health", mock_health)

        # Start upstream on a random port
        runner = web.AppRunner(upstream_app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        # Get the actual port
        self._upstream_port = site._server.sockets[0].getsockname()[1]
        self._upstream_runner = runner

        # Build relay pointing to mock upstream
        config = RelayConfig(
            upstream_url="http://127.0.0.1:%d" % self._upstream_port,
            agent_id="agent_test",
            machine_id="mac_test",
        )
        relay = AgentRelay(config)
        relay._upstream_healthy = True  # Skip health check for tests

        app = web.Application()
        from lumen_argus_agent.relay import _RELAY_KEY, _handle_request

        app[_RELAY_KEY] = relay
        app.router.add_route("*", "/{path_info:.*}", _handle_request)

        # Store relay for session management
        self._relay = relay
        return app

    async def setUpAsync(self):
        await super().setUpAsync()
        # Create upstream session for relay
        import aiohttp as aio

        self._relay._upstream_session = aio.ClientSession(auto_decompress=False)

    async def tearDownAsync(self):
        if self._relay._upstream_session:
            await self._relay._upstream_session.close()
        await self._upstream_runner.cleanup()
        await super().tearDownAsync()

    @unittest_run_loop
    async def test_forwards_request(self):
        resp = await self.client.post(
            "/v1/messages",
            json={"model": "claude-sonnet-4-20250514", "messages": [{"role": "user", "content": "hello"}]},
        )
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertEqual(data["response"], "ok")

    @unittest_run_loop
    async def test_injects_identity_headers(self):
        await self.client.post(
            "/v1/messages",
            json={"model": "test"},
            headers={"x-api-key": "sk-ant-test"},
        )
        self.assertEqual(len(self._upstream_headers), 1)
        h = self._upstream_headers[0]
        self.assertEqual(h.get("X-Lumen-Argus-Agent-Id"), "agent_test")
        self.assertEqual(h.get("X-Lumen-Argus-Device-Id"), "mac_test")
        # OS-level fields should be present
        self.assertIn("X-Lumen-Argus-OS-Platform", h)
        self.assertIn("X-Lumen-Argus-Hostname", h)
        self.assertIn("X-Lumen-Argus-Username", h)

    @unittest_run_loop
    async def test_preserves_original_headers(self):
        await self.client.post(
            "/v1/messages",
            json={"model": "test"},
            headers={"x-api-key": "sk-ant-my-key", "anthropic-version": "2024-01-01"},
        )
        h = self._upstream_headers[0]
        # aiohttp normalizes header names to title case
        h_lower = {k.lower(): v for k, v in h.items()}
        self.assertEqual(h_lower.get("x-api-key"), "sk-ant-my-key")
        self.assertEqual(h_lower.get("anthropic-version"), "2024-01-01")

    @unittest_run_loop
    async def test_forwards_body(self):
        body = {"model": "claude-sonnet-4-20250514", "messages": [{"role": "user", "content": "test"}]}
        await self.client.post("/v1/messages", json=body)
        received = json.loads(self._upstream_bodies[0])
        self.assertEqual(received["model"], "claude-sonnet-4-20250514")
        self.assertEqual(received["messages"][0]["content"], "test")

    @unittest_run_loop
    async def test_sse_streaming(self):
        resp = await self.client.post(
            "/v1/messages/stream",
            json={"model": "test", "stream": True},
        )
        self.assertEqual(resp.status, 200)
        body = await resp.read()
        self.assertIn(b"data: chunk1", body)
        self.assertIn(b"data: chunk2", body)
        self.assertIn(b"data: [DONE]", body)


class TestAgentRelayFailMode(AioHTTPTestCase):
    """Test fail-open and fail-closed behavior."""

    async def get_application(self):
        # Upstream on unreachable port
        config = RelayConfig(
            upstream_url="http://127.0.0.1:19999",
            fail_mode="closed",
        )
        relay = AgentRelay(config)
        relay._upstream_healthy = False

        app = web.Application()
        from lumen_argus_agent.relay import _RELAY_KEY, _handle_request

        app[_RELAY_KEY] = relay
        app.router.add_route("*", "/{path_info:.*}", _handle_request)
        return app

    @unittest_run_loop
    async def test_fail_closed_returns_503(self):
        resp = await self.client.post(
            "/v1/messages",
            json={"model": "test"},
            headers={"x-api-key": "test"},
        )
        self.assertEqual(resp.status, 503)
        data = await resp.json()
        self.assertIn("fail-closed", data["error"]["message"])

    @unittest_run_loop
    async def test_fail_open_attempts_direct(self):
        relay = self.app[_RELAY_KEY]
        relay.config.fail_mode = "open"
        # Direct will also fail (no real API), but we check it attempts
        resp = await self.client.post(
            "/v1/messages",
            json={"model": "test"},
            headers={"x-api-key": "test"},
        )
        # Either 502 (upstream unreachable) or connection error
        self.assertIn(resp.status, (502, 503))


class TestRelayConfig(unittest.TestCase):
    """RelayConfig defaults."""

    def test_defaults(self):
        config = RelayConfig()
        self.assertEqual(config.bind, "127.0.0.1")
        self.assertEqual(config.port, 8070)
        self.assertEqual(config.upstream_url, "http://localhost:8080")
        self.assertEqual(config.fail_mode, "open")
        self.assertEqual(config.agent_id, "")
        self.assertEqual(config.agent_token, "")
        self.assertEqual(config.timeout, 150)
        self.assertEqual(config.connect_timeout, 10)
        self.assertEqual(config.max_connections, 50)


class TestRelayStateFile(unittest.TestCase):
    """Relay state file write/read/remove."""

    def setUp(self):
        import tempfile

        self._tmp = tempfile.mkdtemp()
        # Patch the state path to a temp directory
        import lumen_argus_agent.relay as relay_mod

        self._orig_dir = relay_mod._ARGUS_DIR
        self._orig_path = relay_mod.RELAY_STATE_PATH
        relay_mod._ARGUS_DIR = self._tmp
        relay_mod.RELAY_STATE_PATH = os.path.join(self._tmp, "relay.json")

    def tearDown(self):
        import shutil

        import lumen_argus_agent.relay as relay_mod

        relay_mod._ARGUS_DIR = self._orig_dir
        relay_mod.RELAY_STATE_PATH = self._orig_path
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_write_and_load(self):
        from lumen_argus_agent.relay import _write_relay_state, load_relay_state

        config = RelayConfig(port=9999, bind="0.0.0.0", upstream_url="http://proxy:8080", fail_mode="closed")
        _write_relay_state(config)

        state = load_relay_state()
        self.assertIsNotNone(state)
        self.assertEqual(state["port"], 9999)
        self.assertEqual(state["bind"], "0.0.0.0")
        self.assertEqual(state["upstream_url"], "http://proxy:8080")
        self.assertEqual(state["fail_mode"], "closed")
        self.assertEqual(state["pid"], os.getpid())

    def test_load_missing_returns_none(self):
        from lumen_argus_agent.relay import load_relay_state

        self.assertIsNone(load_relay_state())

    def test_remove(self):
        from lumen_argus_agent.relay import _remove_relay_state, _write_relay_state, load_relay_state

        config = RelayConfig()
        _write_relay_state(config)
        self.assertIsNotNone(load_relay_state())

        _remove_relay_state()
        self.assertIsNone(load_relay_state())

    def test_stale_pid_cleaned_up(self):
        """State file with dead PID is automatically removed."""
        import json

        import lumen_argus_agent.relay as relay_mod
        from lumen_argus_agent.relay import load_relay_state

        state = {"port": 8070, "bind": "127.0.0.1", "pid": 999999999, "upstream_url": ""}
        with open(relay_mod.RELAY_STATE_PATH, "w") as f:
            json.dump(state, f)

        # Dead PID should cause cleanup
        result = load_relay_state()
        self.assertIsNone(result)
        self.assertFalse(os.path.exists(relay_mod.RELAY_STATE_PATH))


class TestReloadEnrollmentConfig(unittest.TestCase):
    """SIGHUP enrollment reload."""

    def setUp(self):
        # Reload now persists to ~/.lumen-argus/relay.json when config
        # changes; patch globally so no test writes to the host.
        from unittest.mock import patch

        self._write_state_patch = patch("lumen_argus_agent.relay._write_relay_state")
        self.write_state = self._write_state_patch.start()
        self.addCleanup(self._write_state_patch.stop)

    def test_updates_token(self):
        from unittest.mock import patch

        from lumen_argus_agent.relay import AgentRelay, _reload_enrollment_config

        config = RelayConfig(agent_token="old_token", fail_mode="open")
        relay = AgentRelay(config)

        enrollment = {"agent_token": "new_token", "policy": {}}
        with patch("lumen_argus_core.enrollment.load_enrollment", return_value=enrollment):
            _reload_enrollment_config(relay)

        self.assertEqual(relay.config.agent_token, "new_token")

    def test_updates_fail_mode(self):
        from unittest.mock import patch

        from lumen_argus_agent.relay import AgentRelay, _reload_enrollment_config

        config = RelayConfig(fail_mode="open")
        relay = AgentRelay(config)

        enrollment = {"policy": {"fail_mode": "closed"}}
        with patch("lumen_argus_core.enrollment.load_enrollment", return_value=enrollment):
            _reload_enrollment_config(relay)

        self.assertEqual(relay.config.fail_mode, "closed")
        # Adopters read relay.json, so the new fail_mode must land on disk.
        self.write_state.assert_called_once_with(config)

    def test_updates_privacy_flags(self):
        from unittest.mock import patch

        from lumen_argus_agent.relay import AgentRelay, _reload_enrollment_config

        config = RelayConfig(send_username=True, send_hostname=True)
        relay = AgentRelay(config)

        enrollment = {"policy": {"relay_send_username": False, "relay_send_hostname": False}}
        with patch("lumen_argus_core.enrollment.load_enrollment", return_value=enrollment):
            _reload_enrollment_config(relay)

        self.assertFalse(relay.config.send_username)
        self.assertFalse(relay.config.send_hostname)

    def test_no_enrollment_no_change(self):
        from unittest.mock import patch

        from lumen_argus_agent.relay import AgentRelay, _reload_enrollment_config

        config = RelayConfig(agent_token="keep", fail_mode="open")
        relay = AgentRelay(config)

        with patch("lumen_argus_core.enrollment.load_enrollment", return_value=None):
            _reload_enrollment_config(relay)

        self.assertEqual(relay.config.agent_token, "keep")
        self.assertEqual(relay.config.fail_mode, "open")
        self.write_state.assert_not_called()

    def test_ignores_invalid_fail_mode(self):
        from unittest.mock import patch

        from lumen_argus_agent.relay import AgentRelay, _reload_enrollment_config

        config = RelayConfig(fail_mode="open")
        relay = AgentRelay(config)

        enrollment = {"policy": {"fail_mode": "invalid"}}
        with patch("lumen_argus_core.enrollment.load_enrollment", return_value=enrollment):
            _reload_enrollment_config(relay)

        self.assertEqual(relay.config.fail_mode, "open")


if __name__ == "__main__":
    unittest.main()
