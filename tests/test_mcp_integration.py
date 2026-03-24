"""Integration tests for MCP proxy with real test servers.

Tests all 4 transport modes end-to-end with the test MCP servers
from tests/fixtures/. Verifies security features (poisoning, drift,
session binding, confused deputy, env filter) with actual JSON-RPC
message exchange.
"""

import asyncio
import json
import os
import shutil
import sys
import tempfile
import unittest

from tests.fixtures.mcp_handler import create_state, handle_message

# ---------------------------------------------------------------------------
# A. Handler dispatch tests (pure function — no I/O, fast)
# ---------------------------------------------------------------------------


class TestMCPHandler(unittest.TestCase):
    """Test the shared JSON-RPC dispatch logic directly."""

    def test_initialize(self):
        state = create_state()
        responses = handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            state,
        )
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0]["id"], 1)
        self.assertIn("protocolVersion", responses[0]["result"])
        self.assertTrue(state["initialized"])

    def test_tools_list_clean(self):
        state = create_state()
        responses = handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            state,
        )
        tools = responses[0]["result"]["tools"]
        self.assertEqual(len(tools), 2)
        names = {t["name"] for t in tools}
        self.assertEqual(names, {"read_file", "write_file"})

    def test_tools_list_poisoned(self):
        state = create_state({"poisoned"})
        responses = handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            state,
        )
        tools = responses[0]["result"]["tools"]
        self.assertEqual(len(tools), 3)
        evil = [t for t in tools if t["name"] == "evil_tool"]
        self.assertEqual(len(evil), 1)
        self.assertIn("<IMPORTANT>", evil[0]["description"])

    def test_tools_list_drift(self):
        state = create_state({"drift"})
        # First call — clean
        r1 = handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, state)
        t1 = {t["name"]: t for t in r1[0]["result"]["tools"]}
        self.assertNotIn("exfil_url", json.dumps(t1["read_file"]["inputSchema"]))

        # Second call — drifted
        r2 = handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, state)
        t2 = {t["name"]: t for t in r2[0]["result"]["tools"]}
        self.assertIn("exfil_url", json.dumps(t2["read_file"]["inputSchema"]))

    def test_tools_list_extra_tool(self):
        state = create_state({"extra_tool"})
        r1 = handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, state)
        self.assertEqual(len(r1[0]["result"]["tools"]), 2)

        r2 = handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, state)
        self.assertEqual(len(r2[0]["result"]["tools"]), 3)
        names = {t["name"] for t in r2[0]["result"]["tools"]}
        self.assertIn("execute_shell", names)

    def test_tools_call_echo(self):
        state = create_state()
        responses = handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "/tmp/test.txt"}},
            },
            state,
        )
        self.assertEqual(responses[0]["id"], 3)
        text = responses[0]["result"]["content"][0]["text"]
        self.assertIn("read_file", text)
        self.assertIn("/tmp/test.txt", text)

    def test_tools_call_secret_in_result(self):
        state = create_state({"secret_in_result"})
        responses = handle_message(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "/tmp"}},
            },
            state,
        )
        text = responses[0]["result"]["content"][0]["text"]
        self.assertIn("AKIAIOSFODNN7EXAMPLE", text)

    def test_unsolicited_response(self):
        state = create_state({"unsolicited"})
        responses = handle_message(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {}},
            },
            state,
        )
        # Should get 2 responses: real + unsolicited
        self.assertEqual(len(responses), 2)
        self.assertEqual(responses[0]["id"], 5)
        self.assertEqual(responses[1]["id"], 99999)

    def test_notification_no_response(self):
        state = create_state()
        responses = handle_message(
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            state,
        )
        self.assertEqual(len(responses), 0)

    def test_unknown_method(self):
        state = create_state()
        responses = handle_message(
            {"jsonrpc": "2.0", "id": 10, "method": "unknown/method", "params": {}},
            state,
        )
        self.assertIn("error", responses[0])
        self.assertEqual(responses[0]["error"]["code"], -32601)


# ---------------------------------------------------------------------------
# B. Scanner integration — MCPScanner + handler (no network)
# ---------------------------------------------------------------------------


class TestMCPScannerIntegration(unittest.TestCase):
    """Test MCPScanner features against handler-generated messages."""

    def test_poisoning_detected(self):
        """MCPScanner detects poisoned tool descriptions from handler."""
        from lumen_argus.mcp.scanner import MCPScanner

        scanner = MCPScanner(scan_tool_descriptions=True, detect_drift=False)
        state = create_state({"poisoned"})
        responses = handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            state,
        )
        tools = responses[0]["result"]["tools"]
        findings = scanner.process_tools_list(tools)
        self.assertTrue(len(findings) > 0)
        self.assertTrue(any(f.detector == "mcp_tool_poison" for f in findings))

    def test_clean_tools_no_findings(self):
        from lumen_argus.mcp.scanner import MCPScanner

        scanner = MCPScanner(scan_tool_descriptions=True, detect_drift=False)
        state = create_state()
        responses = handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            state,
        )
        tools = responses[0]["result"]["tools"]
        findings = scanner.process_tools_list(tools)
        self.assertEqual(len(findings), 0)

    def test_drift_detected(self):
        """MCPScanner detects tool drift between two tools/list calls."""
        from lumen_argus.analytics.store import AnalyticsStore
        from lumen_argus.mcp.scanner import MCPScanner

        tmpdir = tempfile.mkdtemp()
        try:
            store = AnalyticsStore(db_path=tmpdir + "/test.db")
            scanner = MCPScanner(scan_tool_descriptions=False, detect_drift=True, store=store)
            state = create_state({"drift"})

            # First tools/list — establishes baseline
            r1 = handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, state)
            findings1 = scanner.process_tools_list(r1[0]["result"]["tools"])
            self.assertEqual(len(findings1), 0)

            # Second tools/list — drifted definitions
            r2 = handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, state)
            findings2 = scanner.process_tools_list(r2[0]["result"]["tools"])
            self.assertTrue(any(f.type == "tool_drift" for f in findings2))
        finally:
            shutil.rmtree(tmpdir)

    def test_no_drift_on_identical(self):
        from lumen_argus.analytics.store import AnalyticsStore
        from lumen_argus.mcp.scanner import MCPScanner

        tmpdir = tempfile.mkdtemp()
        try:
            store = AnalyticsStore(db_path=tmpdir + "/test.db")
            scanner = MCPScanner(scan_tool_descriptions=False, detect_drift=True, store=store)
            state = create_state()

            r1 = handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, state)
            scanner.process_tools_list(r1[0]["result"]["tools"])

            r2 = handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, state)
            findings = scanner.process_tools_list(r2[0]["result"]["tools"])
            self.assertEqual(len(findings), 0)
        finally:
            shutil.rmtree(tmpdir)

    def test_session_binding_blocks_unknown(self):
        """Session binding rejects tools not in the initial tools/list."""
        from lumen_argus.mcp.scanner import MCPScanner
        from lumen_argus.mcp.session_binding import SessionBinding

        sb = SessionBinding(action="block")
        scanner = MCPScanner(session_binding=sb, scan_tool_descriptions=False, detect_drift=False)
        state = create_state()

        # Establish baseline from first tools/list
        r1 = handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, state)
        scanner.process_tools_list(r1[0]["result"]["tools"])

        # Known tool passes
        self.assertTrue(sb.validate_tool("read_file"))
        self.assertTrue(sb.validate_tool("write_file"))

        # Unknown tool blocked
        self.assertFalse(sb.validate_tool("execute_shell"))

    def test_session_binding_allows_known(self):
        from lumen_argus.mcp.scanner import MCPScanner
        from lumen_argus.mcp.session_binding import SessionBinding

        sb = SessionBinding(action="block")
        scanner = MCPScanner(session_binding=sb, scan_tool_descriptions=False, detect_drift=False)
        state = create_state()

        r1 = handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, state)
        scanner.process_tools_list(r1[0]["result"]["tools"])

        self.assertTrue(sb.validate_tool("read_file"))

    def test_request_tracker_rejects_unsolicited(self):
        """RequestTracker rejects response IDs that were never tracked."""
        from lumen_argus.mcp.request_tracker import RequestTracker

        tracker = RequestTracker(action="block")
        state = create_state({"unsolicited"})

        # Track a real request
        tracker.track(5)

        handle_message(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {}},
            },
            state,
        )

        # Real response passes
        self.assertTrue(tracker.validate(5))
        # Unsolicited response (ID 99999) fails
        self.assertFalse(tracker.validate(99999))

    def test_secret_scanning_in_tool_args(self):
        """Scanner detects secrets in tool call arguments."""
        from lumen_argus.detectors.secrets import SecretsDetector
        from lumen_argus.mcp.scanner import MCPScanner

        scanner = MCPScanner(detectors=[SecretsDetector()], action="block")
        msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {
                    "path": "/tmp/config.yml",
                    "content": "aws_secret_key: AKIAIOSFODNN7EXAMPLE",
                },
            },
        }
        findings = scanner.scan_request(msg)
        self.assertTrue(len(findings) > 0)

    def test_clean_args_no_findings(self):
        from lumen_argus.detectors.secrets import SecretsDetector
        from lumen_argus.mcp.scanner import MCPScanner

        scanner = MCPScanner(detectors=[SecretsDetector()], action="alert")
        msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/tmp/readme.md"},
            },
        }
        findings = scanner.scan_request(msg)
        self.assertEqual(len(findings), 0)


# ---------------------------------------------------------------------------
# C. Environment filter integration (stdio only)
# ---------------------------------------------------------------------------


class TestEnvFilterIntegration(unittest.TestCase):
    """Test environment restriction for subprocess mode."""

    def test_env_filter_strips_secrets(self):
        from lumen_argus.mcp.env_filter import filter_env

        os.environ["AWS_SECRET_ACCESS_KEY"] = "test-secret-key"
        try:
            env = filter_env()
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
        finally:
            del os.environ["AWS_SECRET_ACCESS_KEY"]

    def test_env_filter_passes_safe_vars(self):
        from lumen_argus.mcp.env_filter import filter_env

        env = filter_env()
        self.assertIn("PATH", env)
        self.assertIn("HOME", env)

    def test_env_filter_passthrough_extra(self):
        from lumen_argus.mcp.env_filter import filter_env

        env = filter_env(extra_vars={"MY_CUSTOM_VAR": "value123"})
        self.assertEqual(env["MY_CUSTOM_VAR"], "value123")

    def test_env_filter_config_allowlist(self):
        from lumen_argus.mcp.env_filter import filter_env

        os.environ["CUSTOM_TOOL_PATH"] = "/usr/local/tool"
        try:
            env = filter_env(config_allowlist=["CUSTOM_TOOL_PATH"])
            self.assertEqual(env["CUSTOM_TOOL_PATH"], "/usr/local/tool")
        finally:
            del os.environ["CUSTOM_TOOL_PATH"]


# ---------------------------------------------------------------------------
# D. Pro hooks integration (mock-based)
# ---------------------------------------------------------------------------


class TestProHooksIntegration(unittest.TestCase):
    """Test policy engine and escalation hooks with mock implementations."""

    def test_policy_engine_blocks_tool_call(self):
        from lumen_argus.models import Finding
        from lumen_argus.mcp.proxy import _run_policy_engine

        class MockPolicyEngine:
            def evaluate(self, tool_name, arguments):
                if "rm" in json.dumps(arguments):
                    return [
                        Finding(
                            detector="mcp_policy",
                            type="destructive_command",
                            severity="critical",
                            location="tools/call.%s" % tool_name,
                            value_preview="rm -rf",
                            matched_value="rm -rf /",
                            action="block",
                        )
                    ]
                return []

        engine = MockPolicyEngine()
        # Dangerous call — blocked
        findings = _run_policy_engine(engine, "bash", {"command": "rm -rf /"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].action, "block")

        # Safe call — allowed
        findings = _run_policy_engine(engine, "read_file", {"path": "/tmp"})
        self.assertEqual(len(findings), 0)

    def test_escalation_signal_accumulation(self):
        """Mock escalation function receives correct signal types."""
        from lumen_argus.mcp.proxy import _signal_escalation

        signals = []

        def mock_escalation(signal_type, session_id, details):
            signals.append({"type": signal_type, "session": session_id, "details": details})
            return "elevated" if len(signals) >= 3 else "normal"

        _signal_escalation(mock_escalation, "block", "sess-1", {"tool": "bash"})
        _signal_escalation(mock_escalation, "near_miss", "sess-1", {"tool": "read_file"})
        _signal_escalation(mock_escalation, "drift", "sess-1", {"tool": "write_file"})
        level = _signal_escalation(mock_escalation, "clean", "sess-1", {"tool": "read_file"})

        self.assertEqual(len(signals), 4)
        self.assertEqual(signals[0]["type"], "block")
        self.assertEqual(signals[2]["type"], "drift")
        self.assertEqual(signals[0]["session"], "sess-1")
        # After 3+ signals, returns "elevated"
        self.assertEqual(level, "elevated")

    def test_escalation_receives_session_id(self):
        from lumen_argus.mcp.proxy import _signal_escalation

        captured = {}

        def capture_fn(signal_type, session_id, details):
            captured["session_id"] = session_id
            return "normal"

        _signal_escalation(capture_fn, "clean", "mcp-session-abc", {"tool": "read"})
        self.assertEqual(captured["session_id"], "mcp-session-abc")


# ---------------------------------------------------------------------------
# E. HTTP server integration (real network)
# ---------------------------------------------------------------------------


class TestHTTPServerIntegration(unittest.TestCase):
    """Test HTTP MCP server fixture with real HTTP requests."""

    def _run(self, coro):
        return asyncio.run(asyncio.wait_for(coro, timeout=10))

    def test_http_server_initialize(self):
        async def _test():
            import aiohttp
            from tests.fixtures.mcp_http_server import create_app, start_server, stop_server

            app = create_app(scenarios=set())
            runner, url = await start_server(app)
            try:
                async with aiohttp.ClientSession() as session:
                    resp = await session.post(
                        url,
                        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                    )
                    data = await resp.json()
                    self.assertEqual(data["id"], 1)
                    self.assertIn("protocolVersion", data["result"])
                    self.assertIn("Mcp-Session-Id", resp.headers)
            finally:
                await stop_server(runner)

        self._run(_test())

    def test_http_server_tools_list(self):
        async def _test():
            import aiohttp
            from tests.fixtures.mcp_http_server import create_app, start_server, stop_server

            app = create_app(scenarios=set())
            runner, url = await start_server(app)
            try:
                async with aiohttp.ClientSession() as session:
                    resp = await session.post(
                        url,
                        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                    )
                    data = await resp.json()
                    tools = data["result"]["tools"]
                    self.assertEqual(len(tools), 2)
            finally:
                await stop_server(runner)

        self._run(_test())

    def test_http_server_health(self):
        async def _test():
            import aiohttp
            from tests.fixtures.mcp_http_server import create_app, start_server, stop_server

            app = create_app(scenarios=set())
            runner, url = await start_server(app)
            try:
                async with aiohttp.ClientSession() as session:
                    resp = await session.get(url + "/health")
                    data = await resp.json()
                    self.assertEqual(data["status"], "healthy")
            finally:
                await stop_server(runner)

        self._run(_test())

    def test_http_server_poisoned_scenario(self):
        async def _test():
            import aiohttp
            from tests.fixtures.mcp_http_server import create_app, start_server, stop_server

            app = create_app(scenarios={"poisoned"})
            runner, url = await start_server(app)
            try:
                async with aiohttp.ClientSession() as session:
                    resp = await session.post(
                        url,
                        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                    )
                    data = await resp.json()
                    tools = data["result"]["tools"]
                    evil = [t for t in tools if t["name"] == "evil_tool"]
                    self.assertEqual(len(evil), 1)
            finally:
                await stop_server(runner)

        self._run(_test())


# ---------------------------------------------------------------------------
# F. WebSocket server integration (real network)
# ---------------------------------------------------------------------------


class TestWebSocketServerIntegration(unittest.TestCase):
    """Test WebSocket MCP server fixture with real WS connections."""

    def _run(self, coro):
        return asyncio.run(asyncio.wait_for(coro, timeout=10))

    def test_ws_server_initialize(self):
        async def _test():
            import aiohttp
            from tests.fixtures.mcp_ws_server import create_app, start_server, stop_server

            app = create_app(scenarios=set())
            runner, ws_url = await start_server(app)
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.ws_connect(ws_url) as ws:
                        await ws.send_str(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}))
                        msg = await ws.receive()
                        data = json.loads(msg.data)
                        self.assertEqual(data["id"], 1)
                        self.assertIn("protocolVersion", data["result"])
            finally:
                await stop_server(runner)

        self._run(_test())

    def test_ws_server_tools_call(self):
        async def _test():
            import aiohttp
            from tests.fixtures.mcp_ws_server import create_app, start_server, stop_server

            app = create_app(scenarios=set())
            runner, ws_url = await start_server(app)
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.ws_connect(ws_url) as ws:
                        await ws.send_str(
                            json.dumps(
                                {
                                    "jsonrpc": "2.0",
                                    "id": 3,
                                    "method": "tools/call",
                                    "params": {"name": "read_file", "arguments": {"path": "/tmp"}},
                                }
                            )
                        )
                        msg = await ws.receive()
                        data = json.loads(msg.data)
                        self.assertEqual(data["id"], 3)
                        self.assertIn("read_file", data["result"]["content"][0]["text"])
            finally:
                await stop_server(runner)

        self._run(_test())

    def test_ws_server_unsolicited(self):
        """WebSocket server sends unsolicited response for confused deputy testing."""

        async def _test():
            import aiohttp
            from tests.fixtures.mcp_ws_server import create_app, start_server, stop_server

            app = create_app(scenarios={"unsolicited"})
            runner, ws_url = await start_server(app)
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.ws_connect(ws_url) as ws:
                        await ws.send_str(
                            json.dumps(
                                {
                                    "jsonrpc": "2.0",
                                    "id": 5,
                                    "method": "tools/call",
                                    "params": {"name": "read_file", "arguments": {}},
                                }
                            )
                        )
                        # Should receive 2 messages: real + unsolicited
                        msg1 = await ws.receive()
                        data1 = json.loads(msg1.data)
                        self.assertEqual(data1["id"], 5)

                        msg2 = await ws.receive()
                        data2 = json.loads(msg2.data)
                        self.assertEqual(data2["id"], 99999)
            finally:
                await stop_server(runner)

        self._run(_test())


# ---------------------------------------------------------------------------
# G. Stdio subprocess integration (real process spawn)
# ---------------------------------------------------------------------------


class TestStdioSubprocessIntegration(unittest.TestCase):
    """Test stdio MCP server fixture as a real subprocess."""

    _READLINE_TIMEOUT = 15  # generous for cold CI runners (Python startup + imports)

    def _server_path(self):
        return os.path.join(os.path.dirname(__file__), "fixtures", "mcp_stdio_server.py")

    async def _read_response(self, proc):
        """Read a JSON-RPC response line with timeout and error diagnostics."""
        line = await asyncio.wait_for(proc.stdout.readline(), timeout=self._READLINE_TIMEOUT)
        if not line:
            stderr = await proc.stderr.read()
            rc = proc.returncode
            self.fail("subprocess exited (code=%s) before responding: %s" % (rc, stderr.decode(errors="replace")[:500]))
        return json.loads(line)

    async def _cleanup_proc(self, proc):
        """Reliably terminate subprocess — kill if wait times out."""
        try:
            proc.stdin.close()
        except Exception:
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except (asyncio.TimeoutError, Exception):
            proc.kill()
            await proc.wait()

    def test_stdio_server_roundtrip(self):
        """Spawn stdio server, send initialize + tools/list, verify responses."""

        async def _test():
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                self._server_path(),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                # Send initialize
                init_msg = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
                proc.stdin.write(init_msg.encode() + b"\n")
                await proc.stdin.drain()
                data = await self._read_response(proc)
                self.assertEqual(data["id"], 1)
                self.assertIn("protocolVersion", data["result"])

                # Send tools/list
                list_msg = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
                proc.stdin.write(list_msg.encode() + b"\n")
                await proc.stdin.drain()
                data = await self._read_response(proc)
                self.assertEqual(len(data["result"]["tools"]), 2)
            finally:
                await self._cleanup_proc(proc)

        asyncio.run(asyncio.wait_for(_test(), timeout=30))

    def test_stdio_server_poisoned_flag(self):
        """Stdio server with --poisoned flag returns poisoned tool."""

        async def _test():
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                self._server_path(),
                "--poisoned",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                msg = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
                proc.stdin.write(msg.encode() + b"\n")
                await proc.stdin.drain()
                data = await self._read_response(proc)
                tools = data["result"]["tools"]
                self.assertEqual(len(tools), 3)
                evil = [t for t in tools if t["name"] == "evil_tool"]
                self.assertEqual(len(evil), 1)
            finally:
                await self._cleanup_proc(proc)

        asyncio.run(asyncio.wait_for(_test(), timeout=30))

    def test_stdio_server_env_filter(self):
        """Verify child process does not inherit sensitive env vars when filtered."""
        from lumen_argus.mcp.env_filter import filter_env

        async def _test():
            os.environ["AWS_SECRET_ACCESS_KEY"] = "test-secret"
            try:
                env = filter_env()
                # Spawn a Python subprocess that prints its env
                proc = await asyncio.create_subprocess_exec(
                    sys.executable,
                    "-c",
                    "import os, json; print(json.dumps(dict(os.environ)))",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    env=env,
                )
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=15)
                child_env = json.loads(line)
                self.assertNotIn("AWS_SECRET_ACCESS_KEY", child_env)
                self.assertIn("PATH", child_env)
                await asyncio.wait_for(proc.wait(), timeout=5)
            finally:
                del os.environ["AWS_SECRET_ACCESS_KEY"]

        asyncio.run(asyncio.wait_for(_test(), timeout=30))


if __name__ == "__main__":
    unittest.main()
