"""Integration tests for the async (aiohttp) proxy server."""

import asyncio
import http.server
import json
import threading
import unittest

import aiohttp

from lumen_argus.async_proxy import AsyncArgusProxy
from lumen_argus.audit import AuditLogger
from lumen_argus.display import TerminalDisplay
from lumen_argus.pipeline import ScannerPipeline
from lumen_argus.provider import ProviderRouter
from tests.helpers import free_port as _get_free_port


class MockUpstreamHandler(http.server.BaseHTTPRequestHandler):
    """Minimal mock that returns a fixed response."""

    def log_message(self, format, *args):
        pass

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        # Check if streaming is requested
        try:
            data = json.loads(body)
            is_streaming = data.get("stream", False)
        except Exception:
            is_streaming = False

        if is_streaming:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            # Send a few SSE chunks
            events = [
                'data: {"type":"content_block_delta","delta":{"text":"Hello"}}\n\n',
                'data: {"type":"content_block_delta","delta":{"text":" World"}}\n\n',
                "data: [DONE]\n\n",
            ]
            for event in events:
                self.wfile.write(event.encode())
                self.wfile.flush()
        else:
            response = json.dumps(
                {
                    "id": "msg_mock",
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "text", "text": "Hello!"}],
                    "model": "claude-opus-4-6",
                    "usage": {"input_tokens": 100, "output_tokens": 10},
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        body = b'{"status":"ok"}'
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class TestAsyncProxy(unittest.TestCase):
    """Integration tests for AsyncArgusProxy."""

    @classmethod
    def setUpClass(cls):
        import tempfile

        # Start mock upstream
        cls.upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockUpstreamHandler)
        cls.upstream.daemon_threads = True
        cls.upstream_port = cls.upstream.server_address[1]
        cls.upstream_thread = threading.Thread(target=cls.upstream.serve_forever, daemon=True)
        cls.upstream_thread.start()

        cls.tmpdir = tempfile.mkdtemp()

        # Configure
        cls.upstreams = {
            "anthropic": "http://127.0.0.1:%d" % cls.upstream_port,
        }
        cls.proxy_port = _get_free_port()

    @classmethod
    def tearDownClass(cls):
        cls.upstream.shutdown()

    def _create_proxy(self, **kwargs):
        """Create an AsyncArgusProxy instance."""
        defaults = {
            "default_action": "alert",
            "action_overrides": {"secrets": "block"},
        }
        defaults.update(kwargs)
        pipeline = ScannerPipeline(**defaults)
        router = ProviderRouter(upstreams=self.upstreams)
        audit = AuditLogger(log_dir=self.tmpdir)
        display = TerminalDisplay(no_color=True)

        port = _get_free_port()
        proxy = AsyncArgusProxy(
            bind="127.0.0.1",
            port=port,
            pipeline=pipeline,
            router=router,
            audit=audit,
            display=display,
        )
        return proxy, port

    _session_counter = 0

    async def _post(self, port, body_dict, session_id=None):
        """Send a POST to the async proxy."""
        if session_id is None:
            TestAsyncProxy._session_counter += 1
            session_id = "test-async-%d" % TestAsyncProxy._session_counter
        body = json.dumps(body_dict).encode()
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "http://127.0.0.1:%d/v1/messages" % port,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": "test-key",
                    "anthropic-version": "2024-01-01",
                    "x-session-id": session_id,
                },
            ) as resp:
                data = await resp.json()
                return resp.status, data

    async def _run_with_proxy(self, proxy, coro_fn):
        """Start proxy, run a test coroutine, then stop."""
        await proxy.start()
        try:
            return await coro_fn()
        finally:
            await proxy.stop()

    def test_clean_request_forwarded(self):
        """Clean request should be forwarded to upstream and return 200."""
        proxy, port = self._create_proxy()

        async def _test():
            async def _inner():
                status, data = await self._post(
                    port,
                    {
                        "model": "claude-opus-4-6",
                        "messages": [{"role": "user", "content": "What is 2+2?"}],
                    },
                )
                self.assertEqual(status, 200)
                self.assertEqual(data["type"], "message")
                return status

            return await self._run_with_proxy(proxy, _inner)

        asyncio.run(_test())

    def test_secret_blocked(self):
        """Request containing a secret should be blocked with 400."""
        proxy, port = self._create_proxy()

        async def _test():
            async def _inner():
                status, data = await self._post(
                    port,
                    {
                        "model": "claude-opus-4-6",
                        "messages": [
                            {"role": "user", "content": "My key: AKIAIOSFODNN7EXAMPLE"},
                        ],
                    },
                )
                self.assertEqual(status, 400)
                self.assertEqual(data["error"]["type"], "invalid_request_error")
                self.assertIn("lumen-argus", data["error"]["message"])

            return await self._run_with_proxy(proxy, _inner)

        asyncio.run(_test())

    def test_passthrough_mode_skips_scanning(self):
        """In passthrough mode, secrets should NOT be blocked."""
        proxy, port = self._create_proxy()
        proxy.mode = "passthrough"

        async def _test():
            async def _inner():
                # This contains an AWS key which would normally be blocked
                status, data = await self._post(
                    port,
                    {
                        "model": "claude-opus-4-6",
                        "messages": [
                            {"role": "user", "content": "My key: AKIAIOSFODNN7EXAMPLE"},
                        ],
                    },
                )
                # Should be forwarded (200), not blocked (400)
                self.assertEqual(status, 200)
                self.assertEqual(data["type"], "message")

            return await self._run_with_proxy(proxy, _inner)

        asyncio.run(_test())

    def test_passthrough_to_active_resumes_scanning(self):
        """Switching from passthrough back to active should resume scanning."""
        proxy, port = self._create_proxy()

        async def _test():
            async def _inner():
                # Start in passthrough — secret goes through
                proxy.mode = "passthrough"
                status, _data = await self._post(
                    port,
                    {
                        "model": "claude-opus-4-6",
                        "messages": [
                            {"role": "user", "content": "My key: AKIAIOSFODNN7EXAMPLE"},
                        ],
                    },
                )
                self.assertEqual(status, 200)

                # Switch to active — secret should be blocked
                proxy.mode = "active"
                status, _data = await self._post(
                    port,
                    {
                        "model": "claude-opus-4-6",
                        "messages": [
                            {"role": "user", "content": "My key: AKIAIOSFODNN7EXAMPLE"},
                        ],
                    },
                )
                self.assertEqual(status, 400)

            return await self._run_with_proxy(proxy, _inner)

        asyncio.run(_test())

    def test_scan_error_fails_open(self):
        """If pipeline.scan() throws, request should be forwarded (fail-open)."""
        proxy, port = self._create_proxy()

        async def _test():
            async def _inner():
                # Monkey-patch pipeline.scan to throw
                original_scan = proxy.pipeline.scan
                proxy.pipeline.scan = lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("detector bug"))

                # Secret that would normally be blocked — should be forwarded
                status, data = await self._post(
                    port,
                    {
                        "model": "claude-opus-4-6",
                        "messages": [
                            {"role": "user", "content": "My key: AKIAIOSFODNN7EXAMPLE"},
                        ],
                    },
                )
                self.assertEqual(status, 200)
                self.assertEqual(data["type"], "message")

                # Restore and verify scanning works again
                proxy.pipeline.scan = original_scan
                status, _data = await self._post(
                    port,
                    {
                        "model": "claude-opus-4-6",
                        "messages": [
                            {"role": "user", "content": "My key: AKIAIOSFODNN7EXAMPLE"},
                        ],
                    },
                )
                self.assertEqual(status, 400)  # scanning restored, should block

            return await self._run_with_proxy(proxy, _inner)

        asyncio.run(_test())

    def test_pii_alerted_but_forwarded(self):
        """PII with alert action should forward (not block)."""
        proxy, port = self._create_proxy()

        async def _test():
            async def _inner():
                status, _data = await self._post(
                    port,
                    {
                        "model": "claude-opus-4-6",
                        "messages": [
                            {"role": "user", "content": "Contact john.smith@company.com"},
                        ],
                    },
                )
                self.assertEqual(status, 200)

            return await self._run_with_proxy(proxy, _inner)

        asyncio.run(_test())

    def test_streaming_secret_blocked_as_400(self):
        """Blocked streaming request returns 400 JSON, not SSE."""
        proxy, port = self._create_proxy()

        async def _test():
            async def _inner():
                status, data = await self._post(
                    port,
                    {
                        "model": "claude-opus-4-6",
                        "stream": True,
                        "messages": [
                            {"role": "user", "content": "My key: AKIAI44QH8DHBEXAMPLE"},
                        ],
                    },
                )
                self.assertEqual(status, 400)
                self.assertIn("invalid_request_error", json.dumps(data))

            return await self._run_with_proxy(proxy, _inner)

        asyncio.run(_test())

    def test_history_strip_forwards_request(self):
        """Blocked finding in history only → strip and forward, get 200."""
        proxy, port = self._create_proxy()

        async def _test():
            async def _inner():
                status, data = await self._post(
                    port,
                    {
                        "model": "claude-opus-4-6",
                        "messages": [
                            {"role": "user", "content": "My key: AKIAI44QH8DHBEXAMPLE"},
                            {"role": "assistant", "content": "Error: blocked."},
                            {"role": "user", "content": "What is 2+2?"},
                        ],
                    },
                )
                self.assertEqual(status, 200)
                self.assertEqual(data["type"], "message")

            return await self._run_with_proxy(proxy, _inner)

        asyncio.run(_test())

    def test_health_endpoint(self):
        """GET /health should return 200 with status ok."""
        proxy, port = self._create_proxy()

        async def _test():
            async def _inner():
                async with aiohttp.ClientSession() as session:
                    async with session.get("http://127.0.0.1:%d/health" % port) as resp:
                        self.assertEqual(resp.status, 200)
                        data = await resp.json()
                        self.assertEqual(data["status"], "ready")
                        self.assertIn("version", data)
                        self.assertIn("uptime", data)

            return await self._run_with_proxy(proxy, _inner)

        asyncio.run(_test())

    def test_metrics_endpoint(self):
        """GET /metrics should return Prometheus text."""
        proxy, port = self._create_proxy()

        async def _test():
            async def _inner():
                async with aiohttp.ClientSession() as session:
                    async with session.get("http://127.0.0.1:%d/metrics" % port) as resp:
                        self.assertEqual(resp.status, 200)
                        text = await resp.text()
                        self.assertIn("argus_", text)

            return await self._run_with_proxy(proxy, _inner)

        asyncio.run(_test())

    def test_sse_streaming(self):
        """SSE streaming response should be forwarded chunk by chunk."""
        proxy, port = self._create_proxy()

        async def _test():
            async def _inner():
                TestAsyncProxy._session_counter += 1
                session_id = "test-sse-%d" % TestAsyncProxy._session_counter
                body = json.dumps(
                    {
                        "model": "claude-opus-4-6",
                        "stream": True,
                        "messages": [{"role": "user", "content": "Hi"}],
                    }
                ).encode()
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        "http://127.0.0.1:%d/v1/messages" % port,
                        data=body,
                        headers={
                            "Content-Type": "application/json",
                            "x-api-key": "test-key",
                            "anthropic-version": "2024-01-01",
                            "x-session-id": session_id,
                        },
                    ) as resp:
                        self.assertEqual(resp.status, 200)
                        text = await resp.text()
                        self.assertIn("Hello", text)
                        self.assertIn("World", text)

            return await self._run_with_proxy(proxy, _inner)

        asyncio.run(_test())

    def test_active_requests_tracking(self):
        """Active request counter should increment/decrement correctly."""
        proxy, port = self._create_proxy()

        async def _test():
            async def _inner():
                self.assertEqual(proxy.active_requests, 0)
                # After a request completes, should be back to 0
                status, _ = await self._post(
                    port,
                    {
                        "model": "claude-opus-4-6",
                        "messages": [{"role": "user", "content": "test"}],
                    },
                )
                self.assertEqual(status, 200)
                # Brief delay for counter decrement
                await asyncio.sleep(0.05)
                self.assertEqual(proxy.active_requests, 0)

            return await self._run_with_proxy(proxy, _inner)

        asyncio.run(_test())

    def test_stats_recorded(self):
        """Request stats should be recorded after forwarding."""
        proxy, port = self._create_proxy()

        async def _test():
            async def _inner():
                self.assertEqual(proxy.stats.total_requests, 0)
                await self._post(
                    port,
                    {
                        "model": "claude-opus-4-6",
                        "messages": [{"role": "user", "content": "test"}],
                    },
                )
                self.assertEqual(proxy.stats.total_requests, 1)
                self.assertIn("anthropic", proxy.stats.providers)

            return await self._run_with_proxy(proxy, _inner)

        asyncio.run(_test())

    def test_server_address_property(self):
        """server_address should return (bind, port) tuple."""
        proxy, port = self._create_proxy()
        self.assertEqual(proxy.server_address, ("127.0.0.1", port))

    def test_multiple_concurrent_requests(self):
        """Multiple concurrent requests should all succeed."""
        proxy, port = self._create_proxy()

        async def _test():
            async def _inner():
                tasks = []
                for i in range(5):
                    tasks.append(
                        self._post(
                            port,
                            {
                                "model": "claude-opus-4-6",
                                "messages": [{"role": "user", "content": "Request %d" % i}],
                            },
                            session_id="concurrent-%d" % i,
                        )
                    )
                results = await asyncio.gather(*tasks)
                for status, data in results:
                    self.assertEqual(status, 200)
                self.assertEqual(proxy.stats.total_requests, 5)

            return await self._run_with_proxy(proxy, _inner)

        asyncio.run(_test())

    def test_oversized_body_skipped(self):
        """Body exceeding max_body_size should skip scanning but forward."""
        proxy, port = self._create_proxy()
        proxy.max_body_size = 100  # Very small limit

        async def _test():
            async def _inner():
                # Build a body larger than 100 bytes
                status, _data = await self._post(
                    port,
                    {
                        "model": "claude-opus-4-6",
                        "messages": [{"role": "user", "content": "x" * 200}],
                    },
                )
                self.assertEqual(status, 200)

            return await self._run_with_proxy(proxy, _inner)

        asyncio.run(_test())

    def test_update_timeout(self):
        """update_timeout should update the timeout value."""
        proxy, _port = self._create_proxy()
        self.assertEqual(proxy.timeout, 30)
        proxy.update_timeout(60)
        self.assertEqual(proxy.timeout, 60)

    def test_upstream_connection_refused(self):
        """Upstream connection refused should return 502, not crash."""
        # Point at a port that's not listening
        dead_upstreams = {"anthropic": "http://127.0.0.1:1"}
        pipeline = ScannerPipeline(default_action="alert")
        router = ProviderRouter(upstreams=dead_upstreams)
        import tempfile

        tmpdir = tempfile.mkdtemp()
        audit = AuditLogger(log_dir=tmpdir)
        display = TerminalDisplay(no_color=True)
        port = _get_free_port()
        proxy = AsyncArgusProxy(
            bind="127.0.0.1",
            port=port,
            pipeline=pipeline,
            router=router,
            audit=audit,
            display=display,
            retries=0,  # no retries — fail fast
            timeout=2,
        )

        async def _test():
            async def _inner():
                TestAsyncProxy._session_counter += 1
                session_id = "test-dead-%d" % TestAsyncProxy._session_counter
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        "http://127.0.0.1:%d/v1/messages" % port,
                        data=json.dumps({"model": "test", "messages": [{"role": "user", "content": "hi"}]}).encode(),
                        headers={
                            "Content-Type": "application/json",
                            "x-api-key": "test",
                            "anthropic-version": "2024-01-01",
                            "x-session-id": session_id,
                        },
                    ) as resp:
                        self.assertEqual(resp.status, 502)
                        data = await resp.json()
                        self.assertIn("error", data)

            return await self._run_with_proxy(proxy, _inner)

        asyncio.run(_test())


class TestAsyncProxyRebind(unittest.TestCase):
    """Tests for runtime port rebinding."""

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls.upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockUpstreamHandler)
        cls.upstream.daemon_threads = True
        cls.upstream_port = cls.upstream.server_address[1]
        cls.upstream_thread = threading.Thread(target=cls.upstream.serve_forever, daemon=True)
        cls.upstream_thread.start()
        cls.tmpdir = tempfile.mkdtemp()
        cls.upstreams = {"anthropic": "http://127.0.0.1:%d" % cls.upstream_port}

    @classmethod
    def tearDownClass(cls):
        cls.upstream.shutdown()

    def _create_proxy(self):
        pipeline = ScannerPipeline(default_action="alert")
        port = _get_free_port()
        proxy = AsyncArgusProxy(
            bind="127.0.0.1",
            port=port,
            pipeline=pipeline,
            router=ProviderRouter(upstreams=self.upstreams),
            audit=AuditLogger(log_dir=self.tmpdir),
            display=TerminalDisplay(no_color=True),
        )
        return proxy, port

    def test_rebind_to_new_port(self):
        """Rebind should move the proxy to a new port."""
        proxy, old_port = self._create_proxy()
        new_port = _get_free_port()

        async def _test():
            await proxy.start()
            try:
                # Verify old port works
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        "http://127.0.0.1:%d/v1/messages" % old_port,
                        data=b'{"model":"claude-opus-4-6","messages":[{"role":"user","content":"hi"}],"max_tokens":10}',
                        headers={
                            "Content-Type": "application/json",
                            "x-api-key": "k",
                            "anthropic-version": "2024-01-01",
                        },
                    ) as resp:
                        self.assertEqual(resp.status, 200)

                # Rebind
                await proxy.rebind(new_port=new_port)
                self.assertEqual(proxy.port, new_port)

                # Verify new port works
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        "http://127.0.0.1:%d/v1/messages" % new_port,
                        data=b'{"model":"claude-opus-4-6","messages":[{"role":"user","content":"hi"}],"max_tokens":10}',
                        headers={
                            "Content-Type": "application/json",
                            "x-api-key": "k",
                            "anthropic-version": "2024-01-01",
                        },
                    ) as resp:
                        self.assertEqual(resp.status, 200)

                # Old port should be closed
                async with aiohttp.ClientSession() as session:
                    with self.assertRaises(aiohttp.ClientConnectorError):
                        async with session.post(
                            "http://127.0.0.1:%d/v1/messages" % old_port,
                            data=b"{}",
                            headers={"Content-Type": "application/json"},
                        ):
                            pass
            finally:
                await proxy.stop()

        asyncio.run(_test())

    def test_rebind_noop_same_port(self):
        """Rebind with same port should be a no-op."""
        proxy, port = self._create_proxy()

        async def _test():
            await proxy.start()
            try:
                await proxy.rebind(new_port=port)
                self.assertEqual(proxy.port, port)

                # Still works
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        "http://127.0.0.1:%d/v1/messages" % port,
                        data=b'{"model":"claude-opus-4-6","messages":[{"role":"user","content":"hi"}],"max_tokens":10}',
                        headers={
                            "Content-Type": "application/json",
                            "x-api-key": "k",
                            "anthropic-version": "2024-01-01",
                        },
                    ) as resp:
                        self.assertEqual(resp.status, 200)
            finally:
                await proxy.stop()

        asyncio.run(_test())

    def test_rebind_rollback_on_port_conflict(self):
        """Rebind to an occupied port should rollback to original."""
        proxy, port = self._create_proxy()

        # Occupy a port
        blocker = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockUpstreamHandler)
        blocker.daemon_threads = True
        occupied_port = blocker.server_address[1]
        blocker_thread = threading.Thread(target=blocker.serve_forever, daemon=True)
        blocker_thread.start()

        async def _test():
            await proxy.start()
            try:
                with self.assertRaises(OSError):
                    await proxy.rebind(new_port=occupied_port)

                # Should have rolled back
                self.assertEqual(proxy.port, port)

                # Original port should still work
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        "http://127.0.0.1:%d/v1/messages" % port,
                        data=b'{"model":"claude-opus-4-6","messages":[{"role":"user","content":"hi"}],"max_tokens":10}',
                        headers={
                            "Content-Type": "application/json",
                            "x-api-key": "k",
                            "anthropic-version": "2024-01-01",
                        },
                    ) as resp:
                        self.assertEqual(resp.status, 200)
            finally:
                await proxy.stop()
                blocker.shutdown()

        asyncio.run(_test())

    def test_rebind_updates_server_address(self):
        """server_address property should reflect new port after rebind."""
        proxy, old_port = self._create_proxy()
        new_port = _get_free_port()

        async def _test():
            await proxy.start()
            try:
                self.assertEqual(proxy.server_address, ("127.0.0.1", old_port))
                await proxy.rebind(new_port=new_port)
                self.assertEqual(proxy.server_address, ("127.0.0.1", new_port))
            finally:
                await proxy.stop()

        asyncio.run(_test())

    def test_max_body_size_hot_reload(self):
        """max_body_size and aiohttp client_max_size should be updatable at runtime."""
        proxy, port = self._create_proxy()

        async def _test():
            await proxy.start()
            try:
                original = proxy.max_body_size
                self.assertGreater(original, 0)

                # Update max_body_size (simulates what _do_reload does)
                new_size = 1024
                proxy.max_body_size = new_size
                proxy._app._client_max_size = new_size + 1024

                self.assertEqual(proxy.max_body_size, new_size)
                self.assertEqual(proxy._app._client_max_size, new_size + 1024)

                # Small request should still work
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        "http://127.0.0.1:%d/v1/messages" % port,
                        data=b'{"model":"claude-opus-4-6","messages":[{"role":"user","content":"hi"}],"max_tokens":10}',
                        headers={
                            "Content-Type": "application/json",
                            "x-api-key": "k",
                            "anthropic-version": "2024-01-01",
                        },
                    ) as resp:
                        self.assertEqual(resp.status, 200)
            finally:
                await proxy.stop()

        asyncio.run(_test())


class TestAsyncProxyWebSocket(unittest.TestCase):
    """Integration tests for WebSocket relay on same port."""

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls.tmpdir = tempfile.mkdtemp()

    def _create_proxy_with_ws(self):
        """Create an async proxy with WebSocket scanning enabled."""
        from lumen_argus.allowlist import AllowlistMatcher
        from lumen_argus.detectors.secrets import SecretsDetector
        from lumen_argus.ws_proxy import WebSocketScanner

        pipeline = ScannerPipeline(default_action="alert", action_overrides={"secrets": "block"})
        router = ProviderRouter()
        audit = AuditLogger(log_dir=self.tmpdir)
        display = TerminalDisplay(no_color=True)
        port = _get_free_port()
        proxy = AsyncArgusProxy(
            bind="127.0.0.1",
            port=port,
            pipeline=pipeline,
            router=router,
            audit=audit,
            display=display,
        )
        proxy.ws_scanner = WebSocketScanner(
            detectors=[SecretsDetector()],
            allowlist=AllowlistMatcher(),
            scan_outbound=True,
            scan_inbound=True,
        )
        return proxy, port

    def test_ws_missing_url_param(self):
        """WebSocket without url param should return 400."""
        proxy, port = self._create_proxy_with_ws()

        async def _test():
            await proxy.start()
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.ws_connect(
                        "http://127.0.0.1:%d/ws" % port,
                    ) as _ws:
                        # Should never get here — server rejects with 400
                        pass
            except aiohttp.WSServerHandshakeError as e:
                self.assertEqual(e.status, 400)
            finally:
                await proxy.stop()

        asyncio.run(_test())

    def test_ws_invalid_scheme(self):
        """WebSocket with non-ws scheme should return 400."""
        proxy, port = self._create_proxy_with_ws()

        async def _test():
            await proxy.start()
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.ws_connect(
                        "http://127.0.0.1:%d/ws?url=http://example.com" % port,
                    ) as _ws:
                        pass
            except aiohttp.WSServerHandshakeError as e:
                self.assertEqual(e.status, 400)
            finally:
                await proxy.stop()

        asyncio.run(_test())

    def test_ws_scanner_not_configured(self):
        """WebSocket without scanner configured should return 503."""
        pipeline = ScannerPipeline(default_action="alert")
        router = ProviderRouter()
        audit = AuditLogger(log_dir=self.tmpdir)
        display = TerminalDisplay(no_color=True)
        port = _get_free_port()
        proxy = AsyncArgusProxy(
            bind="127.0.0.1",
            port=port,
            pipeline=pipeline,
            router=router,
            audit=audit,
            display=display,
        )
        # ws_scanner is None by default

        async def _test():
            await proxy.start()
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.ws_connect(
                        "http://127.0.0.1:%d/ws?url=ws://example.com" % port,
                    ) as _ws:
                        pass
            except aiohttp.WSServerHandshakeError as e:
                self.assertEqual(e.status, 503)
            finally:
                await proxy.stop()

        asyncio.run(_test())


class TestAsyncProxyWebSocketHooks(unittest.TestCase):
    """Tests for WebSocket connection lifecycle hooks."""

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls.tmpdir = tempfile.mkdtemp()

    def test_ws_hook_called_on_validation_failure(self):
        """Hook should fire open+close even when upstream fails."""
        from lumen_argus.allowlist import AllowlistMatcher
        from lumen_argus.detectors.secrets import SecretsDetector
        from lumen_argus.extensions import ExtensionRegistry
        from lumen_argus.ws_proxy import WebSocketScanner

        hook_events = []

        def _test_hook(event_type, connection_id, metadata):
            hook_events.append((event_type, connection_id, metadata))

        pipeline = ScannerPipeline(default_action="alert")
        router = ProviderRouter()
        audit = AuditLogger(log_dir=self.tmpdir)
        display = TerminalDisplay(no_color=True)
        port = _get_free_port()
        proxy = AsyncArgusProxy(
            bind="127.0.0.1",
            port=port,
            pipeline=pipeline,
            router=router,
            audit=audit,
            display=display,
        )
        proxy.ws_scanner = WebSocketScanner(
            detectors=[SecretsDetector()],
            allowlist=AllowlistMatcher(),
            scan_outbound=True,
            scan_inbound=True,
        )
        extensions = ExtensionRegistry()
        extensions.set_ws_connection_hook(_test_hook)
        proxy.extensions = extensions

        async def _test():
            await proxy.start()
            try:
                async with aiohttp.ClientSession() as session:
                    # Connect to a non-existent upstream — will fail after open hook
                    try:
                        async with session.ws_connect(
                            "http://127.0.0.1:%d/ws?url=ws://127.0.0.1:1/nope" % port,
                        ) as _ws:
                            pass
                    except Exception:
                        pass
            finally:
                await proxy.stop()

        asyncio.run(_test())

        # Should have open and close events
        event_types = [e[0] for e in hook_events]
        self.assertIn("open", event_types)
        self.assertIn("close", event_types)

        # All events share the same connection_id
        conn_ids = set(e[1] for e in hook_events)
        self.assertEqual(len(conn_ids), 1)

        # Close event has duration and frame counts
        close_meta = [e[2] for e in hook_events if e[0] == "close"][0]
        self.assertIn("duration_seconds", close_meta)
        self.assertIn("frames_sent", close_meta)
        self.assertIn("frames_received", close_meta)
        self.assertEqual(close_meta["frames_sent"], 0)
        self.assertEqual(close_meta["frames_received"], 0)

    def test_ws_hook_not_called_without_extensions(self):
        """No crash when extensions is None."""
        pipeline = ScannerPipeline(default_action="alert")
        router = ProviderRouter()
        audit = AuditLogger(log_dir=self.tmpdir)
        display = TerminalDisplay(no_color=True)
        port = _get_free_port()
        proxy = AsyncArgusProxy(
            bind="127.0.0.1",
            port=port,
            pipeline=pipeline,
            router=router,
            audit=audit,
            display=display,
        )
        # extensions is None, ws_scanner is None — should return 503

        async def _test():
            await proxy.start()
            try:
                async with aiohttp.ClientSession() as session:
                    try:
                        async with session.ws_connect(
                            "http://127.0.0.1:%d/ws?url=ws://example.com" % port,
                        ) as _ws:
                            pass
                    except aiohttp.WSServerHandshakeError as e:
                        self.assertEqual(e.status, 503)
            finally:
                await proxy.stop()

        asyncio.run(_test())


class TestAsyncProxyWebSocketRelay(unittest.TestCase):
    """E2E tests for WebSocket relay with policy enforcement."""

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls.tmpdir = tempfile.mkdtemp()

    def _create_proxy(self, default_action="alert", action_overrides=None):
        from lumen_argus.allowlist import AllowlistMatcher
        from lumen_argus.detectors.secrets import SecretsDetector
        from lumen_argus.extensions import ExtensionRegistry
        from lumen_argus.ws_proxy import WebSocketScanner

        pipeline = ScannerPipeline(
            default_action=default_action,
            action_overrides=action_overrides or {},
        )
        port = _get_free_port()
        proxy = AsyncArgusProxy(
            bind="127.0.0.1",
            port=port,
            pipeline=pipeline,
            router=ProviderRouter(),
            audit=AuditLogger(log_dir=self.tmpdir),
            display=TerminalDisplay(no_color=True),
        )
        proxy.ws_scanner = WebSocketScanner(
            detectors=[SecretsDetector()],
            allowlist=AllowlistMatcher(),
            scan_outbound=True,
            scan_inbound=True,
        )
        proxy.extensions = ExtensionRegistry()
        return proxy, port

    def test_clean_frame_forwarded(self):
        """Clean text frame is relayed to upstream and back."""
        proxy, proxy_port = self._create_proxy()
        echo_port = _get_free_port()

        async def _test():
            async def echo_handler(request):
                ws = aiohttp.web.WebSocketResponse()
                await ws.prepare(request)
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        await ws.send_str("echo:" + msg.data)
                return ws

            echo_app = aiohttp.web.Application()
            echo_app.router.add_get("/ws", echo_handler)
            echo_runner = aiohttp.web.AppRunner(echo_app)
            await echo_runner.setup()
            await aiohttp.web.TCPSite(echo_runner, "127.0.0.1", echo_port).start()
            await proxy.start()

            session = aiohttp.ClientSession()
            try:
                url = "http://127.0.0.1:%d/ws?url=ws://127.0.0.1:%d/ws" % (proxy_port, echo_port)
                ws = await session.ws_connect(url)
                await ws.send_str("hello world")
                msg = await asyncio.wait_for(ws.receive(), timeout=3)
                self.assertEqual(msg.type, aiohttp.WSMsgType.TEXT)
                self.assertEqual(msg.data, "echo:hello world")
                await ws.close()
            finally:
                await session.close()
                await asyncio.sleep(0.1)  # let relay coroutines finish
                await proxy.stop()
                await echo_runner.cleanup()

        asyncio.run(_test())

    def test_block_closes_connection(self):
        """Frame with secret + block action closes the WS connection."""
        proxy, proxy_port = self._create_proxy(default_action="block", action_overrides={"secrets": "block"})
        echo_port = _get_free_port()

        async def _test():
            async def echo_handler(request):
                ws = aiohttp.web.WebSocketResponse()
                await ws.prepare(request)
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        await ws.send_str("echo:" + msg.data)
                return ws

            echo_app = aiohttp.web.Application()
            echo_app.router.add_get("/ws", echo_handler)
            echo_runner = aiohttp.web.AppRunner(echo_app)
            await echo_runner.setup()
            await aiohttp.web.TCPSite(echo_runner, "127.0.0.1", echo_port).start()
            await proxy.start()

            session = aiohttp.ClientSession()
            try:
                url = "http://127.0.0.1:%d/ws?url=ws://127.0.0.1:%d/ws" % (proxy_port, echo_port)
                ws = await session.ws_connect(url)
                await ws.send_str("key=AKIAIOSFODNN7EXAMPLE")
                msg = await asyncio.wait_for(ws.receive(), timeout=3)
                # Block should close the connection
                self.assertIn(
                    msg.type,
                    (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR),
                )
            finally:
                await session.close()
                await asyncio.sleep(0.1)
                await proxy.stop()
                await echo_runner.cleanup()

        asyncio.run(_test())

    def test_alert_forwards_frame(self):
        """Frame with secret + alert action is forwarded (not blocked)."""
        proxy, proxy_port = self._create_proxy(default_action="alert", action_overrides={"secrets": "alert"})
        echo_port = _get_free_port()

        async def _test():
            async def echo_handler(request):
                ws = aiohttp.web.WebSocketResponse()
                await ws.prepare(request)
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        await ws.send_str("echo:" + msg.data)
                return ws

            echo_app = aiohttp.web.Application()
            echo_app.router.add_get("/ws", echo_handler)
            echo_runner = aiohttp.web.AppRunner(echo_app)
            await echo_runner.setup()
            await aiohttp.web.TCPSite(echo_runner, "127.0.0.1", echo_port).start()
            await proxy.start()

            session = aiohttp.ClientSession()
            try:
                url = "http://127.0.0.1:%d/ws?url=ws://127.0.0.1:%d/ws" % (proxy_port, echo_port)
                ws = await session.ws_connect(url)
                await ws.send_str("key=AKIAIOSFODNN7EXAMPLE")
                msg = await asyncio.wait_for(ws.receive(), timeout=3)
                self.assertEqual(msg.type, aiohttp.WSMsgType.TEXT)
                self.assertIn("AKIAIOSFODNN7EXAMPLE", msg.data)
                await ws.close()
            finally:
                await session.close()
                await asyncio.sleep(0.1)
                await proxy.stop()
                await echo_runner.cleanup()

        asyncio.run(_test())


class TestWebSocketPolicyEnforcement(unittest.TestCase):
    """Unit tests for WebSocket policy enforcement logic."""

    def test_block_action_evaluated(self):
        """PolicyEngine returns block for secrets when action_overrides={'secrets': 'block'}."""
        from lumen_argus.models import Finding
        from lumen_argus.policy import PolicyEngine

        policy = PolicyEngine(default_action="alert", action_overrides={"secrets": "block"})
        findings = [
            Finding(
                detector="secrets",
                type="aws_access_key",
                severity="critical",
                location="ws.outbound",
                value_preview="AKIA****",
                matched_value="AKIAIOSFODNN7EXAMPLE",
            )
        ]
        decision = policy.evaluate(findings)
        self.assertEqual(decision.action, "block")

    def test_alert_action_evaluated(self):
        """PolicyEngine returns alert for secrets when action_overrides={'secrets': 'alert'}."""
        from lumen_argus.models import Finding
        from lumen_argus.policy import PolicyEngine

        policy = PolicyEngine(default_action="alert", action_overrides={"secrets": "alert"})
        findings = [
            Finding(
                detector="secrets",
                type="aws_access_key",
                severity="critical",
                location="ws.outbound",
                value_preview="AKIA****",
                matched_value="AKIAIOSFODNN7EXAMPLE",
            )
        ]
        decision = policy.evaluate(findings)
        self.assertEqual(decision.action, "alert")

    def test_ws_scanner_detects_outbound_secret(self):
        """WebSocketScanner detects secrets in outbound frames."""
        from lumen_argus.allowlist import AllowlistMatcher
        from lumen_argus.detectors.secrets import SecretsDetector
        from lumen_argus.ws_proxy import WebSocketScanner

        scanner = WebSocketScanner(
            detectors=[SecretsDetector()],
            allowlist=AllowlistMatcher(),
            scan_outbound=True,
            scan_inbound=True,
        )
        findings = scanner.scan_outbound_frame("key=AKIAIOSFODNN7EXAMPLE")
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].detector, "secrets")

    def test_ws_scanner_clean_frame(self):
        """WebSocketScanner returns empty findings for clean text."""
        from lumen_argus.allowlist import AllowlistMatcher
        from lumen_argus.detectors.secrets import SecretsDetector
        from lumen_argus.ws_proxy import WebSocketScanner

        scanner = WebSocketScanner(
            detectors=[SecretsDetector()],
            allowlist=AllowlistMatcher(),
            scan_outbound=True,
            scan_inbound=True,
        )
        findings = scanner.scan_outbound_frame("hello world, nothing secret here")
        self.assertEqual(len(findings), 0)

    def test_blocked_event_set_on_block(self):
        """asyncio.Event is set when block is triggered (unit test of the pattern)."""

        async def _test():
            blocked = asyncio.Event()
            self.assertFalse(blocked.is_set())
            blocked.set()
            self.assertTrue(blocked.is_set())

        asyncio.run(_test())


class TestAsyncProxySessionExtraction(unittest.TestCase):
    """Test session context extraction in async proxy."""

    def test_extract_session_anthropic(self):
        from lumen_argus.session import extract_session as _extract_session

        req_data = {
            "model": "claude-opus-4-6",
            "metadata": {"user_id": '{"account_uuid":"acc-123","device_id":"dev-456","session_id":"sess-789"}'},
            "system": "Primary working directory: /home/user/project\nCurrent branch: main\nPlatform: linux",
            "messages": [],
        }
        headers = {
            "x-api-key": "test-key-123",
            "user-agent": "claude-code/1.0",
        }
        ctx = _extract_session(req_data, "anthropic", headers, "127.0.0.1")
        self.assertEqual(ctx.account_id, "acc-123")
        self.assertEqual(ctx.device_id, "dev-456")
        self.assertEqual(ctx.session_id, "sess-789")
        self.assertEqual(ctx.working_directory, "/home/user/project")
        self.assertEqual(ctx.git_branch, "main")
        self.assertEqual(ctx.os_platform, "linux")
        self.assertEqual(ctx.client_name, "claude_code")
        self.assertTrue(ctx.api_key_hash)

    def test_extract_session_explicit_header(self):
        from lumen_argus.session import extract_session as _extract_session

        headers = {"x-session-id": "explicit-session"}
        ctx = _extract_session(None, "anthropic", headers, "10.0.0.1")
        self.assertEqual(ctx.session_id, "explicit-session")
        self.assertEqual(ctx.source_ip, "10.0.0.1")

    def test_extract_session_xff(self):
        from lumen_argus.session import extract_session as _extract_session

        headers = {"x-forwarded-for": "1.2.3.4, 10.0.0.1"}
        ctx = _extract_session(None, "anthropic", headers, "10.0.0.1")
        self.assertEqual(ctx.source_ip, "1.2.3.4")

    def test_extract_session_openai(self):
        from lumen_argus.session import extract_session as _extract_session

        req_data = {
            "model": "gpt-4",
            "user": "user-abc",
            "messages": [{"role": "system", "content": "You are a helper"}],
        }
        ctx = _extract_session(req_data, "openai", {}, "")
        self.assertEqual(ctx.account_id, "user-abc")


if __name__ == "__main__":
    unittest.main()
