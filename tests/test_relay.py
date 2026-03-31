"""Integration tests for the relay server."""

import asyncio
import http.server
import json
import threading
import unittest

import aiohttp

from lumen_argus.provider import ProviderRouter
from lumen_argus.relay import ArgusRelay, RelayState
from tests.helpers import free_port


class MockUpstreamHandler(http.server.BaseHTTPRequestHandler):
    """Mock LLM provider that returns a fixed response."""

    def log_message(self, format, *args):
        pass

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(content_length)
        response = json.dumps(
            {
                "id": "msg_mock",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "Hello from upstream!"}],
                "model": "claude-opus-4-6",
                "usage": {"input_tokens": 10, "output_tokens": 5},
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def do_GET(self):
        body = b'{"status":"ready"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class MockEngineHandler(http.server.BaseHTTPRequestHandler):
    """Mock engine that acts like the proxy — forwards to upstream."""

    upstream_port = 0  # set by test setup

    def log_message(self, format, *args):
        pass

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        # Forward to upstream
        import urllib.request

        req = urllib.request.Request(
            "http://127.0.0.1:%d%s" % (self.__class__.upstream_port, self.path),
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as resp:
            data = resp.read()
            self.send_response(resp.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            body = b'{"status":"ready"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


class TestRelayHealthy(unittest.TestCase):
    """Test relay with a healthy engine."""

    @classmethod
    def setUpClass(cls):
        # Start mock upstream
        cls.upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockUpstreamHandler)
        cls.upstream.daemon_threads = True
        cls.upstream_port = cls.upstream.server_address[1]
        threading.Thread(target=cls.upstream.serve_forever, daemon=True).start()

        # Start mock engine (forwards to upstream)
        MockEngineHandler.upstream_port = cls.upstream_port
        cls.engine = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockEngineHandler)
        cls.engine.daemon_threads = True
        cls.engine_port = cls.engine.server_address[1]
        threading.Thread(target=cls.engine.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.upstream.shutdown()
        cls.engine.shutdown()

    def _create_relay(self, fail_mode="open"):
        port = free_port()
        relay = ArgusRelay(
            bind="127.0.0.1",
            port=port,
            engine_url="http://127.0.0.1:%d" % self.engine_port,
            fail_mode=fail_mode,
            router=ProviderRouter(upstreams={"anthropic": "http://127.0.0.1:%d" % self.upstream_port}),
            health_interval=1,
            health_timeout=1,
            queue_timeout=3,
            timeout=10,
        )
        return relay, port

    def test_forward_via_engine(self):
        """Healthy engine: relay → engine → upstream (200)."""
        relay, port = self._create_relay()

        async def _test():
            await relay.start()
            # Wait for health check to mark engine healthy
            await asyncio.sleep(1.5)
            self.assertEqual(relay.state, RelayState.HEALTHY)
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        "http://127.0.0.1:%d/v1/messages" % port,
                        data=json.dumps(
                            {"model": "claude-opus-4-6", "messages": [{"role": "user", "content": "hi"}]}
                        ).encode(),
                        headers={
                            "Content-Type": "application/json",
                            "x-api-key": "test-key",
                            "anthropic-version": "2024-01-01",
                        },
                    ) as resp:
                        self.assertEqual(resp.status, 200)
                        data = await resp.json()
                        self.assertEqual(data["type"], "message")
            finally:
                await relay.stop()

        asyncio.run(_test())

    def test_health_endpoint(self):
        """Relay /health should include engine state."""
        relay, port = self._create_relay()

        async def _test():
            await relay.start()
            await asyncio.sleep(1.5)
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get("http://127.0.0.1:%d/health" % port) as resp:
                        self.assertEqual(resp.status, 200)
                        data = await resp.json()
                        self.assertEqual(data["status"], "ok")
                        self.assertEqual(data["engine"], "healthy")
                        self.assertEqual(data["fail_mode"], "open")
            finally:
                await relay.stop()

        asyncio.run(_test())

    def test_queue_on_startup(self):
        """During STARTING state, requests wait for engine then succeed."""
        relay, port = self._create_relay()

        async def _test():
            await relay.start()
            self.assertEqual(relay.state, RelayState.STARTING)
            try:
                # Send request immediately — relay should queue it during startup
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        "http://127.0.0.1:%d/v1/messages" % port,
                        data=json.dumps(
                            {"model": "claude-opus-4-6", "messages": [{"role": "user", "content": "hi"}]}
                        ).encode(),
                        headers={
                            "Content-Type": "application/json",
                            "x-api-key": "test-key",
                            "anthropic-version": "2024-01-01",
                        },
                    ) as resp:
                        # Should succeed after health check finds engine
                        self.assertEqual(resp.status, 200)
            finally:
                await relay.stop()

        asyncio.run(_test())


class TestRelayFailOpen(unittest.TestCase):
    """Test relay with engine down and fail_mode=open."""

    @classmethod
    def setUpClass(cls):
        # Start mock upstream (no engine — it's "down")
        cls.upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockUpstreamHandler)
        cls.upstream.daemon_threads = True
        cls.upstream_port = cls.upstream.server_address[1]
        threading.Thread(target=cls.upstream.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.upstream.shutdown()

    def test_direct_upstream_when_engine_down(self):
        """Engine down + fail-open: relay → direct upstream (200)."""
        port = free_port()
        engine_port = free_port()  # nothing listening here
        relay = ArgusRelay(
            bind="127.0.0.1",
            port=port,
            engine_url="http://127.0.0.1:%d" % engine_port,
            fail_mode="open",
            router=ProviderRouter(upstreams={"anthropic": "http://127.0.0.1:%d" % self.upstream_port}),
            health_interval=1,
            health_timeout=1,
            queue_timeout=1,
            timeout=10,
        )

        async def _test():
            await relay.start()
            # Wait for health check to mark engine unhealthy
            await asyncio.sleep(1.5)
            self.assertEqual(relay.state, RelayState.UNHEALTHY)
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        "http://127.0.0.1:%d/v1/messages" % port,
                        data=json.dumps(
                            {"model": "claude-opus-4-6", "messages": [{"role": "user", "content": "hi"}]}
                        ).encode(),
                        headers={
                            "Content-Type": "application/json",
                            "x-api-key": "test-key",
                            "anthropic-version": "2024-01-01",
                        },
                    ) as resp:
                        self.assertEqual(resp.status, 200)
                        data = await resp.json()
                        self.assertEqual(data["type"], "message")
            finally:
                await relay.stop()

        asyncio.run(_test())


class TestRelayFailClosed(unittest.TestCase):
    """Test relay with engine down and fail_mode=closed."""

    def test_503_when_engine_down(self):
        """Engine down + fail-closed: relay → 503."""
        port = free_port()
        engine_port = free_port()  # nothing listening
        relay = ArgusRelay(
            bind="127.0.0.1",
            port=port,
            engine_url="http://127.0.0.1:%d" % engine_port,
            fail_mode="closed",
            health_interval=1,
            health_timeout=1,
            queue_timeout=1,
            timeout=10,
        )

        async def _test():
            await relay.start()
            await asyncio.sleep(1.5)
            self.assertEqual(relay.state, RelayState.UNHEALTHY)
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        "http://127.0.0.1:%d/v1/messages" % port,
                        data=b'{"model":"claude-opus-4-6","messages":[]}',
                        headers={
                            "Content-Type": "application/json",
                            "x-api-key": "k",
                            "anthropic-version": "2024-01-01",
                        },
                    ) as resp:
                        self.assertEqual(resp.status, 503)
                        data = await resp.json()
                        self.assertIn("error", data)
            finally:
                await relay.stop()

        asyncio.run(_test())


class TestRelayStateTransitions(unittest.TestCase):
    """Test engine state transitions: healthy → unhealthy → healthy."""

    @classmethod
    def setUpClass(cls):
        cls.upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockUpstreamHandler)
        cls.upstream.daemon_threads = True
        cls.upstream_port = cls.upstream.server_address[1]
        threading.Thread(target=cls.upstream.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.upstream.shutdown()

    def test_transition_on_engine_stop_and_restart(self):
        """Relay should detect engine going down and coming back up."""
        # Start engine
        MockEngineHandler.upstream_port = self.upstream_port
        engine = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockEngineHandler)
        engine.daemon_threads = True
        engine_port = engine.server_address[1]
        engine_thread = threading.Thread(target=engine.serve_forever, daemon=True)
        engine_thread.start()

        port = free_port()
        relay = ArgusRelay(
            bind="127.0.0.1",
            port=port,
            engine_url="http://127.0.0.1:%d" % engine_port,
            fail_mode="open",
            router=ProviderRouter(upstreams={"anthropic": "http://127.0.0.1:%d" % self.upstream_port}),
            health_interval=0.5,
            health_timeout=0.5,
            queue_timeout=2,
            timeout=10,
        )

        async def _test():
            await relay.start()
            await asyncio.sleep(1)
            self.assertEqual(relay.state, RelayState.HEALTHY)

            # Kill engine
            engine.shutdown()
            engine.server_close()
            await asyncio.sleep(1.5)
            self.assertEqual(relay.state, RelayState.UNHEALTHY)

            # Restart engine on same port
            engine2 = http.server.ThreadingHTTPServer(("127.0.0.1", engine_port), MockEngineHandler)
            engine2.daemon_threads = True
            threading.Thread(target=engine2.serve_forever, daemon=True).start()
            await asyncio.sleep(1.5)
            self.assertEqual(relay.state, RelayState.HEALTHY)

            engine2.shutdown()
            await relay.stop()

        asyncio.run(_test())


class TestRelayConfig(unittest.TestCase):
    """Test config dataclasses for relay/engine."""

    def test_relay_config_defaults(self):
        from lumen_argus.config import RelayConfig

        rc = RelayConfig()
        self.assertEqual(rc.port, 8080)
        self.assertEqual(rc.fail_mode, "open")
        self.assertEqual(rc.engine_url, "http://localhost:8090")
        self.assertEqual(rc.health_check_interval, 2)

    def test_engine_config_defaults(self):
        from lumen_argus.config import EngineConfig

        ec = EngineConfig()
        self.assertEqual(ec.port, 8090)

    def test_config_has_relay_and_engine(self):
        from lumen_argus.config import Config

        c = Config()
        self.assertEqual(c.relay.port, 8080)
        self.assertEqual(c.engine.port, 8090)


if __name__ == "__main__":
    unittest.main()
