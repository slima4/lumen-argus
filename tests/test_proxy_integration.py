"""Integration test: start proxy, mock upstream, verify end-to-end behavior."""

import http.server
import json
import threading
import time
import unittest
import urllib.request
from urllib.error import HTTPError

from lumen_argus.audit import AuditLogger
from lumen_argus.display import TerminalDisplay
from lumen_argus.pipeline import ScannerPipeline
from lumen_argus.provider import ProviderRouter
from lumen_argus.proxy import ArgusProxyServer


class MockUpstreamHandler(http.server.BaseHTTPRequestHandler):
    """Minimal mock that returns a fixed response."""

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


class TestProxyIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import tempfile

        # Start mock upstream on an ephemeral port
        cls.upstream = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0),
            MockUpstreamHandler,
        )
        cls.upstream.daemon_threads = True
        cls.upstream_port = cls.upstream.server_address[1]
        cls.upstream_thread = threading.Thread(target=cls.upstream.serve_forever, daemon=True)
        cls.upstream_thread.start()

        # Create temp dir for audit logs
        cls.tmpdir = tempfile.mkdtemp()

        # Configure proxy to point to our mock upstream (HTTP not HTTPS)
        cls.upstreams = {
            "anthropic": "http://127.0.0.1:%d" % cls.upstream_port,
        }
        cls.pipeline = ScannerPipeline(
            default_action="alert",
            action_overrides={"secrets": "block"},
        )
        cls.router = ProviderRouter(upstreams=cls.upstreams)
        cls.audit = AuditLogger(log_dir=cls.tmpdir)
        cls.display = TerminalDisplay(no_color=True)

        cls.proxy = ArgusProxyServer(
            bind="127.0.0.1",
            port=0,  # ephemeral port
            pipeline=cls.pipeline,
            router=cls.router,
            audit=cls.audit,
            display=cls.display,
        )
        cls.proxy_port = cls.proxy.server_address[1]
        cls.proxy_thread = threading.Thread(target=cls.proxy.serve_forever, daemon=True)
        cls.proxy_thread.start()

        # Give servers time to start
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.proxy.shutdown()
        cls.upstream.shutdown()
        cls.audit.close()

    _session_counter = 0

    def _post(self, body_dict, session_id=None):
        """Send a POST to the proxy with a unique session ID."""
        if session_id is None:
            TestProxyIntegration._session_counter += 1
            session_id = "test-sess-%d" % TestProxyIntegration._session_counter
        body = json.dumps(body_dict).encode()
        req = urllib.request.Request(
            "http://127.0.0.1:%d/v1/messages" % self.proxy_port,
            data=body,
            headers={
                "Content-Type": "application/json",
                "x-api-key": "test-key",
                "anthropic-version": "2024-01-01",
                "x-session-id": session_id,
            },
            method="POST",
        )
        try:
            resp = urllib.request.urlopen(req)
            return resp.status, json.loads(resp.read())
        except HTTPError as e:
            return e.code, json.loads(e.read())

    def test_clean_request_forwarded(self):
        status, data = self._post(
            {
                "model": "claude-opus-4-6",
                "messages": [{"role": "user", "content": "What is 2+2?"}],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["type"], "message")

    def test_secret_blocked(self):
        status, data = self._post(
            {
                "model": "claude-opus-4-6",
                "messages": [
                    {"role": "user", "content": "My key: AKIAIOSFODNN7EXAMPLE"},
                ],
            }
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["type"], "invalid_request_error")
        self.assertIn("lumen-argus", data["error"]["message"])

    def test_pii_alerted_but_forwarded(self):
        status, data = self._post(
            {
                "model": "claude-opus-4-6",
                "messages": [
                    {"role": "user", "content": "Contact john.smith@company.com for details"},
                ],
            }
        )
        # Alert action should forward (not block)
        self.assertEqual(status, 200)

    def test_streaming_secret_blocked_as_400(self):
        """#2: Blocked streaming request returns 400 JSON, not SSE."""
        TestProxyIntegration._session_counter += 1
        session_id = "test-sess-%d" % TestProxyIntegration._session_counter
        body = json.dumps(
            {
                "model": "claude-opus-4-6",
                "stream": True,
                "messages": [
                    {"role": "user", "content": "My key: AKIAI44QH8DHBEXAMPLE"},
                ],
            }
        ).encode()
        req = urllib.request.Request(
            "http://127.0.0.1:%d/v1/messages" % self.proxy_port,
            data=body,
            headers={
                "Content-Type": "application/json",
                "x-api-key": "test-key",
                "anthropic-version": "2024-01-01",
                "x-session-id": session_id,
            },
            method="POST",
        )
        with self.assertRaises(HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 400)
        data = ctx.exception.read().decode()
        self.assertIn("invalid_request_error", data)

    def test_history_strip_forwards_request(self):
        """#3: Blocked finding in history only → strip and forward, get 200."""
        status, data = self._post(
            {
                "model": "claude-opus-4-6",
                "messages": [
                    {"role": "user", "content": "My key: AKIAI44QH8DHBEXAMPLE"},
                    {"role": "assistant", "content": "Error: blocked."},
                    {"role": "user", "content": "What is 2+2?"},
                ],
            }
        )
        # Secret is in messages[0] (history), not in messages[2] (latest)
        # Proxy should strip messages[0]+[1] and forward messages[2]
        self.assertEqual(status, 200)
        self.assertEqual(data["type"], "message")


if __name__ == "__main__":
    unittest.main()
