"""Integration test: start proxy, mock upstream, verify end-to-end behavior."""

import http.server
import json
import ssl
import threading
import time
import unittest
import urllib.request
from urllib.error import HTTPError

from lumen_argus.allowlist import AllowlistMatcher
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

        response = json.dumps({
            "id": "msg_mock",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Hello!"}],
            "model": "claude-opus-4-6",
            "usage": {"input_tokens": 100, "output_tokens": 10},
        }).encode()

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
            ("127.0.0.1", 0), MockUpstreamHandler,
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

    def _post(self, body_dict):
        """Send a POST to the proxy."""
        body = json.dumps(body_dict).encode()
        req = urllib.request.Request(
            "http://127.0.0.1:%d/v1/messages" % self.proxy_port,
            data=body,
            headers={
                "Content-Type": "application/json",
                "x-api-key": "test-key",
                "anthropic-version": "2024-01-01",
            },
            method="POST",
        )
        try:
            resp = urllib.request.urlopen(req)
            return resp.status, json.loads(resp.read())
        except HTTPError as e:
            return e.code, json.loads(e.read())

    def test_clean_request_forwarded(self):
        status, data = self._post({
            "model": "claude-opus-4-6",
            "messages": [{"role": "user", "content": "What is 2+2?"}],
        })
        self.assertEqual(status, 200)
        self.assertEqual(data["type"], "message")

    def test_secret_blocked(self):
        status, data = self._post({
            "model": "claude-opus-4-6",
            "messages": [
                {"role": "user", "content": "My key: AKIAIOSFODNN7EXAMPLE"},
            ],
        })
        self.assertEqual(status, 403)
        self.assertEqual(data["error"]["type"], "request_blocked")
        self.assertTrue(len(data["error"]["findings"]) > 0)

    def test_pii_alerted_but_forwarded(self):
        status, data = self._post({
            "model": "claude-opus-4-6",
            "messages": [
                {"role": "user", "content": "Contact john.smith@company.com for details"},
            ],
        })
        # Alert action should forward (not block)
        self.assertEqual(status, 200)

    def test_streaming_secret_blocked_as_sse(self):
        """#2: Blocked SSE request should return SSE error event."""
        body = json.dumps({
            "model": "claude-opus-4-6",
            "stream": True,
            "messages": [
                {"role": "user", "content": "My key: AKIAIOSFODNN7EXAMPLE"},
            ],
        }).encode()
        req = urllib.request.Request(
            "http://127.0.0.1:%d/v1/messages" % self.proxy_port,
            data=body,
            headers={
                "Content-Type": "application/json",
                "x-api-key": "test-key",
                "anthropic-version": "2024-01-01",
            },
            method="POST",
        )
        resp = urllib.request.urlopen(req)
        # SSE block returns 200 with text/event-stream
        self.assertEqual(resp.status, 200)
        content_type = resp.headers.get("Content-Type", "")
        self.assertIn("text/event-stream", content_type)
        data = resp.read().decode()
        self.assertIn("event: error", data)
        self.assertIn("request_blocked", data)


if __name__ == "__main__":
    unittest.main()
