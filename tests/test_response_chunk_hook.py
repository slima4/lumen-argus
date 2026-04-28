"""Tests for the response_chunk_hook extension surface and SSE wiring."""

import asyncio
import http.server
import json
import logging
import threading
import unittest

import aiohttp

from lumen_argus.async_proxy import AsyncArgusProxy
from lumen_argus.audit import AuditLogger
from lumen_argus.display import TerminalDisplay
from lumen_argus.extensions import ExtensionRegistry
from lumen_argus.pipeline import ScannerPipeline
from lumen_argus.provider import ProviderRouter
from tests.helpers import free_port as _get_free_port


class TestResponseChunkHookSurface(unittest.TestCase):
    def test_default_unset(self):
        ext = ExtensionRegistry()
        self.assertIsNone(ext.get_response_chunk_hook())

    def test_set_then_get_returns_hook(self):
        ext = ExtensionRegistry()

        def hook(chunk: bytes, session: object) -> bytes:
            return chunk.upper()

        ext.set_response_chunk_hook(hook)
        self.assertIs(ext.get_response_chunk_hook(), hook)

    def test_overwrite_last_wins(self):
        ext = ExtensionRegistry()

        def hook_a(chunk: bytes, session: object) -> bytes:
            return chunk

        def hook_b(chunk: bytes, session: object) -> bytes:
            return chunk

        ext.set_response_chunk_hook(hook_a)
        ext.set_response_chunk_hook(hook_b)
        self.assertIs(ext.get_response_chunk_hook(), hook_b)


class _SSEUpstreamHandler(http.server.BaseHTTPRequestHandler):
    """Minimal mock that always returns SSE chunks for POST."""

    def log_message(self, format, *args):  # silence access log
        pass

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(content_length)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for event in (
            'data: {"type":"content_block_delta","delta":{"text":"alpha"}}\n\n',
            'data: {"type":"content_block_delta","delta":{"text":"bravo"}}\n\n',
            "data: [DONE]\n\n",
        ):
            self.wfile.write(event.encode())
            self.wfile.flush()


class TestResponseChunkHookEndToEnd(unittest.TestCase):
    """Spin up a real proxy + mock SSE upstream and drive chunks through the hook."""

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls.upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SSEUpstreamHandler)
        cls.upstream.daemon_threads = True
        cls.upstream_port = cls.upstream.server_address[1]
        cls.upstream_thread = threading.Thread(target=cls.upstream.serve_forever, daemon=True)
        cls.upstream_thread.start()
        cls.tmpdir = tempfile.mkdtemp()

    @classmethod
    def tearDownClass(cls):
        cls.upstream.shutdown()

    def _build_proxy(self, response_chunk_hook=None):
        pipeline = ScannerPipeline(default_action="alert", action_overrides={"secrets": "block"})
        router = ProviderRouter(upstreams={"anthropic": "http://127.0.0.1:%d" % self.upstream_port})
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
            response_chunk_hook=response_chunk_hook,
        )
        return proxy, port

    async def _stream(self, port: int) -> str:
        body = json.dumps(
            {
                "model": "claude-opus-4-6",
                "stream": True,
                "messages": [{"role": "user", "content": "ping"}],
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
                    "x-session-id": "chunk-hook-test",
                },
            ) as resp:
                self.assertEqual(resp.status, 200)
                return await resp.text()

    async def _run(self, proxy, body_coro):
        await proxy.start()
        try:
            return await body_coro()
        finally:
            await proxy.stop()

    def test_passthrough_when_hook_unset(self):
        proxy, port = self._build_proxy(response_chunk_hook=None)

        async def _go():
            return await self._stream(port)

        text = asyncio.run(self._run(proxy, _go))
        self.assertIn("alpha", text)
        self.assertIn("bravo", text)

    def test_uppercase_hook_rewrites_chunks(self):
        seen_sessions = []

        def to_upper(chunk: bytes, session) -> bytes:
            seen_sessions.append(session)
            return chunk.upper()

        proxy, port = self._build_proxy(response_chunk_hook=to_upper)

        async def _go():
            return await self._stream(port)

        text = asyncio.run(self._run(proxy, _go))
        self.assertIn("ALPHA", text)
        self.assertIn("BRAVO", text)
        self.assertNotIn("alpha", text)
        self.assertNotIn("bravo", text)
        self.assertTrue(seen_sessions, "hook must receive the SessionContext")

    def test_raising_hook_falls_back_to_unmodified(self):
        def boom(chunk: bytes, session) -> bytes:
            raise RuntimeError("hook exploded")

        proxy, port = self._build_proxy(response_chunk_hook=boom)

        # Capture the fail-open log line to prove the hook actually ran
        # and the original chunk was still forwarded.
        log = logging.getLogger("argus.proxy")
        records: list[logging.LogRecord] = []

        class _Capture(logging.Handler):
            def emit(self, record):
                records.append(record)

        handler = _Capture(level=logging.ERROR)
        log.addHandler(handler)
        try:

            async def _go():
                return await self._stream(port)

            text = asyncio.run(self._run(proxy, _go))
        finally:
            log.removeHandler(handler)

        self.assertIn("alpha", text)
        self.assertIn("bravo", text)
        matching = [r for r in records if "response chunk hook failed" in r.getMessage()]
        self.assertTrue(matching, "expected fail-open error log when hook raises")
        self.assertTrue(
            any(r.exc_info is not None for r in matching),
            "fail-open log must include the original exception traceback",
        )


if __name__ == "__main__":
    unittest.main()
