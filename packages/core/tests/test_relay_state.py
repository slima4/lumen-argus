"""Tests for the relay-state provider registry.

The registry inverts the core→agent dependency for ``get_service_status``
— core never imports the agent package. Tests pin the public contract:
register / unregister / get-when-empty / replace. Agent-side adapter
tests live in ``packages/agent/tests/test_relay_state_adapter.py``.
"""

from __future__ import annotations

import unittest
from typing import Any

from lumen_argus_core import relay_state


class _StubProvider:
    """Minimal provider satisfying the Protocol."""

    def __init__(self, state: dict[str, Any] | None = None) -> None:
        self._state = state
        self.load_calls = 0

    def load(self) -> dict[str, Any] | None:
        self.load_calls += 1
        return self._state


class TestRelayStateRegistry(unittest.TestCase):
    def setUp(self) -> None:
        # Save whatever the agent package registered at import time so
        # other test modules don't observe a wiped slate.
        self._saved = relay_state.get_provider()
        relay_state.unregister_provider()

    def tearDown(self) -> None:
        relay_state.unregister_provider()
        if self._saved is not None:
            relay_state.register_provider(self._saved)

    def test_get_provider_returns_none_before_registration(self) -> None:
        self.assertIsNone(relay_state.get_provider())

    def test_register_and_get_provider(self) -> None:
        p = _StubProvider()
        relay_state.register_provider(p)
        self.assertIs(relay_state.get_provider(), p)

    def test_register_replaces_previous_provider(self) -> None:
        first = _StubProvider()
        second = _StubProvider()
        relay_state.register_provider(first)
        relay_state.register_provider(second)
        self.assertIs(relay_state.get_provider(), second)

    def test_provider_satisfies_protocol(self) -> None:
        self.assertIsInstance(_StubProvider(), relay_state.RelayStateProvider)

    def test_unregister_clears_provider(self) -> None:
        relay_state.register_provider(_StubProvider())
        relay_state.unregister_provider()
        self.assertIsNone(relay_state.get_provider())


class TestRelayServiceIntegration(unittest.TestCase):
    """``relay_service.get_service_status`` dispatches through the registry."""

    def setUp(self) -> None:
        self._saved = relay_state.get_provider()
        relay_state.unregister_provider()

    def tearDown(self) -> None:
        relay_state.unregister_provider()
        if self._saved is not None:
            relay_state.register_provider(self._saved)

    def test_no_provider_reports_running_unknown(self) -> None:
        from lumen_argus_core.relay_service import get_service_status

        status = get_service_status()
        self.assertEqual(status["running"], "unknown")

    def test_provider_returning_state_reports_running_true(self) -> None:
        from lumen_argus_core.relay_service import get_service_status

        relay_state.register_provider(_StubProvider({"port": 8070, "upstream_url": "http://proxy:8080", "pid": 1234}))
        status = get_service_status()
        self.assertEqual(status["running"], "true")
        self.assertEqual(status["port"], "8070")
        self.assertEqual(status["upstream_url"], "http://proxy:8080")
        self.assertEqual(status["pid"], "1234")

    def test_provider_returning_none_reports_running_false(self) -> None:
        from lumen_argus_core.relay_service import get_service_status

        relay_state.register_provider(_StubProvider(None))
        status = get_service_status()
        self.assertEqual(status["running"], "false")

    def test_provider_raising_reports_running_unknown(self) -> None:
        from lumen_argus_core.relay_service import get_service_status

        class _Broken:
            def load(self) -> dict[str, Any] | None:
                raise RuntimeError("disk error")

        relay_state.register_provider(_Broken())
        with self.assertLogs("argus.relay.service", level="WARNING"):
            status = get_service_status()
        self.assertEqual(status["running"], "unknown")


class TestValidateRelayState(unittest.TestCase):
    """``validate_relay_state`` is pure shape validation (#77 SRP split)."""

    def test_happy_path(self):
        ok = relay_state.validate_relay_state({"pid": 100, "port": 8070, "bind": "127.0.0.1", "boot_token": "abc"})
        self.assertEqual(ok, (100, 8070, "127.0.0.1", "abc"))

    def test_missing_boot_token(self):
        result = relay_state.validate_relay_state({"pid": 100, "port": 8070, "bind": "127.0.0.1"})
        self.assertIsInstance(result, str)
        self.assertIn("boot_token", result)

    def test_empty_boot_token_rejected(self):
        result = relay_state.validate_relay_state({"pid": 100, "port": 8070, "bind": "127.0.0.1", "boot_token": ""})
        self.assertIsInstance(result, str)
        self.assertIn("boot_token", result)

    def test_missing_pid(self):
        result = relay_state.validate_relay_state({"port": 8070, "bind": "127.0.0.1", "boot_token": "x"})
        self.assertIsInstance(result, str)
        self.assertIn("pid", result)

    def test_zero_pid_rejected(self):
        result = relay_state.validate_relay_state({"pid": 0, "port": 8070, "bind": "127.0.0.1", "boot_token": "x"})
        self.assertIsInstance(result, str)
        self.assertIn("pid", result)

    def test_missing_port(self):
        result = relay_state.validate_relay_state({"pid": 100, "bind": "127.0.0.1", "boot_token": "x"})
        self.assertIsInstance(result, str)
        self.assertIn("port", result)

    def test_negative_port_rejected(self):
        result = relay_state.validate_relay_state({"pid": 100, "port": -1, "bind": "127.0.0.1", "boot_token": "x"})
        self.assertIsInstance(result, str)
        self.assertIn("port", result)

    def test_port_above_65535_rejected(self):
        """Out-of-range port would crash probe_loopback_health with OverflowError."""
        result = relay_state.validate_relay_state({"pid": 100, "port": 999999, "bind": "127.0.0.1", "boot_token": "x"})
        self.assertIsInstance(result, str)
        self.assertIn("port", result)

    def test_port_max_accepted(self):
        ok = relay_state.validate_relay_state({"pid": 100, "port": 65535, "bind": "127.0.0.1", "boot_token": "x"})
        self.assertEqual(ok, (100, 65535, "127.0.0.1", "x"))

    def test_missing_bind_defaults_to_loopback(self):
        ok = relay_state.validate_relay_state({"pid": 100, "port": 8070, "boot_token": "x"})
        self.assertEqual(ok, (100, 8070, "127.0.0.1", "x"))


class TestLoopbackHostFor(unittest.TestCase):
    """``loopback_host_for`` maps wildcard binds to loopback (#77 SRP split)."""

    def test_zero_zero_zero_zero_maps_to_loopback(self):
        self.assertEqual(relay_state.loopback_host_for("0.0.0.0"), "127.0.0.1")

    def test_loopback_passthrough(self):
        self.assertEqual(relay_state.loopback_host_for("127.0.0.1"), "127.0.0.1")

    def test_other_bind_passthrough(self):
        self.assertEqual(relay_state.loopback_host_for("192.168.1.10"), "192.168.1.10")


class TestReadRelayStateFile(unittest.TestCase):
    """``read_relay_state_file`` reads + parses; raises on corruption (#77 SRP split)."""

    def setUp(self) -> None:
        import tempfile

        self._tmp = tempfile.mkdtemp()
        import os

        self._path = os.path.join(self._tmp, "relay.json")

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_parses_valid_json(self):
        import json

        with open(self._path, "w") as f:
            json.dump({"pid": 1}, f)
        self.assertEqual(relay_state.read_relay_state_file(self._path), {"pid": 1})

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            relay_state.read_relay_state_file(self._path)

    def test_corrupt_json_raises(self):
        import json

        with open(self._path, "w") as f:
            f.write("{not json")
        with self.assertRaises(json.JSONDecodeError):
            relay_state.read_relay_state_file(self._path)

    def test_non_object_top_level_raises(self):
        """A bare list/string at the top level is not a relay state record."""
        with open(self._path, "w") as f:
            f.write("[1, 2, 3]")
        with self.assertRaises(TypeError):
            relay_state.read_relay_state_file(self._path)


class TestProbeLoopbackHealth(unittest.TestCase):
    """``probe_loopback_health`` classifies /health probe outcomes (#77)."""

    def setUp(self) -> None:
        import socket
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from threading import Thread

        self._BaseHTTPRequestHandler = BaseHTTPRequestHandler
        self._HTTPServer = HTTPServer
        self._Thread = Thread
        self._socket = socket

    def _serve(self, handler_factory):
        """Spin up a single-shot HTTP server on an ephemeral port; return (host, port, shutdown)."""
        server = self._HTTPServer(("127.0.0.1", 0), handler_factory)
        thread = self._Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def shutdown():
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        return server.server_address[0], server.server_address[1], shutdown

    def _make_handler(self, status: int, body: bytes):
        cls = self._BaseHTTPRequestHandler

        class H(cls):
            def do_GET(self):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a, **kw):  # quiet test output
                pass

        return H

    def test_match(self):
        import json

        handler = self._make_handler(200, json.dumps({"boot_token": "abc"}).encode())
        host, port, stop = self._serve(handler)
        try:
            self.assertEqual(
                relay_state.probe_loopback_health(host, port, "abc", timeout=1.0),
                relay_state.PROBE_MATCH,
            )
        finally:
            stop()

    def test_mismatch_wrong_token(self):
        import json

        handler = self._make_handler(200, json.dumps({"boot_token": "other"}).encode())
        host, port, stop = self._serve(handler)
        try:
            self.assertEqual(
                relay_state.probe_loopback_health(host, port, "ours", timeout=1.0),
                relay_state.PROBE_MISMATCH,
            )
        finally:
            stop()

    def test_mismatch_missing_field(self):
        """200 + JSON object without boot_token is a foreign service, not ambiguous."""
        import json

        handler = self._make_handler(200, json.dumps({"hello": "world"}).encode())
        host, port, stop = self._serve(handler)
        try:
            self.assertEqual(
                relay_state.probe_loopback_health(host, port, "ours", timeout=1.0),
                relay_state.PROBE_MISMATCH,
            )
        finally:
            stop()

    def test_mismatch_non_object_body(self):
        handler = self._make_handler(200, b'"not a dict"')
        host, port, stop = self._serve(handler)
        try:
            self.assertEqual(
                relay_state.probe_loopback_health(host, port, "ours", timeout=1.0),
                relay_state.PROBE_MISMATCH,
            )
        finally:
            stop()

    def test_refused(self):
        # Find a free port, close the socket — the port is now refusing connections.
        s = self._socket.socket(self._socket.AF_INET, self._socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertEqual(
            relay_state.probe_loopback_health("127.0.0.1", port, "ours", timeout=1.0),
            relay_state.PROBE_REFUSED,
        )

    def test_ambiguous_non_200(self):
        handler = self._make_handler(503, b"unavailable")
        host, port, stop = self._serve(handler)
        try:
            # urllib raises HTTPError on 4xx/5xx — classified as ambiguous so
            # we don't churn the file on a relay returning 503 during startup.
            self.assertEqual(
                relay_state.probe_loopback_health(host, port, "ours", timeout=1.0),
                relay_state.PROBE_AMBIGUOUS,
            )
        finally:
            stop()

    def test_ambiguous_timeout(self):
        cls = self._BaseHTTPRequestHandler

        class Slow(cls):
            def do_GET(self):
                import time

                time.sleep(2)  # exceeds probe timeout
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a, **kw):
                pass

        host, port, stop = self._serve(Slow)
        try:
            self.assertEqual(
                relay_state.probe_loopback_health(host, port, "ours", timeout=0.2),
                relay_state.PROBE_AMBIGUOUS,
            )
        finally:
            stop()


if __name__ == "__main__":
    unittest.main()
