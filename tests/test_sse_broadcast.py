"""Tests for SSE event broadcasting from pipeline and dashboard API."""

import json
import unittest
from unittest.mock import MagicMock, patch

from lumen_argus.dashboard.api import (
    _broadcast_sse,
    _handle_config_update,
    _handle_pipeline_update,
    _handle_rule_clone,
    _handle_rule_create,
    _handle_rule_delete,
    _handle_rule_update,
    _handle_rules_bulk_update,
)
from lumen_argus.dashboard.sse import SSEBroadcaster
from lumen_argus.extensions import ExtensionRegistry
from lumen_argus.models import SessionContext
from lumen_argus.pipeline import ScannerPipeline
from tests.helpers import StoreTestCase


def _drain_queue(queue):
    """Read all available payloads from a queue and return concatenated string."""
    parts = []
    while not queue.empty():
        parts.append(queue.get_nowait())
    return "".join(parts)


class TestBroadcastSSEHelper(unittest.TestCase):
    """Test the _broadcast_sse helper function."""

    def test_no_extensions(self):
        """Should not raise when extensions is None."""
        _broadcast_sse(None, "test", {"key": "value"})

    def test_no_broadcaster(self):
        """Should not raise when broadcaster is not set."""
        extensions = ExtensionRegistry()
        _broadcast_sse(extensions, "test", {"key": "value"})

    def test_broadcasts_event(self):
        """Should call broadcaster.broadcast with correct args."""
        broadcaster = SSEBroadcaster(heartbeat_interval=9999)
        queue = broadcaster.subscribe()

        extensions = ExtensionRegistry()
        extensions.set_sse_broadcaster(broadcaster)

        _broadcast_sse(extensions, "rules", {"action": "created"})

        output = _drain_queue(queue)
        self.assertIn("event: rules", output)
        self.assertIn('"action": "created"', output)
        broadcaster.unsubscribe(queue)

    def test_empty_data_default(self):
        """Should broadcast empty dict when data is None."""
        broadcaster = SSEBroadcaster(heartbeat_interval=9999)
        queue = broadcaster.subscribe()

        extensions = ExtensionRegistry()
        extensions.set_sse_broadcaster(broadcaster)

        _broadcast_sse(extensions, "config")

        output = _drain_queue(queue)
        self.assertIn("event: config", output)
        self.assertIn("data: {}", output)
        broadcaster.unsubscribe(queue)

    def test_exception_suppressed(self):
        """Should not raise when broadcaster.broadcast fails."""
        broadcaster = MagicMock()
        broadcaster.broadcast.side_effect = RuntimeError("boom")

        extensions = ExtensionRegistry()
        extensions.set_sse_broadcaster(broadcaster)

        # Should not raise
        _broadcast_sse(extensions, "test")


class TestPipelineSSEBroadcast(StoreTestCase):
    """Test that pipeline.scan() broadcasts finding and scan events."""

    def _make_pipeline(self, broadcaster):
        extensions = ExtensionRegistry()
        extensions.set_sse_broadcaster(broadcaster)
        extensions.set_analytics_store(self.store)
        return ScannerPipeline(extensions=extensions)

    def test_scan_event_on_clean_request(self):
        """A clean request should broadcast a scan event with action=pass."""
        broadcaster = SSEBroadcaster(heartbeat_interval=9999)
        queue = broadcaster.subscribe()

        pipeline = self._make_pipeline(broadcaster)
        body = json.dumps({"messages": [{"role": "user", "content": "hello world"}]}).encode()
        pipeline.scan(body, "anthropic")

        output = _drain_queue(queue)
        events = _parse_sse_events(output)

        scan_events = [e for e in events if e["event"] == "scan"]
        self.assertEqual(len(scan_events), 1)
        self.assertEqual(scan_events[0]["data"]["action"], "pass")
        self.assertEqual(scan_events[0]["data"]["findings_count"], 0)

        # No finding events for clean request
        finding_events = [e for e in events if e["event"] == "finding"]
        self.assertEqual(len(finding_events), 0)

        broadcaster.unsubscribe(queue)

    def test_finding_event_on_secret(self):
        """A request with a secret should broadcast both scan and finding events."""
        broadcaster = SSEBroadcaster(heartbeat_interval=9999)
        queue = broadcaster.subscribe()

        pipeline = self._make_pipeline(broadcaster)
        body = json.dumps({"messages": [{"role": "user", "content": "key: AKIAIOSFODNN7EXAMPLE"}]}).encode()
        session = SessionContext(client_name="aider")
        pipeline.scan(body, "anthropic", session=session)

        output = _drain_queue(queue)
        events = _parse_sse_events(output)

        # Should have scan event
        scan_events = [e for e in events if e["event"] == "scan"]
        self.assertEqual(len(scan_events), 1)
        self.assertGreater(scan_events[0]["data"]["findings_count"], 0)
        self.assertEqual(scan_events[0]["data"]["client"], "aider")

        # Should have at least one finding event
        finding_events = [e for e in events if e["event"] == "finding"]
        self.assertGreater(len(finding_events), 0)
        f = finding_events[0]["data"]
        self.assertIn("detector", f)
        self.assertIn("type", f)
        self.assertIn("severity", f)
        self.assertIn("timestamp", f)
        self.assertEqual(f["client"], "aider")
        # matched_value must never be in the broadcast
        self.assertNotIn("matched_value", f)

        broadcaster.unsubscribe(queue)

    def test_no_broadcast_without_broadcaster(self):
        """Pipeline should not fail when no broadcaster is set."""
        extensions = ExtensionRegistry()
        extensions.set_analytics_store(self.store)
        pipeline = ScannerPipeline(extensions=extensions)

        body = json.dumps({"messages": [{"role": "user", "content": "hello"}]}).encode()
        result = pipeline.scan(body, "anthropic")
        self.assertEqual(result.action, "pass")


class TestAPISSEBroadcast(StoreTestCase):
    """Test that dashboard API handlers broadcast SSE events."""

    def _make_extensions(self):
        broadcaster = SSEBroadcaster(heartbeat_interval=9999)
        queue = broadcaster.subscribe()
        extensions = ExtensionRegistry()
        extensions.set_sse_broadcaster(broadcaster)
        return extensions, broadcaster, queue

    def test_rule_create_broadcasts(self):
        extensions, broadcaster, queue = self._make_extensions()
        body = json.dumps({"name": "test_rule", "pattern": "secret_\\w+", "detector": "secrets"}).encode()
        status, _ = _handle_rule_create(body, self.store, extensions)
        self.assertEqual(status, 201)

        output = _drain_queue(queue)
        self.assertIn("event: rules", output)
        broadcaster.unsubscribe(queue)

    def test_rule_update_broadcasts(self):
        extensions, broadcaster, queue = self._make_extensions()
        # Create a rule first
        self.store.create_rule({"name": "my_rule", "pattern": "test", "source": "dashboard", "tier": "custom"})
        # Drain the create event
        _drain_queue(queue)

        body = json.dumps({"severity": "warning"}).encode()
        status, _ = _handle_rule_update("my_rule", body, self.store, extensions)
        self.assertEqual(status, 200)

        output = _drain_queue(queue)
        self.assertIn("event: rules", output)
        broadcaster.unsubscribe(queue)

    def test_rule_delete_broadcasts(self):
        extensions, broadcaster, queue = self._make_extensions()
        self.store.create_rule({"name": "del_rule", "pattern": "test", "source": "dashboard", "tier": "custom"})
        _drain_queue(queue)

        status, _ = _handle_rule_delete("del_rule", self.store, extensions)
        self.assertEqual(status, 200)

        output = _drain_queue(queue)
        self.assertIn("event: rules", output)
        broadcaster.unsubscribe(queue)

    def test_rule_delete_no_broadcast_on_404(self):
        extensions, broadcaster, queue = self._make_extensions()
        status, _ = _handle_rule_delete("nonexistent", self.store, extensions)
        self.assertEqual(status, 404)

        output = _drain_queue(queue)
        self.assertNotIn("event: rules", output)
        broadcaster.unsubscribe(queue)

    def test_rule_clone_broadcasts(self):
        extensions, broadcaster, queue = self._make_extensions()
        self.store.create_rule({"name": "orig", "pattern": "test", "source": "dashboard", "tier": "custom"})
        _drain_queue(queue)

        body = json.dumps({"new_name": "orig_clone"}).encode()
        status, _ = _handle_rule_clone("orig", body, self.store, extensions)
        self.assertEqual(status, 201)

        output = _drain_queue(queue)
        self.assertIn("event: rules", output)
        broadcaster.unsubscribe(queue)

    def test_rules_bulk_update_broadcasts(self):
        extensions, broadcaster, queue = self._make_extensions()
        self.store.create_rule({"name": "r1", "pattern": "a", "source": "dashboard", "tier": "custom"})
        self.store.create_rule({"name": "r2", "pattern": "b", "source": "dashboard", "tier": "custom"})
        _drain_queue(queue)

        body = json.dumps({"names": ["r1", "r2"], "update": {"severity": "low"}}).encode()
        status, _ = _handle_rules_bulk_update(body, self.store, extensions)
        self.assertEqual(status, 200)

        output = _drain_queue(queue)
        self.assertIn("event: rules", output)
        broadcaster.unsubscribe(queue)

    def test_bulk_update_no_broadcast_when_none_updated(self):
        extensions, broadcaster, queue = self._make_extensions()
        body = json.dumps({"names": ["nonexistent"], "update": {"severity": "low"}}).encode()
        status, _ = _handle_rules_bulk_update(body, self.store, extensions)
        self.assertEqual(status, 200)

        output = _drain_queue(queue)
        self.assertNotIn("event: rules", output)
        broadcaster.unsubscribe(queue)

    @patch("lumen_argus.dashboard.api._send_sighup")
    def test_config_update_broadcasts(self, mock_sighup):
        extensions, broadcaster, queue = self._make_extensions()
        body = json.dumps({"default_action": "alert"}).encode()
        status, _ = _handle_config_update(body, None, self.store, extensions)
        self.assertIn(status, (200, 207))

        output = _drain_queue(queue)
        self.assertIn("event: config", output)
        broadcaster.unsubscribe(queue)

    @patch("lumen_argus.dashboard.api._send_sighup")
    def test_config_update_no_broadcast_on_failure(self, mock_sighup):
        extensions, broadcaster, queue = self._make_extensions()
        body = json.dumps({"invalid.nested.deep.key": "value"}).encode()
        status, _ = _handle_config_update(body, None, self.store, extensions)
        self.assertEqual(status, 400)

        output = _drain_queue(queue)
        self.assertNotIn("event: config", output)
        broadcaster.unsubscribe(queue)

    @patch("lumen_argus.dashboard.api._send_sighup")
    def test_pipeline_update_broadcasts(self, mock_sighup):
        extensions, broadcaster, queue = self._make_extensions()
        body = json.dumps({"default_action": "block"}).encode()
        status, _ = _handle_pipeline_update(body, None, self.store, extensions)
        self.assertIn(status, (200, 207))

        output = _drain_queue(queue)
        self.assertIn("event: config", output)
        broadcaster.unsubscribe(queue)


def _parse_sse_events(text: str) -> list[dict]:
    """Parse SSE text into a list of {event, data} dicts."""
    events = []
    current_event = None
    current_data = None
    for line in text.split("\n"):
        if line.startswith("event: "):
            current_event = line[7:].strip()
        elif line.startswith("data: "):
            current_data = line[6:].strip()
        elif line == "" and current_event and current_data:
            try:
                data = json.loads(current_data)
            except json.JSONDecodeError:
                data = current_data
            events.append({"event": current_event, "data": data})
            current_event = None
            current_data = None
    return events


if __name__ == "__main__":
    unittest.main()
