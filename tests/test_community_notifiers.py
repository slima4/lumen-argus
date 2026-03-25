"""Tests for community webhook notifier, basic dispatcher, and builder."""

import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler

from lumen_argus.analytics.store import AnalyticsStore
from lumen_argus.models import Finding
from lumen_argus.notifiers.dispatcher import BasicDispatcher
from lumen_argus.notifiers.webhook import WEBHOOK_CHANNEL_TYPE, WebhookNotifier, build_notifier


def _make_finding(severity="critical", action="block", detector="secrets", ftype="aws_access_key"):
    return Finding(
        detector=detector,
        type=ftype,
        severity=severity,
        action=action,
        location="messages[0].content",
        matched_value="AKIAIOSFODNN7EXAMPLE",
        value_preview="AKIA...MPLE",
    )


class TestWebhookNotifier(unittest.TestCase):
    """Test WebhookNotifier sends correct payload and filters by severity."""

    def setUp(self):
        self.received = []
        self.server = None

    def tearDown(self):
        if self.server:
            self.server.shutdown()

    def _start_server(self):
        received = self.received

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                received.append(
                    {
                        "body": json.loads(body),
                        "headers": dict(self.headers),
                    }
                )
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        port = self.server.server_address[1]
        t = threading.Thread(target=self.server.serve_forever, daemon=True)
        t.start()
        return port

    def test_sends_post_with_correct_payload(self):
        port = self._start_server()
        notifier = WebhookNotifier(url="http://127.0.0.1:%d/hook" % port, min_severity="info")
        findings = [_make_finding()]
        notifier.notify(findings, provider="anthropic", model="claude-4")
        time.sleep(0.2)
        self.assertEqual(len(self.received), 1)
        payload = self.received[0]["body"]
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["provider"], "anthropic")
        self.assertEqual(payload["model"], "claude-4")
        self.assertEqual(payload["findings"][0]["detector"], "secrets")
        self.assertEqual(payload["findings"][0]["type"], "aws_access_key")
        self.assertEqual(payload["findings"][0]["severity"], "critical")

    def test_filters_by_min_severity(self):
        port = self._start_server()
        notifier = WebhookNotifier(url="http://127.0.0.1:%d/hook" % port, min_severity="critical")
        findings = [_make_finding(severity="warning"), _make_finding(severity="info")]
        notifier.notify(findings, provider="test")
        time.sleep(0.2)
        self.assertEqual(len(self.received), 0)

    def test_sends_only_matching_severity(self):
        port = self._start_server()
        notifier = WebhookNotifier(url="http://127.0.0.1:%d/hook" % port, min_severity="high")
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="warning"),
            _make_finding(severity="high"),
        ]
        notifier.notify(findings, provider="test")
        time.sleep(0.2)
        self.assertEqual(len(self.received), 1)
        self.assertEqual(self.received[0]["body"]["count"], 2)

    def test_includes_custom_headers(self):
        port = self._start_server()
        notifier = WebhookNotifier(
            url="http://127.0.0.1:%d/hook" % port,
            headers={"X-Custom": "test-val"},
            min_severity="info",
        )
        notifier.notify([_make_finding()], provider="test")
        time.sleep(0.2)
        self.assertEqual(len(self.received), 1)
        self.assertEqual(self.received[0]["headers"].get("X-Custom"), "test-val")

    def test_raises_on_connection_error(self):
        notifier = WebhookNotifier(url="http://127.0.0.1:1/hook", min_severity="info")
        with self.assertRaises(Exception):
            notifier.notify([_make_finding()], provider="test")

    def test_empty_findings_noop(self):
        port = self._start_server()
        notifier = WebhookNotifier(url="http://127.0.0.1:%d/hook" % port, min_severity="info")
        notifier.notify([], provider="test")
        time.sleep(0.1)
        self.assertEqual(len(self.received), 0)

    def test_accepts_kwargs(self):
        """Forward compatibility: notify() accepts arbitrary kwargs."""
        port = self._start_server()
        notifier = WebhookNotifier(url="http://127.0.0.1:%d/hook" % port, min_severity="info")
        notifier.notify([_make_finding()], provider="test", session_id="abc")
        time.sleep(0.2)
        self.assertEqual(len(self.received), 1)


class TestBasicDispatcher(unittest.TestCase):
    """Test BasicDispatcher fire-and-forget behavior."""

    def test_dispatches_in_background(self):
        notified = []

        class MockNotifier:
            def notify(self, findings, provider="", model="", **kwargs):
                notified.append({"findings": findings, "provider": provider})

        class MockStore:
            def list_notification_channels(self):
                return [
                    {"id": 1, "name": "test-wh", "type": "webhook", "enabled": True, "events": []},
                ]

        dispatcher = BasicDispatcher(store=MockStore(), builder=lambda ch: MockNotifier())
        dispatcher.rebuild()
        findings = [_make_finding()]
        dispatcher.dispatch(findings, provider="anthropic")
        time.sleep(0.3)
        self.assertEqual(len(notified), 1)
        self.assertEqual(notified[0]["provider"], "anthropic")

    def test_filters_by_channel_events(self):
        notified = []

        class MockNotifier:
            def notify(self, findings, **kwargs):
                notified.append(findings)

        class MockStore:
            def list_notification_channels(self):
                return [
                    {"id": 1, "name": "block-only", "type": "webhook", "enabled": True, "events": ["block"]},
                ]

        dispatcher = BasicDispatcher(store=MockStore(), builder=lambda ch: MockNotifier())
        dispatcher.rebuild()
        dispatcher.dispatch([_make_finding(action="alert")], provider="test")
        time.sleep(0.2)
        self.assertEqual(len(notified), 0)

        dispatcher.dispatch([_make_finding(action="block")], provider="test")
        time.sleep(0.2)
        self.assertEqual(len(notified), 1)

    def test_handles_notifier_exception_gracefully(self):
        class FailNotifier:
            def notify(self, findings, **kwargs):
                raise Exception("connection refused")

        class MockStore:
            def list_notification_channels(self):
                return [{"id": 1, "name": "fail", "type": "webhook", "enabled": True, "events": []}]

        dispatcher = BasicDispatcher(store=MockStore(), builder=lambda ch: FailNotifier())
        dispatcher.rebuild()
        dispatcher.dispatch([_make_finding()], provider="test")
        time.sleep(0.2)

    def test_rebuild_skips_disabled_channels(self):
        class MockStore:
            def list_notification_channels(self):
                return [
                    {"id": 1, "name": "active", "type": "webhook", "enabled": True, "events": []},
                    {"id": 2, "name": "off", "type": "webhook", "enabled": False, "events": []},
                ]

        class N:
            def notify(self, findings, **kw):
                pass

        dispatcher = BasicDispatcher(store=MockStore(), builder=lambda ch: N())
        dispatcher.rebuild()
        self.assertEqual(len(dispatcher._notifiers), 1)

    def test_empty_findings_noop(self):
        class MockStore:
            def list_notification_channels(self):
                return [{"id": 1, "name": "wh", "type": "webhook", "enabled": True, "events": []}]

        notified = []

        class N:
            def notify(self, findings, **kw):
                notified.append(1)

        dispatcher = BasicDispatcher(store=MockStore(), builder=lambda ch: N())
        dispatcher.rebuild()
        dispatcher.dispatch([], provider="test")
        time.sleep(0.1)
        self.assertEqual(len(notified), 0)

    def test_no_store_rebuild_noop(self):
        dispatcher = BasicDispatcher()
        dispatcher.rebuild()

    def test_events_json_string_parsed(self):
        """Events stored as JSON string should be parsed during rebuild."""
        notified = []

        class MockNotifier:
            def notify(self, findings, **kwargs):
                notified.append(findings)

        class MockStore:
            def list_notification_channels(self):
                return [
                    {"id": 1, "name": "wh", "type": "webhook", "enabled": True, "events": '["block"]'},
                ]

        dispatcher = BasicDispatcher(store=MockStore(), builder=lambda ch: MockNotifier())
        dispatcher.rebuild()
        dispatcher.dispatch([_make_finding(action="alert")], provider="test")
        time.sleep(0.2)
        self.assertEqual(len(notified), 0)

        dispatcher.dispatch([_make_finding(action="block")], provider="test")
        time.sleep(0.2)
        self.assertEqual(len(notified), 1)

    def test_last_status_sent(self):
        class MockNotifier:
            def notify(self, findings, **kwargs):
                pass

        class MockStore:
            def list_notification_channels(self):
                return [{"id": 1, "name": "wh", "type": "webhook", "enabled": True, "events": []}]

        dispatcher = BasicDispatcher(store=MockStore(), builder=lambda ch: MockNotifier())
        dispatcher.rebuild()
        self.assertEqual(dispatcher.get_last_status(), {})
        dispatcher.dispatch([_make_finding()], provider="test")
        time.sleep(0.3)
        status = dispatcher.get_last_status()
        self.assertIn(1, status)
        self.assertEqual(status[1]["status"], "sent")
        self.assertEqual(status[1]["error"], "")
        self.assertIn("T", status[1]["timestamp"])

    def test_last_status_failed(self):
        class FailNotifier:
            def notify(self, findings, **kwargs):
                raise Exception("timeout")

        class MockStore:
            def list_notification_channels(self):
                return [{"id": 1, "name": "fail", "type": "webhook", "enabled": True, "events": []}]

        dispatcher = BasicDispatcher(store=MockStore(), builder=lambda ch: FailNotifier())
        dispatcher.rebuild()
        dispatcher.dispatch([_make_finding()], provider="test")
        time.sleep(0.3)
        status = dispatcher.get_last_status()
        self.assertIn(1, status)
        self.assertEqual(status[1]["status"], "failed")
        self.assertIn("timeout", status[1]["error"])

    def test_last_status_reset_on_rebuild(self):
        class MockNotifier:
            def notify(self, findings, **kwargs):
                pass

        class MockStore:
            def list_notification_channels(self):
                return [{"id": 1, "name": "wh", "type": "webhook", "enabled": True, "events": []}]

        dispatcher = BasicDispatcher(store=MockStore(), builder=lambda ch: MockNotifier())
        dispatcher.rebuild()
        dispatcher.dispatch([_make_finding()], provider="test")
        time.sleep(0.3)
        self.assertTrue(len(dispatcher.get_last_status()) > 0)
        dispatcher.rebuild()
        self.assertEqual(dispatcher.get_last_status(), {})


class TestChannelStatusEnrichment(unittest.TestCase):
    """Test that GET /api/v1/notifications/channels enriches with dispatch status."""

    def test_channels_enriched_with_last_status(self):
        from lumen_argus.dashboard.api import handle_community_api
        from lumen_argus.extensions import ExtensionRegistry

        tmpdir = tempfile.mkdtemp()
        db_path = os.path.join(tmpdir, "test.db")
        store = AnalyticsStore(db_path=db_path)
        ext = ExtensionRegistry()
        ext.register_channel_types(WEBHOOK_CHANNEL_TYPE)

        ch = store.create_notification_channel(
            {
                "name": "test-wh",
                "type": "webhook",
                "config": {"url": "https://example.com"},
            }
        )

        class MockDispatcher:
            def get_last_status(self):
                return {ch["id"]: {"status": "sent", "error": "", "timestamp": "2026-03-25T12:00:00Z"}}

        ext.set_dispatcher(MockDispatcher())

        status, body = handle_community_api("/api/v1/notifications/channels", "GET", b"", store, extensions=ext)
        self.assertEqual(status, 200)
        data = json.loads(body)
        channels = data["channels"]
        self.assertEqual(len(channels), 1)
        self.assertEqual(channels[0]["last_status"], "sent")
        self.assertEqual(channels[0]["last_status_at"], "2026-03-25T12:00:00Z")
        self.assertEqual(channels[0]["last_error"], "")

        shutil.rmtree(tmpdir, ignore_errors=True)

    def test_channels_without_dispatcher_status(self):
        from lumen_argus.dashboard.api import handle_community_api
        from lumen_argus.extensions import ExtensionRegistry

        tmpdir = tempfile.mkdtemp()
        db_path = os.path.join(tmpdir, "test.db")
        store = AnalyticsStore(db_path=db_path)
        ext = ExtensionRegistry()
        ext.register_channel_types(WEBHOOK_CHANNEL_TYPE)

        store.create_notification_channel(
            {
                "name": "test-wh",
                "type": "webhook",
                "config": {"url": "https://example.com"},
            }
        )

        status, body = handle_community_api("/api/v1/notifications/channels", "GET", b"", store, extensions=ext)
        self.assertEqual(status, 200)
        data = json.loads(body)
        channels = data["channels"]
        self.assertEqual(len(channels), 1)
        self.assertNotIn("last_status", channels[0])

        shutil.rmtree(tmpdir, ignore_errors=True)


class TestBuildNotifier(unittest.TestCase):
    """Test the build_notifier factory function."""

    def test_creates_webhook_notifier(self):
        notifier = build_notifier(
            {
                "type": "webhook",
                "config": {"url": "https://example.com/hook", "min_severity": "high"},
            }
        )
        self.assertIsInstance(notifier, WebhookNotifier)
        self.assertEqual(notifier.url, "https://example.com/hook")
        self.assertEqual(notifier.min_severity, "high")

    def test_returns_none_for_unknown_type(self):
        self.assertIsNone(build_notifier({"type": "slack", "config": {}}))

    def test_handles_json_string_config(self):
        notifier = build_notifier(
            {
                "type": "webhook",
                "config": json.dumps({"url": "https://example.com/hook"}),
            }
        )
        self.assertIsInstance(notifier, WebhookNotifier)

    def test_returns_none_for_missing_url(self):
        self.assertIsNone(build_notifier({"type": "webhook", "config": {}}))

    def test_handles_json_string_headers(self):
        notifier = build_notifier(
            {
                "type": "webhook",
                "config": {"url": "https://x.com", "headers": '{"X-Key": "val"}'},
            }
        )
        self.assertIsInstance(notifier, WebhookNotifier)
        self.assertEqual(notifier.headers, {"X-Key": "val"})

    def test_handles_empty_config(self):
        self.assertIsNone(build_notifier({"type": "webhook", "config": None}))


class TestChannelTypeRegistration(unittest.TestCase):
    """Test that community channel types are registered and available."""

    def test_webhook_type_registered(self):
        from lumen_argus.extensions import ExtensionRegistry

        ext = ExtensionRegistry()
        ext.register_channel_types(WEBHOOK_CHANNEL_TYPE)
        types = ext.get_channel_types()
        self.assertIn("webhook", types)
        self.assertEqual(types["webhook"]["label"], "Webhook")

    def test_pro_override_replaces_community_types(self):
        from lumen_argus.extensions import ExtensionRegistry

        ext = ExtensionRegistry()
        ext.register_channel_types(WEBHOOK_CHANNEL_TYPE)
        ext.register_channel_types(
            {
                "webhook": {"label": "Webhook (Pro)", "fields": []},
                "slack": {"label": "Slack", "fields": []},
                "email": {"label": "Email", "fields": []},
            }
        )
        types = ext.get_channel_types()
        self.assertEqual(types["webhook"]["label"], "Webhook (Pro)")
        self.assertIn("slack", types)
        self.assertIn("email", types)

    def test_pro_override_replaces_dispatcher(self):
        from lumen_argus.extensions import ExtensionRegistry

        ext = ExtensionRegistry()

        class CommunityDispatcher:
            name = "community"

        class ProDispatcher:
            name = "pro"

        ext.set_dispatcher(CommunityDispatcher())
        self.assertEqual(ext.get_dispatcher().name, "community")

        ext.set_dispatcher(ProDispatcher())
        self.assertEqual(ext.get_dispatcher().name, "pro")


class TestEndToEndDispatch(unittest.TestCase):
    """Integration: create channel, dispatch finding, verify HTTP POST."""

    def test_webhook_end_to_end(self):
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                received.append(json.loads(body))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        try:
            tmpdir = tempfile.mkdtemp()
            db_path = os.path.join(tmpdir, "test.db")
            store = AnalyticsStore(db_path=db_path)

            store.create_notification_channel(
                {
                    "name": "test-hook",
                    "type": "webhook",
                    "config": {"url": "http://127.0.0.1:%d/hook" % port, "min_severity": "info"},
                    "events": ["block", "alert"],
                }
            )

            dispatcher = BasicDispatcher(store=store, builder=build_notifier)
            dispatcher.rebuild()
            self.assertEqual(len(dispatcher._notifiers), 1)

            finding = _make_finding(severity="critical", action="block")
            dispatcher.dispatch([finding], provider="anthropic", model="claude-4")
            time.sleep(0.5)

            self.assertEqual(len(received), 1)
            self.assertEqual(received[0]["count"], 1)
            self.assertEqual(received[0]["provider"], "anthropic")
        finally:
            server.shutdown()
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
