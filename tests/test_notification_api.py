"""Tests for notification channel API endpoints."""

import json
import unittest

from lumen_argus.dashboard.api import handle_community_api
from lumen_argus.extensions import ExtensionRegistry
from tests.helpers import StoreTestCase


class TestNotificationAPI(StoreTestCase):
    """Test community notification API endpoints."""

    def setUp(self):
        super().setUp()
        self.ext = ExtensionRegistry()
        # Register channel types (simulating Pro)
        self.ext.register_channel_types(
            {
                "webhook": {
                    "label": "Webhook",
                    "fields": {
                        "url": {"label": "URL", "required": True, "type": "url"},
                    },
                },
                "email": {
                    "label": "Email",
                    "fields": {
                        "smtp_host": {"label": "SMTP Host", "required": True, "type": "text"},
                    },
                },
            }
        )

    def _api(self, path, method="GET", body=b""):
        return handle_community_api(
            path,
            method,
            body,
            self.store,
            extensions=self.ext,
        )

    def test_get_types(self):
        status, body = self._api("/api/v1/notifications/types")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("webhook", data["types"])
        self.assertIn("email", data["types"])
        # No limit metadata in the types response — community is unlimited;
        # plugin-imposed caps surface only via the 409 on POST.
        self.assertNotIn("channel_limit", data)
        self.assertNotIn("channel_count", data)

    def test_get_channels_empty(self):
        status, body = self._api("/api/v1/notifications/channels")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["channels"], [])
        self.assertNotIn("channel_limit", data)
        self.assertNotIn("channel_count", data)

    def test_create_channel(self):
        payload = json.dumps(
            {
                "name": "test",
                "type": "webhook",
                "config": {"url": "https://example.com"},
            }
        ).encode()
        status, body = self._api("/api/v1/notifications/channels", "POST", payload)
        self.assertEqual(status, 201)
        data = json.loads(body)
        self.assertEqual(data["name"], "test")
        self.assertIn("config_masked", data)
        self.assertNotIn("config", data)

    def test_create_channel_unknown_type(self):
        payload = json.dumps(
            {
                "name": "test",
                "type": "unknown_type",
                "config": {},
            }
        ).encode()
        status, body = self._api("/api/v1/notifications/channels", "POST", payload)
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertEqual(data["error"], "unknown channel type")

    def test_create_channel_limit_enforced(self):
        self.ext.set_channel_limit(1)
        # Create first — should succeed
        payload = json.dumps(
            {
                "name": "first",
                "type": "webhook",
                "config": {"url": "https://a.com"},
            }
        ).encode()
        status, _ = self._api("/api/v1/notifications/channels", "POST", payload)
        self.assertEqual(status, 201)
        # Create second — should fail with 409
        payload = json.dumps(
            {
                "name": "second",
                "type": "email",
                "config": {"smtp_host": "mail.com"},
            }
        ).encode()
        status, body = self._api("/api/v1/notifications/channels", "POST", payload)
        self.assertEqual(status, 409)
        data = json.loads(body)
        self.assertEqual(data["error"], "channel_limit_reached")

    def test_get_channel_by_id(self):
        create_payload = json.dumps(
            {
                "name": "test",
                "type": "webhook",
                "config": {"url": "https://example.com"},
            }
        ).encode()
        _, create_body = self._api("/api/v1/notifications/channels", "POST", create_payload)
        channel_id = json.loads(create_body)["id"]
        status, body = self._api("/api/v1/notifications/channels/%d" % channel_id)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["name"], "test")
        # GET by ID returns full config (for edit form)
        self.assertIn("config", data)

    def test_get_channel_not_found(self):
        status, _ = self._api("/api/v1/notifications/channels/999")
        self.assertEqual(status, 404)

    def test_update_channel(self):
        create_payload = json.dumps(
            {
                "name": "test",
                "type": "webhook",
                "config": {"url": "https://old.com"},
            }
        ).encode()
        _, create_body = self._api("/api/v1/notifications/channels", "POST", create_payload)
        channel_id = json.loads(create_body)["id"]

        update_payload = json.dumps({"name": "renamed"}).encode()
        status, body = self._api("/api/v1/notifications/channels/%d" % channel_id, "PUT", update_payload)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["name"], "renamed")

    def test_delete_channel(self):
        create_payload = json.dumps(
            {
                "name": "test",
                "type": "webhook",
                "config": {},
            }
        ).encode()
        _, create_body = self._api("/api/v1/notifications/channels", "POST", create_payload)
        channel_id = json.loads(create_body)["id"]

        status, body = self._api("/api/v1/notifications/channels/%d" % channel_id, "DELETE")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["deleted"], channel_id)

    def test_test_channel_no_builder(self):
        """Test endpoint returns error when no notifier builder registered."""
        create_payload = json.dumps(
            {
                "name": "test",
                "type": "webhook",
                "config": {},
            }
        ).encode()
        _, create_body = self._api("/api/v1/notifications/channels", "POST", create_payload)
        channel_id = json.loads(create_body)["id"]

        status, body = self._api("/api/v1/notifications/channels/%d/test" % channel_id, "POST")
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertEqual(data["error"], "notifications_unavailable")

    def test_test_channel_with_builder(self):
        """Test endpoint works when notifier builder is registered."""

        class MockNotifier:
            def notify(self, findings, provider="", model=""):
                pass

        self.ext.set_notifier_builder(lambda ch: MockNotifier())

        create_payload = json.dumps(
            {
                "name": "test",
                "type": "webhook",
                "config": {"url": "https://x.com"},
            }
        ).encode()
        _, create_body = self._api("/api/v1/notifications/channels", "POST", create_payload)
        channel_id = json.loads(create_body)["id"]

        status, body = self._api("/api/v1/notifications/channels/%d/test" % channel_id, "POST")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["status"], "sent")

    def test_test_channel_builder_failure(self):
        """Test endpoint returns 502 when notifier raises."""

        class FailNotifier:
            def notify(self, findings, provider="", model=""):
                raise Exception("connection refused")

        self.ext.set_notifier_builder(lambda ch: FailNotifier())

        create_payload = json.dumps(
            {
                "name": "test",
                "type": "webhook",
                "config": {},
            }
        ).encode()
        _, create_body = self._api("/api/v1/notifications/channels", "POST", create_payload)
        channel_id = json.loads(create_body)["id"]

        status, body = self._api("/api/v1/notifications/channels/%d/test" % channel_id, "POST")
        self.assertEqual(status, 502)
        data = json.loads(body)
        self.assertEqual(data["status"], "failed")
        self.assertIn("connection refused", data["error"])

    def test_batch_action(self):
        a = self.store.create_notification_channel(
            {
                "name": "a",
                "type": "webhook",
                "config": {},
            }
        )
        b = self.store.create_notification_channel(
            {
                "name": "b",
                "type": "webhook",
                "config": {},
            }
        )
        payload = json.dumps(
            {
                "action": "disable",
                "ids": [a["id"], b["id"]],
            }
        ).encode()
        status, body = self._api("/api/v1/notifications/channels/batch", "POST", payload)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["affected"], 2)

    def test_config_masked_sensitive_fields(self):
        create_payload = json.dumps(
            {
                "name": "test",
                "type": "webhook",
                "config": {"url": "https://secret-webhook-url.example.com/hook"},
            }
        ).encode()
        _, _create_body = self._api("/api/v1/notifications/channels", "POST", create_payload)

        _status, body = self._api("/api/v1/notifications/channels")
        data = json.loads(body)
        ch = data["channels"][0]
        self.assertIn("config_masked", ch)
        self.assertNotIn("config", ch)
        # URL should be masked
        masked_url = ch["config_masked"]["url"]
        self.assertIn("****", masked_url)
        self.assertNotEqual(masked_url, "https://secret-webhook-url.example.com/hook")


class TestNotificationAPIWithoutPro(StoreTestCase):
    """Test API behavior when Pro is not loaded (no channel types)."""

    def setUp(self):
        super().setUp()
        self.ext = ExtensionRegistry()
        # No channel types registered — simulates source install

    def _api(self, path, method="GET", body=b""):
        return handle_community_api(
            path,
            method,
            body,
            self.store,
            extensions=self.ext,
        )

    def test_get_channels_shows_unavailable(self):
        status, body = self._api("/api/v1/notifications/channels")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data.get("notifications_unavailable"))
        self.assertIn("pip install", data.get("message", ""))
        # Should still return empty channels list
        self.assertIsInstance(data["channels"], list)

    def test_get_channels_shows_yaml_channels_without_pro(self):
        """YAML channels in DB should be visible even without Pro."""
        self.store.create_notification_channel(
            {
                "name": "yaml-alert",
                "type": "webhook",
                "config": {"url": "https://example.com"},
                "source": "yaml",
            }
        )
        status, body = self._api("/api/v1/notifications/channels")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["notifications_unavailable"])
        self.assertEqual(len(data["channels"]), 1)
        self.assertEqual(data["channels"][0]["name"], "yaml-alert")
        # Config should be masked
        self.assertIn("config_masked", data["channels"][0])
        self.assertNotIn("config", data["channels"][0])

    def test_get_types_returns_empty(self):
        status, body = self._api("/api/v1/notifications/types")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["types"], {})


if __name__ == "__main__":
    unittest.main()
