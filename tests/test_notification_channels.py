"""Tests for notification channel DB CRUD, reconciliation, and limit enforcement."""

import os
import sqlite3
import tempfile
import unittest

from lumen_argus.analytics.store import AnalyticsStore


class TestNotificationChannelsCRUD(unittest.TestCase):
    """Test notification_channels table CRUD operations."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.store = AnalyticsStore(db_path=self.db_path)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_table_created(self):
        conn = sqlite3.connect(self.db_path)
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        conn.close()
        self.assertIn("notification_channels", tables)

    def test_create_channel(self):
        ch = self.store.create_notification_channel(
            {
                "name": "test-webhook",
                "type": "webhook",
                "config": {"url": "https://example.com/hook"},
                "events": ["block"],
                "min_severity": "high",
            }
        )
        self.assertIsNotNone(ch["id"])
        self.assertEqual(ch["name"], "test-webhook")
        self.assertEqual(ch["type"], "webhook")
        self.assertIsInstance(ch["config"], dict)
        self.assertEqual(ch["config"]["url"], "https://example.com/hook")
        self.assertIsInstance(ch["events"], list)
        self.assertEqual(ch["events"], ["block"])
        self.assertTrue(ch["enabled"])
        self.assertEqual(ch["source"], "dashboard")

    def test_create_channel_name_required(self):
        with self.assertRaises(ValueError):
            self.store.create_notification_channel({"type": "webhook"})

    def test_create_channel_type_required(self):
        with self.assertRaises(ValueError):
            self.store.create_notification_channel({"name": "test"})

    def test_create_channel_duplicate_name(self):
        self.store.create_notification_channel(
            {
                "name": "dup",
                "type": "webhook",
                "config": {},
            }
        )
        with self.assertRaises(ValueError):
            self.store.create_notification_channel(
                {
                    "name": "dup",
                    "type": "email",
                    "config": {},
                }
            )

    def test_list_channels(self):
        self.store.create_notification_channel(
            {
                "name": "a",
                "type": "webhook",
                "config": {},
            }
        )
        self.store.create_notification_channel(
            {
                "name": "b",
                "type": "email",
                "config": {},
                "source": "yaml",
            }
        )
        all_ch = self.store.list_notification_channels()
        self.assertEqual(len(all_ch), 2)

        yaml_ch = self.store.list_notification_channels(source="yaml")
        self.assertEqual(len(yaml_ch), 1)
        self.assertEqual(yaml_ch[0]["name"], "b")

        dash_ch = self.store.list_notification_channels(source="dashboard")
        self.assertEqual(len(dash_ch), 1)
        self.assertEqual(dash_ch[0]["name"], "a")

    def test_get_channel_by_id(self):
        created = self.store.create_notification_channel(
            {
                "name": "test",
                "type": "webhook",
                "config": {"url": "https://example.com"},
            }
        )
        ch = self.store.get_notification_channel(created["id"])
        self.assertIsNotNone(ch)
        self.assertEqual(ch["name"], "test")
        self.assertIsInstance(ch["config"], dict)

    def test_get_channel_not_found(self):
        self.assertIsNone(self.store.get_notification_channel(999))

    def test_count_channels(self):
        self.assertEqual(self.store.count_notification_channels(), 0)
        self.store.create_notification_channel(
            {
                "name": "a",
                "type": "webhook",
                "config": {},
            }
        )
        self.assertEqual(self.store.count_notification_channels(), 1)

    def test_update_channel(self):
        created = self.store.create_notification_channel(
            {
                "name": "test",
                "type": "webhook",
                "config": {"url": "old"},
            }
        )
        updated = self.store.update_notification_channel(
            created["id"],
            {
                "name": "renamed",
                "config": {"url": "new"},
                "enabled": False,
            },
        )
        self.assertEqual(updated["name"], "renamed")
        self.assertEqual(updated["config"]["url"], "new")
        self.assertFalse(updated["enabled"])

    def test_update_channel_not_found(self):
        result = self.store.update_notification_channel(999, {"name": "x"})
        self.assertIsNone(result)

    def test_update_channel_duplicate_name(self):
        self.store.create_notification_channel(
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
        with self.assertRaises(ValueError):
            self.store.update_notification_channel(b["id"], {"name": "a"})

    def test_delete_channel(self):
        created = self.store.create_notification_channel(
            {
                "name": "test",
                "type": "webhook",
                "config": {},
            }
        )
        self.assertTrue(self.store.delete_notification_channel(created["id"]))
        self.assertEqual(self.store.count_notification_channels(), 0)

    def test_delete_channel_not_found(self):
        self.assertFalse(self.store.delete_notification_channel(999))

    def test_json_fields_parsed(self):
        """config and events must be returned as parsed objects, not strings."""
        self.store.create_notification_channel(
            {
                "name": "test",
                "type": "webhook",
                "config": {"url": "https://example.com", "headers": {"X-Key": "val"}},
                "events": ["block", "alert"],
            }
        )
        channels = self.store.list_notification_channels()
        ch = channels[0]
        self.assertIsInstance(ch["config"], dict)
        self.assertIsInstance(ch["events"], list)
        self.assertEqual(ch["config"]["headers"], {"X-Key": "val"})
        self.assertEqual(ch["events"], ["block", "alert"])

    def test_config_string_input(self):
        """config passed as JSON string should be handled."""
        ch = self.store.create_notification_channel(
            {
                "name": "test",
                "type": "webhook",
                "config": '{"url": "https://example.com"}',
            }
        )
        self.assertIsInstance(ch["config"], dict)
        self.assertEqual(ch["config"]["url"], "https://example.com")

    def test_events_string_input(self):
        """events passed as JSON string should be handled."""
        ch = self.store.create_notification_channel(
            {
                "name": "test",
                "type": "webhook",
                "config": {},
                "events": '["block"]',
            }
        )
        self.assertIsInstance(ch["events"], list)

    def test_enabled_bool_conversion(self):
        """enabled should be returned as bool, not int."""
        ch = self.store.create_notification_channel(
            {
                "name": "test",
                "type": "webhook",
                "config": {},
            }
        )
        self.assertIsInstance(ch["enabled"], bool)
        self.assertTrue(ch["enabled"])


class TestBulkUpdateChannels(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.store = AnalyticsStore(db_path=self.db_path)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_bulk_disable(self):
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
                "type": "email",
                "config": {},
            }
        )
        count = self.store.bulk_update_channels([a["id"], b["id"]], "disable")
        self.assertEqual(count, 2)
        channels = self.store.list_notification_channels()
        for ch in channels:
            self.assertFalse(ch["enabled"])

    def test_bulk_delete_only_dashboard(self):
        """Bulk delete only affects dashboard-managed channels."""
        a = self.store.create_notification_channel(
            {
                "name": "a",
                "type": "webhook",
                "config": {},
                "source": "yaml",
            }
        )
        b = self.store.create_notification_channel(
            {
                "name": "b",
                "type": "webhook",
                "config": {},
                "source": "dashboard",
            }
        )
        count = self.store.bulk_update_channels([a["id"], b["id"]], "delete")
        self.assertEqual(count, 1)  # only dashboard channel deleted
        remaining = self.store.list_notification_channels()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["name"], "a")

    def test_bulk_enable_works_on_yaml(self):
        """Enable/disable works on any source (admin kill switch)."""
        a = self.store.create_notification_channel(
            {
                "name": "a",
                "type": "webhook",
                "config": {},
                "source": "yaml",
            }
        )
        self.store.bulk_update_channels([a["id"]], "disable")
        ch = self.store.get_notification_channel(a["id"])
        self.assertFalse(ch["enabled"])

    def test_bulk_empty_ids(self):
        count = self.store.bulk_update_channels([], "enable")
        self.assertEqual(count, 0)


class TestReconcileYamlChannels(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.store = AnalyticsStore(db_path=self.db_path)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_create_from_yaml(self):
        result = self.store.reconcile_yaml_channels(
            [
                {"name": "alerts", "type": "webhook", "url": "https://example.com"},
            ]
        )
        self.assertEqual(result["created"], ["alerts"])
        channels = self.store.list_notification_channels()
        self.assertEqual(len(channels), 1)
        self.assertEqual(channels[0]["source"], "yaml")
        self.assertEqual(channels[0]["config"]["url"], "https://example.com")

    def test_update_existing_yaml(self):
        self.store.reconcile_yaml_channels(
            [
                {"name": "alerts", "type": "webhook", "url": "https://old.com"},
            ]
        )
        result = self.store.reconcile_yaml_channels(
            [
                {"name": "alerts", "type": "webhook", "url": "https://new.com"},
            ]
        )
        self.assertEqual(result["updated"], ["alerts"])
        ch = self.store.list_notification_channels()[0]
        self.assertEqual(ch["config"]["url"], "https://new.com")

    def test_yaml_overwrites_enabled(self):
        """YAML is fully authoritative — enabled is overwritten."""
        self.store.reconcile_yaml_channels(
            [
                {"name": "alerts", "type": "webhook", "url": "https://example.com"},
            ]
        )
        # Admin disables via dashboard
        ch = self.store.list_notification_channels()[0]
        self.store.update_notification_channel(ch["id"], {"enabled": False})
        ch = self.store.get_notification_channel(ch["id"])
        self.assertFalse(ch["enabled"])

        # YAML reconcile with enabled=true restores it
        self.store.reconcile_yaml_channels(
            [
                {"name": "alerts", "type": "webhook", "url": "https://example.com", "enabled": True},
            ]
        )
        ch = self.store.list_notification_channels()[0]
        self.assertTrue(ch["enabled"])

    def test_delete_removed_yaml(self):
        self.store.reconcile_yaml_channels(
            [
                {"name": "a", "type": "webhook", "url": "https://a.com"},
                {"name": "b", "type": "email", "smtp_host": "mail.com"},
            ]
        )
        result = self.store.reconcile_yaml_channels(
            [
                {"name": "a", "type": "webhook", "url": "https://a.com"},
            ]
        )
        self.assertEqual(result["deleted"], ["b"])
        self.assertEqual(self.store.count_notification_channels(), 1)

    def test_dashboard_channels_untouched(self):
        self.store.create_notification_channel(
            {
                "name": "manual",
                "type": "webhook",
                "config": {},
                "source": "dashboard",
            }
        )
        result = self.store.reconcile_yaml_channels([])
        self.assertEqual(result["deleted"], [])
        self.assertEqual(self.store.count_notification_channels(), 1)

    def test_name_collision_with_dashboard(self):
        """YAML channel with same name as dashboard channel is skipped."""
        self.store.create_notification_channel(
            {
                "name": "alerts",
                "type": "webhook",
                "config": {},
                "source": "dashboard",
            }
        )
        result = self.store.reconcile_yaml_channels(
            [
                {"name": "alerts", "type": "slack", "webhook_url": "https://slack.com"},
            ]
        )
        self.assertEqual(result["created"], [])
        # Dashboard channel unchanged
        ch = self.store.list_notification_channels()[0]
        self.assertEqual(ch["type"], "webhook")

    def test_limit_enforcement_on_new_creates(self):
        """Reconciliation respects channel limit for new creates."""
        result = self.store.reconcile_yaml_channels(
            [
                {"name": "a", "type": "webhook", "url": "https://a.com"},
                {"name": "b", "type": "email", "smtp_host": "mail.com"},
            ],
            channel_limit=1,
        )
        self.assertEqual(len(result["created"]), 1)
        self.assertEqual(result["created"], ["a"])
        self.assertEqual(self.store.count_notification_channels(), 1)

    def test_limit_allows_updates(self):
        """Existing YAML channels are always updated even at limit."""
        self.store.reconcile_yaml_channels(
            [
                {"name": "a", "type": "webhook", "url": "https://old.com"},
            ],
            channel_limit=1,
        )
        # At limit now, but update should still work
        result = self.store.reconcile_yaml_channels(
            [
                {"name": "a", "type": "webhook", "url": "https://new.com"},
            ],
            channel_limit=1,
        )
        self.assertEqual(result["updated"], ["a"])
        ch = self.store.list_notification_channels()[0]
        self.assertEqual(ch["config"]["url"], "https://new.com")

    def test_limit_none_is_unlimited(self):
        result = self.store.reconcile_yaml_channels(
            [
                {"name": "a", "type": "webhook", "url": "https://a.com"},
                {"name": "b", "type": "email", "smtp_host": "mail.com"},
                {"name": "c", "type": "slack", "webhook_url": "https://slack.com"},
            ],
            channel_limit=None,
        )
        self.assertEqual(len(result["created"]), 3)

    def test_reconcile_empty_list_deletes_all_yaml(self):
        self.store.reconcile_yaml_channels(
            [
                {"name": "a", "type": "webhook", "url": "https://a.com"},
            ]
        )
        result = self.store.reconcile_yaml_channels([])
        self.assertEqual(result["deleted"], ["a"])
        self.assertEqual(self.store.count_notification_channels(), 0)

    def test_config_extraction(self):
        """Type-specific keys go into config, top-level keys stay separate."""
        self.store.reconcile_yaml_channels(
            [
                {
                    "name": "test",
                    "type": "webhook",
                    "url": "https://example.com",
                    "headers": {"X-Key": "val"},
                    "events": ["block"],
                    "min_severity": "critical",
                }
            ]
        )
        ch = self.store.list_notification_channels()[0]
        self.assertEqual(ch["config"]["url"], "https://example.com")
        self.assertEqual(ch["config"]["headers"], {"X-Key": "val"})
        self.assertEqual(ch["events"], ["block"])
        self.assertEqual(ch["min_severity"], "critical")


class TestNotificationConfigParsing(unittest.TestCase):
    """Test config.py notification section parsing and validation."""

    def test_parse_notifications(self):
        from lumen_argus.config import load_config
        import tempfile

        tmpdir = tempfile.mkdtemp()
        config_path = os.path.join(tmpdir, "config.yaml")
        with open(config_path, "w") as f:
            f.write("""
notifications:
  - name: test-alert
    type: webhook
    url: "https://example.com/hook"
    events: [block, alert]
    min_severity: high
""")
        config = load_config(config_path=config_path)
        self.assertEqual(len(config.notifications), 1)
        self.assertEqual(config.notifications[0]["name"], "test-alert")
        self.assertEqual(config.notifications[0]["type"], "webhook")
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)

    def test_empty_notifications(self):
        from lumen_argus.config import Config

        config = Config()
        self.assertEqual(config.notifications, [])


class TestExtensionHooks(unittest.TestCase):
    """Test notification-related extension hooks."""

    def test_channel_types(self):
        from lumen_argus.extensions import ExtensionRegistry

        reg = ExtensionRegistry()
        self.assertEqual(reg.get_channel_types(), {})
        reg.register_channel_types({"webhook": {"label": "Webhook", "fields": {}}})
        self.assertEqual(reg.get_channel_types()["webhook"]["label"], "Webhook")

    def test_channel_limit(self):
        from lumen_argus.extensions import ExtensionRegistry

        reg = ExtensionRegistry()
        self.assertEqual(reg.get_channel_limit(), 1)  # freemium default
        reg.set_channel_limit(None)
        self.assertIsNone(reg.get_channel_limit())
        reg.set_channel_limit(5)
        self.assertEqual(reg.get_channel_limit(), 5)

    def test_dispatcher(self):
        from lumen_argus.extensions import ExtensionRegistry

        reg = ExtensionRegistry()
        self.assertIsNone(reg.get_dispatcher())

        class MockDispatcher:
            dispatched = False

            def dispatch(self, findings, provider=""):
                self.dispatched = True

        d = MockDispatcher()
        reg.set_dispatcher(d)
        self.assertIs(reg.get_dispatcher(), d)

    def test_notifier_builder(self):
        from lumen_argus.extensions import ExtensionRegistry

        reg = ExtensionRegistry()
        self.assertIsNone(reg.get_notifier_builder())
        reg.set_notifier_builder(lambda ch: None)
        self.assertIsNotNone(reg.get_notifier_builder())


class TestConfigValidation(unittest.TestCase):
    """Test config validation warns on unknown notification keys."""

    def test_unknown_notification_key_warns(self):
        from lumen_argus.config import _validate_config

        data = {
            "notifications": [
                {"name": "test", "type": "webhook", "unknown_key": "value"},
            ],
        }
        warnings = _validate_config(data, "test")
        self.assertTrue(any("unknown key" in w and "unknown_key" in w for w in warnings))

    def test_missing_name_warns(self):
        from lumen_argus.config import _validate_config

        data = {"notifications": [{"type": "webhook"}]}
        warnings = _validate_config(data, "test")
        self.assertTrue(any("missing required 'name'" in w for w in warnings))

    def test_missing_type_warns(self):
        from lumen_argus.config import _validate_config

        data = {"notifications": [{"name": "test"}]}
        warnings = _validate_config(data, "test")
        self.assertTrue(any("missing required 'type'" in w for w in warnings))

    def test_valid_notification_no_warnings(self):
        from lumen_argus.config import _validate_config

        data = {
            "notifications": [
                {"name": "test", "type": "webhook", "url": "https://example.com"},
            ],
        }
        warnings = _validate_config(data, "test")
        notif_warnings = [w for w in warnings if "notifications" in w]
        self.assertEqual(notif_warnings, [])


class TestPipelineDispatch(unittest.TestCase):
    """Test that pipeline dispatches findings via extensions.get_dispatcher()."""

    def test_dispatch_called_with_findings(self):
        from lumen_argus.extensions import ExtensionRegistry
        from lumen_argus.pipeline import ScannerPipeline

        dispatched = []

        class MockDispatcher:
            def dispatch(self, findings, provider="", model="", **kwargs):
                dispatched.append((findings, provider))

        ext = ExtensionRegistry()
        ext.set_dispatcher(MockDispatcher())

        pipeline = ScannerPipeline(
            default_action="alert",
            action_overrides={},
            allowlist=None,
            entropy_threshold=4.5,
            extensions=ext,
        )

        # Scan a body with a known secret to trigger findings
        body = b'{"messages":[{"role":"user","content":"AKIAIOSFODNN7EXAMPLE aws key"}]}'
        result = pipeline.scan(body, provider="anthropic")

        if result.findings:
            self.assertTrue(len(dispatched) > 0)
            self.assertEqual(dispatched[0][1], "anthropic")

    def test_none_dispatcher_graceful(self):
        """Pipeline works fine when no dispatcher is set."""
        from lumen_argus.extensions import ExtensionRegistry
        from lumen_argus.pipeline import ScannerPipeline

        ext = ExtensionRegistry()
        # No dispatcher set

        pipeline = ScannerPipeline(
            default_action="alert",
            action_overrides={},
            allowlist=None,
            entropy_threshold=4.5,
            extensions=ext,
        )

        body = b'{"messages":[{"role":"user","content":"hello"}]}'
        result = pipeline.scan(body, provider="anthropic")
        # Should not raise
        self.assertIsNotNone(result)


class TestToAddrsReconciliation(unittest.TestCase):
    """Test that to_addrs string is split to list during YAML reconciliation."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.store = AnalyticsStore(db_path=self.db_path)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_to_addrs_comma_string_split(self):
        self.store.reconcile_yaml_channels(
            [
                {
                    "name": "email-test",
                    "type": "email",
                    "smtp_host": "mail.com",
                    "to_addrs": "a@x.com, b@x.com, c@x.com",
                }
            ]
        )
        ch = self.store.list_notification_channels()[0]
        self.assertIsInstance(ch["config"]["to_addrs"], list)
        self.assertEqual(ch["config"]["to_addrs"], ["a@x.com", "b@x.com", "c@x.com"])

    def test_to_addrs_list_unchanged(self):
        self.store.reconcile_yaml_channels(
            [
                {
                    "name": "email-test",
                    "type": "email",
                    "smtp_host": "mail.com",
                    "to_addrs": ["a@x.com", "b@x.com"],
                }
            ]
        )
        ch = self.store.list_notification_channels()[0]
        self.assertEqual(ch["config"]["to_addrs"], ["a@x.com", "b@x.com"])


if __name__ == "__main__":
    unittest.main()
