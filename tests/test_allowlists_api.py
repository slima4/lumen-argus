"""Tests for community allowlist DB store, API endpoints, and scan-time integration."""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock

from lumen_argus.analytics.store import AnalyticsStore
from lumen_argus.dashboard.api import handle_community_api
from tests.helpers import StoreTestCase


class TestAllowlistStore(StoreTestCase):
    pass

    def test_add_and_list(self):
        entry = self.store.add_allowlist_entry("secrets", "sk-ant-*")
        self.assertEqual(entry["list_type"], "secrets")
        self.assertEqual(entry["pattern"], "sk-ant-*")
        self.assertEqual(entry["source"], "api")
        entries = self.store.list_allowlist_entries()
        self.assertEqual(len(entries), 1)

    def test_add_multiple_types(self):
        self.store.add_allowlist_entry("secrets", "AKIA*")
        self.store.add_allowlist_entry("pii", "*@example.com")
        self.store.add_allowlist_entry("paths", "*.test")
        all_entries = self.store.list_allowlist_entries()
        self.assertEqual(len(all_entries), 3)
        secrets = self.store.list_allowlist_entries(list_type="secrets")
        self.assertEqual(len(secrets), 1)
        pii = self.store.list_allowlist_entries(list_type="pii")
        self.assertEqual(len(pii), 1)

    def test_add_invalid_type(self):
        with self.assertRaises(ValueError):
            self.store.add_allowlist_entry("invalid", "test")

    def test_add_empty_pattern(self):
        with self.assertRaises(ValueError):
            self.store.add_allowlist_entry("secrets", "")
        with self.assertRaises(ValueError):
            self.store.add_allowlist_entry("secrets", "  ")

    def test_delete(self):
        entry = self.store.add_allowlist_entry("secrets", "test*")
        self.assertTrue(self.store.delete_allowlist_entry(entry["id"]))
        self.assertEqual(len(self.store.list_allowlist_entries()), 0)

    def test_delete_nonexistent(self):
        self.assertFalse(self.store.delete_allowlist_entry(999))

    def test_pattern_stripped(self):
        entry = self.store.add_allowlist_entry("secrets", "  sk-ant-*  ")
        self.assertEqual(entry["pattern"], "sk-ant-*")

    def test_audit_fields(self):
        entry = self.store.add_allowlist_entry("secrets", "test*", description="Test rule", created_by="admin")
        self.assertEqual(entry["description"], "Test rule")
        self.assertEqual(entry["created_by"], "admin")
        self.assertEqual(entry["updated_by"], "admin")
        self.assertIn("created_at", entry)
        self.assertIn("updated_at", entry)
        self.assertTrue(entry["enabled"])

    def test_update(self):
        entry = self.store.add_allowlist_entry("secrets", "old*")
        updated = self.store.update_allowlist_entry(entry["id"], {"pattern": "new*", "updated_by": "editor"})
        self.assertEqual(updated["pattern"], "new*")
        self.assertEqual(updated["updated_by"], "editor")

    def test_update_nonexistent(self):
        result = self.store.update_allowlist_entry(999, {"pattern": "x"})
        self.assertIsNone(result)

    def test_disable_entry(self):
        entry = self.store.add_allowlist_entry("pii", "*@test.com")
        self.store.update_allowlist_entry(entry["id"], {"enabled": False})
        # Disabled entries excluded from scan-time list
        enabled = self.store.list_enabled_allowlist_entries()
        self.assertEqual(len(enabled), 0)
        # But still in full list
        all_entries = self.store.list_allowlist_entries()
        self.assertEqual(len(all_entries), 1)

    def test_get_by_id(self):
        entry = self.store.add_allowlist_entry("paths", "*.key")
        fetched = self.store.get_allowlist_entry(entry["id"])
        self.assertEqual(fetched["pattern"], "*.key")
        self.assertEqual(fetched["list_type"], "paths")


class TestAllowlistAPI(StoreTestCase):
    def setUp(self):
        super().setUp()
        self.config = MagicMock()
        self.config.allowlist.secrets = ["config-secret-*"]
        self.config.allowlist.pii = ["*@config.com"]
        self.config.allowlist.paths = ["*.key"]

    def _api(self, path, method="GET", body=b""):
        return handle_community_api(path, method, body, self.store, config=self.config)

    # --- GET /api/v1/allowlists ---

    def test_list_merges_config_and_api(self):
        self.store.add_allowlist_entry("secrets", "api-secret-*")
        status, body = self._api("/api/v1/allowlists")
        self.assertEqual(status, 200)
        data = json.loads(body)
        # Should have config entry + api entry
        self.assertEqual(len(data["secrets"]), 2)
        sources = [e["source"] for e in data["secrets"]]
        self.assertIn("config", sources)
        self.assertIn("api", sources)
        # PII and paths from config only
        self.assertEqual(len(data["pii"]), 1)
        self.assertEqual(len(data["paths"]), 1)
        # api_entries separate list
        self.assertEqual(len(data["api_entries"]), 1)

    def test_list_no_store(self):
        status, body = handle_community_api("/api/v1/allowlists", "GET", b"", None, config=self.config)
        data = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(len(data["secrets"]), 1)  # config only
        self.assertEqual(len(data["api_entries"]), 0)

    # --- POST /api/v1/allowlists ---

    def test_add_entry(self):
        status, body = self._api(
            "/api/v1/allowlists", "POST", json.dumps({"type": "secrets", "pattern": "test*"}).encode()
        )
        self.assertEqual(status, 201)
        data = json.loads(body)
        self.assertEqual(data["list_type"], "secrets")
        self.assertEqual(data["source"], "api")

    def test_add_invalid_type(self):
        status, body = self._api("/api/v1/allowlists", "POST", json.dumps({"type": "bad", "pattern": "test"}).encode())
        self.assertEqual(status, 400)

    def test_add_empty_pattern(self):
        status, body = self._api("/api/v1/allowlists", "POST", json.dumps({"type": "secrets", "pattern": ""}).encode())
        self.assertEqual(status, 400)

    def test_add_no_store(self):
        status, body = handle_community_api(
            "/api/v1/allowlists", "POST", json.dumps({"type": "secrets", "pattern": "x"}).encode(), None
        )
        self.assertEqual(status, 500)

    # --- DELETE /api/v1/allowlists/:id ---

    def test_delete_entry(self):
        entry = self.store.add_allowlist_entry("pii", "*@test.com")
        status, body = self._api("/api/v1/allowlists/%d" % entry["id"], "DELETE")
        self.assertEqual(status, 200)

    def test_delete_nonexistent(self):
        status, body = self._api("/api/v1/allowlists/999", "DELETE")
        self.assertEqual(status, 404)

    def test_delete_invalid_id(self):
        status, body = self._api("/api/v1/allowlists/abc", "DELETE")
        self.assertEqual(status, 400)

    # --- POST /api/v1/allowlists/test ---

    def test_pattern_value_match(self):
        status, body = self._api(
            "/api/v1/allowlists/test",
            "POST",
            json.dumps({"pattern": "sk-ant-*", "value": "sk-ant-api03-example"}).encode(),
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["value_match"])

    def test_pattern_no_match(self):
        status, body = self._api(
            "/api/v1/allowlists/test",
            "POST",
            json.dumps({"pattern": "sk-ant-*", "value": "ghp_something"}).encode(),
        )
        data = json.loads(body)
        self.assertFalse(data["value_match"])

    def test_pattern_empty(self):
        status, body = self._api("/api/v1/allowlists/test", "POST", json.dumps({"pattern": ""}).encode())
        self.assertEqual(status, 400)


class TestAllowlistScanIntegration(unittest.TestCase):
    """Test that DB entries are applied at scan time."""

    def test_build_allowlist_merges_db(self):
        tmpdir = tempfile.mkdtemp()
        try:
            store = AnalyticsStore(db_path=os.path.join(tmpdir, "test.db"))
            store.add_allowlist_entry("secrets", "AKIA_TEST_*")
            store.add_allowlist_entry("pii", "*@test.org")

            config = MagicMock()
            config.allowlist.secrets = ["yaml-secret"]
            config.allowlist.pii = []
            config.allowlist.paths = []

            from lumen_argus.scanner import _build_allowlist

            al = _build_allowlist(config, store=store)
            # YAML entry
            self.assertTrue(al.is_allowed_secret("yaml-secret"))
            # DB entry
            self.assertTrue(al.is_allowed_secret("AKIA_TEST_1234"))
            # DB PII entry
            self.assertTrue(al.is_allowed_pii("user@test.org"))
            # Not in either
            self.assertFalse(al.is_allowed_secret("random"))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_build_allowlist_without_store(self):
        config = MagicMock()
        config.allowlist.secrets = ["only-yaml"]
        config.allowlist.pii = []
        config.allowlist.paths = []

        from lumen_argus.scanner import _build_allowlist

        al = _build_allowlist(config)
        self.assertTrue(al.is_allowed_secret("only-yaml"))


if __name__ == "__main__":
    unittest.main()
