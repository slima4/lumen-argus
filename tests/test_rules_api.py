"""Tests for community rules API endpoints."""

import json
import os
import shutil
import tempfile
import unittest

from lumen_argus.analytics.store import AnalyticsStore
from lumen_argus.dashboard.api import handle_community_api


class TestRulesAPI(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.store = AnalyticsStore(db_path=os.path.join(self._tmpdir, "test.db"))
        # Seed some rules
        self.store.import_rules(
            [
                {
                    "name": "aws_key",
                    "pattern": "AKIA[A-Z0-9]{16}",
                    "detector": "secrets",
                    "severity": "critical",
                    "tags": ["cloud", "aws"],
                },
                {
                    "name": "email_addr",
                    "pattern": "[a-z]+@example\\.com",
                    "detector": "pii",
                    "severity": "warning",
                    "tags": ["pii"],
                },
                {
                    "name": "github_token",
                    "pattern": "ghp_[A-Za-z0-9]{36}",
                    "detector": "secrets",
                    "severity": "high",
                    "tags": ["cloud"],
                },
            ],
            tier="community",
        )

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _api(self, path, method="GET", body=b""):
        return handle_community_api(path, method, body, self.store)

    # --- GET /api/v1/rules ---

    def test_list_returns_all(self):
        status, body = self._api("/api/v1/rules")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["total"], 3)
        self.assertEqual(len(data["rules"]), 3)

    def test_list_pagination(self):
        status, body = self._api("/api/v1/rules?limit=2&offset=0")
        data = json.loads(body)
        self.assertEqual(len(data["rules"]), 2)
        self.assertEqual(data["total"], 3)
        self.assertEqual(data["limit"], 2)
        self.assertEqual(data["offset"], 0)

    def test_list_search(self):
        status, body = self._api("/api/v1/rules?search=aws")
        data = json.loads(body)
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["rules"][0]["name"], "aws_key")

    def test_list_filter_detector(self):
        status, body = self._api("/api/v1/rules?detector=pii")
        data = json.loads(body)
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["rules"][0]["name"], "email_addr")

    def test_list_filter_severity(self):
        status, body = self._api("/api/v1/rules?severity=critical")
        data = json.loads(body)
        self.assertEqual(data["total"], 1)

    def test_list_filter_tier(self):
        status, body = self._api("/api/v1/rules?tier=community")
        data = json.loads(body)
        self.assertEqual(data["total"], 3)

    def test_list_filter_enabled(self):
        self.store.update_rule("aws_key", {"enabled": False})
        status, body = self._api("/api/v1/rules?enabled=true")
        data = json.loads(body)
        self.assertEqual(data["total"], 2)

    def test_list_filter_tag(self):
        status, body = self._api("/api/v1/rules?tag=cloud")
        data = json.loads(body)
        self.assertEqual(data["total"], 2)

    def test_list_no_store(self):
        status, body = handle_community_api("/api/v1/rules", "GET", b"", None)
        data = json.loads(body)
        self.assertEqual(data["rules"], [])
        self.assertEqual(data["total"], 0)

    # --- GET /api/v1/rules/stats ---

    def test_stats(self):
        status, body = self._api("/api/v1/rules/stats")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["total"], 3)
        self.assertEqual(data["enabled"], 3)
        self.assertIn("by_tier", data)
        self.assertIn("by_detector", data)
        self.assertIn("tags", data)
        self.assertTrue(len(data["tags"]) > 0)

    # --- GET /api/v1/rules/:name ---

    def test_detail(self):
        status, body = self._api("/api/v1/rules/aws_key")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["name"], "aws_key")
        self.assertEqual(data["detector"], "secrets")
        self.assertIsInstance(data["tags"], list)

    def test_detail_not_found(self):
        status, body = self._api("/api/v1/rules/nonexistent")
        self.assertEqual(status, 404)

    def test_detail_url_encoded(self):
        # Create rule with special chars
        self.store.create_rule({"name": "test rule", "pattern": "test"})
        status, body = self._api("/api/v1/rules/test+rule")
        self.assertEqual(status, 200)

    # --- POST /api/v1/rules ---

    def test_create(self):
        rule_data = json.dumps(
            {"name": "new_rule", "pattern": "NEW_[A-Z]{8}", "detector": "secrets", "severity": "high"}
        ).encode()
        status, body = self._api("/api/v1/rules", "POST", rule_data)
        self.assertEqual(status, 201)
        data = json.loads(body)
        self.assertEqual(data["name"], "new_rule")
        self.assertEqual(data["source"], "dashboard")
        self.assertEqual(data["tier"], "custom")

    def test_create_missing_name(self):
        status, body = self._api("/api/v1/rules", "POST", json.dumps({"pattern": "test"}).encode())
        self.assertEqual(status, 400)

    def test_create_missing_pattern(self):
        status, body = self._api("/api/v1/rules", "POST", json.dumps({"name": "x"}).encode())
        self.assertEqual(status, 400)

    def test_create_invalid_regex(self):
        status, body = self._api("/api/v1/rules", "POST", json.dumps({"name": "bad", "pattern": "[invalid"}).encode())
        self.assertEqual(status, 400)
        self.assertIn("invalid regex", json.loads(body)["error"])

    def test_create_duplicate(self):
        rule_data = json.dumps({"name": "aws_key", "pattern": "test"}).encode()
        status, body = self._api("/api/v1/rules", "POST", rule_data)
        self.assertEqual(status, 409)

    def test_create_rejects_redact_action(self):
        rule_data = json.dumps({"name": "x", "pattern": "test", "action": "redact"}).encode()
        status, body = self._api("/api/v1/rules", "POST", rule_data)
        self.assertEqual(status, 400)
        self.assertIn("invalid action", json.loads(body)["error"])

    def test_create_allows_alert_action(self):
        rule_data = json.dumps({"name": "x", "pattern": "test", "action": "alert"}).encode()
        status, body = self._api("/api/v1/rules", "POST", rule_data)
        self.assertEqual(status, 201)

    def test_create_allows_block_action(self):
        rule_data = json.dumps({"name": "y", "pattern": "test", "action": "block"}).encode()
        status, body = self._api("/api/v1/rules", "POST", rule_data)
        self.assertEqual(status, 201)

    def test_create_allows_default_action(self):
        rule_data = json.dumps({"name": "z", "pattern": "test", "action": ""}).encode()
        status, body = self._api("/api/v1/rules", "POST", rule_data)
        self.assertEqual(status, 201)

    # --- PUT /api/v1/rules/:name ---

    def test_update(self):
        data = json.dumps({"severity": "critical", "enabled": False}).encode()
        status, body = self._api("/api/v1/rules/aws_key", "PUT", data)
        self.assertEqual(status, 200)
        updated = json.loads(body)
        self.assertEqual(updated["severity"], "critical")
        self.assertFalse(updated["enabled"])

    def test_update_not_found(self):
        status, body = self._api("/api/v1/rules/nonexistent", "PUT", json.dumps({"enabled": False}).encode())
        self.assertEqual(status, 404)

    def test_update_rejects_redact_action(self):
        data = json.dumps({"action": "redact"}).encode()
        status, body = self._api("/api/v1/rules/aws_key", "PUT", data)
        self.assertEqual(status, 400)
        self.assertIn("invalid action", json.loads(body)["error"])

    def test_update_allows_block(self):
        data = json.dumps({"action": "block"}).encode()
        status, body = self._api("/api/v1/rules/aws_key", "PUT", data)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["action"], "block")

    # --- DELETE /api/v1/rules/:name ---

    def test_delete_dashboard_rule(self):
        # Create a dashboard rule first
        self.store.create_rule({"name": "to_delete", "pattern": "test", "source": "dashboard"})
        status, body = self._api("/api/v1/rules/to_delete", "DELETE")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["deleted"], "to_delete")

    def test_delete_import_rule_fails(self):
        # Import rules have source='import', delete should fail
        status, body = self._api("/api/v1/rules/aws_key", "DELETE")
        self.assertEqual(status, 404)

    def test_delete_nonexistent(self):
        status, body = self._api("/api/v1/rules/nonexistent", "DELETE")
        self.assertEqual(status, 404)

    # --- POST /api/v1/rules/:name/clone ---

    def test_clone(self):
        status, body = self._api(
            "/api/v1/rules/aws_key/clone", "POST", json.dumps({"new_name": "aws_key_custom"}).encode()
        )
        self.assertEqual(status, 201)
        data = json.loads(body)
        self.assertEqual(data["name"], "aws_key_custom")
        self.assertEqual(data["tier"], "custom")
        self.assertEqual(data["source"], "dashboard")

    def test_clone_default_name(self):
        status, body = self._api("/api/v1/rules/aws_key/clone", "POST", b"")
        self.assertEqual(status, 201)
        data = json.loads(body)
        self.assertEqual(data["name"], "aws_key_custom")

    def test_clone_conflict(self):
        # Clone once
        self._api("/api/v1/rules/aws_key/clone", "POST", b"")
        # Clone again — same default name should conflict
        status, body = self._api("/api/v1/rules/aws_key/clone", "POST", b"")
        self.assertEqual(status, 409)

    def test_clone_nonexistent(self):
        status, body = self._api("/api/v1/rules/nonexistent/clone", "POST", json.dumps({"new_name": "x"}).encode())
        self.assertEqual(status, 409)


if __name__ == "__main__":
    unittest.main()
