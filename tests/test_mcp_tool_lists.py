"""Tests for MCP tool list DB storage and API endpoints."""

import json
import unittest

from lumen_argus.config import Config
from lumen_argus.dashboard.api import handle_community_api
from tests.helpers import StoreTestCase


class TestMCPToolListStore(StoreTestCase):
    """Test MCP tool list store methods."""

    def test_empty_lists(self):
        lists = self.store.get_mcp_tool_lists()
        self.assertEqual(lists["allowed"], [])
        self.assertEqual(lists["blocked"], [])

    def test_add_allowed_tool(self):
        entry_id = self.store.add_mcp_tool_entry("allowed", "read_file")
        self.assertIsNotNone(entry_id)
        lists = self.store.get_mcp_tool_lists()
        self.assertEqual(len(lists["allowed"]), 1)
        self.assertEqual(lists["allowed"][0]["tool_name"], "read_file")
        self.assertEqual(lists["allowed"][0]["source"], "api")

    def test_add_blocked_tool(self):
        self.store.add_mcp_tool_entry("blocked", "execute_command")
        lists = self.store.get_mcp_tool_lists()
        self.assertEqual(len(lists["blocked"]), 1)
        self.assertEqual(lists["blocked"][0]["tool_name"], "execute_command")

    def test_add_duplicate_returns_none(self):
        id1 = self.store.add_mcp_tool_entry("blocked", "rm_tool")
        self.assertIsNotNone(id1)
        id2 = self.store.add_mcp_tool_entry("blocked", "rm_tool")  # duplicate
        self.assertIsNone(id2)
        lists = self.store.get_mcp_tool_lists()
        self.assertEqual(len(lists["blocked"]), 1)  # still just one entry

    def test_invalid_list_type(self):
        with self.assertRaises(ValueError):
            self.store.add_mcp_tool_entry("invalid", "tool")

    def test_empty_tool_name(self):
        with self.assertRaises(ValueError):
            self.store.add_mcp_tool_entry("allowed", "")

    def test_delete_entry(self):
        entry_id = self.store.add_mcp_tool_entry("blocked", "bad_tool")
        deleted = self.store.delete_mcp_tool_entry(entry_id)
        self.assertTrue(deleted)
        lists = self.store.get_mcp_tool_lists()
        self.assertEqual(len(lists["blocked"]), 0)

    def test_delete_nonexistent(self):
        deleted = self.store.delete_mcp_tool_entry(999)
        self.assertFalse(deleted)

    def test_delete_config_entry_fails(self):
        """Config-sourced entries cannot be deleted via API."""
        self.store.reconcile_mcp_tool_lists([], ["config_tool"])
        lists = self.store.get_mcp_tool_lists()
        entry_id = lists["blocked"][0]["id"]
        deleted = self.store.delete_mcp_tool_entry(entry_id)
        self.assertFalse(deleted)  # source='config' not deletable

    def test_reconcile_creates_config_entries(self):
        result = self.store.reconcile_mcp_tool_lists(["read_file", "write_file"], ["execute_command"])
        self.assertEqual(result["created"], 3)
        lists = self.store.get_mcp_tool_lists()
        self.assertEqual(len(lists["allowed"]), 2)
        self.assertEqual(len(lists["blocked"]), 1)
        self.assertTrue(all(e["source"] == "config" for e in lists["allowed"]))

    def test_reconcile_deletes_removed_entries(self):
        self.store.reconcile_mcp_tool_lists(["a", "b"], [])
        self.store.reconcile_mcp_tool_lists(["a"], [])  # b removed
        lists = self.store.get_mcp_tool_lists()
        self.assertEqual(len(lists["allowed"]), 1)
        self.assertEqual(lists["allowed"][0]["tool_name"], "a")

    def test_reconcile_preserves_api_entries(self):
        self.store.add_mcp_tool_entry("blocked", "api_managed_tool")
        self.store.reconcile_mcp_tool_lists([], ["config_tool"])
        lists = self.store.get_mcp_tool_lists()
        self.assertEqual(len(lists["blocked"]), 2)


class TestMCPToolListAPI(StoreTestCase):
    """Test MCP tool list API endpoints."""

    def setUp(self):
        super().setUp()
        self.config = Config()

    def test_get_empty_lists(self):
        status, body = handle_community_api("/api/v1/mcp/tools", "GET", b"", self.store, config=self.config)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["allowed"], [])
        self.assertEqual(data["blocked"], [])

    def test_post_add_tool(self):
        payload = json.dumps({"list_type": "blocked", "tool_name": "dangerous"}).encode()
        status, body = handle_community_api("/api/v1/mcp/tools", "POST", payload, self.store, config=self.config)
        self.assertEqual(status, 201)
        data = json.loads(body)
        self.assertEqual(data["tool_name"], "dangerous")
        self.assertEqual(data["list_type"], "blocked")
        self.assertIn("id", data)

    def test_post_duplicate_returns_409(self):
        payload = json.dumps({"list_type": "blocked", "tool_name": "dup_tool"}).encode()
        status1, _ = handle_community_api("/api/v1/mcp/tools", "POST", payload, self.store, config=self.config)
        self.assertEqual(status1, 201)
        status2, body2 = handle_community_api("/api/v1/mcp/tools", "POST", payload, self.store, config=self.config)
        self.assertEqual(status2, 409)
        self.assertIn("already", json.loads(body2)["error"])

    def test_post_invalid_list_type(self):
        payload = json.dumps({"list_type": "invalid", "tool_name": "tool"}).encode()
        status, body = handle_community_api("/api/v1/mcp/tools", "POST", payload, self.store, config=self.config)
        self.assertEqual(status, 400)

    def test_delete_tool(self):
        # Add then delete
        payload = json.dumps({"list_type": "blocked", "tool_name": "temp"}).encode()
        _, add_body = handle_community_api("/api/v1/mcp/tools", "POST", payload, self.store, config=self.config)
        entry_id = json.loads(add_body)["id"]

        status, body = handle_community_api(
            "/api/v1/mcp/tools/%d" % entry_id, "DELETE", b"", self.store, config=self.config
        )
        self.assertEqual(status, 200)

    def test_delete_nonexistent(self):
        status, body = handle_community_api("/api/v1/mcp/tools/999", "DELETE", b"", self.store, config=self.config)
        self.assertEqual(status, 404)

    def test_get_includes_config_entries(self):
        """GET should include config-sourced entries from Config object."""
        self.config.mcp.blocked_tools = ["config_blocked"]
        status, body = handle_community_api("/api/v1/mcp/tools", "GET", b"", self.store, config=self.config)
        data = json.loads(body)
        blocked_names = [e["tool_name"] for e in data["blocked"]]
        self.assertIn("config_blocked", blocked_names)

    def test_pipeline_mcp_tools_count(self):
        """Pipeline API should include MCP tool list counts."""
        self.store.add_mcp_tool_entry("blocked", "tool_a")
        self.store.add_mcp_tool_entry("blocked", "tool_b")
        self.store.add_mcp_tool_entry("blocked", "tool_c")

        status, body = handle_community_api("/api/v1/pipeline", "GET", b"", self.store, config=self.config)
        data = json.loads(body)
        mcp_stage = next(s for s in data["stages"] if s["name"] == "mcp_arguments")
        self.assertIn("mcp_tools", mcp_stage)
        self.assertEqual(mcp_stage["mcp_tools"]["blocked_count"], 3)
        self.assertEqual(mcp_stage["mcp_tools"]["allowed_count"], 0)


if __name__ == "__main__":
    unittest.main()
