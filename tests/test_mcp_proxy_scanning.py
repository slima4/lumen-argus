"""Tests for MCP-aware scanning in the HTTP proxy."""

import json
import shutil
import tempfile
import unittest

from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.analytics.store import AnalyticsStore
from lumen_argus.detectors.secrets import SecretsDetector
from lumen_argus.mcp.scanner import (
    MCPScanner,
    detect_mcp_request,
    detect_mcp_response,
)


class TestDetectMCPRequest(unittest.TestCase):
    """Test MCP JSON-RPC detection in HTTP request bodies."""

    def test_tools_call_detected(self):
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "/tmp/test"}},
            }
        ).encode()
        info = detect_mcp_request(body)
        self.assertIsNotNone(info)
        self.assertEqual(info["tool_name"], "read_file")
        self.assertEqual(info["arguments"], {"path": "/tmp/test"})
        self.assertEqual(info["request_id"], 1)

    def test_non_mcp_request(self):
        body = json.dumps({"model": "test", "messages": []}).encode()
        self.assertIsNone(detect_mcp_request(body))

    def test_non_tools_call(self):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
        self.assertIsNone(detect_mcp_request(body))

    def test_invalid_json(self):
        self.assertIsNone(detect_mcp_request(b"not json"))

    def test_empty_body(self):
        self.assertIsNone(detect_mcp_request(b""))


class TestDetectMCPResponse(unittest.TestCase):
    """Test MCP JSON-RPC response detection."""

    def test_tool_response_detected(self):
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "content": [{"type": "text", "text": "file contents here"}],
                },
            }
        ).encode()
        info = detect_mcp_response(body)
        self.assertIsNotNone(info)
        self.assertEqual(info["request_id"], 1)
        self.assertEqual(len(info["content"]), 1)

    def test_error_response_not_detected(self):
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32602, "message": "Invalid params"},
            }
        ).encode()
        self.assertIsNone(detect_mcp_response(body))

    def test_non_mcp_response(self):
        body = json.dumps({"choices": [{"message": {"content": "hello"}}]}).encode()
        self.assertIsNone(detect_mcp_response(body))


class TestMCPScannerShared(unittest.TestCase):
    """Test the shared MCPScanner used by both proxy and mcp-wrap."""

    def _make_scanner(self, **kwargs):
        defaults = {
            "detectors": [SecretsDetector()],
            "allowlist": AllowlistMatcher(),
            "scan_arguments": True,
            "scan_responses": True,
        }
        defaults.update(kwargs)
        return MCPScanner(**defaults)

    def test_scan_arguments_directly(self):
        scanner = self._make_scanner()
        findings = scanner.scan_arguments("write_file", {"content": "AKIAIOSFODNN7EXAMPLE"})
        self.assertTrue(len(findings) > 0)

    def test_scan_response_content_directly(self):
        scanner = self._make_scanner()
        content = [{"type": "text", "text": "Found key: AKIAIOSFODNN7EXAMPLE"}]
        findings = scanner.scan_response_content(content)
        self.assertTrue(len(findings) > 0)

    def test_is_tool_allowed_public(self):
        """is_tool_allowed is now public (not _is_tool_allowed)."""
        scanner = self._make_scanner(blocked_tools={"dangerous"})
        self.assertFalse(scanner.is_tool_allowed("dangerous"))
        self.assertTrue(scanner.is_tool_allowed("safe"))


class TestMCPDetectedTools(unittest.TestCase):
    """Test MCP tool tracking in analytics store."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.store = AnalyticsStore(db_path=self._tmpdir + "/test.db")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_record_and_get(self):
        self.store.record_mcp_tool_seen("read_file")
        tools = self.store.get_mcp_detected_tools()
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0]["tool_name"], "read_file")
        self.assertEqual(tools[0]["call_count"], 1)

    def test_increment_call_count(self):
        self.store.record_mcp_tool_seen("read_file")
        self.store.record_mcp_tool_seen("read_file")
        self.store.record_mcp_tool_seen("read_file")
        tools = self.store.get_mcp_detected_tools()
        self.assertEqual(tools[0]["call_count"], 3)

    def test_multiple_tools(self):
        self.store.record_mcp_tool_seen("read_file")
        self.store.record_mcp_tool_seen("write_file")
        self.store.record_mcp_tool_seen("read_file")
        tools = self.store.get_mcp_detected_tools()
        self.assertEqual(len(tools), 2)
        # Ordered by call_count desc
        self.assertEqual(tools[0]["tool_name"], "read_file")
        self.assertEqual(tools[0]["call_count"], 2)

    def test_empty_tool_name_ignored(self):
        self.store.record_mcp_tool_seen("")
        tools = self.store.get_mcp_detected_tools()
        self.assertEqual(len(tools), 0)

    def test_last_seen_updated(self):
        self.store.record_mcp_tool_seen("tool_a")
        tools1 = self.store.get_mcp_detected_tools()
        self.store.record_mcp_tool_seen("tool_a")
        tools2 = self.store.get_mcp_detected_tools()
        self.assertGreaterEqual(tools2[0]["last_seen"], tools1[0]["last_seen"])


class TestMCPToolCallLogging(unittest.TestCase):
    """Test MCP tool call logging for chain analysis."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.store = AnalyticsStore(db_path=self._tmpdir + "/test.db")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_record_and_get(self):
        self.store.record_mcp_tool_call("read_file", session_id="s1", status="allowed")
        calls = self.store.get_mcp_tool_calls()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["tool_name"], "read_file")
        self.assertEqual(calls[0]["status"], "allowed")
        self.assertEqual(calls[0]["source"], "proxy")

    def test_session_filter(self):
        self.store.record_mcp_tool_call("tool_a", session_id="s1")
        self.store.record_mcp_tool_call("tool_b", session_id="s2")
        calls = self.store.get_mcp_tool_calls(session_id="s1")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["tool_name"], "tool_a")

    def test_blocked_status(self):
        self.store.record_mcp_tool_call("bad_tool", status="blocked", finding_count=1)
        calls = self.store.get_mcp_tool_calls()
        self.assertEqual(calls[0]["status"], "blocked")
        self.assertEqual(calls[0]["finding_count"], 1)

    def test_mcp_wrap_source(self):
        self.store.record_mcp_tool_call("tool", source="mcp-wrap")
        calls = self.store.get_mcp_tool_calls()
        self.assertEqual(calls[0]["source"], "mcp-wrap")

    def test_cleanup(self):
        # Insert with a manually backdated timestamp
        with self.store._connect() as conn:
            conn.execute(
                "INSERT INTO mcp_tool_calls (tool_name, session_id, timestamp, status, finding_count, source) "
                "VALUES (?, '', '2020-01-01T00:00:00Z', 'allowed', 0, 'proxy')",
                ("old_tool",),
            )
        deleted = self.store.cleanup_mcp_tool_calls(retention_days=30)
        self.assertEqual(deleted, 1)
        self.assertEqual(len(self.store.get_mcp_tool_calls()), 0)


class TestMCPToolDescriptions(unittest.TestCase):
    """Test tool description and schema storage."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.store = AnalyticsStore(db_path=self._tmpdir + "/test.db")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_description_stored(self):
        self.store.record_mcp_tool_seen("read_file", description="Read a file", input_schema='{"type":"object"}')
        tools = self.store.get_mcp_detected_tools()
        self.assertEqual(tools[0]["description"], "Read a file")
        self.assertEqual(tools[0]["input_schema"], '{"type":"object"}')

    def test_description_not_overwritten_with_empty(self):
        """tools/call doesn't provide description — should not blank it."""
        self.store.record_mcp_tool_seen("tool", description="Original desc")
        self.store.record_mcp_tool_seen("tool")  # no description (from tools/call)
        tools = self.store.get_mcp_detected_tools()
        self.assertEqual(tools[0]["description"], "Original desc")
        self.assertEqual(tools[0]["call_count"], 2)

    def test_description_updated_with_new_value(self):
        self.store.record_mcp_tool_seen("tool", description="Old desc")
        self.store.record_mcp_tool_seen("tool", description="New desc")
        tools = self.store.get_mcp_detected_tools()
        self.assertEqual(tools[0]["description"], "New desc")

    def test_default_schema(self):
        self.store.record_mcp_tool_seen("tool")
        tools = self.store.get_mcp_detected_tools()
        self.assertEqual(tools[0]["input_schema"], "{}")


class TestDetectToolsList(unittest.TestCase):
    """Test tools/list response detection."""

    def test_tools_list_detected(self):
        from lumen_argus.mcp.scanner import detect_mcp_tools_list_response

        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "tools": [
                        {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}},
                        {"name": "write_file", "description": "Write a file"},
                    ],
                },
            }
        ).encode()
        tools = detect_mcp_tools_list_response(body)
        self.assertIsNotNone(tools)
        self.assertEqual(len(tools), 2)
        self.assertEqual(tools[0]["name"], "read_file")
        self.assertEqual(tools[0]["description"], "Read a file")

    def test_non_tools_list_returns_none(self):
        from lumen_argus.mcp.scanner import detect_mcp_tools_list_response

        body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"content": []}}).encode()
        self.assertIsNone(detect_mcp_tools_list_response(body))

    def test_detect_mcp_method(self):
        from lumen_argus.mcp.scanner import detect_mcp_method

        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
        self.assertEqual(detect_mcp_method(body), "tools/list")

    def test_detect_mcp_method_non_jsonrpc(self):
        from lumen_argus.mcp.scanner import detect_mcp_method

        body = json.dumps({"model": "test"}).encode()
        self.assertIsNone(detect_mcp_method(body))


if __name__ == "__main__":
    unittest.main()
