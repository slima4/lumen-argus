"""Tests for MCP-aware scanning in the HTTP proxy."""

import json
import shutil
import tempfile
import unittest

from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.analytics.store import AnalyticsStore
from lumen_argus.detectors.secrets import SecretsDetector
from lumen_argus.mcp_scanner import (
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


if __name__ == "__main__":
    unittest.main()
