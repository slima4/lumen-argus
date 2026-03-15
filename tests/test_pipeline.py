"""Tests for the scanner pipeline (integration)."""

import json
import unittest

from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.pipeline import ScannerPipeline


class TestScannerPipeline(unittest.TestCase):
    def setUp(self):
        self.pipeline = ScannerPipeline(
            default_action="alert",
            action_overrides={"secrets": "block"},
        )

    def _make_anthropic_body(self, messages):
        return json.dumps({
            "model": "claude-opus-4-6",
            "messages": messages,
        }).encode()

    def test_clean_request_passes(self):
        body = self._make_anthropic_body([
            {"role": "user", "content": "What is 2 + 2?"},
        ])
        result = self.pipeline.scan(body, "anthropic")
        self.assertEqual(result.action, "pass")
        self.assertEqual(len(result.findings), 0)

    def test_aws_key_blocked(self):
        body = self._make_anthropic_body([
            {"role": "user", "content": "Here is my key: AKIAIOSFODNN7EXAMPLE"},
        ])
        result = self.pipeline.scan(body, "anthropic")
        self.assertEqual(result.action, "block")
        self.assertTrue(len(result.findings) > 0)

    def test_ssn_detected(self):
        body = self._make_anthropic_body([
            {"role": "user", "content": "Patient SSN: 123-45-6789"},
        ])
        result = self.pipeline.scan(body, "anthropic")
        self.assertIn(result.action, ("alert", "block"))
        types = [f.type for f in result.findings]
        self.assertIn("ssn", types)

    def test_private_key_blocked(self):
        body = self._make_anthropic_body([
            {"role": "user", "content": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."},
        ])
        result = self.pipeline.scan(body, "anthropic")
        self.assertEqual(result.action, "block")

    def test_confidential_keyword(self):
        body = self._make_anthropic_body([
            {"role": "user", "content": "This is CONFIDENTIAL information."},
        ])
        result = self.pipeline.scan(body, "anthropic")
        self.assertNotEqual(result.action, "pass")
        types = [f.type for f in result.findings]
        self.assertIn("confidential_keyword", types)

    def test_multiple_findings(self):
        body = self._make_anthropic_body([
            {
                "role": "user",
                "content": "Key: AKIAIOSFODNN7EXAMPLE\nSSN: 123-45-6789\nCONFIDENTIAL",
            },
        ])
        result = self.pipeline.scan(body, "anthropic")
        self.assertTrue(len(result.findings) >= 3)

    def test_allowlisted_secret_passes(self):
        pipeline = ScannerPipeline(
            default_action="alert",
            action_overrides={"secrets": "block"},
            allowlist=AllowlistMatcher(secrets=["AKIAIOSFODNN7EXAMPLE"]),
        )
        body = self._make_anthropic_body([
            {"role": "user", "content": "Key: AKIAIOSFODNN7EXAMPLE"},
        ])
        result = pipeline.scan(body, "anthropic")
        aws_findings = [f for f in result.findings if f.type == "aws_access_key"]
        self.assertEqual(len(aws_findings), 0)

    def test_scan_duration_tracked(self):
        body = self._make_anthropic_body([
            {"role": "user", "content": "Hello world"},
        ])
        result = self.pipeline.scan(body, "anthropic")
        self.assertGreater(result.scan_duration_ms, 0)

    def test_openai_format(self):
        body = json.dumps({
            "model": "gpt-4",
            "messages": [
                {"role": "user", "content": "Key: AKIAIOSFODNN7EXAMPLE"},
            ],
        }).encode()
        result = self.pipeline.scan(body, "openai")
        self.assertEqual(result.action, "block")

    def test_empty_body_passes(self):
        result = self.pipeline.scan(b"", "anthropic")
        self.assertEqual(result.action, "pass")

    def test_invalid_json_passes(self):
        result = self.pipeline.scan(b"not json at all", "anthropic")
        self.assertEqual(result.action, "pass")

    def test_tool_result_with_env_file(self):
        body = json.dumps({
            "model": "claude-opus-4-6",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "content": "DB_PASSWORD=super_secret_123",
                            "input": {"file_path": "/app/.env"},
                        },
                    ],
                },
            ],
        }).encode()
        result = self.pipeline.scan(body, "anthropic")
        # Should detect blocked file pattern
        types = [f.type for f in result.findings]
        self.assertTrue(
            "blocked_file_pattern" in types or len(result.findings) > 0,
            "Expected findings for .env file content",
        )


if __name__ == "__main__":
    unittest.main()
