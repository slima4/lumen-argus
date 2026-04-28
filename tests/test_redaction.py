"""Tests for the community redaction action."""

import json
import unittest

from lumen_argus.redaction import redact_request_body
from tests.helpers import make_finding


class TestRedactRequestBody(unittest.TestCase):
    def test_single_redaction(self):
        body = json.dumps({"content": "my key is AKIAIOSFODNN7EXAMPLE"}).encode()
        findings = [make_finding(matched_value="AKIAIOSFODNN7EXAMPLE", type_="aws_access_key", action="redact")]
        result = redact_request_body(body, findings).decode("utf-8")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", result)
        self.assertIn("[REDACTED:aws_access_key]", result)

    def test_multiple_redactions(self):
        body = json.dumps({"content": "key=AKIAIOSFODNN7EXAMPLE ssn=123-45-6789"}).encode()
        findings = [
            make_finding(matched_value="AKIAIOSFODNN7EXAMPLE", type_="aws_access_key", action="redact"),
            make_finding(matched_value="123-45-6789", type_="ssn", action="redact", detector="pii"),
        ]
        result = redact_request_body(body, findings).decode("utf-8")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", result)
        self.assertNotIn("123-45-6789", result)
        self.assertIn("[REDACTED:aws_access_key]", result)
        self.assertIn("[REDACTED:ssn]", result)

    def test_only_redacts_redact_action(self):
        body = json.dumps({"content": "AKIAIOSFODNN7EXAMPLE"}).encode()
        findings = [make_finding(matched_value="AKIAIOSFODNN7EXAMPLE", type_="aws_access_key", action="alert")]
        result = redact_request_body(body, findings)
        self.assertIn(b"AKIAIOSFODNN7EXAMPLE", result)

    def test_no_findings_returns_unchanged(self):
        body = b'{"content": "safe text"}'
        result = redact_request_body(body, [])
        self.assertEqual(result, body)

    def test_overlapping_matches_longest_wins(self):
        body = b'"short_key" and "short_key_extended"'
        findings = [
            make_finding(matched_value="short_key", type_="short", action="redact"),
            make_finding(matched_value="short_key_extended", type_="extended", action="redact"),
        ]
        result = redact_request_body(body, findings).decode("utf-8")
        self.assertNotIn("short_key_extended", result)
        self.assertIn("[REDACTED:extended]", result)
        self.assertIn("[REDACTED:short]", result)

    def test_empty_matched_value_skipped(self):
        body = b'{"content": "test"}'
        findings = [make_finding(matched_value="", type_="size_check", action="redact")]
        result = redact_request_body(body, findings)
        self.assertEqual(result, body)

    def test_duplicate_values_deduplicated(self):
        body = b'"secret123" and "secret123"'
        findings = [
            make_finding(matched_value="secret123", type_="api_key", action="redact"),
            make_finding(matched_value="secret123", type_="api_key", action="redact"),
        ]
        result = redact_request_body(body, findings).decode("utf-8")
        self.assertNotIn("secret123", result)
        self.assertEqual(result.count("[REDACTED:api_key]"), 2)


if __name__ == "__main__":
    unittest.main()
