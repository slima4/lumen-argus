"""Tests for the community redaction action."""

import json
import unittest

from lumen_argus.models import SessionContext
from lumen_argus.redaction import redact_request_body
from tests.helpers import make_finding

_SESSION = SessionContext()


class TestRedactRequestBody(unittest.TestCase):
    def test_single_redaction(self):
        body = json.dumps({"content": "my key is AKIAIOSFODNN7EXAMPLE"}).encode()
        findings = [make_finding(matched_value="AKIAIOSFODNN7EXAMPLE", type_="aws_access_key", action="redact")]
        result = redact_request_body(body, findings, _SESSION).decode("utf-8")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", result)
        self.assertIn("[REDACTED:aws_access_key]", result)

    def test_multiple_redactions(self):
        body = json.dumps({"content": "key=AKIAIOSFODNN7EXAMPLE ssn=123-45-6789"}).encode()
        findings = [
            make_finding(matched_value="AKIAIOSFODNN7EXAMPLE", type_="aws_access_key", action="redact"),
            make_finding(matched_value="123-45-6789", type_="ssn", action="redact", detector="pii"),
        ]
        result = redact_request_body(body, findings, _SESSION).decode("utf-8")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", result)
        self.assertNotIn("123-45-6789", result)
        self.assertIn("[REDACTED:aws_access_key]", result)
        self.assertIn("[REDACTED:ssn]", result)

    def test_only_redacts_redact_action(self):
        body = json.dumps({"content": "AKIAIOSFODNN7EXAMPLE"}).encode()
        findings = [make_finding(matched_value="AKIAIOSFODNN7EXAMPLE", type_="aws_access_key", action="alert")]
        result = redact_request_body(body, findings, _SESSION)
        self.assertIn(b"AKIAIOSFODNN7EXAMPLE", result)

    def test_no_findings_returns_unchanged(self):
        body = b'{"content": "safe text"}'
        result = redact_request_body(body, [], _SESSION)
        self.assertEqual(result, body)

    def test_overlapping_matches_longest_wins(self):
        body = b'"short_key" and "short_key_extended"'
        findings = [
            make_finding(matched_value="short_key", type_="short", action="redact"),
            make_finding(matched_value="short_key_extended", type_="extended", action="redact"),
        ]
        result = redact_request_body(body, findings, _SESSION).decode("utf-8")
        self.assertNotIn("short_key_extended", result)
        self.assertIn("[REDACTED:extended]", result)
        self.assertIn("[REDACTED:short]", result)

    def test_empty_matched_value_skipped(self):
        body = b'{"content": "test"}'
        findings = [make_finding(matched_value="", type_="size_check", action="redact")]
        result = redact_request_body(body, findings, _SESSION)
        self.assertEqual(result, body)

    def test_duplicate_values_deduplicated(self):
        body = b'"secret123" and "secret123"'
        findings = [
            make_finding(matched_value="secret123", type_="api_key", action="redact"),
            make_finding(matched_value="secret123", type_="api_key", action="redact"),
        ]
        result = redact_request_body(body, findings, _SESSION).decode("utf-8")
        self.assertNotIn("secret123", result)
        self.assertEqual(result.count("[REDACTED:api_key]"), 2)

    def test_canonical_type_higher_severity_wins(self):
        # Two findings, same matched_value, different severity. Highest severity
        # supplies the placeholder type regardless of list position.
        body = b'"AKIAIOSFODNN7EXAMPLE"'
        findings = [
            make_finding(
                matched_value="AKIAIOSFODNN7EXAMPLE",
                type_="gitleaks_aws",
                severity="info",
                detector="rules",
                action="redact",
            ),
            make_finding(
                matched_value="AKIAIOSFODNN7EXAMPLE",
                type_="aws_access_key",
                severity="critical",
                detector="secrets",
                action="redact",
            ),
        ]
        result = redact_request_body(body, findings, _SESSION).decode("utf-8")
        self.assertIn("[REDACTED:aws_access_key]", result)
        self.assertNotIn("gitleaks_aws", result)

    def test_canonical_type_equal_severity_alphabetical_detector_wins(self):
        # Equal severity → tiebreak by (detector, type) ascending.
        body = b'"shared_secret_value"'
        findings = [
            make_finding(
                matched_value="shared_secret_value",
                type_="zzz_late",
                severity="high",
                detector="zeta",
                action="redact",
            ),
            make_finding(
                matched_value="shared_secret_value",
                type_="aaa_early",
                severity="high",
                detector="alpha",
                action="redact",
            ),
        ]
        result = redact_request_body(body, findings, _SESSION).decode("utf-8")
        self.assertIn("[REDACTED:aaa_early]", result)
        self.assertNotIn("zzz_late", result)

    def test_placeholder_type_independent_of_finding_order(self):
        # Regression guard for issue #65: a priority-prepended detector must not
        # silently rename placeholders. Reversing the list must not change output.
        body = b'"AKIAIOSFODNN7EXAMPLE"'
        community = make_finding(
            matched_value="AKIAIOSFODNN7EXAMPLE",
            type_="aws_access_key",
            severity="critical",
            detector="secrets",
            action="redact",
        )
        plugin = make_finding(
            matched_value="AKIAIOSFODNN7EXAMPLE",
            type_="gitleaks_aws_access_key",
            severity="critical",
            detector="rules",
            action="redact",
        )
        forward = redact_request_body(body, [plugin, community], _SESSION)
        reverse = redact_request_body(body, [community, plugin], _SESSION)
        self.assertEqual(forward, reverse)

    def test_session_argument_ignored(self):
        # Different session contexts must produce identical output for the
        # irreversible community implementation.
        body = b'{"content": "AKIAIOSFODNN7EXAMPLE"}'
        findings = [make_finding(matched_value="AKIAIOSFODNN7EXAMPLE", type_="aws_access_key", action="redact")]
        a = redact_request_body(body, findings, SessionContext(session_id="alpha"))
        b = redact_request_body(body, findings, SessionContext(session_id="bravo"))
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
