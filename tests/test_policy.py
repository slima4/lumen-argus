"""Tests for the policy engine."""

import unittest

from lumen_argus.models import Finding
from lumen_argus.policy import PolicyEngine


class TestPolicyEngine(unittest.TestCase):
    def test_no_findings_passes(self):
        engine = PolicyEngine()
        decision = engine.evaluate([])
        self.assertEqual(decision.action, "pass")

    def test_single_finding_uses_default(self):
        engine = PolicyEngine(default_action="alert")
        findings = [
            Finding(
                detector="secrets",
                type="aws_access_key",
                severity="critical",
                location="messages[0]",
                value_preview="AKIA****",
                matched_value="AKIA...",
            ),
        ]
        decision = engine.evaluate(findings)
        self.assertEqual(decision.action, "alert")

    def test_override_trumps_default(self):
        engine = PolicyEngine(
            default_action="alert",
            action_overrides={"secrets": "block"},
        )
        findings = [
            Finding(
                detector="secrets",
                type="aws_access_key",
                severity="critical",
                location="messages[0]",
                value_preview="AKIA****",
                matched_value="AKIA...",
            ),
        ]
        decision = engine.evaluate(findings)
        self.assertEqual(decision.action, "block")

    def test_highest_priority_wins(self):
        engine = PolicyEngine(
            default_action="log",
            action_overrides={"secrets": "block", "pii": "alert"},
        )
        findings = [
            Finding(
                detector="pii",
                type="email",
                severity="warning",
                location="messages[0]",
                value_preview="john****",
                matched_value="john@example.com",
            ),
            Finding(
                detector="secrets",
                type="aws_access_key",
                severity="critical",
                location="messages[1]",
                value_preview="AKIA****",
                matched_value="AKIA...",
            ),
        ]
        decision = engine.evaluate(findings)
        self.assertEqual(decision.action, "block")

    def test_block_beats_alert(self):
        engine = PolicyEngine(default_action="alert")
        findings = [
            Finding(
                detector="pii",
                type="email",
                severity="warning",
                location="messages[0]",
                value_preview="john****",
                matched_value="john@example.com",
                action="alert",
            ),
            Finding(
                detector="secrets",
                type="private_key",
                severity="critical",
                location="messages[1]",
                value_preview="----****",
                matched_value="-----BEGIN...",
                action="block",
            ),
        ]
        decision = engine.evaluate(findings)
        self.assertEqual(decision.action, "block")

    def test_redact_action_preserved(self):
        engine = PolicyEngine(default_action="alert")
        findings = [
            Finding(
                detector="secrets",
                type="aws_access_key",
                severity="critical",
                location="messages[0]",
                value_preview="AKIA****",
                matched_value="AKIA...",
                action="redact",
            ),
        ]
        decision = engine.evaluate(findings)
        self.assertEqual(decision.action, "redact")

    def test_redact_beats_alert(self):
        engine = PolicyEngine(default_action="log")
        findings = [
            Finding(
                detector="pii",
                type="email",
                severity="warning",
                location="messages[0]",
                value_preview="john****",
                matched_value="john@example.com",
                action="alert",
            ),
            Finding(
                detector="secrets",
                type="api_key",
                severity="critical",
                location="messages[1]",
                value_preview="sk-****",
                matched_value="sk-abc...",
                action="redact",
            ),
        ]
        decision = engine.evaluate(findings)
        self.assertEqual(decision.action, "redact")

    def test_block_beats_redact(self):
        engine = PolicyEngine(default_action="log")
        findings = [
            Finding(
                detector="secrets",
                type="api_key",
                severity="critical",
                location="messages[0]",
                value_preview="sk-****",
                matched_value="sk-abc...",
                action="redact",
            ),
            Finding(
                detector="secrets",
                type="private_key",
                severity="critical",
                location="messages[1]",
                value_preview="----****",
                matched_value="-----BEGIN...",
                action="block",
            ),
        ]
        decision = engine.evaluate(findings)
        self.assertEqual(decision.action, "block")

    def test_default_redact_via_override(self):
        engine = PolicyEngine(
            default_action="alert",
            action_overrides={"secrets": "redact"},
        )
        findings = [
            Finding(
                detector="secrets",
                type="aws_access_key",
                severity="critical",
                location="messages[0]",
                value_preview="AKIA****",
                matched_value="AKIA...",
            ),
        ]
        decision = engine.evaluate(findings)
        self.assertEqual(decision.action, "redact")

    def test_all_findings_preserved(self):
        engine = PolicyEngine(default_action="alert")
        findings = [
            Finding(
                detector="pii",
                type="email",
                severity="warning",
                location="messages[0]",
                value_preview="john****",
                matched_value="john@example.com",
            ),
            Finding(
                detector="pii",
                type="ssn",
                severity="critical",
                location="messages[1]",
                value_preview="123-****",
                matched_value="123-45-6789",
            ),
        ]
        decision = engine.evaluate(findings)
        self.assertEqual(len(decision.findings), 2)


if __name__ == "__main__":
    unittest.main()
