"""Tests for custom regex detector and config parsing."""

import re
import unittest

from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.config import CustomRuleConfig, Config, _parse_yaml, _validate_config, load_config
from lumen_argus.detectors.custom import CustomDetector
from lumen_argus.models import ScanField
from lumen_argus.pipeline import ScannerPipeline


def _rule(name, pattern, severity="high", action=""):
    return CustomRuleConfig(
        name=name,
        pattern=pattern,
        compiled=re.compile(pattern),
        severity=severity,
        action=action,
    )


class TestCustomDetector(unittest.TestCase):
    def setUp(self):
        self.allowlist = AllowlistMatcher()

    def _scan(self, rules, text, path="test"):
        detector = CustomDetector(rules)
        fields = [ScanField(path=path, text=text)]
        return detector.scan(fields, self.allowlist)

    def test_basic_match(self):
        rules = [_rule("internal_token", r"itk_[a-zA-Z0-9]{8}")]
        findings = self._scan(rules, "token is itk_AbCd1234 here")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "internal_token")
        self.assertEqual(findings[0].detector, "custom")
        self.assertEqual(findings[0].matched_value, "itk_AbCd1234")

    def test_no_match(self):
        rules = [_rule("internal_token", r"itk_[a-zA-Z0-9]{8}")]
        findings = self._scan(rules, "nothing here")
        self.assertEqual(len(findings), 0)

    def test_severity_default_high(self):
        rules = [_rule("tok", r"tok_\w+")]
        findings = self._scan(rules, "tok_abc123")
        self.assertEqual(findings[0].severity, "high")

    def test_severity_custom(self):
        rules = [_rule("tok", r"tok_\w+", severity="critical")]
        findings = self._scan(rules, "tok_abc123")
        self.assertEqual(findings[0].severity, "critical")

    def test_action_set_on_finding(self):
        rules = [_rule("tok", r"tok_\w+", action="block")]
        findings = self._scan(rules, "tok_abc123")
        self.assertEqual(findings[0].action, "block")

    def test_action_empty_when_not_set(self):
        rules = [_rule("tok", r"tok_\w+")]
        findings = self._scan(rules, "tok_abc123")
        self.assertEqual(findings[0].action, "")

    def test_value_preview_masked(self):
        rules = [_rule("tok", r"tok_[a-z0-9]{20}")]
        findings = self._scan(rules, "tok_abcdef1234567890abcd")
        self.assertIn("****", findings[0].value_preview)
        self.assertTrue(findings[0].value_preview.startswith("tok_"))

    def test_allowlisted_value_skipped(self):
        allowlist = AllowlistMatcher(secrets=["itk_EXAMPLE1"])
        detector = CustomDetector([_rule("tok", r"itk_\w+")])
        fields = [ScanField(path="test", text="itk_EXAMPLE1")]
        findings = detector.scan(fields, allowlist)
        self.assertEqual(len(findings), 0)

    def test_multiple_rules(self):
        rules = [
            _rule("tok_a", r"tka_\w+"),
            _rule("tok_b", r"tkb_\w+"),
        ]
        findings = self._scan(rules, "found tka_123 and tkb_456")
        types = {f.type for f in findings}
        self.assertEqual(types, {"tok_a", "tok_b"})

    def test_multiple_matches_same_rule(self):
        rules = [_rule("tok", r"itk_\w+")]
        findings = self._scan(rules, "itk_first and itk_second")
        self.assertEqual(len(findings), 2)

    def test_empty_rules(self):
        findings = self._scan([], "anything here")
        self.assertEqual(len(findings), 0)

    def test_empty_fields(self):
        detector = CustomDetector([_rule("tok", r"tok_\w+")])
        findings = detector.scan([], self.allowlist)
        self.assertEqual(len(findings), 0)

    def test_capture_group_used(self):
        """If pattern has a capture group, use group(1) as matched value."""
        rules = [_rule("db_pass", r"password[=:]\s*['\"]?(\S+)")]
        findings = self._scan(rules, "password=mysecret123")
        self.assertEqual(findings[0].matched_value, "mysecret123")

    def test_location_from_field(self):
        rules = [_rule("tok", r"itk_\w+")]
        findings = self._scan(rules, "itk_abc", path="messages[3].content")
        self.assertEqual(findings[0].location, "messages[3].content")

    def test_update_rules(self):
        detector = CustomDetector([_rule("old", r"old_\w+")])
        detector.update_rules([_rule("new", r"new_\w+")])
        fields = [ScanField(path="test", text="old_match new_match")]
        findings = detector.scan(fields, self.allowlist)
        types = [f.type for f in findings]
        self.assertNotIn("old", types)
        self.assertIn("new", types)


class TestCustomRuleConfigValidation(unittest.TestCase):
    def test_multiline_yaml_parsed(self):
        """Multi-line sequence items (standard YAML format) parse all fields."""
        data = _parse_yaml("""
custom_rules:
  - name: my_token
    pattern: "tok_[a-z0-9]{16}"
    severity: critical
    action: block
""")
        rules = data.get("custom_rules", [])
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["name"], "my_token")
        self.assertEqual(rules[0]["pattern"], "tok_[a-z0-9]{16}")
        self.assertEqual(rules[0]["severity"], "critical")
        self.assertEqual(rules[0]["action"], "block")

    def test_multiple_multiline_rules_parsed(self):
        """Multiple multi-line rules parse correctly."""
        data = _parse_yaml("""
custom_rules:
  - name: rule_a
    pattern: "aaa_\\w+"
    severity: high
  - name: rule_b
    pattern: "bbb_\\w+"
    severity: critical
    action: block
""")
        rules = data.get("custom_rules", [])
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0]["name"], "rule_a")
        self.assertEqual(rules[1]["name"], "rule_b")
        self.assertEqual(rules[1]["action"], "block")

    def test_valid_custom_rules(self):
        data = _parse_yaml("""
custom_rules:
  - name: my_token
    pattern: "tok_[a-z0-9]{16}"
    severity: critical
    action: block
""")
        warnings = _validate_config(data, "test")
        rule_warnings = [w for w in warnings if "custom_rules" in w]
        self.assertEqual(len(rule_warnings), 0)

    def test_missing_name(self):
        data = _parse_yaml("""
custom_rules:
  - pattern: "tok_\\w+"
""")
        warnings = _validate_config(data, "test")
        self.assertTrue(any("missing required 'name'" in w for w in warnings))

    def test_missing_pattern(self):
        data = _parse_yaml("""
custom_rules:
  - name: my_token
""")
        warnings = _validate_config(data, "test")
        self.assertTrue(any("missing required 'pattern'" in w for w in warnings))

    def test_invalid_regex(self):
        data = _parse_yaml("""
custom_rules:
  - name: bad
    pattern: "[invalid"
""")
        warnings = _validate_config(data, "test")
        self.assertTrue(any("invalid regex" in w for w in warnings))

    def test_invalid_severity(self):
        data = _parse_yaml("""
custom_rules:
  - name: tok
    pattern: "tok_\\w+"
    severity: extreme
""")
        warnings = _validate_config(data, "test")
        self.assertTrue(any("severity" in w and "not valid" in w for w in warnings))

    def test_invalid_action(self):
        data = _parse_yaml("""
custom_rules:
  - name: tok
    pattern: "tok_\\w+"
    action: destroy
""")
        warnings = _validate_config(data, "test")
        self.assertTrue(any("action" in w and "not valid" in w for w in warnings))

    def test_unknown_key(self):
        data = _parse_yaml("""
custom_rules:
  - name: tok
    pattern: "tok_\\w+"
    bogus: true
""")
        warnings = _validate_config(data, "test")
        self.assertTrue(any("unknown key" in w and "bogus" in w for w in warnings))


class TestCustomRulesPipeline(unittest.TestCase):
    def test_pipeline_with_custom_rules(self):
        """Custom rules integrate with the full scan pipeline."""
        rules = [_rule("internal_key", r"ikey_[a-f0-9]{16}")]
        pipeline = ScannerPipeline(
            default_action="alert",
            custom_rules=rules,
        )
        body = b'{"messages":[{"role":"user","content":[{"type":"text","text":"key is ikey_abcdef0123456789"}]}]}'
        result = pipeline.scan(body, "anthropic")
        types = [f.type for f in result.findings]
        self.assertIn("internal_key", types)

    def test_pipeline_reload_updates_rules(self):
        """SIGHUP reload updates custom detector rules."""
        old_rules = [_rule("old_tok", r"old_\w+")]
        new_rules = [_rule("new_tok", r"new_\w+")]
        pipeline = ScannerPipeline(
            default_action="alert",
            custom_rules=old_rules,
        )
        pipeline.reload(
            allowlist=AllowlistMatcher(),
            default_action="alert",
            custom_rules=new_rules,
        )
        body = b'{"messages":[{"role":"user","content":[{"type":"text","text":"new_match123"}]}]}'
        result = pipeline.scan(body, "anthropic")
        types = [f.type for f in result.findings]
        self.assertIn("new_tok", types)


if __name__ == "__main__":
    unittest.main()
