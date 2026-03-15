"""Tests for the config parser."""

import unittest

from lumen_argus.config import _parse_yaml, _validate_config, Config, load_config


class TestYAMLParser(unittest.TestCase):
    def test_simple_mapping(self):
        yaml = """
key1: value1
key2: value2
"""
        result = _parse_yaml(yaml)
        self.assertEqual(result["key1"], "value1")
        self.assertEqual(result["key2"], "value2")

    def test_nested_mapping(self):
        yaml = """
proxy:
  port: 8080
  bind: "127.0.0.1"
"""
        result = _parse_yaml(yaml)
        self.assertEqual(result["proxy"]["port"], 8080)
        self.assertEqual(result["proxy"]["bind"], "127.0.0.1")

    def test_sequence(self):
        yaml = """
items:
  - "one"
  - "two"
  - "three"
"""
        result = _parse_yaml(yaml)
        self.assertEqual(result["items"], ["one", "two", "three"])

    def test_boolean_values(self):
        yaml = """
enabled: true
disabled: false
"""
        result = _parse_yaml(yaml)
        self.assertTrue(result["enabled"])
        self.assertFalse(result["disabled"])

    def test_numeric_values(self):
        yaml = """
port: 8080
threshold: 4.5
"""
        result = _parse_yaml(yaml)
        self.assertEqual(result["port"], 8080)
        self.assertAlmostEqual(result["threshold"], 4.5)

    def test_comments_ignored(self):
        yaml = """
# This is a comment
key: value  # inline comment
"""
        result = _parse_yaml(yaml)
        self.assertEqual(result["key"], "value")

    def test_quoted_strings(self):
        yaml = """
single: 'hello'
double: "world"
"""
        result = _parse_yaml(yaml)
        self.assertEqual(result["single"], "hello")
        self.assertEqual(result["double"], "world")

    def test_full_config(self):
        yaml = """
version: "1"

proxy:
  port: 9090
  bind: "127.0.0.1"

default_action: block

detectors:
  secrets:
    enabled: true
    action: block
    entropy_threshold: 4.5

  pii:
    enabled: true
    action: alert

allowlists:
  secrets:
    - "AKIAIOSFODNN7EXAMPLE"
  pii:
    - "*@example.com"
  paths:
    - "test/**"
"""
        result = _parse_yaml(yaml)
        self.assertEqual(result["proxy"]["port"], 9090)
        self.assertEqual(result["default_action"], "block")
        self.assertEqual(result["detectors"]["secrets"]["action"], "block")
        self.assertEqual(len(result["allowlists"]["secrets"]), 1)
        self.assertEqual(result["allowlists"]["pii"][0], "*@example.com")


class TestConfigLoading(unittest.TestCase):
    def test_default_config(self):
        # Should return defaults when no file exists
        config = load_config(config_path="/nonexistent/path/config.yaml")
        self.assertIsInstance(config, Config)
        self.assertEqual(config.proxy.port, 8080)
        self.assertEqual(config.proxy.bind, "127.0.0.1")
        self.assertEqual(config.default_action, "alert")
        self.assertEqual(config.entropy_threshold, 4.5)


class TestConfigValidation(unittest.TestCase):
    def test_valid_config_no_warnings(self):
        data = _parse_yaml("""
version: "1"
proxy:
  port: 8080
  bind: "127.0.0.1"
default_action: alert
detectors:
  secrets:
    enabled: true
    action: block
""")
        warnings = _validate_config(data, "test")
        self.assertEqual(len(warnings), 0)

    def test_unknown_top_level_key(self):
        data = {"version": "1", "bogus_key": "value"}
        warnings = _validate_config(data, "test")
        self.assertTrue(any("bogus_key" in w for w in warnings))

    def test_invalid_default_action(self):
        data = {"default_action": "explode"}
        warnings = _validate_config(data, "test")
        self.assertTrue(any("default_action" in w and "explode" in w for w in warnings))

    def test_invalid_port_out_of_range(self):
        data = {"proxy": {"port": 99999}}
        warnings = _validate_config(data, "test")
        self.assertTrue(any("port" in w and "out of range" in w for w in warnings))

    def test_invalid_port_zero(self):
        data = {"proxy": {"port": 0}}
        warnings = _validate_config(data, "test")
        self.assertTrue(any("port" in w for w in warnings))

    def test_bind_not_localhost(self):
        data = {"proxy": {"bind": "0.0.0.0"}}
        warnings = _validate_config(data, "test")
        self.assertTrue(any("bind" in w and "0.0.0.0" in w for w in warnings))

    def test_unknown_proxy_key(self):
        data = {"proxy": {"port": 8080, "magic": True}}
        warnings = _validate_config(data, "test")
        self.assertTrue(any("proxy.magic" in w for w in warnings))

    def test_invalid_detector_action(self):
        data = {"detectors": {"secrets": {"action": "nuke"}}}
        warnings = _validate_config(data, "test")
        self.assertTrue(any("nuke" in w for w in warnings))

    def test_entropy_threshold_out_of_range(self):
        data = {"detectors": {"secrets": {"entropy_threshold": 15.0}}}
        warnings = _validate_config(data, "test")
        self.assertTrue(any("entropy_threshold" in w for w in warnings))

    def test_unknown_detector_key(self):
        data = {"detectors": {"secrets": {"action": "block", "magic_mode": True}}}
        warnings = _validate_config(data, "test")
        self.assertTrue(any("magic_mode" in w for w in warnings))

    def test_negative_retention_days(self):
        data = {"audit": {"retention_days": -5}}
        warnings = _validate_config(data, "test")
        self.assertTrue(any("retention_days" in w for w in warnings))

    def test_unknown_audit_key(self):
        data = {"audit": {"log_dir": "/tmp", "compress": True}}
        warnings = _validate_config(data, "test")
        self.assertTrue(any("audit.compress" in w for w in warnings))

    def test_unknown_allowlist_key(self):
        data = {"allowlists": {"secrets": [], "emails": []}}
        warnings = _validate_config(data, "test")
        self.assertTrue(any("allowlists.emails" in w for w in warnings))

    def test_allowlist_not_a_list(self):
        data = {"allowlists": {"secrets": "not a list"}}
        warnings = _validate_config(data, "test")
        self.assertTrue(any("must be a list" in w for w in warnings))

    def test_valid_actions_accepted(self):
        for action in ("log", "alert", "redact", "block"):
            data = {"default_action": action}
            warnings = _validate_config(data, "test")
            self.assertEqual(len(warnings), 0, "action '%s' should be valid" % action)


if __name__ == "__main__":
    unittest.main()
