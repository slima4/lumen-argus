"""Tests for the config parser."""

import unittest

from lumen_argus.config import _parse_yaml, _validate_config, _check_unsupported_yaml, Config, load_config


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

    def test_timeout_out_of_range(self):
        data = {"proxy": {"timeout": 999}}
        warnings = _validate_config(data, "test")
        self.assertTrue(any("timeout" in w for w in warnings))

    def test_retries_out_of_range(self):
        data = {"proxy": {"retries": 10}}
        warnings = _validate_config(data, "test")
        self.assertTrue(any("retries" in w for w in warnings))

    def test_valid_timeout_retries(self):
        data = {"proxy": {"timeout": 30, "retries": 1}}
        warnings = _validate_config(data, "test")
        self.assertEqual(len(warnings), 0)


class TestFlowSequences(unittest.TestCase):
    def test_flow_sequence_parsed(self):
        yaml = """
items: [one, two, three]
"""
        result = _parse_yaml(yaml)
        self.assertEqual(result["items"], ["one", "two", "three"])

    def test_empty_flow_sequence(self):
        yaml = """
items: []
"""
        result = _parse_yaml(yaml)
        self.assertEqual(result["items"], [])

    def test_flow_sequence_with_numbers(self):
        yaml = """
ports: [8080, 9090, 3000]
"""
        result = _parse_yaml(yaml)
        self.assertEqual(result["ports"], [8080, 9090, 3000])

    def test_flow_sequence_with_quoted_strings(self):
        yaml = """
names: ["hello", "world"]
"""
        result = _parse_yaml(yaml)
        self.assertEqual(result["names"], ["hello", "world"])


class TestUnsupportedYAMLDetection(unittest.TestCase):
    def test_block_scalar_warned(self):
        yaml = "description: |\n  multi\n  line\n"
        warnings = _check_unsupported_yaml(yaml, "test")
        self.assertTrue(any("block scalar" in w for w in warnings))

    def test_folded_scalar_warned(self):
        yaml = "description: >\n  folded\n  text\n"
        warnings = _check_unsupported_yaml(yaml, "test")
        self.assertTrue(any("block scalar" in w for w in warnings))

    def test_flow_mapping_warned(self):
        yaml = "proxy: {port: 8080, bind: localhost}\n"
        warnings = _check_unsupported_yaml(yaml, "test")
        self.assertTrue(any("flow mapping" in w for w in warnings))

    def test_normal_config_no_warnings(self):
        yaml = """
proxy:
  port: 8080
  bind: "127.0.0.1"
allowlists:
  secrets:
    - "AKIAIOSFODNN7EXAMPLE"
"""
        warnings = _check_unsupported_yaml(yaml, "test")
        self.assertEqual(len(warnings), 0)


class TestLoggingConfigValidation(unittest.TestCase):
    def test_valid_logging_config(self):
        data = _parse_yaml("""
logging:
  log_dir: "~/.lumen-argus/logs"
  file_level: info
  max_size_mb: 10
  backup_count: 5
""")
        warnings = _validate_config(data, "test")
        self.assertEqual(len(warnings), 0)

    def test_unknown_logging_key(self):
        data = _parse_yaml("""
logging:
  bogus: true
""")
        warnings = _validate_config(data, "test")
        self.assertTrue(any("unknown key 'logging.bogus'" in w for w in warnings))

    def test_invalid_file_level(self):
        data = _parse_yaml("""
logging:
  file_level: verbose
""")
        warnings = _validate_config(data, "test")
        self.assertTrue(any("file_level" in w and "not valid" in w for w in warnings))

    def test_valid_file_levels(self):
        for level in ("debug", "info", "warning", "error"):
            data = _parse_yaml("logging:\n  file_level: %s\n" % level)
            warnings = _validate_config(data, "test")
            logging_warnings = [w for w in warnings if "file_level" in w]
            self.assertEqual(len(logging_warnings), 0, "level '%s' should be valid" % level)

    def test_negative_max_size(self):
        data = _parse_yaml("""
logging:
  max_size_mb: -1
""")
        warnings = _validate_config(data, "test")
        self.assertTrue(any("max_size_mb" in w for w in warnings))

    def test_negative_backup_count(self):
        data = _parse_yaml("""
logging:
  backup_count: -1
""")
        warnings = _validate_config(data, "test")
        self.assertTrue(any("backup_count" in w for w in warnings))

    def test_json_format_warns_pro(self):
        data = _parse_yaml("""
logging:
  format: json
""")
        warnings = _validate_config(data, "test")
        self.assertTrue(any("Pro license" in w and "JSON" in w for w in warnings))

    def test_text_format_no_warning(self):
        data = _parse_yaml("""
logging:
  format: text
""")
        warnings = _validate_config(data, "test")
        format_warnings = [w for w in warnings if "format" in w]
        self.assertEqual(len(format_warnings), 0)

    def test_stdout_output_warns_pro(self):
        data = _parse_yaml("""
logging:
  output: stdout
""")
        warnings = _validate_config(data, "test")
        self.assertTrue(any("Pro license" in w and "stdout" in w for w in warnings))

    def test_both_output_warns_pro(self):
        data = _parse_yaml("""
logging:
  output: both
""")
        warnings = _validate_config(data, "test")
        self.assertTrue(any("Pro license" in w and "both" in w for w in warnings))

    def test_file_output_no_warning(self):
        data = _parse_yaml("""
logging:
  output: file
""")
        warnings = _validate_config(data, "test")
        output_warnings = [w for w in warnings if "output" in w]
        self.assertEqual(len(output_warnings), 0)

    def test_invalid_output(self):
        data = _parse_yaml("""
logging:
  output: syslog
""")
        warnings = _validate_config(data, "test")
        self.assertTrue(any("output" in w and "not valid" in w for w in warnings))


class TestLoggingConfigParsing(unittest.TestCase):
    def test_default_logging_config(self):
        config = load_config(config_path="/nonexistent/path/config.yaml")
        self.assertEqual(config.logging_config.log_dir, "~/.lumen-argus/logs")
        self.assertEqual(config.logging_config.file_level, "info")
        self.assertEqual(config.logging_config.max_size_mb, 10)
        self.assertEqual(config.logging_config.backup_count, 5)


if __name__ == "__main__":
    unittest.main()
