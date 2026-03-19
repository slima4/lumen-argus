"""Tests for log utilities: sanitization, config diff, export, and file handler."""

import logging
import os
import stat
import tempfile
import unittest

from lumen_argus.config import Config, LoggingConfig, AllowlistConfig, DetectorConfig, ProxyConfig
from lumen_argus.log_utils import (
    SecureRotatingFileHandler,
    config_diff,
    export_logs,
    sanitize_log_line,
    setup_file_logging,
)


class TestSanitizeLogLine(unittest.TestCase):
    def test_ip_replaced(self):
        line = "connection from 192.168.1.100 to 10.0.0.1"
        result = sanitize_log_line(line)
        self.assertNotIn("192.168.1.100", result)
        self.assertNotIn("10.0.0.1", result)
        self.assertIn("[IP]", result)

    def test_provider_hosts_preserved(self):
        line = "forwarding to api.anthropic.com:443"
        result = sanitize_log_line(line)
        self.assertIn("api.anthropic.com", result)

    def test_openai_host_preserved(self):
        line = "forwarding to api.openai.com:443"
        result = sanitize_log_line(line)
        self.assertIn("api.openai.com", result)

    def test_gemini_host_preserved(self):
        line = "forwarding to generativelanguage.googleapis.com:443"
        result = sanitize_log_line(line)
        self.assertIn("generativelanguage.googleapis.com", result)

    def test_unknown_host_replaced(self):
        line = "connecting to internal.corp.example.com"
        result = sanitize_log_line(line)
        self.assertNotIn("internal.corp.example.com", result)
        self.assertIn("[HOST]", result)

    def test_file_path_directory_stripped(self):
        line = "app log: /home/alice/.lumen-argus/logs/lumen-argus.log (info level)"
        result = sanitize_log_line(line)
        # Directory path should be stripped
        self.assertNotIn("/home/alice/", result)

    def test_bare_absolute_path_stripped(self):
        line = "user home is /home/alice"
        result = sanitize_log_line(line)
        self.assertNotIn("/home/alice", result)
        self.assertIn("alice", result)  # basename preserved

    def test_tilde_path_stripped(self):
        line = "config at ~/.lumen-argus/config.yaml"
        result = sanitize_log_line(line)
        self.assertNotIn("~/.lumen-argus/", result)

    def test_extra_hosts_preserved(self):
        line = "forwarding to custom.ai.internal.com:443"
        result = sanitize_log_line(line, extra_hosts={"custom.ai.internal.com"})
        self.assertIn("custom.ai.internal.com", result)

    def test_timestamps_preserved(self):
        line = "2026-03-16 14:30:00.123 INFO  [argus.proxy] #42 POST /v1/messages"
        result = sanitize_log_line(line)
        self.assertIn("2026-03-16 14:30:00.123", result)
        self.assertIn("INFO", result)
        self.assertIn("#42", result)

    def test_finding_types_preserved(self):
        line = "2026-03-16 14:30:00.123 INFO  [argus.proxy] #42 BLOCK aws_access_key, email (2 findings)"
        result = sanitize_log_line(line)
        self.assertIn("aws_access_key", result)
        self.assertIn("email", result)
        self.assertIn("BLOCK", result)


class TestConfigDiff(unittest.TestCase):
    def _make_config(self, **kwargs):
        config = Config()
        for k, v in kwargs.items():
            setattr(config, k, v)
        return config

    def test_no_changes(self):
        c1 = Config()
        c2 = Config()
        self.assertEqual(config_diff(c1, c2), [])

    def test_default_action_changed(self):
        c1 = Config(default_action="alert")
        c2 = Config(default_action="block")
        changes = config_diff(c1, c2)
        self.assertEqual(len(changes), 1)
        self.assertIn("default_action", changes[0])
        self.assertIn("alert -> block", changes[0])

    def test_detector_action_changed(self):
        c1 = Config(secrets=DetectorConfig(action="alert"))
        c2 = Config(secrets=DetectorConfig(action="block"))
        changes = config_diff(c1, c2)
        self.assertEqual(len(changes), 1)
        self.assertIn("detectors.secrets.action", changes[0])

    def test_detector_enabled_changed(self):
        c1 = Config(pii=DetectorConfig(enabled=True))
        c2 = Config(pii=DetectorConfig(enabled=False))
        changes = config_diff(c1, c2)
        self.assertEqual(len(changes), 1)
        self.assertIn("detectors.pii.enabled", changes[0])

    def test_allowlist_count_changed(self):
        c1 = Config(allowlist=AllowlistConfig(secrets=["a"]))
        c2 = Config(allowlist=AllowlistConfig(secrets=["a", "b", "c"]))
        changes = config_diff(c1, c2)
        self.assertEqual(len(changes), 1)
        self.assertIn("allowlist.secrets", changes[0])
        self.assertIn("+2", changes[0])
        self.assertIn("now 3", changes[0])

    def test_allowlist_content_changed_same_count(self):
        """Swapping entries without changing count should still be detected."""
        c1 = Config(allowlist=AllowlistConfig(pii=["*@example.com"]))
        c2 = Config(allowlist=AllowlistConfig(pii=["*@evil.com"]))
        changes = config_diff(c1, c2)
        self.assertEqual(len(changes), 1)
        self.assertIn("allowlist.pii", changes[0])
        self.assertIn("changed", changes[0])

    def test_allowlist_same_content_no_change(self):
        c1 = Config(allowlist=AllowlistConfig(secrets=["a", "b"]))
        c2 = Config(allowlist=AllowlistConfig(secrets=["b", "a"]))
        changes = config_diff(c1, c2)
        self.assertEqual(changes, [])

    def test_timeout_changed(self):
        c1 = Config(proxy=ProxyConfig(timeout=120))
        c2 = Config(proxy=ProxyConfig(timeout=60))
        changes = config_diff(c1, c2)
        self.assertEqual(len(changes), 1)
        self.assertIn("proxy.timeout", changes[0])

    def test_file_level_changed(self):
        c1 = Config(logging_config=LoggingConfig(file_level="info"))
        c2 = Config(logging_config=LoggingConfig(file_level="debug"))
        changes = config_diff(c1, c2)
        self.assertEqual(len(changes), 1)
        self.assertIn("logging.file_level", changes[0])

    def test_multiple_changes(self):
        c1 = Config(default_action="alert", proxy=ProxyConfig(timeout=120))
        c2 = Config(default_action="block", proxy=ProxyConfig(timeout=60))
        changes = config_diff(c1, c2)
        self.assertEqual(len(changes), 2)


class TestSetupFileLogging(unittest.TestCase):
    def test_creates_log_dir_and_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = os.path.join(tmpdir, "logs")
            lc = LoggingConfig(log_dir=log_dir, file_level="info")
            handler, path, level = setup_file_logging(lc)
            try:
                self.assertTrue(os.path.isdir(log_dir))
                self.assertTrue(os.path.exists(path))
                self.assertEqual(path, os.path.join(log_dir, "lumen-argus.log"))
                self.assertEqual(level, logging.INFO)
            finally:
                handler.close()

    def test_file_permissions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            lc = LoggingConfig(log_dir=tmpdir, file_level="warning")
            handler, path, level = setup_file_logging(lc)
            try:
                mode = stat.S_IMODE(os.stat(path).st_mode)
                self.assertEqual(mode, 0o600)
            finally:
                handler.close()

    def test_dir_permissions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = os.path.join(tmpdir, "newlogs")
            lc = LoggingConfig(log_dir=log_dir)
            handler, path, level = setup_file_logging(lc)
            try:
                mode = stat.S_IMODE(os.stat(log_dir).st_mode)
                self.assertEqual(mode, 0o700)
            finally:
                handler.close()

    def test_file_level_parsed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            lc = LoggingConfig(log_dir=tmpdir, file_level="debug")
            handler, path, level = setup_file_logging(lc)
            try:
                self.assertEqual(level, logging.DEBUG)
                self.assertEqual(handler.level, logging.DEBUG)
            finally:
                handler.close()


class TestSecureRotatingFileHandler(unittest.TestCase):
    def test_rollover_secures_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.log")
            handler = SecureRotatingFileHandler(
                path, maxBytes=50, backupCount=2, encoding="utf-8",
            )
            os.chmod(path, 0o600)
            try:
                # Write enough to trigger rotation
                record = logging.LogRecord(
                    "test", logging.INFO, "", 0,
                    "x" * 60, (), None,
                )
                handler.emit(record)
                handler.emit(record)

                # Check base file permissions
                mode = stat.S_IMODE(os.stat(path).st_mode)
                self.assertEqual(mode, 0o600)

                # Check rotated file permissions
                rotated = path + ".1"
                if os.path.exists(rotated):
                    mode = stat.S_IMODE(os.stat(rotated).st_mode)
                    self.assertEqual(mode, 0o600)
            finally:
                handler.close()


    def test_new_file_created_with_secure_permissions(self):
        """File should be 0o600 from creation — no race window."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "fresh.log")
            self.assertFalse(os.path.exists(path))
            handler = SecureRotatingFileHandler(
                path, maxBytes=1024, backupCount=1, encoding="utf-8",
            )
            try:
                # File should exist with secure permissions immediately
                self.assertTrue(os.path.exists(path))
                mode = stat.S_IMODE(os.stat(path).st_mode)
                self.assertEqual(mode, 0o600)
            finally:
                handler.close()


class TestExportLogs(unittest.TestCase):
    def test_export_missing_file(self):
        config = Config(logging_config=LoggingConfig(log_dir="/nonexistent/path"))
        result = export_logs(config)
        self.assertEqual(result, 1)

    def test_export_reads_current_log(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "lumen-argus.log")
            with open(log_file, "w") as f:
                f.write("line1\nline2\n")
            config = Config(logging_config=LoggingConfig(log_dir=tmpdir))

            # Capture stdout
            import io
            from unittest.mock import patch
            buf = io.StringIO()
            with patch("sys.stdout", buf):
                result = export_logs(config)

            self.assertEqual(result, 0)
            self.assertEqual(buf.getvalue(), "line1\nline2\n")

    def test_export_reads_rotated_files_in_order(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "lumen-argus.log")
            with open(log_file, "w") as f:
                f.write("current\n")
            with open(log_file + ".1", "w") as f:
                f.write("previous\n")
            with open(log_file + ".2", "w") as f:
                f.write("oldest\n")

            config = Config(logging_config=LoggingConfig(log_dir=tmpdir, backup_count=5))

            import io
            from unittest.mock import patch
            buf = io.StringIO()
            with patch("sys.stdout", buf):
                export_logs(config)

            output = buf.getvalue()
            # Oldest first, then previous, then current
            oldest_pos = output.index("oldest")
            previous_pos = output.index("previous")
            current_pos = output.index("current")
            self.assertLess(oldest_pos, previous_pos)
            self.assertLess(previous_pos, current_pos)

    def test_export_sanitize(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "lumen-argus.log")
            with open(log_file, "w") as f:
                f.write("connection from 192.168.1.1 to api.anthropic.com\n")

            config = Config(logging_config=LoggingConfig(log_dir=tmpdir))

            import io
            from unittest.mock import patch
            buf = io.StringIO()
            with patch("sys.stdout", buf):
                export_logs(config, sanitize=True)

            output = buf.getvalue()
            self.assertNotIn("192.168.1.1", output)
            self.assertIn("api.anthropic.com", output)


if __name__ == "__main__":
    unittest.main()
