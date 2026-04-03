"""Tests for agent enrollment and heartbeat — community side.

Tests that the agent CLI handles enrollment gracefully:
- Enrollment state management (save, load, delete, permissions)
- CLI error handling (not enrolled, no server, unreachable server)
- Enrollment config YAML parsing (defaults, custom values, minimum intervals)
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from unittest.mock import patch

from lumen_argus_core.enrollment import (
    _save_enrollment,
    is_enrolled,
    load_enrollment,
    unenroll,
)


class TestEnrollmentState(unittest.TestCase):
    """Test enrollment state file management."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.enrollment_file = os.path.join(self.tmpdir, "enrollment.json")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_not_enrolled_by_default(self):
        with patch("lumen_argus_core.enrollment._ENROLLMENT_FILE", self.enrollment_file):
            self.assertFalse(is_enrolled())
            self.assertIsNone(load_enrollment())

    def test_save_and_load(self):
        state = {
            "server": "https://argus.corp.io",
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "organization": "Acme Corp",
            "policy": {"fail_mode": "closed"},
            "enrolled_at": "2026-04-02T10:30:00Z",
            "agent_id": "agent_abc123",
            "machine_id": "mac_def456",
        }
        with (
            patch("lumen_argus_core.enrollment._ENROLLMENT_FILE", self.enrollment_file),
            patch("lumen_argus_core.enrollment._ARGUS_DIR", self.tmpdir),
        ):
            _save_enrollment(state)
            self.assertTrue(is_enrolled())
            loaded = load_enrollment()
            self.assertEqual(loaded["server"], "https://argus.corp.io")
            self.assertEqual(loaded["organization"], "Acme Corp")
            self.assertEqual(loaded["policy"]["fail_mode"], "closed")

    def test_file_permissions(self):
        state = {"server": "https://test.io", "agent_id": "a", "machine_id": "m", "enrolled_at": "now"}
        with (
            patch("lumen_argus_core.enrollment._ENROLLMENT_FILE", self.enrollment_file),
            patch("lumen_argus_core.enrollment._ARGUS_DIR", self.tmpdir),
        ):
            _save_enrollment(state)
            mode = os.stat(self.enrollment_file).st_mode & 0o777
            self.assertEqual(mode, 0o600, "enrollment.json must have 0600 permissions")

    def test_unenroll_when_not_enrolled(self):
        with patch("lumen_argus_core.enrollment._ENROLLMENT_FILE", self.enrollment_file):
            self.assertFalse(unenroll())

    def test_unenroll_removes_file(self):
        state = {"server": "https://test.io", "agent_id": "a", "machine_id": "m", "enrolled_at": "now"}
        with (
            patch("lumen_argus_core.enrollment._ENROLLMENT_FILE", self.enrollment_file),
            patch("lumen_argus_core.enrollment._ARGUS_DIR", self.tmpdir),
            patch("lumen_argus_core.enrollment._CA_CERT_FILE", os.path.join(self.tmpdir, "ca.pem")),
            patch("lumen_argus_core.enrollment.deregister_agent"),
        ):
            _save_enrollment(state)
            self.assertTrue(is_enrolled())
            self.assertTrue(unenroll())
            self.assertFalse(is_enrolled())
            self.assertFalse(os.path.exists(self.enrollment_file))

    def test_load_corrupted_file(self):
        with open(self.enrollment_file, "w") as f:
            f.write("not json")
        with patch("lumen_argus_core.enrollment._ENROLLMENT_FILE", self.enrollment_file):
            self.assertIsNone(load_enrollment())


class TestAgentCLIEnrollment(unittest.TestCase):
    """Test agent CLI enrollment commands via subprocess."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run(self, *args):
        env = {**os.environ, "HOME": self.tmpdir, "USERPROFILE": self.tmpdir}
        return subprocess.run(
            [sys.executable, "-m", "lumen_argus_agent", *args],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )

    def test_heartbeat_not_enrolled(self):
        result = self._run("heartbeat")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Not enrolled", result.stderr)

    def test_enroll_no_server(self):
        result = self._run("enroll", "--non-interactive")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--server", result.stderr)

    def test_unenroll_when_not_enrolled(self):
        result = self._run("enroll", "--undo")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Not currently enrolled", result.stdout)

    def test_enroll_unreachable_server(self):
        result = self._run("enroll", "--server", "http://127.0.0.1:1", "--non-interactive")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed", result.stderr.lower())


class TestHeartbeat(unittest.TestCase):
    """Test heartbeat telemetry logic."""

    @staticmethod
    def _mock_urlopen_response(body: bytes = b"{}"):
        """Create a mock urlopen return value that works as context manager."""
        resp = unittest.mock.MagicMock()
        resp.__enter__ = lambda s: resp
        resp.__exit__ = lambda s, *a: None
        resp.read.return_value = body
        return resp

    def test_heartbeat_not_enrolled_returns_false(self):
        from lumen_argus_core.telemetry import send_heartbeat

        with patch("lumen_argus_core.telemetry.load_enrollment", return_value=None):
            self.assertFalse(send_heartbeat())

    def test_heartbeat_sends_correct_payload(self):
        from lumen_argus_core.telemetry import send_heartbeat

        enrollment = {
            "server": "https://argus.corp.io",
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "agent_id": "agent_test123",
            "enrolled_at": "2026-04-02T10:30:00Z",
        }

        mock_report = unittest.mock.MagicMock()
        mock_report.clients = []

        mock_resp = self._mock_urlopen_response()

        with (
            patch("lumen_argus_core.telemetry.load_enrollment", return_value=enrollment),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report),
            patch("lumen_argus_core.setup_wizard.protection_status", return_value={"enabled": True}),
            patch("lumen_argus_core.telemetry.urllib.request.urlopen", return_value=mock_resp) as mock_urlopen,
        ):
            result = send_heartbeat()
            self.assertTrue(result)
            req = mock_urlopen.call_args[0][0]
            self.assertIn("/api/v1/enrollment/heartbeat", req.full_url)
            import json

            payload = json.loads(req.data)
            self.assertEqual(payload["agent_id"], "agent_test123")
            self.assertTrue(payload["protection_enabled"])
            self.assertIn("heartbeat_at", payload)

    def test_heartbeat_payload_includes_tool_detail(self):
        """Heartbeat tools array includes display_name, install_method, proxy_config_type."""
        from lumen_argus_core.detect import DetectedClient
        from lumen_argus_core.telemetry import send_heartbeat

        client = DetectedClient(
            client_id="claude",
            display_name="Claude Code",
            installed=True,
            version="1.2.0",
            install_method="binary",
            proxy_configured=True,
            routing_active=True,
            proxy_config_type="env_var",
        )

        enrollment = {
            "server": "https://argus.corp.io",
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "agent_id": "agent_test123",
            "enrolled_at": "2026-04-02T10:30:00Z",
        }

        mock_report = unittest.mock.MagicMock()
        mock_report.clients = [client]
        mock_resp = self._mock_urlopen_response()

        with (
            patch("lumen_argus_core.telemetry.load_enrollment", return_value=enrollment),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report),
            patch("lumen_argus_core.setup_wizard.protection_status", return_value={"enabled": True}),
            patch("lumen_argus_core.telemetry.urllib.request.urlopen", return_value=mock_resp) as mock_urlopen,
        ):
            send_heartbeat()
            import json

            payload = json.loads(mock_urlopen.call_args[0][0].data)
            self.assertEqual(len(payload["tools"]), 1)
            tool = payload["tools"][0]
            self.assertEqual(tool["client_id"], "claude")
            self.assertEqual(tool["display_name"], "Claude Code")
            self.assertEqual(tool["install_method"], "binary")
            self.assertEqual(tool["proxy_config_type"], "env_var")

    def test_heartbeat_empty_string_urls_fall_back_to_server(self):
        """Empty string proxy_url/dashboard_url should fall back to server."""
        from lumen_argus_core.telemetry import send_heartbeat

        enrollment = {
            "server": "https://argus.corp.io",
            "proxy_url": "",
            "dashboard_url": "",
            "agent_id": "agent_test123",
            "enrolled_at": "2026-04-02T10:30:00Z",
        }

        mock_report = unittest.mock.MagicMock()
        mock_report.clients = []
        mock_resp = self._mock_urlopen_response()

        with (
            patch("lumen_argus_core.telemetry.load_enrollment", return_value=enrollment),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report) as mock_detect,
            patch("lumen_argus_core.setup_wizard.protection_status", return_value={"enabled": True}),
            patch("lumen_argus_core.telemetry.urllib.request.urlopen", return_value=mock_resp) as mock_urlopen,
        ):
            result = send_heartbeat()
            self.assertTrue(result)
            mock_detect.assert_called_once_with(proxy_url="https://argus.corp.io")
            req = mock_urlopen.call_args[0][0]
            self.assertEqual(
                req.full_url,
                "https://argus.corp.io/api/v1/enrollment/heartbeat",
            )

    def test_heartbeat_handles_http_error(self):
        from lumen_argus_core.telemetry import send_heartbeat

        enrollment = {
            "server": "https://argus.corp.io",
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "agent_id": "agent_test123",
            "enrolled_at": "2026-04-02T10:30:00Z",
        }

        mock_report = unittest.mock.MagicMock()
        mock_report.clients = []

        import urllib.error

        with (
            patch("lumen_argus_core.telemetry.load_enrollment", return_value=enrollment),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report),
            patch("lumen_argus_core.setup_wizard.protection_status", return_value={"enabled": False}),
            patch(
                "lumen_argus_core.telemetry.urllib.request.urlopen",
                side_effect=urllib.error.HTTPError(None, 500, "Server Error", {}, None),
            ),
        ):
            self.assertFalse(send_heartbeat())

    def test_heartbeat_sends_auth_header_when_token_present(self):
        """Heartbeat includes Authorization header when agent_token is in enrollment."""
        from lumen_argus_core.telemetry import send_heartbeat

        enrollment = {
            "server": "https://argus.corp.io",
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "agent_id": "agent_test123",
            "enrolled_at": "2026-04-02T10:30:00Z",
            "agent_token": "la_agent_testtoken123456",
        }

        mock_report = unittest.mock.MagicMock()
        mock_report.clients = []
        mock_resp = self._mock_urlopen_response()

        with (
            patch("lumen_argus_core.telemetry.load_enrollment", return_value=enrollment),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report),
            patch("lumen_argus_core.setup_wizard.protection_status", return_value={"enabled": True}),
            patch("lumen_argus_core.telemetry.urllib.request.urlopen", return_value=mock_resp) as mock_urlopen,
        ):
            send_heartbeat()
            req = mock_urlopen.call_args[0][0]
            self.assertEqual(req.get_header("Authorization"), "Bearer la_agent_testtoken123456")

    def test_heartbeat_no_auth_header_without_token(self):
        """Heartbeat omits Authorization header when no agent_token."""
        from lumen_argus_core.telemetry import send_heartbeat

        enrollment = {
            "server": "https://argus.corp.io",
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "agent_id": "agent_test123",
            "enrolled_at": "2026-04-02T10:30:00Z",
        }

        mock_report = unittest.mock.MagicMock()
        mock_report.clients = []
        mock_resp = self._mock_urlopen_response()

        with (
            patch("lumen_argus_core.telemetry.load_enrollment", return_value=enrollment),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report),
            patch("lumen_argus_core.setup_wizard.protection_status", return_value={"enabled": True}),
            patch("lumen_argus_core.telemetry.urllib.request.urlopen", return_value=mock_resp) as mock_urlopen,
        ):
            send_heartbeat()
            req = mock_urlopen.call_args[0][0]
            self.assertIsNone(req.get_header("Authorization"))

    def test_heartbeat_rotates_token_from_response(self):
        """Heartbeat updates enrollment.json when proxy returns new_token."""
        from lumen_argus_core.telemetry import send_heartbeat

        enrollment = {
            "server": "https://argus.corp.io",
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "agent_id": "agent_test123",
            "enrolled_at": "2026-04-02T10:30:00Z",
            "agent_token": "la_agent_oldtoken",
        }

        mock_report = unittest.mock.MagicMock()
        mock_report.clients = []
        mock_resp = self._mock_urlopen_response(b'{"new_token": "la_agent_newtoken"}')

        with (
            patch("lumen_argus_core.telemetry.load_enrollment", return_value=enrollment),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report),
            patch("lumen_argus_core.setup_wizard.protection_status", return_value={"enabled": True}),
            patch("lumen_argus_core.telemetry.urllib.request.urlopen", return_value=mock_resp),
            patch("lumen_argus_core.telemetry.update_agent_token") as mock_rotate,
        ):
            send_heartbeat()
            mock_rotate.assert_called_once_with("la_agent_newtoken")


class TestEnrollCA(unittest.TestCase):
    """Test CA certificate handling during enrollment."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_enroll_saves_ca_cert(self):
        from lumen_argus_core.enrollment import enroll

        ca_pem = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----"
        config_response = {
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "organization": "Test Corp",
            "policy": {},
            "ca_cert": ca_pem,
        }
        ca_cert_path = os.path.join(self.tmpdir, "ca.pem")

        with (
            patch("lumen_argus_core.enrollment.fetch_enrollment_config", return_value=config_response),
            patch("lumen_argus_core.enrollment.register_agent", return_value={}),
            patch("lumen_argus_core.enrollment._ENROLLMENT_FILE", os.path.join(self.tmpdir, "enrollment.json")),
            patch("lumen_argus_core.enrollment._ARGUS_DIR", self.tmpdir),
            patch("lumen_argus_core.enrollment._CA_CERT_FILE", ca_cert_path),
        ):
            state = enroll("https://argus.corp.io")
            self.assertEqual(state["organization"], "Test Corp")
            # Verify CA cert was written
            self.assertTrue(os.path.isfile(ca_cert_path))
            with open(ca_cert_path) as f:
                self.assertEqual(f.read(), ca_pem)
            # Verify permissions
            mode = os.stat(ca_cert_path).st_mode & 0o777
            self.assertEqual(mode, 0o600)

    def test_enroll_without_ca_cert(self):
        from lumen_argus_core.enrollment import enroll

        config_response = {
            "proxy_url": "https://argus.corp.io:8080",
            "organization": "No Cert Corp",
            "policy": {},
        }
        ca_cert_path = os.path.join(self.tmpdir, "ca.pem")

        with (
            patch("lumen_argus_core.enrollment.fetch_enrollment_config", return_value=config_response),
            patch("lumen_argus_core.enrollment.register_agent", return_value={}),
            patch("lumen_argus_core.enrollment._ENROLLMENT_FILE", os.path.join(self.tmpdir, "enrollment.json")),
            patch("lumen_argus_core.enrollment._ARGUS_DIR", self.tmpdir),
            patch("lumen_argus_core.enrollment._CA_CERT_FILE", ca_cert_path),
        ):
            enroll("https://argus.corp.io")
            self.assertFalse(os.path.exists(ca_cert_path))


class TestEnrollmentConfig(unittest.TestCase):
    """Test that enrollment config loads correctly from YAML."""

    def test_default_enrollment_config(self):
        from lumen_argus.config import load_config

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            with open(cfg_path, "w") as f:
                f.write("")
            config = load_config(config_path=cfg_path)
            self.assertEqual(config.enrollment.organization, "")
            self.assertEqual(config.enrollment.proxy_url, "")
            self.assertEqual(config.enrollment.policy.fail_mode, "open")
            self.assertTrue(config.enrollment.policy.auto_configure)
            self.assertTrue(config.enrollment.policy.allow_disable_protection)
            self.assertEqual(config.enrollment.policy.telemetry_interval_seconds, 300)
            self.assertEqual(config.enrollment.policy.watch_interval_seconds, 300)

    def test_enrollment_config_from_yaml(self):
        from lumen_argus.config import load_config

        yaml_content = """
enrollment:
  organization: "Test Corp"
  proxy_url: "https://proxy.test.io:8080"
  policy:
    fail_mode: closed
    auto_configure: false
    allow_disable_protection: false
    telemetry_interval_seconds: 600
    watch_interval_seconds: 120
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            with open(cfg_path, "w") as f:
                f.write(yaml_content)
            config = load_config(config_path=cfg_path)
            self.assertEqual(config.enrollment.organization, "Test Corp")
            self.assertEqual(config.enrollment.proxy_url, "https://proxy.test.io:8080")
            self.assertEqual(config.enrollment.policy.fail_mode, "closed")
            self.assertFalse(config.enrollment.policy.auto_configure)
            self.assertFalse(config.enrollment.policy.allow_disable_protection)
            self.assertEqual(config.enrollment.policy.telemetry_interval_seconds, 600)
            self.assertEqual(config.enrollment.policy.watch_interval_seconds, 120)

    def test_enrollment_interval_minimum(self):
        from lumen_argus.config import load_config

        yaml_content = """
enrollment:
  policy:
    telemetry_interval_seconds: 10
    watch_interval_seconds: 5
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            with open(cfg_path, "w") as f:
                f.write(yaml_content)
            config = load_config(config_path=cfg_path)
            self.assertEqual(config.enrollment.policy.telemetry_interval_seconds, 60, "minimum 60s enforced")
            self.assertEqual(config.enrollment.policy.watch_interval_seconds, 60, "minimum 60s enforced")


if __name__ == "__main__":
    unittest.main()
