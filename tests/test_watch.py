"""Tests for the watch daemon — background tool detection and service management."""

import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from lumen_argus_core.watch import (
    WatchState,
    generate_launchd_plist,
    generate_systemd_unit,
    get_service_status,
    install_service,
    scan_once,
    uninstall_service,
)


class TestWatchState(unittest.TestCase):
    """Test watch state persistence."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_file = os.path.join(self.tmpdir, "state.json")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_default_state(self):
        state = WatchState()
        self.assertEqual(state.known_clients, {})
        self.assertEqual(state.last_scan, "")
        self.assertEqual(state.proxy_url, "http://localhost:8080")

    def test_save_and_load(self):
        state = WatchState(
            known_clients={"aider": "binary", "copilot": "vscode_ext"},
            last_scan="2026-03-28T10:00:00Z",
        )
        with (
            patch("lumen_argus_core.watch._STATE_DIR", self.tmpdir),
            patch("lumen_argus_core.watch._STATE_FILE", self.state_file),
        ):
            from lumen_argus_core.watch import _load_state, _save_state

            _save_state(state)
            loaded = _load_state()
        self.assertEqual(loaded.known_clients, {"aider": "binary", "copilot": "vscode_ext"})
        self.assertEqual(loaded.last_scan, "2026-03-28T10:00:00Z")

    def test_load_missing_file(self):
        with patch("lumen_argus_core.watch._STATE_FILE", "/nonexistent/state.json"):
            from lumen_argus_core.watch import _load_state

            state = _load_state()
        self.assertEqual(state.known_clients, {})

    def test_load_corrupt_file(self):
        with open(self.state_file, "w") as f:
            f.write("not json")
        with patch("lumen_argus_core.watch._STATE_FILE", self.state_file):
            from lumen_argus_core.watch import _load_state

            state = _load_state()
        self.assertEqual(state.known_clients, {})


class TestScanOnce(unittest.TestCase):
    """Test single detection pass."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_file = os.path.join(self.tmpdir, "state.json")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_detects_new_tools(self):
        """First scan should report all installed tools as new."""
        mock_client = MagicMock()
        mock_client.installed = True
        mock_client.client_id = "aider"
        mock_client.install_method = "binary"
        mock_client.proxy_configured = False

        mock_report = MagicMock()
        mock_report.clients = [mock_client]

        with (
            patch("lumen_argus_core.watch._STATE_DIR", self.tmpdir),
            patch("lumen_argus_core.watch._STATE_FILE", self.state_file),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report),
        ):
            new_ids = scan_once(proxy_url="http://localhost:8080")
        self.assertEqual(new_ids, ["aider"])

    def test_no_new_tools_on_second_scan(self):
        """Second scan with same tools should report nothing new."""
        mock_client = MagicMock()
        mock_client.installed = True
        mock_client.client_id = "aider"
        mock_client.install_method = "binary"

        mock_report = MagicMock()
        mock_report.clients = [mock_client]

        with (
            patch("lumen_argus_core.watch._STATE_DIR", self.tmpdir),
            patch("lumen_argus_core.watch._STATE_FILE", self.state_file),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report),
        ):
            scan_once(proxy_url="http://localhost:8080")
            new_ids = scan_once(proxy_url="http://localhost:8080")
        self.assertEqual(new_ids, [])

    def test_auto_configure_calls_setup(self):
        """auto_configure=True should call run_setup for new tools."""
        mock_client = MagicMock()
        mock_client.installed = True
        mock_client.client_id = "aider"
        mock_client.install_method = "binary"

        mock_report = MagicMock()
        mock_report.clients = [mock_client]

        with (
            patch("lumen_argus_core.watch._STATE_DIR", self.tmpdir),
            patch("lumen_argus_core.watch._STATE_FILE", self.state_file),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report),
            patch("lumen_argus_core.setup_wizard.run_setup") as mock_setup,
        ):
            scan_once(proxy_url="http://localhost:8080", auto_configure=True)
        mock_setup.assert_called_once_with(
            proxy_url="http://localhost:8080",
            client_id="aider",
            non_interactive=True,
            dry_run=False,
        )


class TestServiceGeneration(unittest.TestCase):
    """Test launchd plist and systemd unit generation."""

    def test_launchd_plist_content(self):
        plist = generate_launchd_plist(proxy_url="http://localhost:9090", interval=600)
        self.assertIn("io.lumen-argus.watch", plist)
        self.assertIn("http://localhost:9090", plist)
        self.assertIn("<true/>", plist)  # RunAtLoad
        self.assertIn("watch.log", plist)

    def test_launchd_plist_auto_configure(self):
        plist = generate_launchd_plist(auto_configure=True)
        self.assertIn("--auto-configure", plist)

    def test_systemd_unit_content(self):
        unit = generate_systemd_unit(proxy_url="http://localhost:9090", interval=600)
        self.assertIn("lumen-argus", unit)
        self.assertIn("http://localhost:9090", unit)
        self.assertIn("[Service]", unit)
        self.assertIn("Restart=on-failure", unit)
        self.assertIn("default.target", unit)

    def test_systemd_unit_auto_configure(self):
        unit = generate_systemd_unit(auto_configure=True)
        self.assertIn("--auto-configure", unit)


class TestServiceInstall(unittest.TestCase):
    """Test service install/uninstall/status."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @patch("platform.system", return_value="Darwin")
    def test_install_macos(self, _):
        plist_path = os.path.join(self.tmpdir, "io.lumen-argus.watch.plist")
        with (
            patch("lumen_argus_core.watch._LAUNCHD_PLIST_DIR", self.tmpdir),
            patch("lumen_argus_core.watch._LAUNCHD_PLIST_PATH", plist_path),
        ):
            path = install_service()
        self.assertEqual(path, plist_path)
        self.assertTrue(os.path.isfile(plist_path))

    @patch("platform.system", return_value="Linux")
    def test_install_linux(self, _):
        unit_path = os.path.join(self.tmpdir, "lumen-argus-watch.service")
        with (
            patch("lumen_argus_core.watch._SYSTEMD_UNIT_DIR", self.tmpdir),
            patch("lumen_argus_core.watch._SYSTEMD_SERVICE_PATH", unit_path),
        ):
            path = install_service()
        self.assertEqual(path, unit_path)
        self.assertTrue(os.path.isfile(unit_path))

    @patch("platform.system", return_value="Darwin")
    def test_uninstall_macos(self, _):
        plist_path = os.path.join(self.tmpdir, "io.lumen-argus.watch.plist")
        with open(plist_path, "w") as f:
            f.write("<plist/>")
        with patch("lumen_argus_core.watch._LAUNCHD_PLIST_PATH", plist_path):
            result = uninstall_service()
        self.assertTrue(result)
        self.assertFalse(os.path.exists(plist_path))

    @patch("platform.system", return_value="Darwin")
    def test_uninstall_not_installed(self, _):
        with patch("lumen_argus_core.watch._LAUNCHD_PLIST_PATH", os.path.join(self.tmpdir, "nope.plist")):
            result = uninstall_service()
        self.assertFalse(result)

    def test_status_not_installed(self):
        with (
            patch("lumen_argus_core.watch._LAUNCHD_PLIST_PATH", "/nonexistent"),
            patch("lumen_argus_core.watch._SYSTEMD_SERVICE_PATH", "/nonexistent"),
            patch("lumen_argus_core.watch._STATE_FILE", "/nonexistent"),
        ):
            status = get_service_status()
        self.assertEqual(status["installed"], "false")
        self.assertEqual(status["last_scan"], "")


if __name__ == "__main__":
    unittest.main()
