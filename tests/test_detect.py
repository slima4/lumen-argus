"""Tests for the client detection engine."""

import json
import os
import platform
import shutil
import tempfile
import unittest
from unittest.mock import patch

from lumen_argus.clients import CLIENT_REGISTRY, ClientDef
from lumen_argus.detect import (
    DetectedClient,
    DetectionReport,
    IDEVariant,
    InstallMethod,
    _extract_env_value,
    _scan_binary,
    _scan_brew_package,
    _scan_neovim_plugin,
    _scan_npm_package,
    _scan_shell_profiles,
    _scan_vscode_extension,
    detect_installed_clients,
)


class TestExtractEnvValue(unittest.TestCase):
    """Test shell env var extraction from profile lines."""

    def test_export_unquoted(self):
        self.assertEqual(
            _extract_env_value("export OPENAI_BASE_URL=http://localhost:8080", "OPENAI_BASE_URL"),
            "http://localhost:8080",
        )

    def test_export_double_quoted(self):
        self.assertEqual(
            _extract_env_value('export OPENAI_BASE_URL="http://localhost:8080"', "OPENAI_BASE_URL"),
            "http://localhost:8080",
        )

    def test_no_export(self):
        self.assertEqual(
            _extract_env_value("OPENAI_BASE_URL=http://localhost:8080", "OPENAI_BASE_URL"), "http://localhost:8080"
        )

    def test_fish_set(self):
        self.assertEqual(
            _extract_env_value("set -x OPENAI_BASE_URL http://localhost:8080", "OPENAI_BASE_URL"),
            "http://localhost:8080",
        )

    def test_no_match(self):
        self.assertEqual(_extract_env_value("export PATH=/usr/bin", "OPENAI_BASE_URL"), "")

    def test_with_comment(self):
        val = _extract_env_value("export OPENAI_BASE_URL=http://localhost:8080 # proxy", "OPENAI_BASE_URL")
        self.assertEqual(val, "http://localhost:8080")


class TestScanBinary(unittest.TestCase):
    """Test binary detection via shutil.which."""

    def test_found(self):
        client = ClientDef(
            id="test_tool",
            display_name="Test",
            category="cli",
            provider="openai",
            ua_prefixes=("test/",),
            env_var="OPENAI_BASE_URL",
            setup_cmd="test",
            website="https://test.com",
            detect_binary=("python3",),
        )
        result = _scan_binary(client)
        self.assertIsNotNone(result)
        self.assertTrue(result.installed)
        self.assertEqual(result.install_method, InstallMethod.BINARY)
        self.assertTrue(result.install_path)

    def test_not_found(self):
        client = ClientDef(
            id="test_tool",
            display_name="Test",
            category="cli",
            provider="openai",
            ua_prefixes=("test/",),
            env_var="OPENAI_BASE_URL",
            setup_cmd="test",
            website="https://test.com",
            detect_binary=("nonexistent_binary_12345",),
        )
        result = _scan_binary(client)
        self.assertIsNone(result)

    def test_empty_binary(self):
        client = ClientDef(
            id="test_tool",
            display_name="Test",
            category="cli",
            provider="openai",
            ua_prefixes=("test/",),
            env_var="OPENAI_BASE_URL",
            setup_cmd="test",
            website="https://test.com",
        )
        result = _scan_binary(client)
        self.assertIsNone(result)


class TestScanVSCodeExtension(unittest.TestCase):
    """Test VS Code extension detection with mock filesystem."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_extension_found(self):
        ext_dir = os.path.join(self.tmpdir, "extensions")
        os.makedirs(os.path.join(ext_dir, "github.copilot-1.200.0"))

        client = ClientDef(
            id="copilot",
            display_name="GitHub Copilot",
            category="ide",
            provider="openai",
            ua_prefixes=("copilot/",),
            env_var="OPENAI_BASE_URL",
            setup_cmd="test",
            website="https://test.com",
            detect_vscode_ext="github.copilot",
        )
        with patch(
            "lumen_argus.detect._VSCODE_VARIANTS", (IDEVariant(name="Test", extensions=(ext_dir,), settings=()),)
        ):
            result = _scan_vscode_extension(client)
        self.assertIsNotNone(result)
        self.assertEqual(result.version, "1.200.0")
        self.assertEqual(result.install_method, InstallMethod.VSCODE_EXT)

    def test_extension_not_found(self):
        ext_dir = os.path.join(self.tmpdir, "extensions")
        os.makedirs(ext_dir)

        client = ClientDef(
            id="copilot",
            display_name="GitHub Copilot",
            category="ide",
            provider="openai",
            ua_prefixes=("copilot/",),
            env_var="OPENAI_BASE_URL",
            setup_cmd="test",
            website="https://test.com",
            detect_vscode_ext="github.copilot",
        )
        with patch(
            "lumen_argus.detect._VSCODE_VARIANTS", (IDEVariant(name="Test", extensions=(ext_dir,), settings=()),)
        ):
            result = _scan_vscode_extension(client)
        self.assertIsNone(result)

    def test_multiple_versions_picks_latest(self):
        ext_dir = os.path.join(self.tmpdir, "extensions")
        os.makedirs(os.path.join(ext_dir, "github.copilot-1.100.0"))
        os.makedirs(os.path.join(ext_dir, "github.copilot-1.200.0"))

        client = ClientDef(
            id="copilot",
            display_name="GitHub Copilot",
            category="ide",
            provider="openai",
            ua_prefixes=("copilot/",),
            env_var="OPENAI_BASE_URL",
            setup_cmd="test",
            website="https://test.com",
            detect_vscode_ext="github.copilot",
        )
        with patch(
            "lumen_argus.detect._VSCODE_VARIANTS", (IDEVariant(name="Test", extensions=(ext_dir,), settings=()),)
        ):
            result = _scan_vscode_extension(client)
        self.assertEqual(result.version, "1.200.0")


class TestScanShellProfiles(unittest.TestCase):
    """Test shell profile scanning with mock files."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.zshrc = os.path.join(self.tmpdir, ".zshrc")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_finds_env_var(self):
        with open(self.zshrc, "w") as f:
            f.write("# shell config\nexport OPENAI_BASE_URL=http://localhost:8080\n")
        mock_profiles = {"zsh": (self.zshrc,)}
        with patch("lumen_argus.detect._SHELL_PROFILES", mock_profiles):
            with patch.dict(os.environ, {"SHELL": "/bin/zsh"}):
                result = _scan_shell_profiles("http://localhost:8080")
        self.assertIn("OPENAI_BASE_URL", result)
        self.assertEqual(result["OPENAI_BASE_URL"][0], "http://localhost:8080")

    def test_skips_comments(self):
        with open(self.zshrc, "w") as f:
            f.write("# export OPENAI_BASE_URL=http://localhost:8080\n")
        mock_profiles = {"zsh": (self.zshrc,)}
        with patch("lumen_argus.detect._SHELL_PROFILES", mock_profiles):
            with patch.dict(os.environ, {"SHELL": "/bin/zsh"}):
                result = _scan_shell_profiles()
        self.assertNotIn("OPENAI_BASE_URL", result)

    def test_empty_file(self):
        with open(self.zshrc, "w") as f:
            f.write("")
        mock_profiles = {"zsh": (self.zshrc,)}
        with patch("lumen_argus.detect._SHELL_PROFILES", mock_profiles):
            with patch.dict(os.environ, {"SHELL": "/bin/zsh"}):
                result = _scan_shell_profiles()
        self.assertEqual(len(result), 0)


class TestScanNpmPackage(unittest.TestCase):
    """Test npm global package detection with mock filesystem."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_package_found(self):
        client = ClientDef(
            id="codex_cli",
            display_name="Codex CLI",
            category="cli",
            provider="openai",
            ua_prefixes=("codex/",),
            env_var="OPENAI_BASE_URL",
            setup_cmd="test",
            website="https://test.com",
            detect_npm="@openai/codex",
        )
        # NPM_CONFIG_PREFIX/lib/node_modules is where npm installs globals
        lib_dir = os.path.join(self.tmpdir, "lib", "node_modules", "@openai", "codex")
        os.makedirs(lib_dir)
        with open(os.path.join(lib_dir, "package.json"), "w") as f:
            json.dump({"name": "@openai/codex", "version": "0.1.0"}, f)

        with patch.dict(os.environ, {"NPM_CONFIG_PREFIX": self.tmpdir}):
            result = _scan_npm_package(client)
        self.assertIsNotNone(result)
        self.assertEqual(result.version, "0.1.0")
        self.assertEqual(result.install_method, InstallMethod.NPM)

    def test_package_not_found(self):
        client = ClientDef(
            id="codex_cli",
            display_name="Codex CLI",
            category="cli",
            provider="openai",
            ua_prefixes=("codex/",),
            env_var="OPENAI_BASE_URL",
            setup_cmd="test",
            website="https://test.com",
            detect_npm="@openai/codex",
        )
        with patch.dict(os.environ, {"NPM_CONFIG_PREFIX": self.tmpdir}):
            result = _scan_npm_package(client)
        self.assertIsNone(result)

    def test_no_detect_npm(self):
        client = ClientDef(
            id="test",
            display_name="Test",
            category="cli",
            provider="openai",
            ua_prefixes=("test/",),
            env_var="OPENAI_BASE_URL",
            setup_cmd="test",
            website="https://test.com",
        )
        result = _scan_npm_package(client)
        self.assertIsNone(result)


class TestScanBrewPackage(unittest.TestCase):
    """Test homebrew formula detection with mock filesystem."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @unittest.skipUnless(platform.system() == "Darwin", "macOS only")
    def test_formula_found(self):
        cellar = os.path.join(self.tmpdir, "Cellar")
        os.makedirs(os.path.join(cellar, "aider", "0.50.1"))

        client = ClientDef(
            id="aider",
            display_name="Aider",
            category="cli",
            provider="multi",
            ua_prefixes=("aider/",),
            env_var="OPENAI_BASE_URL",
            setup_cmd="test",
            website="https://test.com",
            detect_brew="aider",
        )
        with patch("lumen_argus.detect._BREW_CELLAR_PATHS", [cellar]):
            result = _scan_brew_package(client)
        self.assertIsNotNone(result)
        self.assertEqual(result.version, "0.50.1")
        self.assertEqual(result.install_method, InstallMethod.BREW)

    def test_skips_non_darwin(self):
        client = ClientDef(
            id="aider",
            display_name="Aider",
            category="cli",
            provider="multi",
            ua_prefixes=("aider/",),
            env_var="OPENAI_BASE_URL",
            setup_cmd="test",
            website="https://test.com",
            detect_brew="aider",
        )
        with patch("platform.system", return_value="Linux"):
            result = _scan_brew_package(client)
        self.assertIsNone(result)

    def test_no_detect_brew(self):
        client = ClientDef(
            id="test",
            display_name="Test",
            category="cli",
            provider="openai",
            ua_prefixes=("test/",),
            env_var="OPENAI_BASE_URL",
            setup_cmd="test",
            website="https://test.com",
        )
        result = _scan_brew_package(client)
        self.assertIsNone(result)


class TestScanNeovimPlugin(unittest.TestCase):
    """Test Neovim plugin detection with mock filesystem."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_lazy_nvim_plugin_found(self):
        lazy_dir = os.path.join(self.tmpdir, "lazy")
        os.makedirs(os.path.join(lazy_dir, "copilot.vim"))

        client = ClientDef(
            id="copilot",
            display_name="GitHub Copilot",
            category="ide",
            provider="openai",
            ua_prefixes=("copilot/",),
            env_var="OPENAI_BASE_URL",
            setup_cmd="test",
            website="https://test.com",
            detect_neovim_plugin="copilot.vim",
        )
        with patch("lumen_argus.detect._NEOVIM_PLUGIN_DIRS", [lazy_dir]):
            result = _scan_neovim_plugin(client)
        self.assertIsNotNone(result)
        self.assertEqual(result.install_method, InstallMethod.NEOVIM_PLUGIN)
        self.assertIn("copilot.vim", result.install_path)

    def test_plugin_not_found(self):
        lazy_dir = os.path.join(self.tmpdir, "lazy")
        os.makedirs(lazy_dir)

        client = ClientDef(
            id="copilot",
            display_name="GitHub Copilot",
            category="ide",
            provider="openai",
            ua_prefixes=("copilot/",),
            env_var="OPENAI_BASE_URL",
            setup_cmd="test",
            website="https://test.com",
            detect_neovim_plugin="copilot.vim",
        )
        with patch("lumen_argus.detect._NEOVIM_PLUGIN_DIRS", [lazy_dir]):
            result = _scan_neovim_plugin(client)
        self.assertIsNone(result)

    def test_no_detect_neovim(self):
        client = ClientDef(
            id="test",
            display_name="Test",
            category="cli",
            provider="openai",
            ua_prefixes=("test/",),
            env_var="OPENAI_BASE_URL",
            setup_cmd="test",
            website="https://test.com",
        )
        result = _scan_neovim_plugin(client)
        self.assertIsNone(result)


class TestDetectInstalledClients(unittest.TestCase):
    """Test the main detection orchestrator."""

    def test_returns_report(self):
        with (
            patch("lumen_argus.detect._scan_binary", return_value=None),
            patch("lumen_argus.detect._scan_pip_package", return_value=None),
            patch("lumen_argus.detect._scan_npm_package", return_value=None),
            patch("lumen_argus.detect._scan_brew_package", return_value=None),
            patch("lumen_argus.detect._scan_vscode_extension", return_value=None),
            patch("lumen_argus.detect._scan_app_bundle", return_value=None),
            patch("lumen_argus.detect._scan_jetbrains_plugin", return_value=None),
            patch("lumen_argus.detect._scan_neovim_plugin", return_value=None),
            patch("lumen_argus.detect._scan_shell_profiles", return_value={}),
        ):
            report = detect_installed_clients()
        self.assertIsInstance(report, DetectionReport)
        self.assertEqual(len(report.clients), len(CLIENT_REGISTRY))
        self.assertEqual(report.total_detected, 0)

    def test_report_to_dict(self):
        report = DetectionReport(
            clients=[DetectedClient(client_id="test", installed=True)],
            platform="Darwin arm64",
            total_detected=1,
            total_configured=0,
        )
        d = report.to_dict()
        self.assertEqual(d["total_detected"], 1)
        self.assertEqual(len(d["clients"]), 1)

    def test_scanner_exception_handled(self):
        """Scanner exceptions are logged, not raised."""

        def bad_scanner(client):
            raise RuntimeError("scanner crash")

        with (
            patch("lumen_argus.detect._scan_binary", side_effect=bad_scanner),
            patch("lumen_argus.detect._scan_pip_package", return_value=None),
            patch("lumen_argus.detect._scan_vscode_extension", return_value=None),
            patch("lumen_argus.detect._scan_app_bundle", return_value=None),
            patch("lumen_argus.detect._scan_jetbrains_plugin", return_value=None),
            patch("lumen_argus.detect._scan_shell_profiles", return_value={}),
        ):
            report = detect_installed_clients()
        self.assertEqual(report.total_detected, 0)


class TestDetectedClientDict(unittest.TestCase):
    def test_to_dict(self):
        c = DetectedClient(client_id="aider", installed=True, version="0.50.1")
        d = c.to_dict()
        self.assertEqual(d["client_id"], "aider")
        self.assertTrue(d["installed"])


if __name__ == "__main__":
    unittest.main()
