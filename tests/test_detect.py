"""Tests for the client detection engine."""

import json
import os
import platform
import shutil
import tempfile
import unittest
from unittest.mock import patch

from lumen_argus_core.clients import CLIENT_REGISTRY, ClientDef, ProxyConfig, ProxyConfigType
from lumen_argus_core.detect import (
    DetectedClient,
    DetectionReport,
    IDEVariant,
    InstallMethod,
    _extract_env_value,
    _get_powershell_profiles,
    _get_vscode_variants,
    _scan_binary,
    _scan_brew_package,
    _scan_neovim_plugin,
    _scan_npm_package,
    _scan_shell_profiles,
    _scan_vscode_extension,
    detect_ci_environment,
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
            proxy_config=ProxyConfig(
                config_type=ProxyConfigType.ENV_VAR,
                env_var="OPENAI_BASE_URL",
                setup_cmd="test",
                setup_instructions="Set OPENAI_BASE_URL.",
            ),
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
            proxy_config=ProxyConfig(
                config_type=ProxyConfigType.ENV_VAR,
                env_var="OPENAI_BASE_URL",
                setup_cmd="test",
                setup_instructions="Set OPENAI_BASE_URL.",
            ),
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
            proxy_config=ProxyConfig(
                config_type=ProxyConfigType.ENV_VAR,
                env_var="OPENAI_BASE_URL",
                setup_cmd="test",
                setup_instructions="Set OPENAI_BASE_URL.",
            ),
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
            proxy_config=ProxyConfig(
                config_type=ProxyConfigType.ENV_VAR,
                env_var="OPENAI_BASE_URL",
                setup_cmd="test",
                setup_instructions="Set OPENAI_BASE_URL.",
            ),
            website="https://test.com",
            detect_vscode_ext="github.copilot",
        )
        with patch(
            "lumen_argus_core.detect._VSCODE_VARIANTS", (IDEVariant(name="Test", extensions=(ext_dir,), settings=()),)
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
            proxy_config=ProxyConfig(
                config_type=ProxyConfigType.ENV_VAR,
                env_var="OPENAI_BASE_URL",
                setup_cmd="test",
                setup_instructions="Set OPENAI_BASE_URL.",
            ),
            website="https://test.com",
            detect_vscode_ext="github.copilot",
        )
        with patch(
            "lumen_argus_core.detect._VSCODE_VARIANTS", (IDEVariant(name="Test", extensions=(ext_dir,), settings=()),)
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
            proxy_config=ProxyConfig(
                config_type=ProxyConfigType.ENV_VAR,
                env_var="OPENAI_BASE_URL",
                setup_cmd="test",
                setup_instructions="Set OPENAI_BASE_URL.",
            ),
            website="https://test.com",
            detect_vscode_ext="github.copilot",
        )
        with patch(
            "lumen_argus_core.detect._VSCODE_VARIANTS", (IDEVariant(name="Test", extensions=(ext_dir,), settings=()),)
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

    def _scan(self, proxy_url: str = "") -> dict:
        """Run _scan_shell_profiles with mock profiles and no env file leakage."""
        mock_profiles = {"zsh": (self.zshrc,)}
        with (
            patch("lumen_argus_core.detect._SHELL_PROFILES", mock_profiles),
            patch("lumen_argus_core.detect._ENV_FILE_PATH", "/nonexistent/env"),
            patch.dict(os.environ, {"SHELL": "/bin/zsh"}),
        ):
            return _scan_shell_profiles(proxy_url)

    def test_finds_env_var(self):
        with open(self.zshrc, "w") as f:
            f.write("# shell config\nexport OPENAI_BASE_URL=http://localhost:8080\n")
        result = self._scan("http://localhost:8080")
        self.assertIn("OPENAI_BASE_URL", result)
        self.assertEqual(result["OPENAI_BASE_URL"][0][0], "http://localhost:8080")
        self.assertEqual(result["OPENAI_BASE_URL"][0][3], "")  # no client tag

    def test_skips_comments(self):
        with open(self.zshrc, "w") as f:
            f.write("# export OPENAI_BASE_URL=http://localhost:8080\n")
        result = self._scan()
        self.assertNotIn("OPENAI_BASE_URL", result)

    def test_empty_file(self):
        with open(self.zshrc, "w") as f:
            f.write("")
        result = self._scan()
        self.assertEqual(len(result), 0)

    def test_extracts_client_tag(self):
        with open(self.zshrc, "w") as f:
            f.write("export OPENAI_BASE_URL=http://localhost:8080  # lumen-argus:managed client=opencode\n")
        result = self._scan("http://localhost:8080")
        entries = result["OPENAI_BASE_URL"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0][0], "http://localhost:8080")
        self.assertEqual(entries[0][3], "opencode")

    def test_multiple_tagged_lines(self):
        """Multiple managed lines for the same var produce separate entries."""
        with open(self.zshrc, "w") as f:
            f.write(
                "export OPENAI_BASE_URL=http://localhost:8080"
                "  # lumen-argus:managed client=opencode\n"
                "export OPENAI_BASE_URL=http://localhost:8080"
                "  # lumen-argus:managed client=aider\n"
            )
        result = self._scan("http://localhost:8080")
        entries = result["OPENAI_BASE_URL"]
        self.assertEqual(len(entries), 2)
        tags = {e[3] for e in entries}
        self.assertEqual(tags, {"opencode", "aider"})


class TestMatchShellEntry(unittest.TestCase):
    """Test _match_shell_entry client tag filtering."""

    def test_exact_tag_match(self):
        from lumen_argus_core.detect import _match_shell_entry

        entries = [
            ("http://localhost:8080", "~/.zshrc", 1, "opencode"),
            ("http://localhost:8080", "~/.zshrc", 2, "aider"),
        ]
        result = _match_shell_entry(entries, "opencode")
        self.assertIsNotNone(result)
        self.assertEqual(result[3], "opencode")

    def test_untagged_matches_any_client(self):
        from lumen_argus_core.detect import _match_shell_entry

        entries = [("http://localhost:8080", "~/.zshrc", 1, "")]
        result = _match_shell_entry(entries, "copilot")
        self.assertIsNotNone(result)

    def test_other_client_tag_rejected(self):
        from lumen_argus_core.detect import _match_shell_entry

        entries = [("http://localhost:8080", "~/.zshrc", 1, "opencode")]
        result = _match_shell_entry(entries, "copilot")
        self.assertIsNone(result)

    def test_last_applicable_wins(self):
        """Shell semantics: last assignment wins at runtime."""
        from lumen_argus_core.detect import _match_shell_entry

        # Tagged line first, then untagged override — untagged wins (last)
        entries = [
            ("http://localhost:8080", "~/.zshrc", 1, "aider"),
            ("http://corp-proxy:9090", "~/.zshrc", 5, ""),
        ]
        result = _match_shell_entry(entries, "aider")
        self.assertEqual(result[0], "http://corp-proxy:9090")

    def test_tagged_after_untagged_wins(self):
        """Tagged line after untagged — tagged wins (it's last)."""
        from lumen_argus_core.detect import _match_shell_entry

        entries = [
            ("http://corp-proxy:9090", "~/.zshrc", 1, ""),
            ("http://localhost:8080", "~/.zshrc", 5, "aider"),
        ]
        result = _match_shell_entry(entries, "aider")
        self.assertEqual(result[0], "http://localhost:8080")


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
            proxy_config=ProxyConfig(
                config_type=ProxyConfigType.ENV_VAR,
                env_var="OPENAI_BASE_URL",
                setup_cmd="test",
                setup_instructions="Set OPENAI_BASE_URL.",
            ),
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
            proxy_config=ProxyConfig(
                config_type=ProxyConfigType.ENV_VAR,
                env_var="OPENAI_BASE_URL",
                setup_cmd="test",
                setup_instructions="Set OPENAI_BASE_URL.",
            ),
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
            proxy_config=ProxyConfig(
                config_type=ProxyConfigType.ENV_VAR,
                env_var="OPENAI_BASE_URL",
                setup_cmd="test",
                setup_instructions="Set OPENAI_BASE_URL.",
            ),
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
            proxy_config=ProxyConfig(
                config_type=ProxyConfigType.ENV_VAR,
                env_var="OPENAI_BASE_URL",
                setup_cmd="test",
                setup_instructions="Set OPENAI_BASE_URL.",
            ),
            website="https://test.com",
            detect_brew="aider",
        )
        with patch("lumen_argus_core.detect._BREW_CELLAR_PATHS", [cellar]):
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
            proxy_config=ProxyConfig(
                config_type=ProxyConfigType.ENV_VAR,
                env_var="OPENAI_BASE_URL",
                setup_cmd="test",
                setup_instructions="Set OPENAI_BASE_URL.",
            ),
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
            proxy_config=ProxyConfig(
                config_type=ProxyConfigType.ENV_VAR,
                env_var="OPENAI_BASE_URL",
                setup_cmd="test",
                setup_instructions="Set OPENAI_BASE_URL.",
            ),
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
            proxy_config=ProxyConfig(
                config_type=ProxyConfigType.ENV_VAR,
                env_var="OPENAI_BASE_URL",
                setup_cmd="test",
                setup_instructions="Set OPENAI_BASE_URL.",
            ),
            website="https://test.com",
            detect_neovim_plugin="copilot.vim",
        )
        with patch("lumen_argus_core.detect._NEOVIM_PLUGIN_DIRS", [lazy_dir]):
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
            proxy_config=ProxyConfig(
                config_type=ProxyConfigType.ENV_VAR,
                env_var="OPENAI_BASE_URL",
                setup_cmd="test",
                setup_instructions="Set OPENAI_BASE_URL.",
            ),
            website="https://test.com",
            detect_neovim_plugin="copilot.vim",
        )
        with patch("lumen_argus_core.detect._NEOVIM_PLUGIN_DIRS", [lazy_dir]):
            result = _scan_neovim_plugin(client)
        self.assertIsNone(result)

    def test_no_detect_neovim(self):
        client = ClientDef(
            id="test",
            display_name="Test",
            category="cli",
            provider="openai",
            ua_prefixes=("test/",),
            proxy_config=ProxyConfig(
                config_type=ProxyConfigType.ENV_VAR,
                env_var="OPENAI_BASE_URL",
                setup_cmd="test",
                setup_instructions="Set OPENAI_BASE_URL.",
            ),
            website="https://test.com",
        )
        result = _scan_neovim_plugin(client)
        self.assertIsNone(result)


class TestDetectInstalledClients(unittest.TestCase):
    """Test the main detection orchestrator."""

    def test_returns_report(self):
        with (
            patch("lumen_argus_core.detect._scan_binary", return_value=None),
            patch("lumen_argus_core.detect._scan_pip_package", return_value=None),
            patch("lumen_argus_core.detect._scan_npm_package", return_value=None),
            patch("lumen_argus_core.detect._scan_brew_package", return_value=None),
            patch("lumen_argus_core.detect._scan_vscode_extension", return_value=None),
            patch("lumen_argus_core.detect._scan_app_bundle", return_value=None),
            patch("lumen_argus_core.detect._scan_jetbrains_plugin", return_value=None),
            patch("lumen_argus_core.detect._scan_neovim_plugin", return_value=None),
            patch("lumen_argus_core.detect._scan_shell_profiles", return_value={}),
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
            patch("lumen_argus_core.detect._scan_binary", side_effect=bad_scanner),
            patch("lumen_argus_core.detect._scan_pip_package", return_value=None),
            patch("lumen_argus_core.detect._scan_vscode_extension", return_value=None),
            patch("lumen_argus_core.detect._scan_app_bundle", return_value=None),
            patch("lumen_argus_core.detect._scan_jetbrains_plugin", return_value=None),
            patch("lumen_argus_core.detect._scan_shell_profiles", return_value={}),
        ):
            report = detect_installed_clients()
        self.assertEqual(report.total_detected, 0)


class TestDetectedClientDict(unittest.TestCase):
    def test_to_dict(self):
        c = DetectedClient(client_id="aider", installed=True, version="0.50.1")
        d = c.to_dict()
        self.assertEqual(d["client_id"], "aider")
        self.assertTrue(d["installed"])

    def test_to_dict_includes_routing_active(self):
        c = DetectedClient(client_id="aider", installed=True, routing_active=True)
        d = c.to_dict()
        self.assertTrue(d["routing_active"])

    def test_routing_active_defaults_false(self):
        c = DetectedClient(client_id="aider", installed=True)
        self.assertFalse(c.routing_active)


class TestReadEnvFileVars(unittest.TestCase):
    """Test reading env file for routing_active check."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.env_file = os.path.join(self.tmpdir, "env")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_reads_var_names(self):
        from lumen_argus_core.detect import _read_env_file_vars

        with open(self.env_file, "w") as f:
            f.write("export OPENAI_BASE_URL=http://localhost:8080  # lumen-argus:managed client=aider\n")
            f.write("export ANTHROPIC_BASE_URL=http://localhost:8080  # lumen-argus:managed client=claude_code\n")
        with patch("lumen_argus_core.detect.os.path.expanduser", return_value=self.env_file):
            result = _read_env_file_vars()
        self.assertIn("OPENAI_BASE_URL", result)
        self.assertIn("ANTHROPIC_BASE_URL", result)
        self.assertEqual(len(result), 2)

    def test_empty_file_returns_empty_set(self):
        from lumen_argus_core.detect import _read_env_file_vars

        with open(self.env_file, "w") as f:
            f.write("")
        with patch("lumen_argus_core.detect.os.path.expanduser", return_value=self.env_file):
            result = _read_env_file_vars()
        self.assertEqual(result, set())

    def test_missing_file_returns_empty_set(self):
        from lumen_argus_core.detect import _read_env_file_vars

        with patch("lumen_argus_core.detect.os.path.expanduser", return_value="/nonexistent/env"):
            result = _read_env_file_vars()
        self.assertEqual(result, set())


class TestCIEnvironmentDetection(unittest.TestCase):
    """Test CI/CD environment detection via env vars."""

    def test_github_actions(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "org/repo"}, clear=False):
            result = detect_ci_environment()
        self.assertIsNotNone(result)
        self.assertEqual(result.env_id, "github_actions")
        self.assertEqual(result.display_name, "GitHub Actions")
        self.assertEqual(result.details["repository"], "org/repo")

    def test_gitlab_ci(self):
        clean_env = {k: v for k, v in os.environ.items() if k != "GITHUB_ACTIONS"}
        clean_env.update({"GITLAB_CI": "true", "CI_PROJECT_NAME": "myproject"})
        with patch.dict(os.environ, clean_env, clear=True):
            result = detect_ci_environment()
        self.assertIsNotNone(result)
        self.assertEqual(result.env_id, "gitlab_ci")

    def test_kubernetes(self):
        env = {"KUBERNETES_SERVICE_HOST": "10.0.0.1"}
        # Remove CI-related vars to avoid false matches
        clean_env = {k: v for k, v in os.environ.items() if k not in ("CI", "GITHUB_ACTIONS", "GITLAB_CI")}
        clean_env.update(env)
        with patch.dict(os.environ, clean_env, clear=True):
            result = detect_ci_environment()
        self.assertIsNotNone(result)
        self.assertEqual(result.env_id, "kubernetes")

    def test_generic_ci(self):
        clean_env = {k: v for k, v in os.environ.items() if k not in ("GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI")}
        clean_env["CI"] = "true"
        with patch.dict(os.environ, clean_env, clear=True):
            result = detect_ci_environment()
        self.assertIsNotNone(result)
        self.assertEqual(result.env_id, "ci_generic")

    def test_no_ci(self):
        clean_env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "KUBERNETES_SERVICE_HOST")
        }
        with patch.dict(os.environ, clean_env, clear=True):
            with patch("os.path.exists", return_value=False):
                result = detect_ci_environment()
        self.assertIsNone(result)

    def test_docker_env_file(self):
        clean_env = {k: v for k, v in os.environ.items() if k not in ("CI", "GITHUB_ACTIONS", "GITLAB_CI")}
        with patch.dict(os.environ, clean_env, clear=True):
            with patch("os.path.exists", return_value=True):
                result = detect_ci_environment()
        self.assertIsNotNone(result)
        self.assertEqual(result.env_id, "docker")

    def test_ci_environment_in_report(self):
        """CI environment should be included in detection report."""
        with (
            patch("lumen_argus_core.detect._scan_binary", return_value=None),
            patch("lumen_argus_core.detect._scan_pip_package", return_value=None),
            patch("lumen_argus_core.detect._scan_npm_package", return_value=None),
            patch("lumen_argus_core.detect._scan_brew_package", return_value=None),
            patch("lumen_argus_core.detect._scan_vscode_extension", return_value=None),
            patch("lumen_argus_core.detect._scan_app_bundle", return_value=None),
            patch("lumen_argus_core.detect._scan_jetbrains_plugin", return_value=None),
            patch("lumen_argus_core.detect._scan_neovim_plugin", return_value=None),
            patch("lumen_argus_core.detect._scan_shell_profiles", return_value={}),
            patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}, clear=False),
        ):
            report = detect_installed_clients()
        self.assertIsNotNone(report.ci_environment)
        self.assertEqual(report.ci_environment.env_id, "github_actions")
        d = report.to_dict()
        self.assertIn("ci_environment", d)

    def test_report_to_dict_no_ci(self):
        """Report without CI env should not include ci_environment key."""
        report = DetectionReport(
            clients=[],
            platform="Test",
            total_detected=0,
            total_configured=0,
        )
        d = report.to_dict()
        self.assertNotIn("ci_environment", d)


class TestPowerShellEnvExtraction(unittest.TestCase):
    """Test PowerShell env var pattern matching."""

    def test_powershell_env_syntax(self):
        line = '$env:OPENAI_BASE_URL = "http://localhost:8080"'
        val = _extract_env_value(line, "OPENAI_BASE_URL")
        self.assertEqual(val, "http://localhost:8080")

    def test_powershell_env_no_spaces(self):
        line = '$env:OPENAI_BASE_URL="http://localhost:8080"'
        val = _extract_env_value(line, "OPENAI_BASE_URL")
        self.assertEqual(val, "http://localhost:8080")


class TestWindowsPaths(unittest.TestCase):
    """Test Windows-specific path detection."""

    @patch("platform.system", return_value="Windows")
    def test_powershell_profiles(self, _):
        with patch.dict(os.environ, {"USERPROFILE": "/Users/testuser"}):
            profiles = _get_powershell_profiles()
        self.assertEqual(len(profiles), 2)
        self.assertIn("PowerShell", profiles[0])
        self.assertIn("WindowsPowerShell", profiles[1])

    @patch("platform.system", return_value="Linux")
    def test_powershell_profiles_non_windows(self, _):
        profiles = _get_powershell_profiles()
        self.assertEqual(profiles, ())

    @patch("platform.system", return_value="Windows")
    def test_vscode_variants_includes_windows(self, _):
        with patch.dict(os.environ, {"APPDATA": "C:\\Users\\test\\AppData\\Roaming"}):
            variants = _get_vscode_variants()
        # Should include both Windows and standard variants
        names = [v.name for v in variants]
        self.assertTrue(any("Windows" in n for n in names))

    @patch("platform.system", return_value="Darwin")
    def test_vscode_variants_no_windows_on_mac(self, _):
        variants = _get_vscode_variants()
        names = [v.name for v in variants]
        self.assertFalse(any("Windows" in n for n in names))


class TestNpmFnmVolta(unittest.TestCase):
    """Test fnm and volta Node manager path detection."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_volta_package_found(self):
        """npm scanner should find packages under volta tools."""
        # Create mock volta structure
        volta_home = os.path.join(self.tmpdir, ".volta")
        node_dir = os.path.join(volta_home, "tools", "image", "node", "20.0.0", "lib", "node_modules")
        pkg_dir = os.path.join(node_dir, "@openai", "codex")
        os.makedirs(pkg_dir)
        with open(os.path.join(pkg_dir, "package.json"), "w") as f:
            json.dump({"name": "@openai/codex", "version": "0.2.0"}, f)

        client = ClientDef(
            id="codex_cli",
            display_name="Codex CLI",
            category="cli",
            provider="openai",
            ua_prefixes=("codex/",),
            proxy_config=ProxyConfig(
                config_type=ProxyConfigType.ENV_VAR,
                env_var="OPENAI_BASE_URL",
                setup_cmd="test",
                setup_instructions="Set OPENAI_BASE_URL.",
            ),
            website="https://test.com",
            detect_npm="@openai/codex",
        )
        with patch.dict(os.environ, {"VOLTA_HOME": volta_home, "NPM_CONFIG_PREFIX": ""}, clear=False):
            result = _scan_npm_package(client)
        self.assertIsNotNone(result)
        self.assertEqual(result.version, "0.2.0")
        self.assertEqual(result.install_method, InstallMethod.NPM)

    def test_fnm_multishell_path(self):
        """npm scanner should find packages under FNM_MULTISHELL_PATH."""
        fnm_ms = os.path.join(self.tmpdir, "fnm_multishell")
        pkg_dir = os.path.join(fnm_ms, "lib", "node_modules", "@openai", "codex")
        os.makedirs(pkg_dir)
        with open(os.path.join(pkg_dir, "package.json"), "w") as f:
            json.dump({"name": "@openai/codex", "version": "0.3.0"}, f)

        # Also need a valid FNM_DIR with node-versions for the code path
        fnm_dir = os.path.join(self.tmpdir, "fnm")
        os.makedirs(os.path.join(fnm_dir, "node-versions"))

        client = ClientDef(
            id="codex_cli",
            display_name="Codex CLI",
            category="cli",
            provider="openai",
            ua_prefixes=("codex/",),
            proxy_config=ProxyConfig(
                config_type=ProxyConfigType.ENV_VAR,
                env_var="OPENAI_BASE_URL",
                setup_cmd="test",
                setup_instructions="Set OPENAI_BASE_URL.",
            ),
            website="https://test.com",
            detect_npm="@openai/codex",
        )
        with patch.dict(
            os.environ,
            {"FNM_DIR": fnm_dir, "FNM_MULTISHELL_PATH": fnm_ms, "NPM_CONFIG_PREFIX": "", "VOLTA_HOME": ""},
            clear=False,
        ):
            result = _scan_npm_package(client)
        self.assertIsNotNone(result)
        self.assertEqual(result.version, "0.3.0")


if __name__ == "__main__":
    unittest.main()
