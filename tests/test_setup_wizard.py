"""Tests for the setup wizard — env file approach, source block, IDE settings, undo, protection."""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from lumen_argus_core.setup_wizard import (
    _SOURCE_BLOCK_BEGIN,
    _SOURCE_BLOCK_END,
    MANAGED_TAG,
    add_env_to_env_file,
    add_env_to_shell_profile,
    disable_protection,
    enable_protection,
    install_shell_hook,
    install_source_block,
    protection_status,
    read_env_file,
    undo_setup,
    update_ide_settings,
    write_env_file,
)


class TestSourceBlock(unittest.TestCase):
    """Test source block installation in shell profiles."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.profile = os.path.join(self.tmpdir, ".zshrc")
        with open(self.profile, "w") as f:
            f.write("# my zshrc\nexport PATH=/usr/bin\n")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_installs_source_block(self):
        with patch("lumen_argus_core.setup_wizard._BACKUP_DIR", os.path.join(self.tmpdir, "backups")):
            change = install_source_block(self.profile)
        self.assertIsNotNone(change)
        with open(self.profile) as f:
            content = f.read()
        self.assertIn(_SOURCE_BLOCK_BEGIN, content)
        self.assertIn(_SOURCE_BLOCK_END, content)
        self.assertIn(".lumen-argus/env", content)

    def test_idempotent(self):
        with patch("lumen_argus_core.setup_wizard._BACKUP_DIR", os.path.join(self.tmpdir, "backups")):
            install_source_block(self.profile)
            change = install_source_block(self.profile)
        self.assertIsNone(change)

    def test_dry_run(self):
        change = install_source_block(self.profile, dry_run=True)
        self.assertIsNotNone(change)
        with open(self.profile) as f:
            content = f.read()
        self.assertNotIn(_SOURCE_BLOCK_BEGIN, content)


class TestEnvFile(unittest.TestCase):
    """Test env file read/write operations."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.env_file = os.path.join(self.tmpdir, "env")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_write_and_read(self):
        entries = [
            ("OPENAI_BASE_URL", "http://localhost:8080", "aider"),
            ("ANTHROPIC_BASE_URL", "http://localhost:8080", "claude_code"),
        ]
        with (
            patch("lumen_argus_core.setup_wizard._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup_wizard._ARGUS_DIR", self.tmpdir),
        ):
            write_env_file(entries)
            result = read_env_file()
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], ("OPENAI_BASE_URL", "http://localhost:8080", "aider"))
        self.assertEqual(result[1], ("ANTHROPIC_BASE_URL", "http://localhost:8080", "claude_code"))

    def test_read_empty_file(self):
        with open(self.env_file, "w") as f:
            f.write("")
        with patch("lumen_argus_core.setup_wizard._ENV_FILE", self.env_file):
            result = read_env_file()
        self.assertEqual(result, [])

    def test_read_nonexistent_file(self):
        with patch("lumen_argus_core.setup_wizard._ENV_FILE", os.path.join(self.tmpdir, "nonexistent")):
            result = read_env_file()
        self.assertEqual(result, [])

    def test_add_env_to_env_file(self):
        with (
            patch("lumen_argus_core.setup_wizard._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup_wizard._ARGUS_DIR", self.tmpdir),
        ):
            change = add_env_to_env_file("OPENAI_BASE_URL", "http://localhost:8080", "aider")
        self.assertIsNotNone(change)
        self.assertEqual(change.method, "env_file")
        with open(self.env_file) as f:
            content = f.read()
        self.assertIn("export OPENAI_BASE_URL=http://localhost:8080", content)
        self.assertIn(MANAGED_TAG, content)
        self.assertIn("client=aider", content)

    def test_add_env_skips_duplicate(self):
        with (
            patch("lumen_argus_core.setup_wizard._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup_wizard._ARGUS_DIR", self.tmpdir),
        ):
            add_env_to_env_file("OPENAI_BASE_URL", "http://localhost:8080", "aider")
            change = add_env_to_env_file("OPENAI_BASE_URL", "http://localhost:8080", "aider")
        self.assertIsNone(change)

    def test_add_env_replaces_same_var_client(self):
        """Updating value for same var+client should replace, not duplicate."""
        with (
            patch("lumen_argus_core.setup_wizard._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup_wizard._ARGUS_DIR", self.tmpdir),
        ):
            add_env_to_env_file("OPENAI_BASE_URL", "http://localhost:8080", "aider")
            add_env_to_env_file("OPENAI_BASE_URL", "http://localhost:9090", "aider")
            result = read_env_file()
        # Should have exactly one entry with new value
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][1], "http://localhost:9090")

    def test_add_env_dry_run(self):
        with (
            patch("lumen_argus_core.setup_wizard._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup_wizard._ARGUS_DIR", self.tmpdir),
        ):
            change = add_env_to_env_file("OPENAI_BASE_URL", "http://localhost:8080", "aider", dry_run=True)
        self.assertIsNotNone(change)
        self.assertFalse(os.path.isfile(self.env_file))

    def test_env_file_tagged_lines(self):
        """Env file lines should have managed tags with client IDs."""
        with (
            patch("lumen_argus_core.setup_wizard._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup_wizard._ARGUS_DIR", self.tmpdir),
        ):
            add_env_to_env_file("OPENAI_BASE_URL", "http://localhost:8080", "aider")
            add_env_to_env_file("ANTHROPIC_BASE_URL", "http://localhost:8080", "claude_code")
        with open(self.env_file) as f:
            content = f.read()
        self.assertIn("client=aider", content)
        self.assertIn("client=claude_code", content)


class TestAddEnvToShellProfile(unittest.TestCase):
    """Test the combined add_env_to_shell_profile (source block + env file)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.profile = os.path.join(self.tmpdir, ".zshrc")
        self.env_file = os.path.join(self.tmpdir, "env")
        with open(self.profile, "w") as f:
            f.write("# my zshrc\nexport PATH=/usr/bin\n")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_adds_source_block_and_env_var(self):
        with (
            patch("lumen_argus_core.setup_wizard._BACKUP_DIR", os.path.join(self.tmpdir, "backups")),
            patch("lumen_argus_core.setup_wizard._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup_wizard._ARGUS_DIR", self.tmpdir),
        ):
            change = add_env_to_shell_profile("OPENAI_BASE_URL", "http://localhost:8080", "aider", self.profile)
        self.assertIsNotNone(change)
        # Source block in profile
        with open(self.profile) as f:
            profile_content = f.read()
        self.assertIn(_SOURCE_BLOCK_BEGIN, profile_content)
        # Env var in env file
        with open(self.env_file) as f:
            env_content = f.read()
        self.assertIn("export OPENAI_BASE_URL=http://localhost:8080", env_content)

    def test_skips_if_already_set(self):
        with (
            patch("lumen_argus_core.setup_wizard._BACKUP_DIR", os.path.join(self.tmpdir, "backups")),
            patch("lumen_argus_core.setup_wizard._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup_wizard._ARGUS_DIR", self.tmpdir),
        ):
            add_env_to_shell_profile("OPENAI_BASE_URL", "http://localhost:8080", "aider", self.profile)
            change = add_env_to_shell_profile("OPENAI_BASE_URL", "http://localhost:8080", "aider", self.profile)
        self.assertIsNone(change)

    def test_dry_run(self):
        with (
            patch("lumen_argus_core.setup_wizard._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup_wizard._ARGUS_DIR", self.tmpdir),
        ):
            change = add_env_to_shell_profile(
                "OPENAI_BASE_URL", "http://localhost:8080", "aider", self.profile, dry_run=True
            )
        self.assertIsNotNone(change)
        # Env file should not exist (dry run)
        self.assertFalse(os.path.isfile(self.env_file))


class TestProtection(unittest.TestCase):
    """Test protection enable/disable/status."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.env_file = os.path.join(self.tmpdir, "env")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_enable_writes_all_env_vars(self):
        with (
            patch("lumen_argus_core.setup_wizard._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup_wizard._ARGUS_DIR", self.tmpdir),
        ):
            result = enable_protection("http://localhost:8080")
        self.assertTrue(result["enabled"])
        self.assertGreater(result["env_vars_set"], 0)
        self.assertTrue(os.path.isfile(self.env_file))
        with open(self.env_file) as f:
            content = f.read()
        self.assertIn("ANTHROPIC_BASE_URL", content)
        self.assertIn("OPENAI_BASE_URL", content)

    def test_disable_truncates_env_file(self):
        with (
            patch("lumen_argus_core.setup_wizard._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup_wizard._ARGUS_DIR", self.tmpdir),
        ):
            enable_protection("http://localhost:8080")
            result = disable_protection()
        self.assertFalse(result["enabled"])
        self.assertEqual(result["env_vars_set"], 0)
        with open(self.env_file) as f:
            content = f.read()
        self.assertEqual(content, "")

    def test_status_enabled(self):
        with (
            patch("lumen_argus_core.setup_wizard._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup_wizard._ARGUS_DIR", self.tmpdir),
        ):
            enable_protection("http://localhost:8080")
            result = protection_status()
        self.assertTrue(result["enabled"])
        self.assertGreater(result["env_vars_set"], 0)

    def test_status_disabled(self):
        with (
            patch("lumen_argus_core.setup_wizard._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup_wizard._ARGUS_DIR", self.tmpdir),
        ):
            result = protection_status()
        self.assertFalse(result["enabled"])
        self.assertEqual(result["env_vars_set"], 0)

    def test_enable_disable_cycle(self):
        with (
            patch("lumen_argus_core.setup_wizard._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup_wizard._ARGUS_DIR", self.tmpdir),
        ):
            enable_protection()
            self.assertTrue(protection_status()["enabled"])
            disable_protection()
            self.assertFalse(protection_status()["enabled"])
            enable_protection()
            self.assertTrue(protection_status()["enabled"])


class TestUpdateIdeSettings(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.settings_file = os.path.join(self.tmpdir, "settings.json")
        with open(self.settings_file, "w") as f:
            json.dump({"editor.fontSize": 14}, f)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_adds_key(self):
        with patch("lumen_argus_core.setup_wizard._BACKUP_DIR", os.path.join(self.tmpdir, "backups")):
            change = update_ide_settings(self.settings_file, "http.proxy", "http://localhost:8080", "copilot")
        self.assertIsNotNone(change)
        with open(self.settings_file) as f:
            settings = json.load(f)
        self.assertEqual(settings["http.proxy"], "http://localhost:8080")
        self.assertEqual(settings["editor.fontSize"], 14)

    def test_skips_if_already_set(self):
        with open(self.settings_file, "w") as f:
            json.dump({"http.proxy": "http://localhost:8080"}, f)
        change = update_ide_settings(self.settings_file, "http.proxy", "http://localhost:8080", "copilot")
        self.assertIsNone(change)

    def test_dry_run(self):
        change = update_ide_settings(self.settings_file, "http.proxy", "http://localhost:8080", "copilot", dry_run=True)
        self.assertIsNotNone(change)
        with open(self.settings_file) as f:
            settings = json.load(f)
        self.assertNotIn("http.proxy", settings)

    def test_handles_jsonc_comments(self):
        with open(self.settings_file, "w") as f:
            f.write('// VS Code settings\n{"editor.fontSize": 14}\n')
        with patch("lumen_argus_core.setup_wizard._BACKUP_DIR", os.path.join(self.tmpdir, "backups")):
            change = update_ide_settings(self.settings_file, "http.proxy", "http://localhost:8080", "copilot")
        self.assertIsNotNone(change)

    def test_missing_file(self):
        change = update_ide_settings("/nonexistent/settings.json", "http.proxy", "http://localhost:8080", "copilot")
        self.assertIsNone(change)


class TestUndoSetup(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.profile = os.path.join(self.tmpdir, ".zshrc")
        self.env_file = os.path.join(self.tmpdir, "env")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_removes_source_block(self):
        with open(self.profile, "w") as f:
            f.write("# my config\n")
            f.write("export PATH=/usr/bin\n")
            f.write("%s\n" % _SOURCE_BLOCK_BEGIN)
            f.write('[ -f "$HOME/.lumen-argus/env" ] && source "$HOME/.lumen-argus/env"\n')
            f.write("%s\n" % _SOURCE_BLOCK_END)
            f.write("export FOO=bar\n")

        mock_profiles = {"zsh": (self.profile,)}
        manifest = os.path.join(self.tmpdir, "manifest.json")
        backup_dir = os.path.join(self.tmpdir, "backups")
        with (
            patch("lumen_argus_core.setup_wizard._SHELL_PROFILES", mock_profiles),
            patch("lumen_argus_core.setup_wizard._MANIFEST_PATH", manifest),
            patch("lumen_argus_core.setup_wizard._BACKUP_DIR", backup_dir),
            patch("lumen_argus_core.setup_wizard._ENV_FILE", self.env_file),
        ):
            reverted = undo_setup()

        self.assertGreater(reverted, 0)
        with open(self.profile) as f:
            content = f.read()
        self.assertNotIn(_SOURCE_BLOCK_BEGIN, content)
        self.assertNotIn(_SOURCE_BLOCK_END, content)
        self.assertIn("export PATH=/usr/bin", content)
        self.assertIn("export FOO=bar", content)

    def test_removes_managed_lines(self):
        with open(self.profile, "w") as f:
            f.write("# my config\n")
            f.write("export PATH=/usr/bin\n")
            f.write("export OPENAI_BASE_URL=http://localhost:8080  %s client=aider\n" % MANAGED_TAG)
            f.write("export FOO=bar\n")

        mock_profiles = {"zsh": (self.profile,)}
        manifest = os.path.join(self.tmpdir, "manifest.json")
        backup_dir = os.path.join(self.tmpdir, "backups")
        with (
            patch("lumen_argus_core.setup_wizard._SHELL_PROFILES", mock_profiles),
            patch("lumen_argus_core.setup_wizard._MANIFEST_PATH", manifest),
            patch("lumen_argus_core.setup_wizard._BACKUP_DIR", backup_dir),
            patch("lumen_argus_core.setup_wizard._ENV_FILE", self.env_file),
        ):
            reverted = undo_setup()

        self.assertEqual(reverted, 1)
        with open(self.profile) as f:
            content = f.read()
        self.assertNotIn(MANAGED_TAG, content)
        self.assertIn("export FOO=bar", content)

    def test_clears_env_file(self):
        """Undo should truncate the env file."""
        with open(self.env_file, "w") as f:
            f.write("export OPENAI_BASE_URL=http://localhost:8080  %s client=aider\n" % MANAGED_TAG)

        mock_profiles = {"zsh": (self.profile,)}
        manifest = os.path.join(self.tmpdir, "manifest.json")
        backup_dir = os.path.join(self.tmpdir, "backups")
        with (
            patch("lumen_argus_core.setup_wizard._SHELL_PROFILES", mock_profiles),
            patch("lumen_argus_core.setup_wizard._MANIFEST_PATH", manifest),
            patch("lumen_argus_core.setup_wizard._BACKUP_DIR", backup_dir),
            patch("lumen_argus_core.setup_wizard._ENV_FILE", self.env_file),
        ):
            reverted = undo_setup()

        self.assertGreater(reverted, 0)
        with open(self.env_file) as f:
            content = f.read()
        self.assertEqual(content, "")


class TestInstallShellHook(unittest.TestCase):
    """Test shell hook installation."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.profile = os.path.join(self.tmpdir, ".zshrc")
        with open(self.profile, "w") as f:
            f.write("# my zshrc\n")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_installs_hook(self):
        with patch("lumen_argus_core.setup_wizard._BACKUP_DIR", os.path.join(self.tmpdir, "backups")):
            change = install_shell_hook(self.profile)
        self.assertIsNotNone(change)
        with open(self.profile) as f:
            content = f.read()
        self.assertIn("lumen-argus detect --check-quiet", content)
        self.assertIn(MANAGED_TAG, content)

    def test_skips_if_already_installed(self):
        with open(self.profile, "a") as f:
            f.write('eval "$(lumen-argus detect --check-quiet 2>/dev/null)"\n')
        change = install_shell_hook(self.profile)
        self.assertIsNone(change)

    def test_dry_run(self):
        change = install_shell_hook(self.profile, dry_run=True)
        self.assertIsNotNone(change)
        with open(self.profile) as f:
            content = f.read()
        self.assertNotIn("check-quiet", content)

    def test_undo_removes_hook(self):
        """Hook lines should be removed by undo_setup since they contain MANAGED_TAG."""
        with patch("lumen_argus_core.setup_wizard._BACKUP_DIR", os.path.join(self.tmpdir, "backups")):
            install_shell_hook(self.profile)

        mock_profiles = {"zsh": (self.profile,)}
        manifest = os.path.join(self.tmpdir, "manifest.json")
        backup_dir = os.path.join(self.tmpdir, "backups")
        env_file = os.path.join(self.tmpdir, "env")
        with (
            patch("lumen_argus_core.setup_wizard._SHELL_PROFILES", mock_profiles),
            patch("lumen_argus_core.setup_wizard._MANIFEST_PATH", manifest),
            patch("lumen_argus_core.setup_wizard._BACKUP_DIR", backup_dir),
            patch("lumen_argus_core.setup_wizard._ENV_FILE", env_file),
        ):
            reverted = undo_setup()
        self.assertGreater(reverted, 0)
        with open(self.profile) as f:
            content = f.read()
        self.assertNotIn(MANAGED_TAG, content)


class TestWindowsSetup(unittest.TestCase):
    """Test PowerShell profile detection and env var format."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @patch("platform.system", return_value="Windows")
    def test_detect_shell_profile_windows(self, _):
        """On Windows, should detect PowerShell profile."""
        from lumen_argus_core.setup_wizard import _detect_shell_profile

        ps_profile = os.path.join(self.tmpdir, "Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1")
        os.makedirs(os.path.dirname(ps_profile))
        with open(ps_profile, "w") as f:
            f.write("# profile\n")

        with patch("lumen_argus_core.detect._get_powershell_profiles", return_value=(ps_profile,)):
            result = _detect_shell_profile()
        self.assertEqual(result, ps_profile)


if __name__ == "__main__":
    unittest.main()
