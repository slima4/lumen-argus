"""Tests for the setup wizard — shell profile modification, IDE settings, undo."""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from lumen_argus.setup_wizard import (
    MANAGED_TAG,
    add_env_to_shell_profile,
    undo_setup,
    update_ide_settings,
)


class TestAddEnvToShellProfile(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.profile = os.path.join(self.tmpdir, ".zshrc")
        with open(self.profile, "w") as f:
            f.write("# my zshrc\nexport PATH=/usr/bin\n")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_adds_export_line(self):
        change = add_env_to_shell_profile("OPENAI_BASE_URL", "http://localhost:8080", "aider", self.profile)
        self.assertIsNotNone(change)
        with open(self.profile) as f:
            content = f.read()
        self.assertIn("export OPENAI_BASE_URL=http://localhost:8080", content)
        self.assertIn(MANAGED_TAG, content)

    def test_skips_if_already_set(self):
        with open(self.profile, "a") as f:
            f.write("export OPENAI_BASE_URL=http://localhost:8080\n")
        change = add_env_to_shell_profile("OPENAI_BASE_URL", "http://localhost:8080", "aider", self.profile)
        self.assertIsNone(change)

    def test_skips_if_different_value(self):
        with open(self.profile, "a") as f:
            f.write("export OPENAI_BASE_URL=https://api.openai.com\n")
        change = add_env_to_shell_profile("OPENAI_BASE_URL", "http://localhost:8080", "aider", self.profile)
        self.assertIsNone(change)  # warns but doesn't overwrite

    def test_dry_run(self):
        change = add_env_to_shell_profile(
            "OPENAI_BASE_URL", "http://localhost:8080", "aider", self.profile, dry_run=True
        )
        self.assertIsNotNone(change)
        with open(self.profile) as f:
            content = f.read()
        self.assertNotIn("OPENAI_BASE_URL", content)

    def test_creates_backup(self):
        with patch("lumen_argus.setup_wizard._BACKUP_DIR", os.path.join(self.tmpdir, "backups")):
            change = add_env_to_shell_profile("OPENAI_BASE_URL", "http://localhost:8080", "aider", self.profile)
        self.assertIsNotNone(change)
        self.assertTrue(change.backup_path)
        self.assertTrue(os.path.exists(change.backup_path))


class TestUpdateIdeSettings(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.settings_file = os.path.join(self.tmpdir, "settings.json")
        with open(self.settings_file, "w") as f:
            json.dump({"editor.fontSize": 14}, f)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_adds_key(self):
        with patch("lumen_argus.setup_wizard._BACKUP_DIR", os.path.join(self.tmpdir, "backups")):
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
        with patch("lumen_argus.setup_wizard._BACKUP_DIR", os.path.join(self.tmpdir, "backups")):
            change = update_ide_settings(self.settings_file, "http.proxy", "http://localhost:8080", "copilot")
        self.assertIsNotNone(change)

    def test_missing_file(self):
        change = update_ide_settings("/nonexistent/settings.json", "http.proxy", "http://localhost:8080", "copilot")
        self.assertIsNone(change)


class TestUndoSetup(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.profile = os.path.join(self.tmpdir, ".zshrc")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

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
            patch("lumen_argus.setup_wizard._SHELL_PROFILES", mock_profiles),
            patch("lumen_argus.setup_wizard._MANIFEST_PATH", manifest),
            patch("lumen_argus.setup_wizard._BACKUP_DIR", backup_dir),
        ):
            reverted = undo_setup()

        self.assertEqual(reverted, 1)
        with open(self.profile) as f:
            content = f.read()
        self.assertNotIn(MANAGED_TAG, content)
        self.assertIn("export PATH=/usr/bin", content)
        self.assertIn("export FOO=bar", content)

    def test_managed_tag_in_line(self):
        line = "export OPENAI_BASE_URL=http://localhost:8080  %s client=aider" % MANAGED_TAG
        self.assertIn(MANAGED_TAG, line)


if __name__ == "__main__":
    unittest.main()
