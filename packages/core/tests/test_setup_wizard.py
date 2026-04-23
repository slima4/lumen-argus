"""Tests for the setup wizard — env file approach, source block, IDE settings, undo, protection."""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from lumen_argus_core.setup._paths import _SOURCE_BLOCK_BEGIN, _SOURCE_BLOCK_END, MANAGED_TAG
from lumen_argus_core.setup.source_block import install_source_block
from lumen_argus_core.setup_wizard import (
    add_env_to_env_file,
    add_env_to_shell_profile,
    disable_protection,
    enable_protection,
    install_shell_hook,
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
        with patch("lumen_argus_core.setup.manifest._BACKUP_DIR", os.path.join(self.tmpdir, "backups")):
            change = install_source_block(self.profile)
        self.assertIsNotNone(change)
        with open(self.profile) as f:
            content = f.read()
        self.assertIn(_SOURCE_BLOCK_BEGIN, content)
        self.assertIn(_SOURCE_BLOCK_END, content)
        self.assertIn(".lumen-argus/env", content)

    def test_idempotent(self):
        with patch("lumen_argus_core.setup.manifest._BACKUP_DIR", os.path.join(self.tmpdir, "backups")):
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
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            write_env_file(entries)
            result = read_env_file()
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], ("OPENAI_BASE_URL", "http://localhost:8080", "aider"))
        self.assertEqual(result[1], ("ANTHROPIC_BASE_URL", "http://localhost:8080", "claude_code"))

    def test_read_empty_file(self):
        with open(self.env_file, "w") as f:
            f.write("")
        with patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file):
            result = read_env_file()
        self.assertEqual(result, [])

    def test_read_nonexistent_file(self):
        with patch("lumen_argus_core.setup.env_file._ENV_FILE", os.path.join(self.tmpdir, "nonexistent")):
            result = read_env_file()
        self.assertEqual(result, [])

    def test_add_env_to_env_file(self):
        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
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
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            add_env_to_env_file("OPENAI_BASE_URL", "http://localhost:8080", "aider")
            change = add_env_to_env_file("OPENAI_BASE_URL", "http://localhost:8080", "aider")
        self.assertIsNone(change)

    def test_add_env_replaces_same_var_client(self):
        """Updating value for same var+client should replace, not duplicate."""
        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            add_env_to_env_file("OPENAI_BASE_URL", "http://localhost:8080", "aider")
            add_env_to_env_file("OPENAI_BASE_URL", "http://localhost:9090", "aider")
            result = read_env_file()
        # Should have exactly one entry with new value
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][1], "http://localhost:9090")

    def test_add_env_dry_run(self):
        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            change = add_env_to_env_file("OPENAI_BASE_URL", "http://localhost:8080", "aider", dry_run=True)
        self.assertIsNotNone(change)
        self.assertFalse(os.path.isfile(self.env_file))

    def test_env_file_tagged_lines(self):
        """Env file lines should have managed tags with client IDs."""
        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            add_env_to_env_file("OPENAI_BASE_URL", "http://localhost:8080", "aider")
            add_env_to_env_file("ANTHROPIC_BASE_URL", "http://localhost:8080", "claude_code")
        with open(self.env_file) as f:
            content = f.read()
        self.assertIn("client=aider", content)
        self.assertIn("client=claude_code", content)

    # ------------------------------------------------------------------
    # Orphan handling — lines written by non-conformant external writers
    # (e.g. an older tray app build) must still be parsed so that
    # protection_status() reports the truth and add_env_to_env_file()
    # can evict them on the next canonical write.
    # ------------------------------------------------------------------

    def _write_raw(self, content: str) -> None:
        with open(self.env_file, "w") as f:
            f.write(content)

    def test_read_env_file_parses_orphan_without_client_tag(self):
        """Lines with `# lumen-argus:managed` but no `client=<id>` are parsed as orphans."""
        self._write_raw("export OPENAI_BASE_URL=http://127.0.0.1:8070  # lumen-argus:managed\n")
        with patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file):
            result = read_env_file()
        self.assertEqual(result, [("OPENAI_BASE_URL", "http://127.0.0.1:8070", "")])

    def test_read_env_file_strips_single_quotes(self):
        """Orphans often come with surrounding single quotes; value must be unquoted."""
        self._write_raw("export ANTHROPIC_BASE_URL='http://127.0.0.1:8070'  # lumen-argus:managed\n")
        with patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file):
            result = read_env_file()
        self.assertEqual(result, [("ANTHROPIC_BASE_URL", "http://127.0.0.1:8070", "")])

    def test_read_env_file_strips_double_quotes(self):
        self._write_raw('export GEMINI_BASE_URL="http://127.0.0.1:8070"  # lumen-argus:managed\n')
        with patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file):
            result = read_env_file()
        self.assertEqual(result, [("GEMINI_BASE_URL", "http://127.0.0.1:8070", "")])

    def test_read_env_file_mixes_canonical_and_orphan(self):
        """Canonical + orphan lines in the same file both surface."""
        self._write_raw(
            "export OPENAI_BASE_URL=http://localhost:8080  # lumen-argus:managed client=aider\n"
            "export COPILOT_PROVIDER_BASE_URL='http://127.0.0.1:8070'  # lumen-argus:managed\n"
        )
        with patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file):
            result = read_env_file()
        self.assertEqual(len(result), 2)
        self.assertIn(("OPENAI_BASE_URL", "http://localhost:8080", "aider"), result)
        self.assertIn(("COPILOT_PROVIDER_BASE_URL", "http://127.0.0.1:8070", ""), result)

    def test_read_env_file_ignores_unmanaged_lines(self):
        """Lines without the managed tag are ignored (not misclassified as orphans)."""
        self._write_raw(
            "export FOO=bar\n"
            "export BAZ=qux  # some other comment\n"
            "export OPENAI_BASE_URL=http://localhost:8080  # lumen-argus:managed client=aider\n"
        )
        with patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file):
            result = read_env_file()
        self.assertEqual(result, [("OPENAI_BASE_URL", "http://localhost:8080", "aider")])

    def test_write_env_file_preserves_orphan_format_round_trip(self):
        """Round-trip of an orphan must not gain a bogus empty `client=` suffix."""
        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            write_env_file([("CUSTOM_VAR", "http://example.com", "")])
            with open(self.env_file) as f:
                content = f.read()
            self.assertIn("export CUSTOM_VAR=http://example.com  # lumen-argus:managed\n", content)
            self.assertNotIn("client=", content)
            # And the round-tripped line still parses as an orphan.
            result = read_env_file()
        self.assertEqual(result, [("CUSTOM_VAR", "http://example.com", "")])

    def test_add_env_evicts_orphan_for_same_var(self):
        """Writing a canonical entry must remove any orphan for the same var."""
        self._write_raw("export ANTHROPIC_BASE_URL='http://127.0.0.1:8070'  # lumen-argus:managed\n")
        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            change = add_env_to_env_file("ANTHROPIC_BASE_URL", "http://localhost:8080", "claude_code")
            result = read_env_file()
            with open(self.env_file) as f:
                content = f.read()
        self.assertIsNotNone(change)
        # Only the canonical entry remains — orphan evicted.
        self.assertEqual(result, [("ANTHROPIC_BASE_URL", "http://localhost:8080", "claude_code")])
        self.assertNotIn("'http://127.0.0.1:8070'", content)
        self.assertIn("client=claude_code", content)

    def test_add_env_preserves_orphan_for_different_var(self):
        """Orphans for unrelated vars must not be touched by a canonical write."""
        self._write_raw("export COPILOT_PROVIDER_BASE_URL='http://127.0.0.1:8070'  # lumen-argus:managed\n")
        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            add_env_to_env_file("ANTHROPIC_BASE_URL", "http://localhost:8080", "claude_code")
            result = read_env_file()
        self.assertEqual(len(result), 2)
        self.assertIn(("COPILOT_PROVIDER_BASE_URL", "http://127.0.0.1:8070", ""), result)
        self.assertIn(("ANTHROPIC_BASE_URL", "http://localhost:8080", "claude_code"), result)

    def test_add_env_evicts_orphan_but_preserves_different_client_same_var(self):
        """Orphan eviction must not harm canonical entries from other clients.

        This is the structural boundary of the filter: cid == "" (evicted)
        vs cid == other_client (preserved). A regression that flipped the
        filter to `cid != ""` would silently drop other clients' entries
        for the same variable, and only this test would notice.
        """
        self._write_raw(
            "export ANTHROPIC_BASE_URL=http://localhost:8080  # lumen-argus:managed client=claude_code\n"
            "export ANTHROPIC_BASE_URL='http://127.0.0.1:8070'  # lumen-argus:managed\n"
        )
        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            add_env_to_env_file("ANTHROPIC_BASE_URL", "http://localhost:8080", "aider")
            result = read_env_file()
        self.assertEqual(len(result), 2)
        self.assertIn(("ANTHROPIC_BASE_URL", "http://localhost:8080", "claude_code"), result)
        self.assertIn(("ANTHROPIC_BASE_URL", "http://localhost:8080", "aider"), result)


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
            patch("lumen_argus_core.setup.manifest._BACKUP_DIR", os.path.join(self.tmpdir, "backups")),
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
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
            patch("lumen_argus_core.setup.manifest._BACKUP_DIR", os.path.join(self.tmpdir, "backups")),
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            add_env_to_shell_profile("OPENAI_BASE_URL", "http://localhost:8080", "aider", self.profile)
            change = add_env_to_shell_profile("OPENAI_BASE_URL", "http://localhost:8080", "aider", self.profile)
        self.assertIsNone(change)

    def test_dry_run(self):
        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
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
        # Stop ``disable_protection`` from invoking the host's real
        # ``launchctl unsetenv`` during the test — otherwise a macOS
        # dev machine running the suite silently loses its shell
        # env vars (ANTHROPIC_BASE_URL, OPENAI_BASE_URL, …) on every
        # run.  The two tests that care about the snapshot contract
        # install their own fake in a nested ``with patch(...)``
        # block; mock.patch layering ensures those still win.
        self._launchctl_patch = patch("lumen_argus_core.setup_wizard.clear_launchctl_env_vars", return_value=[])
        self._launchctl_patch.start()
        self.addCleanup(self._launchctl_patch.stop)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_enable_writes_all_env_vars(self):
        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            result = enable_protection("http://localhost:8080")
        self.assertTrue(result["enabled"])
        self.assertGreater(result["env_vars_set"], 0)
        self.assertTrue(os.path.isfile(self.env_file))
        with open(self.env_file) as f:
            content = f.read()
        self.assertIn("ANTHROPIC_BASE_URL", content)
        self.assertIn("OPENAI_BASE_URL", content)

    def test_enable_default_is_cli_mode(self):
        """Calling `enable_protection` with no kwargs picks CLI mode — the
        safe default for anyone running the binary from a terminal.
        """
        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            result = enable_protection("http://localhost:8080")
            with open(self.env_file) as f:
                content = f.read()
        self.assertEqual(result["managed_by"], "cli")
        self.assertIn("(cli)", content)
        # No liveness guard tokens — user owns the lifecycle.
        for guard_token in ("_la_active", "kill -0", ".app-path"):
            self.assertNotIn(guard_token, content)

    def test_enable_tray_mode_emits_guarded_body(self):
        """Tray / enrollment callers opt into the self-healing guard."""
        from lumen_argus_core.env_template import ManagedBy

        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            result = enable_protection("http://localhost:8080", managed_by=ManagedBy.TRAY)
            with open(self.env_file) as f:
                content = f.read()
        self.assertEqual(result["managed_by"], "tray")
        self.assertIn("(tray)", content)
        for expected in ("_la_active=0", "kill -0", ".app-path", "enrollment.json", "relay.json"):
            self.assertIn(expected, content)

    def test_write_env_file_preserves_tray_mode_when_caller_is_silent(self):
        """``add_env_to_env_file`` is a low-level mutator that does not
        know the lifecycle mode.  If a TRAY-guarded file already exists,
        the next write (via ``write_env_file`` without ``managed_by``)
        must keep it TRAY — otherwise ``setup`` silently strips the
        self-healing guard from every enrolled machine.  This pins that
        invariant at the seam where agent #3 originally flagged the
        regression.
        """
        from lumen_argus_core.env_template import ManagedBy
        from lumen_argus_core.setup_wizard import add_env_to_env_file, write_env_file

        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            # Seed the file in tray mode (as an enrollment flow would).
            write_env_file(
                [("ANTHROPIC_BASE_URL", "http://127.0.0.1:8070", "claude_code")],
                managed_by=ManagedBy.TRAY,
            )
            # A subsequent mutation that knows nothing about the mode.
            add_env_to_env_file("OPENAI_BASE_URL", "http://127.0.0.1:8070", "aider")
            with open(self.env_file) as f:
                content = f.read()

        self.assertIn("(tray)", content)
        self.assertIn("_la_active=0", content)
        # The newly-added export is inside the guard, not below it.
        self.assertIn("  export OPENAI_BASE_URL=http://127.0.0.1:8070", content)

    def test_write_env_file_defaults_to_cli_when_no_file_exists(self):
        """Fresh machine, no ``managed_by`` supplied → CLI default."""
        from lumen_argus_core.setup_wizard import write_env_file

        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            write_env_file([("ANTHROPIC_BASE_URL", "http://localhost:8080", "claude_code")])
            with open(self.env_file) as f:
                content = f.read()
        self.assertIn("(cli)", content)
        self.assertNotIn("_la_active", content)

    def test_status_exposes_managed_by_when_enabled(self):
        """``protection status`` must surface the mode so tray / dashboard
        consumers can verify the file they are looking at is the one they
        wrote.  The documented contract in docs/reference/protection-env-file.md
        is "the chosen mode is echoed back in the status dict".
        """
        from lumen_argus_core.env_template import ManagedBy

        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            enable_protection("http://localhost:8080", managed_by=ManagedBy.TRAY)
            result = protection_status()
        self.assertTrue(result["enabled"])
        self.assertEqual(result["managed_by"], "tray")

    def test_status_managed_by_is_none_when_disabled(self):
        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            result = protection_status()
        self.assertFalse(result["enabled"])
        self.assertIsNone(result["managed_by"])

    def test_disable_truncates_env_file(self):
        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            enable_protection("http://localhost:8080")
            result = disable_protection()
        self.assertFalse(result["enabled"])
        self.assertEqual(result["env_vars_set"], 0)
        with open(self.env_file) as f:
            content = f.read()
        self.assertEqual(content, "")

    def test_disable_clears_launchctl_with_snapshot_from_env_file(self):
        """Regression guard: launchctl cleanup must read the env file
        BEFORE the truncate — if the order flipped, the cleared list
        would always be empty and the GUI session would keep pointing
        at the proxy.  The snapshot+clear pair is what the uninstall
        spec's F2 step promises.
        """
        cleared_calls: list[list[str]] = []

        def fake_clear(names):
            # Record the exact input the caller passed so we can prove
            # we got names, not an empty list from a post-truncate read.
            cleared_calls.append(list(names))
            return list(names)

        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
            patch("lumen_argus_core.setup_wizard.clear_launchctl_env_vars", fake_clear),
        ):
            enable_protection("http://localhost:8080")
            result = disable_protection()

        self.assertEqual(len(cleared_calls), 1)
        # At least the two canonical env vars must be in the snapshot.
        snapshot = cleared_calls[0]
        self.assertIn("ANTHROPIC_BASE_URL", snapshot)
        self.assertIn("OPENAI_BASE_URL", snapshot)
        # And the status dict must expose what was cleared.
        self.assertIn("launchctl_vars_cleared", result)
        self.assertIn("ANTHROPIC_BASE_URL", result["launchctl_vars_cleared"])

    def test_disable_on_empty_file_clears_nothing(self):
        """Idempotent: disable on an already-disabled machine calls
        launchctl with an empty list and returns an empty cleared list.
        """
        cleared_calls: list[list[str]] = []

        def fake_clear(names):
            cleared_calls.append(list(names))
            return list(names)

        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
            patch("lumen_argus_core.setup_wizard.clear_launchctl_env_vars", fake_clear),
        ):
            result = disable_protection()

        self.assertEqual(cleared_calls, [[]])
        self.assertEqual(result["launchctl_vars_cleared"], [])

    def test_status_enabled(self):
        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            enable_protection("http://localhost:8080")
            result = protection_status()
        self.assertTrue(result["enabled"])
        self.assertGreater(result["env_vars_set"], 0)

    def test_status_disabled(self):
        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            result = protection_status()
        self.assertFalse(result["enabled"])
        self.assertEqual(result["env_vars_set"], 0)

    def test_enable_disable_cycle(self):
        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            enable_protection()
            self.assertTrue(protection_status()["enabled"])
            disable_protection()
            self.assertFalse(protection_status()["enabled"])
            enable_protection()
            self.assertTrue(protection_status()["enabled"])

    def test_status_counts_orphan_lines(self):
        """A file with only orphans must still report enabled=True.

        Before the read_env_file regex loosening, an env file containing
        lines written by a non-conformant external writer (no client=<id>
        suffix) would be invisible to protection_status() — reporting
        env_vars_set=0 while the shell actively sourced the exports. This
        pins the corrected behavior.
        """
        with open(self.env_file, "w") as f:
            f.write(
                "export ANTHROPIC_BASE_URL='http://127.0.0.1:8070'  # lumen-argus:managed\n"
                "export OPENAI_BASE_URL='http://127.0.0.1:8070'  # lumen-argus:managed\n"
            )
        with (
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
            patch("lumen_argus_core.setup.env_file._ARGUS_DIR", self.tmpdir),
        ):
            result = protection_status()
        self.assertTrue(result["enabled"])
        self.assertEqual(result["env_vars_set"], 2)


class TestUpdateIdeSettings(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.settings_file = os.path.join(self.tmpdir, "settings.json")
        with open(self.settings_file, "w") as f:
            json.dump({"editor.fontSize": 14}, f)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_adds_key(self):
        with patch("lumen_argus_core.setup.manifest._BACKUP_DIR", os.path.join(self.tmpdir, "backups")):
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
        with patch("lumen_argus_core.setup.manifest._BACKUP_DIR", os.path.join(self.tmpdir, "backups")):
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
            patch("lumen_argus_core.setup.manifest._MANIFEST_PATH", manifest),
            patch("lumen_argus_core.setup.manifest._BACKUP_DIR", backup_dir),
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
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
            patch("lumen_argus_core.setup.manifest._MANIFEST_PATH", manifest),
            patch("lumen_argus_core.setup.manifest._BACKUP_DIR", backup_dir),
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
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
            patch("lumen_argus_core.setup.manifest._MANIFEST_PATH", manifest),
            patch("lumen_argus_core.setup.manifest._BACKUP_DIR", backup_dir),
            patch("lumen_argus_core.setup.env_file._ENV_FILE", self.env_file),
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
        with patch("lumen_argus_core.setup.manifest._BACKUP_DIR", os.path.join(self.tmpdir, "backups")):
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
        with patch("lumen_argus_core.setup.manifest._BACKUP_DIR", os.path.join(self.tmpdir, "backups")):
            install_shell_hook(self.profile)

        mock_profiles = {"zsh": (self.profile,)}
        manifest = os.path.join(self.tmpdir, "manifest.json")
        backup_dir = os.path.join(self.tmpdir, "backups")
        env_file = os.path.join(self.tmpdir, "env")
        with (
            patch("lumen_argus_core.setup_wizard._SHELL_PROFILES", mock_profiles),
            patch("lumen_argus_core.setup.manifest._MANIFEST_PATH", manifest),
            patch("lumen_argus_core.setup.manifest._BACKUP_DIR", backup_dir),
            patch("lumen_argus_core.setup.env_file._ENV_FILE", env_file),
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
