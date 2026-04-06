"""Tests for MCP server setup — wrapping/unwrapping through lumen-argus mcp."""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from lumen_argus_core.detect_models import MCPServerEntry
from lumen_argus_core.mcp_setup import (
    _extract_original,
    _is_wrapped,
    _navigate_json_key,
    _write_json_config,
    run_mcp_setup,
    undo_mcp_setup,
    unwrap_mcp_server,
    wrap_mcp_server,
)


class TestIsWrapped(unittest.TestCase):
    """Test _is_wrapped detection logic."""

    def test_unwrapped_server(self):
        self.assertFalse(_is_wrapped({"command": "npx", "args": ["@mcp/fs"]}))

    def test_wrapped_stdio(self):
        self.assertTrue(_is_wrapped({"command": "lumen-argus", "args": ["mcp", "--", "npx", "@mcp/fs"]}))

    def test_wrapped_upstream(self):
        self.assertTrue(_is_wrapped({"command": "lumen-argus", "args": ["mcp", "--upstream", "http://localhost:3000"]}))

    def test_wrapped_via_agent(self):
        self.assertTrue(_is_wrapped({"command": "lumen-argus-agent", "args": ["mcp", "--", "python", "server.py"]}))

    def test_lumen_argus_non_mcp(self):
        self.assertFalse(_is_wrapped({"command": "lumen-argus", "args": ["serve"]}))

    def test_empty_args(self):
        self.assertFalse(_is_wrapped({"command": "lumen-argus", "args": []}))

    def test_no_command(self):
        self.assertFalse(_is_wrapped({"url": "http://localhost:3000"}))


class TestExtractOriginal(unittest.TestCase):
    """Test _extract_original for parsing wrapped args."""

    def test_standard_wrap(self):
        cmd, args = _extract_original(["mcp", "--", "npx", "-y", "@mcp/fs"])
        self.assertEqual(cmd, "npx")
        self.assertEqual(args, ["-y", "@mcp/fs"])

    def test_no_separator(self):
        cmd, args = _extract_original(["mcp", "--upstream", "http://x"])
        self.assertEqual(cmd, "")
        self.assertEqual(args, [])

    def test_separator_at_end(self):
        cmd, args = _extract_original(["mcp", "--"])
        self.assertEqual(cmd, "")
        self.assertEqual(args, [])

    def test_command_only(self):
        cmd, args = _extract_original(["mcp", "--", "python"])
        self.assertEqual(cmd, "python")
        self.assertEqual(args, [])


class TestNavigateJsonKey(unittest.TestCase):
    """Test _navigate_json_key dot-path traversal."""

    def test_simple_key(self):
        data = {"mcpServers": {"fs": {}}}
        self.assertEqual(_navigate_json_key(data, "mcpServers"), {"fs": {}})

    def test_dot_path(self):
        data = {"mcp": {"servers": {"fs": {}}}}
        self.assertEqual(_navigate_json_key(data, "mcp.servers"), {"fs": {}})

    def test_missing_key(self):
        self.assertIsNone(_navigate_json_key({"other": {}}, "mcpServers"))

    def test_non_dict_intermediate(self):
        self.assertIsNone(_navigate_json_key({"mcp": "string"}, "mcp.servers"))


class TestWrapMCPServer(unittest.TestCase):
    """Test wrap_mcp_server for single-server wrapping."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.backup_dir = os.path.join(self.tmpdir, "backups")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_config(self, data, name="config.json"):
        path = os.path.join(self.tmpdir, name)
        with open(path, "w") as f:
            json.dump(data, f)
        return path

    def _read_config(self, path):
        with open(path) as f:
            return json.load(f)

    @patch("lumen_argus_core.mcp_setup._backup_file")
    def test_wraps_stdio_server(self, mock_backup):
        mock_backup.return_value = "/tmp/backup"
        path = self._write_config(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@mcp/server-filesystem", "/tmp"],
                        "env": {"DEBUG": "1"},
                    }
                }
            }
        )

        change = wrap_mcp_server(path, "filesystem", "mcpServers")

        self.assertIsNotNone(change)
        self.assertEqual(change.method, "mcp_wrap")
        self.assertIn("filesystem", change.detail)

        # Verify file was rewritten
        data = self._read_config(path)
        server = data["mcpServers"]["filesystem"]
        self.assertEqual(server["command"], "lumen-argus")
        self.assertEqual(server["args"], ["mcp", "--", "npx", "-y", "@mcp/server-filesystem", "/tmp"])
        self.assertEqual(server["env"], {"DEBUG": "1"})

    @patch("lumen_argus_core.mcp_setup._backup_file")
    def test_idempotent_already_wrapped(self, mock_backup):
        path = self._write_config(
            {
                "mcpServers": {
                    "fs": {
                        "command": "lumen-argus",
                        "args": ["mcp", "--", "npx", "@mcp/fs"],
                    }
                }
            }
        )

        change = wrap_mcp_server(path, "fs", "mcpServers")
        self.assertIsNone(change)
        mock_backup.assert_not_called()

    def test_dry_run_no_modification(self):
        path = self._write_config({"mcpServers": {"fs": {"command": "npx", "args": ["@mcp/fs"]}}})
        original = self._read_config(path)

        change = wrap_mcp_server(path, "fs", "mcpServers", dry_run=True)

        self.assertIsNotNone(change)
        self.assertEqual(change.method, "mcp_wrap")
        # File should NOT be modified
        self.assertEqual(self._read_config(path), original)

    def test_server_not_found(self):
        path = self._write_config({"mcpServers": {"other": {"command": "npx"}}})
        change = wrap_mcp_server(path, "nonexistent", "mcpServers")
        self.assertIsNone(change)

    def test_missing_file(self):
        change = wrap_mcp_server("/nonexistent/path.json", "fs", "mcpServers")
        self.assertIsNone(change)

    def test_http_server_skipped(self):
        """Servers with url but no command should be skipped."""
        path = self._write_config({"mcpServers": {"remote": {"url": "http://localhost:3000"}}})
        change = wrap_mcp_server(path, "remote", "mcpServers")
        self.assertIsNone(change)

    @patch("lumen_argus_core.mcp_setup._backup_file")
    def test_preserves_other_servers(self, mock_backup):
        """Wrapping one server should not affect others."""
        mock_backup.return_value = "/tmp/backup"
        path = self._write_config(
            {
                "mcpServers": {
                    "target": {"command": "npx", "args": ["target"]},
                    "untouched": {"command": "python", "args": ["other.py"]},
                }
            }
        )

        wrap_mcp_server(path, "target", "mcpServers")

        data = self._read_config(path)
        # Target is wrapped
        self.assertEqual(data["mcpServers"]["target"]["command"], "lumen-argus")
        # Other server untouched
        self.assertEqual(data["mcpServers"]["untouched"]["command"], "python")
        self.assertEqual(data["mcpServers"]["untouched"]["args"], ["other.py"])

    @patch("lumen_argus_core.mcp_setup._backup_file")
    def test_preserves_non_mcp_config(self, mock_backup):
        """Other top-level keys in the config should be preserved."""
        mock_backup.return_value = "/tmp/backup"
        path = self._write_config(
            {
                "globalShortcut": "Ctrl+Space",
                "mcpServers": {"fs": {"command": "npx", "args": ["@mcp/fs"]}},
            }
        )

        wrap_mcp_server(path, "fs", "mcpServers")

        data = self._read_config(path)
        self.assertEqual(data["globalShortcut"], "Ctrl+Space")

    @patch("lumen_argus_core.mcp_setup._backup_file")
    def test_dot_path_key(self, mock_backup):
        mock_backup.return_value = "/tmp/backup"
        path = self._write_config({"mcp": {"servers": {"fs": {"command": "node", "args": ["fs.js"]}}}})

        change = wrap_mcp_server(path, "fs", "mcp.servers")
        self.assertIsNotNone(change)

        data = self._read_config(path)
        self.assertEqual(data["mcp"]["servers"]["fs"]["command"], "lumen-argus")

    @patch("lumen_argus_core.mcp_setup._backup_file")
    def test_client_id_format(self, mock_backup):
        mock_backup.return_value = "/tmp/backup"
        path = self._write_config({"mcpServers": {"fs": {"command": "npx"}}})

        with patch("lumen_argus_core.mcp_setup._source_tool_from_path", return_value="claude_desktop"):
            change = wrap_mcp_server(path, "fs", "mcpServers")

        self.assertEqual(change.client_id, "mcp:claude_desktop:fs")


class TestUnwrapMCPServer(unittest.TestCase):
    """Test unwrap_mcp_server for single-server unwrapping."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_config(self, data):
        path = os.path.join(self.tmpdir, "config.json")
        with open(path, "w") as f:
            json.dump(data, f)
        return path

    def _read_config(self, path):
        with open(path) as f:
            return json.load(f)

    @patch("lumen_argus_core.mcp_setup._backup_file")
    def test_unwraps_server(self, mock_backup):
        mock_backup.return_value = "/tmp/backup"
        path = self._write_config(
            {
                "mcpServers": {
                    "fs": {
                        "command": "lumen-argus",
                        "args": ["mcp", "--", "npx", "-y", "@mcp/fs"],
                        "env": {"KEY": "val"},
                    }
                }
            }
        )

        change = unwrap_mcp_server(path, "fs", "mcpServers")

        self.assertIsNotNone(change)
        self.assertEqual(change.method, "mcp_unwrap")

        data = self._read_config(path)
        server = data["mcpServers"]["fs"]
        self.assertEqual(server["command"], "npx")
        self.assertEqual(server["args"], ["-y", "@mcp/fs"])
        self.assertEqual(server["env"], {"KEY": "val"})

    def test_not_wrapped_returns_none(self):
        path = self._write_config({"mcpServers": {"fs": {"command": "npx", "args": ["@mcp/fs"]}}})
        change = unwrap_mcp_server(path, "fs", "mcpServers")
        self.assertIsNone(change)

    def test_server_not_found(self):
        path = self._write_config({"mcpServers": {}})
        change = unwrap_mcp_server(path, "nonexistent", "mcpServers")
        self.assertIsNone(change)


class TestWriteJsonConfig(unittest.TestCase):
    """Test _write_json_config atomic writes."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_writes_valid_json(self):
        path = os.path.join(self.tmpdir, "test.json")
        data = {"key": "value", "nested": {"a": 1}}
        _write_json_config(path, data)

        with open(path) as f:
            result = json.load(f)
        self.assertEqual(result, data)

    def test_trailing_newline(self):
        path = os.path.join(self.tmpdir, "test.json")
        _write_json_config(path, {"k": "v"})

        with open(path, "rb") as f:
            content = f.read()
        self.assertTrue(content.endswith(b"\n"))

    def test_overwrites_existing(self):
        path = os.path.join(self.tmpdir, "test.json")
        _write_json_config(path, {"old": True})
        _write_json_config(path, {"new": True})

        with open(path) as f:
            result = json.load(f)
        self.assertEqual(result, {"new": True})


class TestRunMCPSetup(unittest.TestCase):
    """Test run_mcp_setup end-to-end."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_config(self, data, name="config.json"):
        path = os.path.join(self.tmpdir, name)
        with open(path, "w") as f:
            json.dump(data, f)
        return path

    @patch("lumen_argus_core.mcp_setup._save_manifest")
    @patch("lumen_argus_core.mcp_setup._backup_file")
    @patch("lumen_argus_core.mcp_setup.detect_mcp_servers")
    def test_non_interactive_wraps_all(self, mock_detect, mock_backup, mock_manifest):
        mock_backup.return_value = "/tmp/backup"
        cfg_path = self._write_config(
            {
                "mcpServers": {
                    "fs": {"command": "npx", "args": ["@mcp/fs"]},
                    "db": {"command": "python", "args": ["db.py"]},
                }
            }
        )

        from lumen_argus_core.detect_models import MCPDetectionReport

        mock_detect.return_value = MCPDetectionReport(
            servers=[
                MCPServerEntry(
                    name="fs",
                    transport="stdio",
                    command="npx",
                    args=["@mcp/fs"],
                    source_tool="test",
                    config_path=cfg_path,
                    scope="global",
                ),
                MCPServerEntry(
                    name="db",
                    transport="stdio",
                    command="python",
                    args=["db.py"],
                    source_tool="test",
                    config_path=cfg_path,
                    scope="global",
                ),
            ],
            platform="test",
            total_detected=2,
            total_scanning=0,
        )

        with patch("lumen_argus_core.mcp_setup._get_json_key_for_config", return_value="mcpServers"):
            changes = run_mcp_setup(non_interactive=True)

        self.assertEqual(len(changes), 2)
        mock_manifest.assert_called_once()

    @patch("lumen_argus_core.mcp_setup.detect_mcp_servers")
    def test_dry_run_no_manifest(self, mock_detect):
        cfg_path = self._write_config({"mcpServers": {"fs": {"command": "npx", "args": ["@mcp/fs"]}}})

        from lumen_argus_core.detect_models import MCPDetectionReport

        mock_detect.return_value = MCPDetectionReport(
            servers=[
                MCPServerEntry(
                    name="fs",
                    transport="stdio",
                    command="npx",
                    args=["@mcp/fs"],
                    source_tool="test",
                    config_path=cfg_path,
                    scope="global",
                ),
            ],
            platform="test",
            total_detected=1,
            total_scanning=0,
        )

        with patch("lumen_argus_core.mcp_setup._get_json_key_for_config", return_value="mcpServers"):
            with patch("lumen_argus_core.mcp_setup._save_manifest") as mock_manifest:
                changes = run_mcp_setup(dry_run=True)

        self.assertEqual(len(changes), 1)
        mock_manifest.assert_not_called()

    @patch("lumen_argus_core.mcp_setup.detect_mcp_servers")
    def test_filters_by_server_name(self, mock_detect):
        cfg_path = self._write_config(
            {
                "mcpServers": {
                    "target": {"command": "npx", "args": ["target"]},
                    "other": {"command": "python", "args": ["other.py"]},
                }
            }
        )

        from lumen_argus_core.detect_models import MCPDetectionReport

        mock_detect.return_value = MCPDetectionReport(
            servers=[
                MCPServerEntry(
                    name="target",
                    transport="stdio",
                    command="npx",
                    args=["target"],
                    source_tool="test",
                    config_path=cfg_path,
                    scope="global",
                ),
                MCPServerEntry(
                    name="other",
                    transport="stdio",
                    command="python",
                    args=["other.py"],
                    source_tool="test",
                    config_path=cfg_path,
                    scope="global",
                ),
            ],
            platform="test",
            total_detected=2,
            total_scanning=0,
        )

        with patch("lumen_argus_core.mcp_setup._get_json_key_for_config", return_value="mcpServers"):
            with patch("lumen_argus_core.mcp_setup._save_manifest"):
                with patch("lumen_argus_core.mcp_setup._backup_file", return_value="/tmp/b"):
                    changes = run_mcp_setup(server_name="target", non_interactive=True)

        self.assertEqual(len(changes), 1)
        self.assertIn("target", changes[0].detail)

    @patch("lumen_argus_core.mcp_setup.detect_mcp_servers")
    def test_skips_http_servers(self, mock_detect):
        from lumen_argus_core.detect_models import MCPDetectionReport

        mock_detect.return_value = MCPDetectionReport(
            servers=[
                MCPServerEntry(
                    name="remote",
                    transport="http",
                    url="http://localhost:3000",
                    source_tool="test",
                    config_path="/tmp/c.json",
                    scope="global",
                ),
            ],
            platform="test",
            total_detected=1,
            total_scanning=0,
        )

        changes = run_mcp_setup(non_interactive=True)
        self.assertEqual(len(changes), 0)

    @patch("lumen_argus_core.mcp_setup.detect_mcp_servers")
    def test_skips_already_wrapped(self, mock_detect):
        from lumen_argus_core.detect_models import MCPDetectionReport

        mock_detect.return_value = MCPDetectionReport(
            servers=[
                MCPServerEntry(
                    name="fs",
                    transport="stdio",
                    scanning_enabled=True,
                    source_tool="test",
                    config_path="/tmp/c.json",
                    scope="global",
                ),
            ],
            platform="test",
            total_detected=1,
            total_scanning=1,
        )

        changes = run_mcp_setup(non_interactive=True)
        self.assertEqual(len(changes), 0)


class TestUndoMCPSetup(unittest.TestCase):
    """Test undo_mcp_setup for unwrapping."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    @patch("lumen_argus_core.mcp_setup._save_manifest")
    @patch("lumen_argus_core.mcp_setup._backup_file")
    @patch("lumen_argus_core.mcp_setup.detect_mcp_servers")
    def test_unwraps_all_wrapped(self, mock_detect, mock_backup, mock_manifest):
        mock_backup.return_value = "/tmp/backup"
        cfg_path = os.path.join(self.tmpdir, "config.json")
        with open(cfg_path, "w") as f:
            json.dump(
                {
                    "mcpServers": {
                        "fs": {"command": "lumen-argus", "args": ["mcp", "--", "npx", "@mcp/fs"]},
                    }
                },
                f,
            )

        from lumen_argus_core.detect_models import MCPDetectionReport

        mock_detect.return_value = MCPDetectionReport(
            servers=[
                MCPServerEntry(
                    name="fs",
                    transport="stdio",
                    scanning_enabled=True,
                    original_command="npx",
                    original_args=["@mcp/fs"],
                    source_tool="test",
                    config_path=cfg_path,
                    scope="global",
                ),
            ],
            platform="test",
            total_detected=1,
            total_scanning=1,
        )

        with patch("lumen_argus_core.mcp_setup._get_json_key_for_config", return_value="mcpServers"):
            count = undo_mcp_setup()

        self.assertEqual(count, 1)

        with open(cfg_path) as f:
            data = json.load(f)
        self.assertEqual(data["mcpServers"]["fs"]["command"], "npx")
        self.assertEqual(data["mcpServers"]["fs"]["args"], ["@mcp/fs"])

    @patch("lumen_argus_core.mcp_setup.detect_mcp_servers")
    def test_nothing_to_unwrap(self, mock_detect):
        from lumen_argus_core.detect_models import MCPDetectionReport

        mock_detect.return_value = MCPDetectionReport(
            servers=[],
            platform="test",
            total_detected=0,
            total_scanning=0,
        )

        count = undo_mcp_setup()
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
