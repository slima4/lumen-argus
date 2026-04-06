"""Tests for MCP server detection from AI tool config files."""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from lumen_argus_core.detect import (
    _parse_mcp_server,
    _read_mcp_config,
    _strip_jsonc_comments,
    detect_mcp_servers,
)
from lumen_argus_core.detect_models import MCPConfigSource, MCPDetectionReport, MCPServerEntry


class TestParseMCPServer(unittest.TestCase):
    """Test _parse_mcp_server for individual server entry parsing."""

    def _source(self, **kwargs):
        defaults = {
            "tool_id": "test",
            "display_name": "Test",
            "config_paths": ("/tmp/test.json",),
            "json_key": "mcpServers",
            "scope": "global",
        }
        defaults.update(kwargs)
        return MCPConfigSource(**defaults)

    def test_stdio_server(self):
        entry = _parse_mcp_server(
            "filesystem",
            {"command": "npx", "args": ["-y", "@mcp/server-filesystem", "/tmp"]},
            self._source(),
            "/tmp/test.json",
        )
        self.assertIsNotNone(entry)
        self.assertEqual(entry.name, "filesystem")
        self.assertEqual(entry.transport, "stdio")
        self.assertEqual(entry.command, "npx")
        self.assertEqual(entry.args, ["-y", "@mcp/server-filesystem", "/tmp"])
        self.assertFalse(entry.scanning_enabled)

    def test_http_server(self):
        entry = _parse_mcp_server(
            "remote",
            {"url": "http://localhost:3000/mcp"},
            self._source(),
            "/tmp/test.json",
        )
        self.assertIsNotNone(entry)
        self.assertEqual(entry.transport, "http")
        self.assertEqual(entry.url, "http://localhost:3000/mcp")
        self.assertEqual(entry.command, "")

    def test_https_server(self):
        entry = _parse_mcp_server(
            "remote",
            {"url": "https://mcp.example.com/api"},
            self._source(),
            "/tmp/test.json",
        )
        self.assertEqual(entry.transport, "http")

    def test_websocket_server(self):
        entry = _parse_mcp_server(
            "ws-server",
            {"url": "ws://localhost:9000/mcp"},
            self._source(),
            "/tmp/test.json",
        )
        self.assertEqual(entry.transport, "ws")

    def test_wrapped_server_detected(self):
        entry = _parse_mcp_server(
            "filesystem",
            {
                "command": "lumen-argus",
                "args": ["mcp", "--", "npx", "-y", "@mcp/server-fs", "/data"],
            },
            self._source(),
            "/tmp/test.json",
        )
        self.assertTrue(entry.scanning_enabled)
        self.assertEqual(entry.original_command, "npx")
        self.assertEqual(entry.original_args, ["-y", "@mcp/server-fs", "/data"])
        # Wrapped server should not expose wrapper command/args
        self.assertEqual(entry.command, "")
        self.assertEqual(entry.args, [])

    def test_wrapped_via_agent(self):
        entry = _parse_mcp_server(
            "fs",
            {
                "command": "lumen-argus-agent",
                "args": ["mcp", "--", "python", "server.py"],
            },
            self._source(),
            "/tmp/test.json",
        )
        self.assertTrue(entry.scanning_enabled)
        self.assertEqual(entry.original_command, "python")

    def test_lumen_argus_non_mcp_not_wrapped(self):
        """lumen-argus command without 'mcp --' is not considered wrapped."""
        entry = _parse_mcp_server(
            "other",
            {"command": "lumen-argus", "args": ["serve"]},
            self._source(),
            "/tmp/test.json",
        )
        self.assertFalse(entry.scanning_enabled)

    def test_env_preserved(self):
        entry = _parse_mcp_server(
            "db",
            {"command": "python", "args": ["db_server.py"], "env": {"DB_URL": "postgres://..."}},
            self._source(),
            "/tmp/test.json",
        )
        self.assertEqual(entry.env, {"DB_URL": "postgres://..."})

    def test_no_command_no_url_returns_none(self):
        entry = _parse_mcp_server(
            "empty",
            {"description": "nothing here"},
            self._source(),
            "/tmp/test.json",
        )
        self.assertIsNone(entry)

    def test_invalid_args_type_defaults_to_empty(self):
        entry = _parse_mcp_server(
            "bad",
            {"command": "node", "args": "not-a-list"},
            self._source(),
            "/tmp/test.json",
        )
        self.assertEqual(entry.args, [])

    def test_invalid_env_type_defaults_to_empty(self):
        entry = _parse_mcp_server(
            "bad",
            {"command": "node", "env": "not-a-dict"},
            self._source(),
            "/tmp/test.json",
        )
        self.assertEqual(entry.env, {})

    def test_upstream_wrapping_detected(self):
        """HTTP bridge mode via --upstream is detected as scanning."""
        entry = _parse_mcp_server(
            "remote",
            {
                "command": "lumen-argus",
                "args": ["mcp", "--upstream", "http://localhost:3000/mcp"],
            },
            self._source(),
            "/tmp/test.json",
        )
        self.assertTrue(entry.scanning_enabled)
        # No original command for HTTP bridge mode
        self.assertEqual(entry.original_command, "")

    def test_env_redacted_in_to_dict(self):
        """Env values must be redacted in serialized output."""
        entry = MCPServerEntry(
            name="db",
            transport="stdio",
            command="python",
            env={"OPENAI_API_KEY": "sk-secret123", "DEBUG": "1"},
        )
        d = entry.to_dict()
        self.assertEqual(d["env"]["OPENAI_API_KEY"], "[REDACTED]")
        self.assertEqual(d["env"]["DEBUG"], "[REDACTED]")

    def test_source_metadata_propagated(self):
        source = self._source(tool_id="claude_desktop", scope="global")
        entry = _parse_mcp_server("fs", {"command": "npx"}, source, "/path/to/config.json")
        self.assertEqual(entry.source_tool, "claude_desktop")
        self.assertEqual(entry.config_path, "/path/to/config.json")
        self.assertEqual(entry.scope, "global")


class TestReadMCPConfig(unittest.TestCase):
    """Test _read_mcp_config for config file reading."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_config(self, data, name="config.json"):
        path = os.path.join(self.tmpdir, name)
        with open(path, "w") as f:
            json.dump(data, f)
        return path

    def _source(self, json_key="mcpServers"):
        return MCPConfigSource(
            tool_id="test",
            display_name="Test",
            config_paths=(),
            json_key=json_key,
            scope="global",
        )

    def test_reads_mcp_servers(self):
        path = self._write_config(
            {
                "mcpServers": {
                    "fs": {"command": "npx", "args": ["@mcp/fs"]},
                    "db": {"command": "python", "args": ["db.py"]},
                }
            }
        )
        entries = _read_mcp_config(path, self._source())
        self.assertEqual(len(entries), 2)
        names = {e.name for e in entries}
        self.assertEqual(names, {"fs", "db"})

    def test_missing_file_returns_empty(self):
        entries = _read_mcp_config("/nonexistent/path.json", self._source())
        self.assertEqual(entries, [])

    def test_invalid_json_returns_empty(self):
        path = os.path.join(self.tmpdir, "bad.json")
        with open(path, "w") as f:
            f.write("{invalid json")
        entries = _read_mcp_config(path, self._source())
        self.assertEqual(entries, [])

    def test_no_mcp_servers_key_returns_empty(self):
        path = self._write_config({"otherKey": {}})
        entries = _read_mcp_config(path, self._source())
        self.assertEqual(entries, [])

    def test_mcp_servers_not_dict_returns_empty(self):
        path = self._write_config({"mcpServers": "not a dict"})
        entries = _read_mcp_config(path, self._source())
        self.assertEqual(entries, [])

    def test_dot_path_key(self):
        """Handles nested keys like 'mcp.servers'."""
        path = self._write_config({"mcp": {"servers": {"fs": {"command": "node", "args": ["fs.js"]}}}})
        entries = _read_mcp_config(path, self._source(json_key="mcp.servers"))
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].name, "fs")

    def test_jsonc_with_comments(self):
        """Config files with // comments are handled."""
        path = os.path.join(self.tmpdir, "config.jsonc")
        with open(path, "w") as f:
            f.write("// MCP config\n")
            f.write("{\n")
            f.write("  // servers\n")
            f.write('  "mcpServers": {\n')
            f.write('    "fs": {"command": "npx"}\n')
            f.write("  }\n")
            f.write("}\n")
        entries = _read_mcp_config(path, self._source())
        self.assertEqual(len(entries), 1)

    def test_jsonc_trailing_comments(self):
        """Trailing // comments on value lines are stripped."""
        path = os.path.join(self.tmpdir, "trailing.json")
        with open(path, "w") as f:
            f.write("{\n")
            f.write('  "mcpServers": {\n')
            f.write('    "fs": {"command": "npx"} // filesystem server\n')
            f.write("  }\n")
            f.write("}\n")
        entries = _read_mcp_config(path, self._source())
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].name, "fs")

    def test_jsonc_preserves_urls_in_strings(self):
        """// inside string values (URLs) must not be stripped."""
        path = os.path.join(self.tmpdir, "url.json")
        with open(path, "w") as f:
            f.write("{\n")
            f.write('  "mcpServers": {\n')
            f.write('    "remote": {"url": "http://localhost:3000/mcp"}\n')
            f.write("  }\n")
            f.write("}\n")
        entries = _read_mcp_config(path, self._source())
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].url, "http://localhost:3000/mcp")

    def test_skips_non_dict_entries(self):
        path = self._write_config(
            {
                "mcpServers": {
                    "good": {"command": "npx"},
                    "bad": "not a dict",
                    "also_bad": 42,
                }
            }
        )
        entries = _read_mcp_config(path, self._source())
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].name, "good")


class TestStripJSONCComments(unittest.TestCase):
    """Test _strip_jsonc_comments for correct comment stripping."""

    def test_full_line_comment(self):
        self.assertEqual(_strip_jsonc_comments("// comment\n{}"), "\n{}")

    def test_trailing_comment(self):
        result = _strip_jsonc_comments('{"key": "value"} // comment\n')
        self.assertEqual(result, '{"key": "value"} \n')

    def test_url_in_string_preserved(self):
        text = '{"url": "http://localhost:3000/mcp"}'
        self.assertEqual(_strip_jsonc_comments(text), text)

    def test_double_slash_in_string_preserved(self):
        text = '{"path": "//network/share"}'
        self.assertEqual(_strip_jsonc_comments(text), text)

    def test_escaped_quote_in_string(self):
        text = r'{"msg": "say \"hello\" // not a comment"}'
        self.assertEqual(_strip_jsonc_comments(text), text)

    def test_comment_after_string_with_slashes(self):
        text = '{"url": "http://x"} // comment'
        self.assertEqual(_strip_jsonc_comments(text), '{"url": "http://x"} ')

    def test_escaped_backslash_at_end_of_string(self):
        # "\\" is a string containing one backslash; closing " is not escaped
        text = r'{"path": "C:\\"}'
        self.assertEqual(_strip_jsonc_comments(text), text)

    def test_escaped_backslash_then_comment(self):
        text = '{"path": "C:\\\\"} // comment\n'
        self.assertEqual(_strip_jsonc_comments(text), '{"path": "C:\\\\"} \n')

    def test_no_comments(self):
        text = '{"key": "value"}'
        self.assertEqual(_strip_jsonc_comments(text), text)

    def test_empty_string(self):
        self.assertEqual(_strip_jsonc_comments(""), "")


def _no_plugins():
    """Patch helper: suppress real plugin detection in tests."""
    return patch("lumen_argus_core.detect._detect_claude_code_plugins", return_value=([], []))


class TestDetectMCPServers(unittest.TestCase):
    """Test detect_mcp_servers end-to-end."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_returns_report_with_empty_sources(self):
        """With no config files found, returns empty report."""
        with patch("lumen_argus_core.mcp_configs.GLOBAL_MCP_SOURCES", ()):
            with patch("lumen_argus_core.mcp_configs.PROJECT_MCP_SOURCES", ()):
                with _no_plugins():
                    report = detect_mcp_servers()
        self.assertIsInstance(report, MCPDetectionReport)
        self.assertIsInstance(report.servers, list)
        self.assertTrue(report.platform)

    def test_detects_servers_from_global_config(self):
        cfg_path = os.path.join(self.tmpdir, "claude_config.json")
        with open(cfg_path, "w") as f:
            json.dump(
                {
                    "mcpServers": {
                        "filesystem": {"command": "npx", "args": ["@mcp/fs"]},
                        "web": {"url": "http://localhost:3000"},
                    }
                },
                f,
            )

        source = MCPConfigSource(
            tool_id="claude_desktop",
            display_name="Claude Desktop",
            config_paths=(cfg_path,),
            json_key="mcpServers",
            scope="global",
        )

        with patch("lumen_argus_core.mcp_configs.GLOBAL_MCP_SOURCES", (source,)):
            with patch("lumen_argus_core.mcp_configs.PROJECT_MCP_SOURCES", ()):
                with _no_plugins():
                    report = detect_mcp_servers()

        self.assertEqual(report.total_detected, 2)
        self.assertEqual(report.total_scanning, 0)
        names = {s.name for s in report.servers}
        self.assertEqual(names, {"filesystem", "web"})

    def test_detects_project_level_config(self):
        project_dir = os.path.join(self.tmpdir, "project")
        os.makedirs(project_dir)
        cfg_path = os.path.join(project_dir, ".mcp.json")
        with open(cfg_path, "w") as f:
            json.dump({"mcpServers": {"local-tool": {"command": "python", "args": ["tool.py"]}}}, f)

        source = MCPConfigSource(
            tool_id="claude_code",
            display_name="Claude Code (project)",
            config_paths=(".mcp.json",),
            json_key="mcpServers",
            scope="project",
        )

        with patch("lumen_argus_core.mcp_configs.GLOBAL_MCP_SOURCES", ()):
            with patch("lumen_argus_core.mcp_configs.PROJECT_MCP_SOURCES", (source,)):
                with _no_plugins():
                    report = detect_mcp_servers(project_dirs=[project_dir])

        # Should find the project-level server (may also check CWD)
        project_servers = [s for s in report.servers if s.scope == "project"]
        self.assertTrue(len(project_servers) >= 1)
        self.assertEqual(project_servers[0].name, "local-tool")

    def test_scanning_count(self):
        cfg_path = os.path.join(self.tmpdir, "config.json")
        with open(cfg_path, "w") as f:
            json.dump(
                {
                    "mcpServers": {
                        "unwrapped": {"command": "npx", "args": ["server"]},
                        "wrapped": {
                            "command": "lumen-argus",
                            "args": ["mcp", "--", "npx", "server"],
                        },
                    }
                },
                f,
            )

        source = MCPConfigSource(
            tool_id="test",
            display_name="Test",
            config_paths=(cfg_path,),
            json_key="mcpServers",
            scope="global",
        )

        with patch("lumen_argus_core.mcp_configs.GLOBAL_MCP_SOURCES", (source,)):
            with patch("lumen_argus_core.mcp_configs.PROJECT_MCP_SOURCES", ()):
                with _no_plugins():
                    report = detect_mcp_servers()

        self.assertEqual(report.total_detected, 2)
        self.assertEqual(report.total_scanning, 1)

    def test_deduplicates_project_dirs(self):
        """Same directory passed twice should not produce duplicates."""
        project_dir = os.path.join(self.tmpdir, "proj")
        os.makedirs(project_dir)
        cfg_path = os.path.join(project_dir, ".mcp.json")
        with open(cfg_path, "w") as f:
            json.dump({"mcpServers": {"t": {"command": "node"}}}, f)

        source = MCPConfigSource(
            tool_id="cc",
            display_name="CC",
            config_paths=(".mcp.json",),
            json_key="mcpServers",
            scope="project",
        )

        real_cfg = os.path.realpath(cfg_path)
        with patch("lumen_argus_core.mcp_configs.GLOBAL_MCP_SOURCES", ()):
            with patch("lumen_argus_core.mcp_configs.PROJECT_MCP_SOURCES", (source,)):
                with _no_plugins():
                    report = detect_mcp_servers(project_dirs=[project_dir, project_dir])

        project_servers = [s for s in report.servers if os.path.realpath(s.config_path) == real_cfg]
        self.assertEqual(len(project_servers), 1)

    def test_deduplicates_same_server_from_multiple_configs(self):
        """Same server name from same tool in multiple config files → last wins."""
        cfg1 = os.path.join(self.tmpdir, "config1.json")
        with open(cfg1, "w") as f:
            json.dump({"mcpServers": {"github": {"command": "docker", "args": ["run", "old-image"]}}}, f)

        cfg2 = os.path.join(self.tmpdir, "config2.json")
        with open(cfg2, "w") as f:
            json.dump({"mcpServers": {"github": {"command": "docker", "args": ["run", "new-image"]}}}, f)

        source = MCPConfigSource(
            tool_id="claude_code",
            display_name="Claude Code",
            config_paths=(cfg1, cfg2),
            json_key="mcpServers",
            scope="global",
        )

        with patch("lumen_argus_core.mcp_configs.GLOBAL_MCP_SOURCES", (source,)):
            with patch("lumen_argus_core.mcp_configs.PROJECT_MCP_SOURCES", ()):
                with _no_plugins():
                    report = detect_mcp_servers()

        github_servers = [s for s in report.servers if s.name == "github"]
        self.assertEqual(len(github_servers), 1)
        # Last config wins
        self.assertEqual(github_servers[0].args, ["run", "new-image"])

    def test_no_dedup_across_different_tools(self):
        """Same server name from different tools should NOT be deduped."""
        cfg1 = os.path.join(self.tmpdir, "claude.json")
        with open(cfg1, "w") as f:
            json.dump({"mcpServers": {"fs": {"command": "npx", "args": ["@mcp/fs"]}}}, f)

        cfg2 = os.path.join(self.tmpdir, "cursor.json")
        with open(cfg2, "w") as f:
            json.dump({"mcpServers": {"fs": {"command": "npx", "args": ["@mcp/fs"]}}}, f)

        source1 = MCPConfigSource(
            tool_id="claude_code",
            display_name="Claude Code",
            config_paths=(cfg1,),
            json_key="mcpServers",
            scope="global",
        )
        source2 = MCPConfigSource(
            tool_id="cursor",
            display_name="Cursor",
            config_paths=(cfg2,),
            json_key="mcpServers",
            scope="global",
        )

        with patch("lumen_argus_core.mcp_configs.GLOBAL_MCP_SOURCES", (source1, source2)):
            with patch("lumen_argus_core.mcp_configs.PROJECT_MCP_SOURCES", ()):
                with _no_plugins():
                    report = detect_mcp_servers()

        fs_servers = [s for s in report.servers if s.name == "fs"]
        self.assertEqual(len(fs_servers), 2)

    def test_to_dict_serialization(self):
        entry = MCPServerEntry(
            name="fs",
            transport="stdio",
            command="npx",
            args=["@mcp/fs"],
            source_tool="claude_desktop",
            config_path="/tmp/config.json",
            scope="global",
        )
        report = MCPDetectionReport(
            servers=[entry],
            platform="Darwin arm64",
            total_detected=1,
            total_scanning=0,
            config_files_checked=["/tmp/config.json"],
        )
        d = report.to_dict()
        self.assertEqual(d["total_detected"], 1)
        self.assertEqual(len(d["servers"]), 1)
        self.assertEqual(d["servers"][0]["name"], "fs")
        # Should be JSON-serializable
        json.dumps(d)


class TestClaudeCodeDetection(unittest.TestCase):
    """Test Claude Code MCP server detection from ~/.claude.json."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_detects_servers_from_claude_json(self):
        """~/.claude.json mcpServers should be detected."""
        cfg_path = os.path.join(self.tmpdir, ".claude.json")
        with open(cfg_path, "w") as f:
            json.dump(
                {
                    "mcpServers": {
                        "github": {
                            "type": "stdio",
                            "command": "docker",
                            "args": ["run", "-i", "--rm", "ghcr.io/github/github-mcp-server"],
                            "env": {},
                        }
                    },
                    "numStartups": 100,
                },
                f,
            )

        source = MCPConfigSource(
            tool_id="claude_code",
            display_name="Claude Code",
            config_paths=(cfg_path,),
            json_key="mcpServers",
            scope="global",
        )

        with patch("lumen_argus_core.mcp_configs.GLOBAL_MCP_SOURCES", (source,)):
            with patch("lumen_argus_core.mcp_configs.PROJECT_MCP_SOURCES", ()):
                with _no_plugins():
                    report = detect_mcp_servers()

        self.assertEqual(report.total_detected, 1)
        server = report.servers[0]
        self.assertEqual(server.name, "github")
        self.assertEqual(server.command, "docker")
        self.assertEqual(server.source_tool, "claude_code")

    def test_both_claude_json_and_settings_json(self):
        """Servers from both ~/.claude.json and ~/.claude/settings.json are detected."""
        claude_json = os.path.join(self.tmpdir, ".claude.json")
        with open(claude_json, "w") as f:
            json.dump({"mcpServers": {"github": {"command": "docker", "args": ["run", "ghcr.io/github/mcp"]}}}, f)

        settings_json = os.path.join(self.tmpdir, "settings.json")
        with open(settings_json, "w") as f:
            json.dump({"mcpServers": {"local-tool": {"command": "python", "args": ["tool.py"]}}}, f)

        source = MCPConfigSource(
            tool_id="claude_code",
            display_name="Claude Code",
            config_paths=(claude_json, settings_json),
            json_key="mcpServers",
            scope="global",
        )

        with patch("lumen_argus_core.mcp_configs.GLOBAL_MCP_SOURCES", (source,)):
            with patch("lumen_argus_core.mcp_configs.PROJECT_MCP_SOURCES", ()):
                with _no_plugins():
                    report = detect_mcp_servers()

        self.assertEqual(report.total_detected, 2)
        names = {s.name for s in report.servers}
        self.assertEqual(names, {"github", "local-tool"})

    def test_claude_json_with_non_mcp_keys_ignored(self):
        """Non-mcpServers keys in ~/.claude.json are ignored."""
        cfg_path = os.path.join(self.tmpdir, ".claude.json")
        with open(cfg_path, "w") as f:
            json.dump(
                {
                    "numStartups": 212,
                    "installMethod": "native",
                    "hooks": {"PreToolUse": []},
                    "enabledPlugins": {"serena@claude-plugins-official": True},
                },
                f,
            )

        source = MCPConfigSource(
            tool_id="claude_code",
            display_name="Claude Code",
            config_paths=(cfg_path,),
            json_key="mcpServers",
            scope="global",
        )

        with patch("lumen_argus_core.mcp_configs.GLOBAL_MCP_SOURCES", (source,)):
            with patch("lumen_argus_core.mcp_configs.PROJECT_MCP_SOURCES", ()):
                with _no_plugins():
                    report = detect_mcp_servers()

        self.assertEqual(report.total_detected, 0)


class TestClaudeCodePluginDetection(unittest.TestCase):
    """Test detection of MCP servers provided by Claude Code plugins."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.claude_dir = os.path.join(self.tmpdir, ".claude")
        self.plugins_dir = os.path.join(self.claude_dir, "plugins")
        self.cache_dir = os.path.join(self.plugins_dir, "cache")
        os.makedirs(self.cache_dir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_json(self, path, data):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f)

    def _setup_plugin(self, plugin_id, mcp_data, enabled=True):
        """Create installed plugin with .mcp.json and enable it."""
        parts = plugin_id.split("@")
        name = parts[0]
        marketplace = parts[1] if len(parts) > 1 else "default"
        install_path = os.path.join(self.cache_dir, marketplace, name, "unknown")
        os.makedirs(install_path, exist_ok=True)

        # Write .mcp.json
        self._write_json(os.path.join(install_path, ".mcp.json"), mcp_data)

        # Write installed_plugins.json
        installed_path = os.path.join(self.plugins_dir, "installed_plugins.json")
        if os.path.isfile(installed_path):
            with open(installed_path) as f:
                installed = json.load(f)
        else:
            installed = {"version": 2, "plugins": {}}
        installed["plugins"][plugin_id] = [{"scope": "user", "installPath": install_path, "version": "unknown"}]
        self._write_json(installed_path, installed)

        # Write settings.json with enabledPlugins
        settings_path = os.path.join(self.claude_dir, "settings.json")
        if os.path.isfile(settings_path):
            with open(settings_path) as f:
                settings = json.load(f)
        else:
            settings = {}
        settings.setdefault("enabledPlugins", {})[plugin_id] = enabled
        self._write_json(settings_path, settings)

        return install_path

    def test_detects_plugin_stdio_server(self):
        """Plugin with stdio MCP server (top-level keys, no wrapper)."""
        self._setup_plugin(
            "serena@claude-plugins-official",
            {"serena": {"command": "uvx", "args": ["--from", "git+https://github.com/oraios/serena", "serena"]}},
        )

        with patch("lumen_argus_core.detect.os.path.expanduser") as mock_expand:
            mock_expand.side_effect = lambda p: p.replace("~", self.tmpdir)
            with patch("lumen_argus_core.mcp_configs.GLOBAL_MCP_SOURCES", ()):
                with patch("lumen_argus_core.mcp_configs.PROJECT_MCP_SOURCES", ()):
                    report = detect_mcp_servers()

        plugin_servers = [s for s in report.servers if s.source_tool == "claude_code_plugin"]
        self.assertEqual(len(plugin_servers), 1)
        self.assertEqual(plugin_servers[0].name, "serena")
        self.assertEqual(plugin_servers[0].command, "uvx")
        self.assertEqual(plugin_servers[0].transport, "stdio")
        self.assertIn("serena", plugin_servers[0].config_path)

    def test_detects_plugin_http_server(self):
        """Plugin with HTTP MCP server (top-level keys)."""
        self._setup_plugin(
            "greptile@claude-plugins-official",
            {"greptile": {"type": "http", "url": "https://api.greptile.com/mcp"}},
        )

        with patch("lumen_argus_core.detect.os.path.expanduser") as mock_expand:
            mock_expand.side_effect = lambda p: p.replace("~", self.tmpdir)
            with patch("lumen_argus_core.mcp_configs.GLOBAL_MCP_SOURCES", ()):
                with patch("lumen_argus_core.mcp_configs.PROJECT_MCP_SOURCES", ()):
                    report = detect_mcp_servers()

        plugin_servers = [s for s in report.servers if s.source_tool == "claude_code_plugin"]
        self.assertEqual(len(plugin_servers), 1)
        self.assertEqual(plugin_servers[0].name, "greptile")
        self.assertEqual(plugin_servers[0].transport, "http")
        self.assertEqual(plugin_servers[0].url, "https://api.greptile.com/mcp")

    def test_detects_plugin_with_mcpservers_wrapper(self):
        """Plugin .mcp.json using mcpServers wrapper key."""
        self._setup_plugin(
            "playwright@skills",
            {
                "mcpServers": {
                    "pw-testrail": {"command": "npx", "args": ["tsx", "index.ts"]},
                    "pw-browserstack": {"command": "npx", "args": ["tsx", "bs.ts"]},
                }
            },
        )

        with patch("lumen_argus_core.detect.os.path.expanduser") as mock_expand:
            mock_expand.side_effect = lambda p: p.replace("~", self.tmpdir)
            with patch("lumen_argus_core.mcp_configs.GLOBAL_MCP_SOURCES", ()):
                with patch("lumen_argus_core.mcp_configs.PROJECT_MCP_SOURCES", ()):
                    report = detect_mcp_servers()

        plugin_servers = [s for s in report.servers if s.source_tool == "claude_code_plugin"]
        self.assertEqual(len(plugin_servers), 2)
        names = {s.name for s in plugin_servers}
        self.assertEqual(names, {"pw-testrail", "pw-browserstack"})

    def test_skips_disabled_plugins(self):
        """Disabled plugins should not have their MCP servers detected."""
        self._setup_plugin(
            "serena@claude-plugins-official",
            {"serena": {"command": "uvx", "args": ["serena"]}},
            enabled=False,
        )

        with patch("lumen_argus_core.detect.os.path.expanduser") as mock_expand:
            mock_expand.side_effect = lambda p: p.replace("~", self.tmpdir)
            with patch("lumen_argus_core.mcp_configs.GLOBAL_MCP_SOURCES", ()):
                with patch("lumen_argus_core.mcp_configs.PROJECT_MCP_SOURCES", ()):
                    report = detect_mcp_servers()

        plugin_servers = [s for s in report.servers if s.source_tool == "claude_code_plugin"]
        self.assertEqual(len(plugin_servers), 0)

    def test_skips_plugins_without_mcp_json(self):
        """Plugins that don't have .mcp.json should be skipped silently."""
        install_path = os.path.join(self.cache_dir, "marketplace", "no-mcp", "unknown")
        os.makedirs(install_path, exist_ok=True)
        # No .mcp.json created

        self._write_json(
            os.path.join(self.plugins_dir, "installed_plugins.json"),
            {"version": 2, "plugins": {"no-mcp@marketplace": [{"installPath": install_path, "version": "unknown"}]}},
        )
        self._write_json(
            os.path.join(self.claude_dir, "settings.json"),
            {"enabledPlugins": {"no-mcp@marketplace": True}},
        )

        with patch("lumen_argus_core.detect.os.path.expanduser") as mock_expand:
            mock_expand.side_effect = lambda p: p.replace("~", self.tmpdir)
            with patch("lumen_argus_core.mcp_configs.GLOBAL_MCP_SOURCES", ()):
                with patch("lumen_argus_core.mcp_configs.PROJECT_MCP_SOURCES", ()):
                    report = detect_mcp_servers()

        self.assertEqual(report.total_detected, 0)

    def test_no_installed_plugins_json(self):
        """Missing installed_plugins.json should not crash."""
        # Don't create any files
        with patch("lumen_argus_core.detect.os.path.expanduser") as mock_expand:
            mock_expand.side_effect = lambda p: p.replace("~", self.tmpdir)
            with patch("lumen_argus_core.mcp_configs.GLOBAL_MCP_SOURCES", ()):
                with patch("lumen_argus_core.mcp_configs.PROJECT_MCP_SOURCES", ()):
                    report = detect_mcp_servers()

        self.assertEqual(report.total_detected, 0)

    def test_display_name_includes_plugin_name(self):
        """Display name should include the plugin name for clarity."""
        self._setup_plugin(
            "serena@claude-plugins-official",
            {"serena": {"command": "uvx", "args": ["serena"]}},
        )

        with patch("lumen_argus_core.detect.os.path.expanduser") as mock_expand:
            mock_expand.side_effect = lambda p: p.replace("~", self.tmpdir)
            with patch("lumen_argus_core.mcp_configs.GLOBAL_MCP_SOURCES", ()):
                with patch("lumen_argus_core.mcp_configs.PROJECT_MCP_SOURCES", ()):
                    report = detect_mcp_servers()

        # The source_tool should be claude_code_plugin (tool_id for grouping)
        server = report.servers[0]
        self.assertEqual(server.source_tool, "claude_code_plugin")


class TestVSCodeDetection(unittest.TestCase):
    """Test VS Code MCP server detection (uses 'servers' key, not 'mcpServers')."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_detects_vscode_global_servers(self):
        cfg_path = os.path.join(self.tmpdir, "mcp.json")
        with open(cfg_path, "w") as f:
            json.dump(
                {
                    "servers": {
                        "filesystem": {
                            "type": "stdio",
                            "command": "npx",
                            "args": ["-y", "@mcp/fs"],
                        },
                        "api": {
                            "type": "http",
                            "url": "http://localhost:3000/mcp",
                        },
                    }
                },
                f,
            )

        source = MCPConfigSource(
            tool_id="vscode",
            display_name="VS Code",
            config_paths=(cfg_path,),
            json_key="servers",
            scope="global",
        )

        with patch("lumen_argus_core.mcp_configs.GLOBAL_MCP_SOURCES", (source,)):
            with patch("lumen_argus_core.mcp_configs.PROJECT_MCP_SOURCES", ()):
                with _no_plugins():
                    report = detect_mcp_servers()

        self.assertEqual(report.total_detected, 2)
        names = {s.name for s in report.servers}
        self.assertEqual(names, {"filesystem", "api"})

        stdio = [s for s in report.servers if s.name == "filesystem"][0]
        self.assertEqual(stdio.transport, "stdio")
        self.assertEqual(stdio.command, "npx")
        self.assertEqual(stdio.source_tool, "vscode")

        http = [s for s in report.servers if s.name == "api"][0]
        self.assertEqual(http.transport, "http")
        self.assertEqual(http.url, "http://localhost:3000/mcp")

    def test_detects_vscode_workspace_servers(self):
        project_dir = os.path.join(self.tmpdir, "project")
        vscode_dir = os.path.join(project_dir, ".vscode")
        os.makedirs(vscode_dir)
        cfg_path = os.path.join(vscode_dir, "mcp.json")
        with open(cfg_path, "w") as f:
            json.dump(
                {"servers": {"local-db": {"type": "stdio", "command": "python", "args": ["db_server.py"]}}},
                f,
            )

        source = MCPConfigSource(
            tool_id="vscode",
            display_name="VS Code (workspace)",
            config_paths=(".vscode/mcp.json",),
            json_key="servers",
            scope="project",
        )

        with patch("lumen_argus_core.mcp_configs.GLOBAL_MCP_SOURCES", ()):
            with patch("lumen_argus_core.mcp_configs.PROJECT_MCP_SOURCES", (source,)):
                with _no_plugins():
                    report = detect_mcp_servers(project_dirs=[project_dir])

        project_servers = [s for s in report.servers if s.scope == "project"]
        self.assertTrue(len(project_servers) >= 1)
        self.assertEqual(project_servers[0].name, "local-db")
        self.assertEqual(project_servers[0].source_tool, "vscode")

    def test_vscode_with_env_and_inputs(self):
        """VS Code configs can have env and inputs — env should be detected, inputs ignored."""
        cfg_path = os.path.join(self.tmpdir, "mcp.json")
        with open(cfg_path, "w") as f:
            json.dump(
                {
                    "servers": {
                        "custom": {
                            "type": "stdio",
                            "command": "node",
                            "args": ["server.js"],
                            "env": {"API_KEY": "secret-123"},
                        },
                    },
                    "inputs": [{"type": "promptString", "id": "api-key"}],
                },
                f,
            )

        source = MCPConfigSource(
            tool_id="vscode",
            display_name="VS Code",
            config_paths=(cfg_path,),
            json_key="servers",
            scope="global",
        )

        with patch("lumen_argus_core.mcp_configs.GLOBAL_MCP_SOURCES", (source,)):
            with patch("lumen_argus_core.mcp_configs.PROJECT_MCP_SOURCES", ()):
                with _no_plugins():
                    report = detect_mcp_servers()

        self.assertEqual(report.total_detected, 1)
        server = report.servers[0]
        self.assertEqual(server.env, {"API_KEY": "secret-123"})
        # to_dict should redact env values
        d = server.to_dict()
        self.assertEqual(d["env"], {"API_KEY": "[REDACTED]"})


if __name__ == "__main__":
    unittest.main()
