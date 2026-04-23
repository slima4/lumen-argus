"""MCP server setup — wrap/unwrap MCP servers through lumen-argus scanning proxy.

Rewrites AI tool config files (Claude Desktop, Claude Code, Cursor, etc.) to
route MCP servers through lumen-argus for DLP scanning:

- **Stdio servers**: ``lumen-argus mcp -- <original-command>``
- **HTTP/WS servers**: ``lumen-argus mcp --upstream <original-url>``
  (converts URL-based server to stdio bridge — AI tool manages lifecycle)

All file modifications follow the same patterns as ``setup.manifest``:
timestamped backups, append-only manifest, idempotent operations.
"""

from __future__ import annotations

import json
import logging
import os
import stat
import tempfile
from typing import Any

from lumen_argus_core.detect import detect_mcp_servers, load_jsonc
from lumen_argus_core.detect_models import MCPServerEntry
from lumen_argus_core.fleet_policies import FleetPolicies, load_fleet_policies
from lumen_argus_core.mcp_configs import GLOBAL_MCP_SOURCES, PROJECT_MCP_SOURCES
from lumen_argus_core.setup._models import SetupChange
from lumen_argus_core.setup.manifest import _backup_file, _save_manifest
from lumen_argus_core.time_utils import now_iso

log = logging.getLogger("argus.setup.mcp")

# Commands that indicate the server is already wrapped
_WRAPPER_COMMANDS = {"lumen-argus", "lumen-argus-agent"}

_WRAPPER_COMMAND = "lumen-argus"


# ---------------------------------------------------------------------------
# CLI dispatch helper (shared by proxy and agent CLIs)
# ---------------------------------------------------------------------------


def dispatch_mcp_setup(args: Any) -> None:
    """CLI dispatch for ``setup --mcp``. Called from both proxy and agent CLIs."""
    if getattr(args, "undo", False):
        count = undo_mcp_setup(
            server_name=getattr(args, "server", ""),
            source_tool=getattr(args, "source", ""),
        )
        if count:
            print("Unwrapped %d MCP server(s)." % count)
        else:
            print("No wrapped MCP servers found.")
        return
    run_mcp_setup(
        server_name=getattr(args, "server", ""),
        source_tool=getattr(args, "source", ""),
        non_interactive=getattr(args, "non_interactive", False),
        dry_run=getattr(args, "dry_run", False),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_mcp_setup(
    server_name: str = "",
    source_tool: str = "",
    non_interactive: bool = False,
    dry_run: bool = False,
) -> list[SetupChange]:
    """Detect MCP servers and wrap selected ones through lumen-argus mcp.

    Args:
        server_name: Wrap only this server (empty = all detected).
        source_tool: Filter by source tool ID (e.g. "claude_desktop").
        non_interactive: Auto-approve all wrapping without prompting.
        dry_run: Show what would change without modifying files.

    Returns:
        List of SetupChange records for each wrapped server.
    """
    report = detect_mcp_servers()
    policies = load_fleet_policies()
    candidates = _filter_wrappable(report.servers, server_name, source_tool)

    if not candidates:
        if server_name or source_tool:
            log.info("no matching unwrapped MCP servers found")
            print("No matching unwrapped MCP servers found.")
        else:
            log.info("no unwrapped MCP servers detected")
            print("No unwrapped MCP servers detected.")
        return []

    # Apply fleet policies: separate blocked, must_scan, and normal servers
    blocked, must_scan, normal = _apply_fleet_policies(candidates, policies)

    # Warn about blocked servers
    for server, reason in blocked:
        log.warning("fleet policy blocks %s: %s", server.name, reason)
        print("  [!] %s — blocked by fleet policy%s" % (server.name, " (%s)" % reason if reason else ""))

    candidates = must_scan + normal

    if not candidates:
        if not blocked:
            log.info("no wrappable MCP servers after fleet policy filtering")
            print("No wrappable MCP servers found.")
        return []

    must_scan_names = {s.name for s in must_scan}

    log.info(
        "found %d wrappable MCP server(s)%s%s",
        len(candidates),
        " (%d must_scan)" % len(must_scan) if must_scan else "",
        " [dry-run]" if dry_run else "",
    )

    changes: list[SetupChange] = []
    for server in candidates:
        if server.name in must_scan_names:
            # must_scan servers are auto-wrapped without prompting
            log.info("auto-wrapping %s (fleet policy: must_scan)", server.name)
        elif not non_interactive and not dry_run:
            if not _prompt_wrap(server):
                log.debug("user skipped %s (%s)", server.name, server.source_tool)
                continue

        json_key = _get_json_key_for_config(server.config_path)
        if not json_key:
            log.warning(
                "unknown config format for %s — skipping %s",
                server.config_path,
                server.name,
            )
            continue

        change = wrap_mcp_server(server.config_path, server.name, json_key, dry_run=dry_run)
        if change:
            changes.append(change)
            action = "[dry-run] would wrap" if dry_run else "wrapped"
            print("  [+] %s %s (%s)" % (action, server.name, server.source_tool))

    if changes and not dry_run:
        _save_manifest(changes)

    _print_summary(changes, dry_run)
    return changes


def undo_mcp_setup(
    server_name: str = "",
    source_tool: str = "",
) -> int:
    """Unwrap MCP servers by restoring original commands.

    Args:
        server_name: Unwrap only this server (empty = all wrapped).
        source_tool: Filter by source tool ID.

    Returns:
        Number of servers unwrapped.
    """
    report = detect_mcp_servers()
    wrapped = [
        s
        for s in report.servers
        if s.scanning_enabled
        and (not server_name or s.name == server_name)
        and (not source_tool or s.source_tool == source_tool)
    ]

    if not wrapped:
        log.info("no wrapped MCP servers found to unwrap")
        return 0

    log.info("found %d wrapped MCP server(s) to unwrap", len(wrapped))

    changes: list[SetupChange] = []
    for server in wrapped:
        json_key = _get_json_key_for_config(server.config_path)
        if not json_key:
            log.warning("unknown config format for %s — skipping", server.config_path)
            continue

        change = unwrap_mcp_server(server.config_path, server.name, json_key)
        if change:
            changes.append(change)
            log.info("unwrapped %s (%s)", server.name, server.source_tool)

    if changes:
        _save_manifest(changes)

    return len(changes)


# ---------------------------------------------------------------------------
# Single-server operations
# ---------------------------------------------------------------------------


def wrap_mcp_server(
    config_path: str,
    server_name: str,
    json_key: str,
    dry_run: bool = False,
) -> SetupChange | None:
    """Wrap a single MCP server in a config file.

    Re-reads the config file fresh (not relying on stale detection data)
    to avoid race conditions between detection and modification.

    Returns None if the server is already wrapped or not found.
    """
    data = load_jsonc(config_path)
    if not data:
        log.warning("could not read config: %s", config_path)
        return None

    servers = _navigate_json_key(data, json_key)
    if not isinstance(servers, dict) or server_name not in servers:
        log.warning("server %s not found in %s", server_name, config_path)
        return None

    server_def = servers[server_name]
    if not isinstance(server_def, dict):
        return None

    if _is_wrapped(server_def):
        log.debug("server %s already wrapped — skipping", server_name)
        return None

    command = server_def.get("command", "")
    url = server_def.get("url", "")
    args = server_def.get("args", [])

    if not isinstance(args, list):
        args = []

    if command:
        # Stdio server: wrap via mcp -- <cmd> <args>
        detail = "wrapped %s: %s → %s mcp -- %s" % (server_name, command, _WRAPPER_COMMAND, command)
        wrap_args = ["mcp", "--", command, *args]
    elif url:
        # HTTP/WS server: wrap via mcp --upstream <url> (bridge mode)
        detail = "wrapped %s: %s → %s mcp --upstream %s" % (server_name, url, _WRAPPER_COMMAND, url)
        wrap_args = ["mcp", "--upstream", url]
    else:
        log.debug("server %s has no command or url — skipping", server_name)
        return None

    if dry_run:
        log.info("[dry-run] would wrap %s in %s", server_name, config_path)
        return SetupChange(
            timestamp=now_iso(),
            client_id="mcp:%s:%s" % (_source_tool_from_path(config_path), server_name),
            method="mcp_wrap",
            file=config_path,
            detail=detail,
        )

    backup_path = _backup_file(config_path)

    # Rewrite the server entry
    server_def["command"] = _WRAPPER_COMMAND
    server_def["args"] = wrap_args
    if url:
        # Remove url field — server is now a stdio bridge process
        server_def.pop("url", None)

    _write_json_config(config_path, data)
    log.info("wrapped %s in %s (backup: %s)", server_name, config_path, backup_path)

    return SetupChange(
        timestamp=now_iso(),
        client_id="mcp:%s:%s" % (_source_tool_from_path(config_path), server_name),
        method="mcp_wrap",
        file=config_path,
        detail=detail,
        backup_path=backup_path,
    )


def unwrap_mcp_server(
    config_path: str,
    server_name: str,
    json_key: str,
) -> SetupChange | None:
    """Unwrap a single MCP server by restoring the original command.

    Extracts the original command and args from the wrapped args list
    (everything after the ``--`` separator).

    Returns None if the server is not wrapped or not found.
    """
    data = load_jsonc(config_path)
    if not data:
        log.warning("could not read config: %s", config_path)
        return None

    servers = _navigate_json_key(data, json_key)
    if not isinstance(servers, dict) or server_name not in servers:
        log.warning("server %s not found in %s", server_name, config_path)
        return None

    server_def = servers[server_name]
    if not isinstance(server_def, dict):
        return None

    if not _is_wrapped(server_def):
        log.debug("server %s not wrapped — skipping", server_name)
        return None

    args = server_def.get("args", [])
    original_url = ""

    if "--" in args:
        # Stdio wrapping: restore original command + args
        original_command, original_args = _extract_original(args)
        if not original_command:
            log.warning("could not extract original command for %s — skipping", server_name)
            return None
        detail = "unwrapped %s: %s mcp -- %s → %s" % (
            server_name,
            _WRAPPER_COMMAND,
            original_command,
            " ".join([original_command, *original_args]) if original_args else original_command,
        )
    elif "--upstream" in args:
        # HTTP/WS bridge wrapping: restore original URL
        original_url = _extract_original_url(args)
        if not original_url:
            log.warning("could not extract original URL for %s — skipping", server_name)
            return None
        original_command = ""
        original_args = []
        detail = "unwrapped %s: %s mcp --upstream → %s" % (server_name, _WRAPPER_COMMAND, original_url)
    else:
        log.warning("wrapped server %s has no -- or --upstream — skipping", server_name)
        return None

    backup_path = _backup_file(config_path)

    if "--upstream" in args:
        # HTTP/WS: restore url, remove command/args
        server_def["url"] = original_url
        server_def.pop("command", None)
        server_def.pop("args", None)
    else:
        # Stdio: restore command/args
        server_def["command"] = original_command
        server_def["args"] = original_args

    _write_json_config(config_path, data)
    log.info("unwrapped %s in %s (backup: %s)", server_name, config_path, backup_path)

    return SetupChange(
        timestamp=now_iso(),
        client_id="mcp:%s:%s" % (_source_tool_from_path(config_path), server_name),
        method="mcp_unwrap",
        file=config_path,
        detail=detail,
        backup_path=backup_path,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _apply_fleet_policies(
    servers: list[MCPServerEntry],
    policies: FleetPolicies | None,
) -> tuple[list[tuple[MCPServerEntry, str]], list[MCPServerEntry], list[MCPServerEntry]]:
    """Partition servers by fleet policy: blocked, must_scan, normal.

    Returns:
        Tuple of (blocked_with_reason, must_scan, normal).
    """
    if not policies:
        return [], [], list(servers)

    blocked: list[tuple[MCPServerEntry, str]] = []
    must_scan: list[MCPServerEntry] = []
    normal: list[MCPServerEntry] = []

    for server in servers:
        policy = policies.get_server_policy(server.name)
        if policy == "blocked":
            sp = next((sp for sp in policies.server_policies if sp.server_name == server.name), None)
            reason = sp.reason if sp else ""
            blocked.append((server, reason))
        elif policy == "must_scan":
            must_scan.append(server)
        else:
            # allowed, review, or no specific policy → normal flow
            normal.append(server)

    return blocked, must_scan, normal


def _filter_wrappable(
    servers: list[MCPServerEntry],
    server_name: str,
    source_tool: str,
) -> list[MCPServerEntry]:
    """Filter to unwrapped servers that can be wrapped, optionally by name and source.

    Stdio servers are wrapped via ``mcp -- <cmd>``.
    HTTP/WS servers are wrapped via ``mcp --upstream <url>`` (bridge mode).
    """
    result = []
    for s in servers:
        if s.scanning_enabled:
            continue  # already wrapped
        if s.transport == "stdio" and not s.command:
            continue  # malformed stdio entry
        if s.transport in ("http", "ws") and not s.url:
            continue  # malformed http/ws entry
        if s.transport not in ("stdio", "http", "ws"):
            continue  # unknown transport
        if server_name and s.name != server_name:
            continue
        if source_tool and s.source_tool != source_tool:
            continue
        result.append(s)
    return result


def _navigate_json_key(data: dict[str, Any], key: str) -> dict[str, Any] | None:
    """Navigate a dot-separated JSON key path. Returns the target dict or None."""
    obj: Any = data
    for part in key.split("."):
        if isinstance(obj, dict):
            obj = obj.get(part)
        else:
            return None
    return obj if isinstance(obj, dict) else None


def _get_json_key_for_config(config_path: str) -> str:
    """Look up the json_key for a config path from the MCP source registry."""
    real_path = os.path.realpath(config_path)
    for source in (*GLOBAL_MCP_SOURCES, *PROJECT_MCP_SOURCES):
        for cfg_path in source.config_paths:
            expanded = os.path.realpath(os.path.expanduser(cfg_path))
            if expanded == real_path:
                return source.json_key
    # Fallback: most tools use "mcpServers"
    log.warning("no registry match for %s — falling back to 'mcpServers' key", config_path)
    return "mcpServers"


def _write_json_config(path: str, data: dict[str, Any]) -> None:
    """Write JSON config atomically via temp file + rename.

    Preserves the original file's permissions when overwriting.
    """
    dir_path = os.path.dirname(path)
    # Capture original permissions before overwrite
    try:
        orig_mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        orig_mode = None

    fd, tmp_path = tempfile.mkstemp(dir=dir_path, prefix=".mcp.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        if orig_mode is not None:
            os.chmod(tmp_path, orig_mode)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _is_wrapped(server_def: dict[str, Any]) -> bool:
    """Check if a server definition is already wrapped through lumen-argus."""
    command = server_def.get("command", "")
    args = server_def.get("args", [])
    if command not in _WRAPPER_COMMANDS:
        return False
    if not isinstance(args, list) or not args or args[0] != "mcp":
        return False
    return "--" in args or "--upstream" in args


def _extract_original(args: list[str]) -> tuple[str, list[str]]:
    """Extract the original command and args from a stdio-wrapped args list.

    Expects: ["mcp", "--", "original_cmd", "arg1", "arg2"]
    Returns: ("original_cmd", ["arg1", "arg2"])
    """
    if "--" not in args:
        return "", []
    idx = args.index("--")
    remaining = args[idx + 1 :]
    if not remaining:
        return "", []
    return remaining[0], remaining[1:]


def _extract_original_url(args: list[str]) -> str:
    """Extract the original upstream URL from a bridge-wrapped args list.

    Expects: ["mcp", "--upstream", "http://example.com/mcp"]
    Returns: "http://example.com/mcp"
    """
    if "--upstream" not in args:
        return ""
    idx = args.index("--upstream")
    if idx + 1 < len(args):
        return args[idx + 1]
    return ""


def _source_tool_from_path(config_path: str) -> str:
    """Derive source_tool ID from a config path via the registry."""
    real_path = os.path.realpath(config_path)
    for source in (*GLOBAL_MCP_SOURCES, *PROJECT_MCP_SOURCES):
        for cfg_path in source.config_paths:
            expanded = os.path.realpath(os.path.expanduser(cfg_path))
            if expanded == real_path:
                return source.tool_id
    return "unknown"


def _prompt_wrap(server: MCPServerEntry) -> bool:
    """Prompt user to wrap an MCP server. Returns True if approved."""
    source = server.source_tool.replace("_", " ").title()
    identifier = server.command or server.url or server.transport
    try:
        answer = input("  Wrap '%s' (%s, %s) through lumen-argus scanning? [y/N] " % (server.name, source, identifier))
        return answer.strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def _print_summary(changes: list[SetupChange], dry_run: bool) -> None:
    """Print setup summary."""
    if not changes:
        return
    prefix = "[dry-run] " if dry_run else ""
    print("\n%s%d MCP server(s) %s." % (prefix, len(changes), "would be wrapped" if dry_run else "wrapped"))
    if not dry_run:
        print("Run 'lumen-argus-agent setup --mcp --undo' to restore original configuration.")

    # Warn about JSONC comment loss
    has_comments = False
    for c in changes:
        if c.file.endswith((".jsonc",)):
            has_comments = True
            break
    if has_comments:
        print("\n  [!] Note: JSON comments are not preserved after wrapping.")
        print("      Backups saved in ~/.lumen-argus/setup/backups/")
