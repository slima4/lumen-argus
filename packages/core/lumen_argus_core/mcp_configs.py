"""MCP server config source registry — where AI tools store MCP server definitions.

Maps each AI tool to its config file path(s), the JSON key that holds
mcpServers entries, and platform-specific location variants.
"""

from __future__ import annotations

import os
import platform

from lumen_argus_core.detect_models import MCPConfigSource

# ---------------------------------------------------------------------------
# Per-tool config sources
# ---------------------------------------------------------------------------

_SYSTEM = platform.system()


def _home(*parts: str) -> str:
    return os.path.join("~", *parts)


def _app_support(*parts: str) -> str:
    """macOS ~/Library/Application Support/<parts>."""
    return os.path.join("~", "Library", "Application Support", *parts)


def _xdg_config(*parts: str) -> str:
    """Linux ~/.config/<parts>."""
    return os.path.join("~", ".config", *parts)


def _appdata(*parts: str) -> str:
    """Windows %APPDATA%/<parts>."""
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        return os.path.join(appdata, *parts)
    # Fallback when APPDATA is unset
    return os.path.join("~", "AppData", "Roaming", *parts)


def _platform_paths(*variants: tuple[str, str, str]) -> tuple[str, ...]:
    """Pick paths for the current platform from (macOS, Linux, Windows) tuples.

    Filters out empty strings.
    """
    idx = {"Darwin": 0, "Linux": 1, "Windows": 2}.get(_SYSTEM, 1)
    return tuple(v[idx] for v in variants if v[idx])


# --- Claude Desktop ---

_CLAUDE_DESKTOP = MCPConfigSource(
    tool_id="claude_desktop",
    display_name="Claude Desktop",
    config_paths=_platform_paths(
        (
            _app_support("Claude", "claude_desktop_config.json"),
            _xdg_config("Claude", "claude_desktop_config.json"),
            _appdata("Claude", "claude_desktop_config.json"),
        ),
    ),
    json_key="mcpServers",
    scope="global",
)

# --- Claude Code (global settings) ---

_CLAUDE_CODE_GLOBAL = MCPConfigSource(
    tool_id="claude_code",
    display_name="Claude Code",
    config_paths=(_home(".claude", "settings.json"),),
    json_key="mcpServers",
    scope="global",
)

# --- Claude Code (project-level) ---

_CLAUDE_CODE_PROJECT = MCPConfigSource(
    tool_id="claude_code",
    display_name="Claude Code (project)",
    config_paths=(".mcp.json",),  # relative to project dir
    json_key="mcpServers",
    scope="project",
)

# --- Cursor ---

_CURSOR = MCPConfigSource(
    tool_id="cursor",
    display_name="Cursor",
    config_paths=(_home(".cursor", "mcp.json"),),
    json_key="mcpServers",
    scope="global",
)

# --- Windsurf ---

_WINDSURF = MCPConfigSource(
    tool_id="windsurf",
    display_name="Windsurf",
    config_paths=(_home(".windsurf", "mcp.json"),),
    json_key="mcpServers",
    scope="global",
)

# --- Cline ---

_CLINE = MCPConfigSource(
    tool_id="cline",
    display_name="Cline",
    config_paths=(_home(".cline", "mcp_servers.json"),),
    json_key="mcpServers",
    scope="global",
    supports_http=False,
)

# --- Roo Code ---

_ROO_CODE = MCPConfigSource(
    tool_id="roo_code",
    display_name="Roo Code",
    config_paths=(_home(".roo-code", "mcp.json"),),
    json_key="mcpServers",
    scope="global",
)

# --- VS Code ---
# VS Code uses a dedicated mcp.json file (not settings.json).
# JSON key is "servers" (not "mcpServers" like other tools).

_VSCODE = MCPConfigSource(
    tool_id="vscode",
    display_name="VS Code",
    config_paths=_platform_paths(
        (
            _app_support("Code", "User", "mcp.json"),
            _xdg_config("Code", "User", "mcp.json"),
            _appdata("Code", "User", "mcp.json"),
        ),
    ),
    json_key="servers",
    scope="global",
)

_VSCODE_WORKSPACE = MCPConfigSource(
    tool_id="vscode",
    display_name="VS Code (workspace)",
    config_paths=(".vscode/mcp.json",),
    json_key="servers",
    scope="project",
)

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

# Global config sources — always checked
GLOBAL_MCP_SOURCES: tuple[MCPConfigSource, ...] = (
    _CLAUDE_DESKTOP,
    _CLAUDE_CODE_GLOBAL,
    _CURSOR,
    _WINDSURF,
    _CLINE,
    _ROO_CODE,
    _VSCODE,
)

# Project-scoped sources — checked per directory
PROJECT_MCP_SOURCES: tuple[MCPConfigSource, ...] = (
    _CLAUDE_CODE_PROJECT,
    _VSCODE_WORKSPACE,
)
