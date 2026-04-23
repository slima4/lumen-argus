"""Data models and constants shared between detect.py and scanners.py.

Extracted to break the circular import between detection orchestration
and install-method scanners.
"""

from __future__ import annotations

import enum
import os
import platform
import re
from dataclasses import asdict, dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# MCP server detection models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MCPConfigSource:
    """Where to find MCP server configuration for a specific AI tool."""

    tool_id: str  # "claude_desktop", "claude_code", "cursor", etc.
    display_name: str  # "Claude Desktop", "Claude Code", etc.
    config_paths: tuple[str, ...]  # Platform-resolved paths (may have fallbacks)
    json_key: str  # "mcpServers" or "mcp.servers" (dot-path for nested)
    scope: str  # "global" | "project"
    supports_http: bool = True  # True if tool supports url-based MCP servers


@dataclass
class MCPServerEntry:
    """A single MCP server discovered from an AI tool's config file."""

    name: str = ""  # Key from mcpServers dict (e.g. "filesystem")
    transport: str = ""  # "stdio" | "http" | "sse"
    command: str = ""  # stdio: "npx", "python", etc.
    args: list[str] = field(default_factory=list)  # stdio: server args
    url: str = ""  # http/sse: "http://localhost:3000/mcp"
    env: dict[str, str] = field(default_factory=dict)  # env vars for server
    source_tool: str = ""  # "claude_desktop" | "cursor" | etc.
    source_display_name: str = ""  # Human-readable source (e.g. "Claude Code Plugin (serena)")
    config_path: str = ""  # Absolute path to config file
    scope: str = ""  # "global" | "project"
    scanning_enabled: bool = False  # True if wrapped through lumen-argus mcp
    original_command: str = ""  # If wrapped (stdio): original command
    original_args: list[str] = field(default_factory=list)  # If wrapped (stdio): original args
    original_url: str = ""  # If wrapped (HTTP/WS bridge): original upstream URL

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Never leak env values — they commonly contain API keys and tokens
        if d.get("env"):
            d["env"] = dict.fromkeys(d["env"], "[REDACTED]")
        return d


@dataclass
class MCPDetectionReport:
    """Aggregate MCP server detection results."""

    servers: list[MCPServerEntry] = field(default_factory=list)
    platform: str = ""
    total_detected: int = 0
    total_scanning: int = 0  # Count with scanning_enabled=True
    config_files_checked: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "total_detected": self.total_detected,
            "total_scanning": self.total_scanning,
            "config_files_checked": self.config_files_checked,
            "servers": [s.to_dict() for s in self.servers],
        }


# ---------------------------------------------------------------------------
# Client detection models
# ---------------------------------------------------------------------------


def format_mcp_table(report: MCPDetectionReport, setup_command: str = "lumen-argus-agent setup --mcp") -> str:
    """Format MCP detection results as a human-readable table.

    Shared by proxy and agent CLIs to avoid duplication.
    """
    lines: list[str] = []
    if report.total_detected == 0:
        lines.append("\nMCP Servers: none detected")
        return "\n".join(lines)

    lines.append("\nMCP Servers (%d detected, %d scanning):\n" % (report.total_detected, report.total_scanning))
    for s in report.servers:
        if s.scanning_enabled:
            marker = "+"
            status = "scanning"
        else:
            marker = "-"
            status = "not scanned"
        source = s.source_display_name or s.source_tool.replace("_", " ").title()
        lines.append("  [%s] %-20s %-7s %-20s %s" % (marker, s.name, s.transport, source, status))

    unscanned = report.total_detected - report.total_scanning
    if unscanned > 0:
        lines.append("\nRun '%s' to scan unprotected MCP servers." % setup_command)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Client detection models
# ---------------------------------------------------------------------------


class InstallMethod(str, enum.Enum):
    """How a client was detected on the system."""

    BINARY = "binary"
    PIP = "pip"
    NPM = "npm"
    BREW = "brew"
    VSCODE_EXT = "vscode_ext"
    APP_BUNDLE = "app_bundle"
    JETBRAINS_PLUGIN = "jetbrains_plugin"
    NEOVIM_PLUGIN = "neovim_plugin"


@dataclass
class DetectedClient:
    """Result of detecting a single AI CLI agent."""

    client_id: str = ""
    display_name: str = ""
    installed: bool = False
    version: str = ""
    install_method: str = ""
    install_path: str = ""
    proxy_configured: bool = False
    proxy_url: str = ""
    proxy_config_location: str = ""
    proxy_config_type: str = ""
    setup_instructions: str = ""
    forward_proxy: bool = False  # True if tool needs HTTPS_PROXY + TLS interception
    website: str = ""
    routing_active: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IDEVariant:
    """VS Code-like IDE variant with extension and settings paths."""

    name: str
    extensions: tuple[str, ...]
    settings: tuple[str, ...]


# VS Code variants and their extensions/settings paths
_VSCODE_VARIANTS: tuple[IDEVariant, ...] = (
    IDEVariant(
        name="VS Code",
        extensions=(
            "~/.vscode/extensions",
            "~/Library/Application Support/Code/User/extensions",
        ),
        settings=(
            "~/Library/Application Support/Code/User/settings.json",
            "~/.config/Code/User/settings.json",
        ),
    ),
    IDEVariant(
        name="VS Code Insiders",
        extensions=("~/.vscode-insiders/extensions",),
        settings=(
            "~/Library/Application Support/Code - Insiders/User/settings.json",
            "~/.config/Code - Insiders/User/settings.json",
        ),
    ),
    IDEVariant(
        name="VSCodium",
        extensions=("~/.vscode-oss/extensions",),
        settings=(
            "~/Library/Application Support/VSCodium/User/settings.json",
            "~/.config/VSCodium/User/settings.json",
        ),
    ),
    IDEVariant(
        name="Cursor",
        extensions=("~/.cursor/extensions",),
        settings=(
            "~/.cursor/User/settings.json",
            "~/Library/Application Support/Cursor/User/settings.json",
        ),
    ),
    IDEVariant(
        name="Windsurf",
        extensions=("~/.windsurf/extensions",),
        settings=(
            "~/.windsurf/User/settings.json",
            "~/Library/Application Support/Windsurf/User/settings.json",
        ),
    ),
    IDEVariant(
        name="Kiro",
        extensions=("~/.kiro/extensions",),
        settings=(
            "~/Library/Application Support/Kiro/User/settings.json",
            "~/.config/Kiro/User/settings.json",
        ),
    ),
    IDEVariant(
        name="Trae",
        extensions=("~/.trae/extensions",),
        settings=(
            "~/Library/Application Support/Trae/User/settings.json",
            "~/.config/Trae/User/settings.json",
        ),
    ),
    IDEVariant(
        name="Antigravity",
        extensions=("~/.antigravity/extensions",),
        settings=(
            "~/Library/Application Support/Antigravity/User/settings.json",
            "~/.config/Antigravity/User/settings.json",
        ),
    ),
)

_WINDOWS_VSCODE_VARIANTS: tuple[IDEVariant, ...] = (
    IDEVariant(
        name="VS Code (Windows)",
        extensions=("~/.vscode/extensions",),
        settings=("%APPDATA%/Code/User/settings.json",),
    ),
    IDEVariant(
        name="VS Code Insiders (Windows)",
        extensions=("~/.vscode-insiders/extensions",),
        settings=("%APPDATA%/Code - Insiders/User/settings.json",),
    ),
    IDEVariant(
        name="VSCodium (Windows)",
        extensions=("~/.vscode-oss/extensions",),
        settings=("%APPDATA%/VSCodium/User/settings.json",),
    ),
    IDEVariant(
        name="Cursor (Windows)",
        extensions=("~/.cursor/extensions",),
        settings=("%APPDATA%/Cursor/User/settings.json",),
    ),
    IDEVariant(
        name="Windsurf (Windows)",
        extensions=("~/.windsurf/extensions",),
        settings=("%APPDATA%/Windsurf/User/settings.json",),
    ),
    IDEVariant(
        name="Kiro (Windows)",
        extensions=("~/.kiro/extensions",),
        settings=("%APPDATA%/Kiro/User/settings.json",),
    ),
    IDEVariant(
        name="Trae (Windows)",
        extensions=("~/.trae/extensions",),
        settings=("%APPDATA%/Trae/User/settings.json",),
    ),
    IDEVariant(
        name="Antigravity (Windows)",
        extensions=("~/.antigravity/extensions",),
        settings=("%APPDATA%/Antigravity/User/settings.json",),
    ),
)


def get_vscode_variants() -> tuple[IDEVariant, ...]:
    """Get VS Code variants for the current platform."""
    if platform.system() == "Windows":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            expanded = []
            for v in _WINDOWS_VSCODE_VARIANTS:
                settings = tuple(s.replace("%APPDATA%", appdata) for s in v.settings)
                expanded.append(IDEVariant(name=v.name, extensions=v.extensions, settings=settings))
            return tuple(expanded) + _VSCODE_VARIANTS
    return _VSCODE_VARIANTS


VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:[.-]\w+)?)")


@dataclass
class CIEnvironment:
    """Detected CI/CD or container environment."""

    env_id: str = ""
    display_name: str = ""
    detected: bool = False
    details: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DetectionReport:
    """Aggregate detection results for all agents."""

    clients: list[DetectedClient] = field(default_factory=list)
    shell_env_vars: dict[str, list[tuple[str, str, int, str]]] = field(default_factory=dict)
    platform: str = ""
    total_detected: int = 0
    total_configured: int = 0
    ci_environment: CIEnvironment | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "platform": self.platform,
            "total_detected": self.total_detected,
            "total_configured": self.total_configured,
            "clients": [c.to_dict() for c in self.clients],
            "shell_env_vars": {
                k: [{"value": e[0], "file": e[1], "line": e[2], "client": e[3]} for e in entries]
                for k, entries in self.shell_env_vars.items()
            },
        }
        if self.ci_environment:
            result["ci_environment"] = self.ci_environment.to_dict()
        return result
