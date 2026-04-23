"""Value objects shared across setup submodules."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SetupChange:
    """Record of a single configuration change written by the setup wizard.

    Emitted by every mutating step (shell profile, IDE settings, env file,
    MCP wrap, forward-proxy alias) and persisted in the manifest so
    :mod:`lumen_argus_core.setup.undo` can reverse them.
    """

    timestamp: str
    client_id: str
    method: str  # "shell_profile" | "ide_settings" | "env_file" | "mcp_wrap" | "forward_proxy_aliases"
    file: str
    detail: str
    backup_path: str = ""
