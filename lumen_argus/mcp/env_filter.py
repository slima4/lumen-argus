"""Environment variable restriction for MCP subprocess mode.

When spawning MCP server subprocesses, restricts the inherited environment
to prevent accidental secret leakage. Only safe system variables are passed
through; sensitive variables (API keys, tokens, credentials, proxy settings)
are stripped.
"""

import logging
import os
from typing import Dict, List, Optional

log = logging.getLogger("argus.mcp")

# Safe variables that are always passed through.
_SAFE_VARS = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "SHELL",
        "TERM",
        "LANG",
        "TZ",
        "TMPDIR",
        "DISPLAY",
        "EDITOR",
        "PWD",
        "LOGNAME",
        "HOSTNAME",
        "SHLVL",
        "COLORTERM",
        "TERM_PROGRAM",
        "TERM_PROGRAM_VERSION",
    }
)

# Prefixes for safe variables (e.g., LC_ALL, XDG_DATA_HOME).
_SAFE_PREFIXES = ("LC_", "XDG_")

# Note: This is an allowlist-only filter — anything not in _SAFE_VARS or
# _SAFE_PREFIXES is automatically stripped. No need for separate blocklists.


def filter_env(
    extra_vars: Optional[Dict[str, str]] = None,
    config_allowlist: Optional[List[str]] = None,
) -> dict:
    """Build a filtered environment for MCP subprocess.

    Returns a new dict containing only safe variables from os.environ,
    plus any explicitly requested extra_vars and config_allowlist entries.

    Args:
        extra_vars: Additional key=value pairs from --env flags.
        config_allowlist: Variable names from config mcp.env_allowlist.
    """
    env = {}
    allowed_extra = set(config_allowlist or [])
    filtered_count = 0

    for key, value in os.environ.items():
        upper = key.upper()

        # Check explicit allowlist from config
        if key in allowed_extra:
            env[key] = value
            continue

        # Check safe vars
        if upper in _SAFE_VARS:
            env[key] = value
            continue

        # Check safe prefixes
        if any(upper.startswith(p) for p in _SAFE_PREFIXES):
            env[key] = value
            continue

        # Everything else is filtered
        filtered_count += 1

    # Add explicit --env overrides (user takes responsibility)
    if extra_vars:
        for key, value in extra_vars.items():
            env[key] = value

    if filtered_count > 0:
        log.info("mcp: filtered %d environment variable(s) from subprocess", filtered_count)

    return env
