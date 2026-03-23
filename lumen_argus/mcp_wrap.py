"""Deprecated — use lumen_argus.mcp.proxy instead.

This module is a backward-compatible shim. All functionality has moved
to lumen_argus.mcp.proxy as part of the MCP proxy unification.

The stdio proxy function is now run_stdio_proxy() in lumen_argus.mcp.proxy.
"""

from lumen_argus.mcp.proxy import run_stdio_proxy as _run_wrapper  # noqa: F401
from lumen_argus.mcp.scanner import MCPScanner  # noqa: F401
