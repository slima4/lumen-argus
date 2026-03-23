"""Deprecated — use lumen_argus.mcp.scanner instead.

This module is a backward-compatible shim. All functionality has moved
to lumen_argus.mcp.scanner as part of the MCP proxy unification.
"""

from lumen_argus.mcp.scanner import (  # noqa: F401
    MCPScanner,
    detect_mcp_method,
    detect_mcp_request,
    detect_mcp_response,
    detect_mcp_tools_list_response,
    extract_text_from_content,
)
