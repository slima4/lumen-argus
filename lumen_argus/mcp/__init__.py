"""MCP scanning package — unified MCP proxy with transport abstraction.

Provides:
- MCPScanner: shared scanning logic for all MCP transports
- MessageTransport: protocol for pluggable transports (stdio, HTTP, WebSocket)
- run_mcp_proxy: transport-agnostic scanning loop
- Helper functions: detect_mcp_request, detect_mcp_response, etc.
"""

from lumen_argus.mcp.scanner import (
    MCPScanner,
    detect_mcp_method,
    detect_mcp_request,
    detect_mcp_response,
    detect_mcp_tools_list_response,
    extract_text_from_content,
)

__all__ = [
    "MCPScanner",
    "detect_mcp_method",
    "detect_mcp_request",
    "detect_mcp_response",
    "detect_mcp_tools_list_response",
    "extract_text_from_content",
]
