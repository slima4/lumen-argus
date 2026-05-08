"""HTTP bridge transport — stdio client to HTTP upstream.

Changes when: HTTP client lifecycle, session handling, or bridge relay logic changes.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

from lumen_argus.mcp.proxy._scanning import _check_tools_call, _handle_response, _track_outbound
from lumen_argus.mcp.scanner import MCPScanner
from lumen_argus.mcp.transport import HTTPClientTransport, StdioTransport

log = logging.getLogger("argus.mcp")


async def run_http_bridge(
    upstream_url: str,
    scanner: MCPScanner,
    policy_engine: Any = None,
    escalation_fn: Any = None,
    tool_policy_evaluator: Any = None,
    approval_gate: Any = None,
    server_id: str = "",
    sse_broadcaster: Any = None,
    audit_logger: Any = None,
) -> int:
    """Run MCP proxy in HTTP bridge mode (stdio client -> HTTP upstream).

    Reads JSON-RPC from stdin, POSTs to upstream, writes response to stdout.
    Handles Mcp-Session-Id for session correlation.
    """
    import aiohttp

    # SSRF protection: only http:// and https:// schemes allowed
    if not upstream_url.startswith(("http://", "https://")):
        log.error("mcp: invalid HTTP upstream URL scheme: %s", upstream_url)
        return 1

    action = scanner._action
    log.info("mcp: HTTP bridge to %s", upstream_url)

    pending_requests: dict[Any, Any] = {}

    timeout = aiohttp.ClientTimeout(total=300, sock_connect=10)
    session = aiohttp.ClientSession(timeout=timeout)
    transport = HTTPClientTransport(session, upstream_url)
    client = await StdioTransport.from_process_stdio()

    try:
        while True:
            data = await client.read_message()
            if data is None:
                break
            line_str = data.decode("utf-8", errors="ignore")
            if not line_str:
                continue

            try:
                msg = json.loads(line_str)
            except json.JSONDecodeError:
                continue  # drop unparseable in HTTP mode

            # Scan outbound
            if isinstance(msg, dict):
                method = msg.get("method", "")

                if method == "tools/call":
                    error = await _check_tools_call(
                        msg,
                        scanner,
                        action,
                        policy_engine,
                        escalation_fn,
                        tool_policy_evaluator=tool_policy_evaluator,
                        approval_gate=approval_gate,
                        server_id=server_id,
                        sse_broadcaster=sse_broadcaster,
                        audit_logger=audit_logger,
                    )
                    if error:
                        sys.stdout.buffer.write(json.dumps(error).encode() + b"\n")
                        sys.stdout.buffer.flush()
                        continue

                _track_outbound(msg, pending_requests, scanner)

            # POST to upstream
            resp_data = await transport.send_and_receive(data)
            if resp_data is None:
                continue

            # Scan response
            should_forward = True
            try:
                resp_msg = json.loads(resp_data)
                if isinstance(resp_msg, dict):
                    should_forward = _handle_response(resp_msg, pending_requests, scanner, escalation_fn)
            except ValueError:
                log.debug("MCP stdio: non-JSON response data, forwarding as-is")

            if should_forward:
                sys.stdout.buffer.write(resp_data + b"\n")
                sys.stdout.buffer.flush()

    except Exception:
        log.error("mcp http bridge error", exc_info=True)
    finally:
        await transport.close()

    log.info("mcp: HTTP bridge closed")
    return 0
