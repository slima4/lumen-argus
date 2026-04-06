"""WebSocket bridge transport — stdio client to WebSocket upstream.

Changes when: WebSocket connection lifecycle, frame relay, or WS-specific logic changes.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any

from lumen_argus.mcp.proxy._scanning import _check_tools_call, _handle_response, _track_outbound
from lumen_argus.mcp.scanner import MCPScanner
from lumen_argus.mcp.transport import StdioTransport, WebSocketClientTransport

log = logging.getLogger("argus.mcp")


async def run_ws_bridge(
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
    """Run MCP proxy in WebSocket bridge mode (stdio client -> WS upstream).

    Reads JSON-RPC from stdin, sends as WS text frames to upstream.
    Receives WS text frames from upstream, writes to stdout.
    """
    import aiohttp

    # SSRF protection: only ws:// and wss:// schemes allowed
    if not (upstream_url.startswith(("ws://", "wss://"))):
        log.error("mcp: invalid WebSocket URL scheme: %s", upstream_url)
        return 1

    action = scanner._action
    log.info("mcp: WebSocket bridge to %s", upstream_url)

    pending_requests: dict[Any, Any] = {}

    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(upstream_url) as ws:
            ws_transport = WebSocketClientTransport(ws)
            client = await StdioTransport.from_process_stdio()

            async def _relay_to_upstream() -> None:
                """stdin -> scan -> WebSocket."""
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
                        await ws_transport.write_message(data)
                        continue

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

                    await ws_transport.write_message(data)

                await ws_transport.close()

            async def _relay_from_upstream() -> None:
                """WebSocket -> scan -> stdout."""
                while True:
                    data = await ws_transport.read_message()
                    if data is None:
                        break
                    line_str = data.decode("utf-8", errors="ignore")

                    try:
                        msg = json.loads(line_str)
                        if isinstance(msg, dict):
                            if not _handle_response(msg, pending_requests, scanner, escalation_fn):
                                continue  # drop unsolicited response
                    except ValueError:
                        log.debug("MCP WS bridge: non-JSON response data, forwarding as-is")

                    sys.stdout.buffer.write(data + b"\n")
                    sys.stdout.buffer.flush()

            _done, pending = await asyncio.wait(
                [
                    asyncio.create_task(_relay_to_upstream()),
                    asyncio.create_task(_relay_from_upstream()),
                ],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for task in _done:
                exc = task.exception()
                if exc:
                    log.error("mcp ws relay error: %s", exc)

    log.info("mcp: WebSocket bridge closed")
    return 0
