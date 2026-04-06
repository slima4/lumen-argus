"""HTTP listener transport — reverse proxy accepting POST requests.

Changes when: HTTP server setup, request validation, routing, or reverse proxy logic changes.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from lumen_argus.mcp.proxy._scanning import _check_tools_call, _handle_response, _jsonrpc_error, _track_outbound
from lumen_argus.mcp.scanner import MCPScanner
from lumen_argus.mcp.transport import HTTPClientTransport

log = logging.getLogger("argus.mcp")

# Maximum request body size for HTTP listener mode (10 MB).
_MAX_BODY_SIZE = 10 * 1024 * 1024


async def run_http_listener(
    listen_host: str,
    listen_port: int,
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
    """Run MCP proxy in HTTP reverse proxy mode (HTTP listener -> HTTP upstream).

    Accepts POST / with JSON-RPC payloads, scans, forwards to upstream.
    Includes /health endpoint for liveness probes.
    """
    import aiohttp
    from aiohttp import web

    # SSRF protection: only http:// and https:// schemes allowed
    if not upstream_url.startswith(("http://", "https://")):
        log.error("mcp: invalid HTTP upstream URL scheme: %s", upstream_url)
        return 1

    action = scanner._action
    start_time = time.monotonic()
    log.info("mcp: HTTP listener on %s:%d -> %s", listen_host, listen_port, upstream_url)

    upstream_session = aiohttp.ClientSession()
    upstream = HTTPClientTransport(upstream_session, upstream_url)

    async def handle_health(request: web.Request) -> web.Response:
        uptime = time.monotonic() - start_time
        return web.json_response(
            {
                "status": "healthy",
                "mode": "mcp-http-listener",
                "uptime_seconds": round(uptime, 1),
                "upstream": upstream_url,
            }
        )

    async def handle_post(request: web.Request) -> web.Response:
        # Extract session ID from MCP header for escalation tracking
        session_id = request.headers.get("Mcp-Session-Id", "")

        # Size limit — check header first, then actual body
        if request.content_length and request.content_length > _MAX_BODY_SIZE:
            return web.json_response(
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Request too large"}},
                status=400,
            )

        body = await request.read()
        if len(body) > _MAX_BODY_SIZE:
            return web.json_response(
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Request too large"}},
                status=400,
            )
        if not body:
            return web.json_response(
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Empty body"}},
                status=400,
            )

        # Validate JSON
        try:
            msg = json.loads(body)
        except json.JSONDecodeError:
            return web.json_response(
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
                status=400,
            )

        # Scan request
        method = msg.get("method", "") if isinstance(msg, dict) else ""
        pending_requests: dict[Any, Any] = {}  # single request/response — local scope

        if isinstance(msg, dict) and method == "tools/call":
            error = await _check_tools_call(
                msg,
                scanner,
                action,
                policy_engine,
                escalation_fn,
                session_id,
                tool_policy_evaluator=tool_policy_evaluator,
                approval_gate=approval_gate,
                server_id=server_id,
                sse_broadcaster=sse_broadcaster,
                audit_logger=audit_logger,
            )
            if error:
                return web.json_response(error, status=400)

        if isinstance(msg, dict):
            _track_outbound(msg, pending_requests, scanner)

        # Forward to upstream
        resp_data = await upstream.send_and_receive(body)
        if resp_data is None:
            return web.Response(status=202)

        # Scan response
        try:
            resp_msg = json.loads(resp_data)
            if isinstance(resp_msg, dict):
                should_forward = _handle_response(resp_msg, pending_requests, scanner, escalation_fn, session_id)
                if not should_forward:
                    return web.json_response(
                        _jsonrpc_error(resp_msg.get("id"), "Unsolicited response rejected"),
                        status=400,
                    )
        except ValueError:
            log.debug("MCP HTTP: non-JSON response data, forwarding as-is")

        # Pass through Mcp-Session-Id
        headers = {}
        if upstream._session_id:
            headers["Mcp-Session-Id"] = upstream._session_id

        return web.Response(
            body=resp_data,
            content_type="application/json",
            headers=headers,
        )

    app = web.Application()
    app.router.add_get("/health", handle_health)
    app.router.add_post("/", handle_post)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, listen_host, listen_port)
    await site.start()
    log.info("mcp: listening on %s:%d", listen_host, listen_port)

    # Run until cancelled
    try:
        await asyncio.Event().wait()
    finally:
        await upstream.close()
        await runner.cleanup()

    return 0
