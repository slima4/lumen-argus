"""Minimal MCP server over HTTP for integration testing.

Accepts POST / with JSON-RPC payloads, dispatches via mcp_handler.
Scenario controlled via X-Test-Scenario header (comma-separated).

Usage:
    from tests.fixtures.mcp_http_server import create_app, start_server, stop_server
"""

import json
import uuid

from aiohttp import web

from tests.fixtures.mcp_handler import create_state, handle_message


def create_app(scenarios=None):
    """Create an aiohttp app for the test MCP HTTP server.

    Args:
        scenarios: Set of scenario names (see mcp_handler.create_state).
                   If None, scenarios are read from X-Test-Scenario header per request.
    """
    app = web.Application()
    app["default_scenarios"] = scenarios
    app["states"] = {}  # session_id -> state

    app.router.add_post("/", _handle_post)
    app.router.add_delete("/", _handle_delete)
    app.router.add_get("/health", _handle_health)
    return app


def _get_state(app, session_id, request):
    """Get or create state for a session, applying scenario overrides."""
    if session_id not in app["states"]:
        scenarios = app["default_scenarios"]
        if scenarios is None:
            header = request.headers.get("X-Test-Scenario", "")
            scenarios = {s.strip().replace("-", "_") for s in header.split(",") if s.strip()}
        app["states"][session_id] = create_state(scenarios)
    return app["states"][session_id]


async def _handle_post(request):
    body = await request.read()
    if not body:
        return web.json_response(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Empty body"}},
            status=400,
        )

    try:
        msg = json.loads(body)
    except json.JSONDecodeError:
        return web.json_response(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
            status=400,
        )

    # Track session via Mcp-Session-Id header
    session_id = request.headers.get("Mcp-Session-Id", "")
    if not session_id:
        session_id = str(uuid.uuid4())

    state = _get_state(request.app, session_id, request)
    responses = handle_message(msg, state)

    if not responses:
        return web.Response(status=202)

    # Return first response (MCP HTTP transport is request/response)
    resp = web.json_response(responses[0])
    resp.headers["Mcp-Session-Id"] = session_id

    # If there are extra responses (unsolicited), they'd need SSE — skip for now
    # The confused deputy test uses stdio mode where multiple lines are natural
    return resp


async def _handle_delete(request):
    """Session termination."""
    return web.json_response({"status": "terminated"})


async def _handle_health(request):
    return web.json_response({"status": "healthy", "mode": "test-mcp-http"})


async def start_server(app, host="127.0.0.1", port=0):
    """Start the server on a random port. Returns (runner, URL)."""
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    # Get the actual port assigned
    actual_port = site._server.sockets[0].getsockname()[1]
    url = "http://%s:%d" % (host, actual_port)
    return runner, url


async def stop_server(runner):
    """Stop the server and clean up."""
    await runner.cleanup()
