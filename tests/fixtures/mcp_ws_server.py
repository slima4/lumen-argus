"""Minimal MCP server over WebSocket for integration testing.

WebSocket endpoint at /ws accepts text frames with JSON-RPC payloads.
Scenario controlled via query parameter: ws://host:port/ws?scenario=poisoned,drift

Usage:
    from tests.fixtures.mcp_ws_server import create_app, start_server, stop_server
"""

import json

import aiohttp
from aiohttp import web

from tests.fixtures.mcp_handler import create_state, handle_message


def create_app(scenarios=None):
    """Create an aiohttp app for the test MCP WebSocket server.

    Args:
        scenarios: Set of scenario names. If None, read from query parameter.
    """
    app = web.Application()
    app["default_scenarios"] = scenarios
    app.router.add_get("/ws", _handle_ws)
    return app


async def _handle_ws(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    # Parse scenarios from query parameter or app default
    scenarios = request.app["default_scenarios"]
    if scenarios is None:
        param = request.query.get("scenario", "")
        scenarios = {s.strip().replace("-", "_") for s in param.split(",") if s.strip()}

    state = create_state(scenarios)

    async for msg in ws:
        if msg.type == aiohttp.WSMsgType.TEXT:
            try:
                parsed = json.loads(msg.data)
            except json.JSONDecodeError:
                continue

            responses = handle_message(parsed, state)
            for resp in responses:
                await ws.send_str(json.dumps(resp))

        elif msg.type == aiohttp.WSMsgType.BINARY:
            await ws.close(code=1003, message=b"Binary frames not supported")
            break

        elif msg.type in (aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSE):
            break

    return ws


async def start_server(app, host="127.0.0.1", port=0):
    """Start the server on a random port. Returns (runner, ws_url)."""
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    actual_port = site._server.sockets[0].getsockname()[1]
    ws_url = "ws://%s:%d/ws" % (host, actual_port)
    return runner, ws_url


async def stop_server(runner):
    """Stop the server and clean up."""
    await runner.cleanup()
