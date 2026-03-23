"""Transport-agnostic MCP scanning proxy.

Orchestrates bidirectional message relay with scanning for all transport
modes. Each mode calls a specific entry point that sets up the appropriate
transports and then runs the shared scanning loop.

Modes:
- run_stdio_proxy: stdio subprocess
- run_http_bridge: stdio client -> HTTP upstream
- run_http_listener: HTTP listener -> HTTP upstream (reverse proxy)
- run_ws_bridge: stdio client -> WebSocket upstream
"""

import asyncio
import json
import logging
import sys
import time
from typing import List, Optional

from lumen_argus.mcp.scanner import MCPScanner
from lumen_argus.mcp.transport import (
    HTTPClientTransport,
    StdioTransport,
    WebSocketClientTransport,
)

log = logging.getLogger("argus.mcp")

# Maximum request body size for HTTP listener mode (10 MB).
_MAX_BODY_SIZE = 10 * 1024 * 1024


async def run_stdio_proxy(
    command: List[str],
    scanner: MCPScanner,
    env: Optional[dict] = None,
) -> int:
    """Run MCP proxy in stdio subprocess mode.

    Spawns the MCP server as a child process, relays stdin/stdout
    bidirectionally with scanning. Returns child exit code.

    The subprocess command is provided by the user via CLI args,
    not from untrusted input. asyncio.create_subprocess_exec is used
    (no shell) to prevent command injection.

    Args:
        command: MCP server command to spawn.
        scanner: Configured MCPScanner instance.
        env: Environment dict for subprocess (None = inherit current).
    """
    action = scanner._action
    log.info("mcp: starting subprocess %s", " ".join(command))

    proc = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )

    pending_requests = {}  # id -> method
    _stdout_lock = asyncio.Lock()

    async def _write_stdout(data: bytes) -> None:
        """Write to stdout with lock to prevent interleaved writes."""
        async with _stdout_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    async def _relay_stdin():
        """Read from client stdin, scan, forward to subprocess."""
        client = await StdioTransport.from_process_stdio()

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
                # Forward unparseable lines transparently
                proc.stdin.write(data + b"\n")
                await proc.stdin.drain()
                continue

            messages = msg if isinstance(msg, list) else [msg]
            forward = []

            for m in messages:
                if not isinstance(m, dict):
                    forward.append(m)
                    continue

                method = m.get("method", "")
                msg_id = m.get("id")

                if method == "tools/call":
                    findings = scanner.scan_request(m)
                    if findings and action == "block":
                        error_resp = {
                            "jsonrpc": "2.0",
                            "id": msg_id,
                            "error": {
                                "code": -32600,
                                "message": "Request blocked by lumen-argus: sensitive data detected",
                            },
                        }
                        await _write_stdout(json.dumps(error_resp).encode() + b"\n")
                    else:
                        if msg_id is not None:
                            pending_requests[msg_id] = "tools/call"
                        forward.append(m)
                else:
                    if msg_id is not None and method:
                        pending_requests[msg_id] = method
                    forward.append(m)

            if forward:
                if len(forward) == 1 and not isinstance(msg, list):
                    proc.stdin.write(data + b"\n")
                else:
                    out = forward[0] if len(forward) == 1 else forward
                    proc.stdin.write(json.dumps(out).encode() + b"\n")
                await proc.stdin.drain()

        proc.stdin.close()

    async def _relay_stdout():
        """Read from subprocess stdout, scan, forward to client."""
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            line_str = line.decode("utf-8", errors="ignore").rstrip("\r\n")
            if not line_str:
                continue

            try:
                msg = json.loads(line_str)
            except json.JSONDecodeError:
                await _write_stdout(line)
                continue

            messages = msg if isinstance(msg, list) else [msg]

            for m in messages:
                if isinstance(m, dict) and "result" in m:
                    msg_id = m.get("id")
                    req_method = pending_requests.pop(msg_id, "")
                    if req_method == "tools/call":
                        findings = scanner.scan_response(m, req_method)
                        if findings:
                            log.debug("mcp response findings: %d", len(findings))
                    elif req_method == "tools/list":
                        tools = m.get("result", {}).get("tools", [])
                        if isinstance(tools, list):
                            log.debug("mcp: tools/list response: %d tools", len(tools))

            await _write_stdout(line)
            sys.stdout.buffer.flush()

    async def _relay_stderr():
        """Pipe subprocess stderr to our stderr."""
        while True:
            line = await proc.stderr.readline()
            if not line:
                break
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()

    try:
        await asyncio.gather(
            _relay_stdin(),
            _relay_stdout(),
            _relay_stderr(),
        )
    except Exception as e:
        log.error("mcp relay error: %s", e)

    await proc.wait()
    log.info("mcp: subprocess exited with code %d", proc.returncode)
    return proc.returncode


async def run_http_bridge(
    upstream_url: str,
    scanner: MCPScanner,
) -> int:
    """Run MCP proxy in HTTP bridge mode (stdio client -> HTTP upstream).

    Reads JSON-RPC from stdin, POSTs to upstream, writes response to stdout.
    Handles Mcp-Session-Id for session correlation.
    """
    import aiohttp

    action = scanner._action
    log.info("mcp: HTTP bridge to %s", upstream_url)

    pending_requests = {}

    async with aiohttp.ClientSession() as session:
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
                    msg_id = msg.get("id")

                    if method == "tools/call":
                        findings = scanner.scan_request(msg)
                        if findings and action == "block":
                            error_resp = {
                                "jsonrpc": "2.0",
                                "id": msg_id,
                                "error": {
                                    "code": -32600,
                                    "message": "Request blocked by lumen-argus: sensitive data detected",
                                },
                            }
                            sys.stdout.buffer.write(json.dumps(error_resp).encode() + b"\n")
                            sys.stdout.buffer.flush()
                            continue

                    if msg_id is not None and method:
                        pending_requests[msg_id] = method

                # POST to upstream
                resp_data = await transport.send_and_receive(data)
                if resp_data is None:
                    continue

                # Scan response
                try:
                    resp_msg = json.loads(resp_data)
                    if isinstance(resp_msg, dict) and "result" in resp_msg:
                        resp_id = resp_msg.get("id")
                        req_method = pending_requests.pop(resp_id, "")
                        if req_method == "tools/call":
                            findings = scanner.scan_response(resp_msg, req_method)
                            if findings:
                                log.debug("mcp response findings: %d", len(findings))
                        elif req_method == "tools/list":
                            tools = resp_msg.get("result", {}).get("tools", [])
                            if isinstance(tools, list):
                                log.debug("mcp: tools/list response: %d tools", len(tools))
                except (json.JSONDecodeError, ValueError):
                    pass

                sys.stdout.buffer.write(resp_data + b"\n")
                sys.stdout.buffer.flush()

        except Exception as e:
            log.error("mcp http bridge error: %s", e)

        await transport.close()

    log.info("mcp: HTTP bridge closed")
    return 0


async def run_http_listener(
    listen_host: str,
    listen_port: int,
    upstream_url: str,
    scanner: MCPScanner,
) -> int:
    """Run MCP proxy in HTTP reverse proxy mode (HTTP listener -> HTTP upstream).

    Accepts POST / with JSON-RPC payloads, scans, forwards to upstream.
    Includes /health endpoint for liveness probes.
    """
    import aiohttp
    from aiohttp import web

    action = scanner._action
    start_time = time.monotonic()
    log.info("mcp: HTTP listener on %s:%d -> %s", listen_host, listen_port, upstream_url)

    upstream_session = aiohttp.ClientSession()
    upstream = HTTPClientTransport(upstream_session, upstream_url)

    async def handle_health(request):
        uptime = time.monotonic() - start_time
        return web.json_response(
            {
                "status": "healthy",
                "mode": "mcp-http-listener",
                "uptime_seconds": round(uptime, 1),
                "upstream": upstream_url,
            }
        )

    async def handle_post(request):
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
        msg_id = msg.get("id") if isinstance(msg, dict) else None
        if isinstance(msg, dict) and msg.get("method") == "tools/call":
            findings = scanner.scan_request(msg)
            if findings and action == "block":
                return web.json_response(
                    {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32600,
                            "message": "Request blocked by lumen-argus: sensitive data detected",
                        },
                    },
                    status=400,
                )

        # Forward to upstream
        resp_data = await upstream.send_and_receive(body)
        if resp_data is None:
            return web.Response(status=202)

        # Scan response
        try:
            resp_msg = json.loads(resp_data)
            if isinstance(resp_msg, dict) and "result" in resp_msg:
                method = msg.get("method", "") if isinstance(msg, dict) else ""
                if method == "tools/call":
                    scanner.scan_response(resp_msg, method)
        except (json.JSONDecodeError, ValueError):
            pass

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
    except asyncio.CancelledError:
        pass
    finally:
        await upstream.close()
        await runner.cleanup()

    return 0


async def run_ws_bridge(
    upstream_url: str,
    scanner: MCPScanner,
) -> int:
    """Run MCP proxy in WebSocket bridge mode (stdio client -> WS upstream).

    Reads JSON-RPC from stdin, sends as WS text frames to upstream.
    Receives WS text frames from upstream, writes to stdout.
    """
    import aiohttp

    # SSRF protection: only ws:// and wss:// schemes allowed
    if not (upstream_url.startswith("ws://") or upstream_url.startswith("wss://")):
        log.error("mcp: invalid WebSocket URL scheme: %s", upstream_url)
        return 1

    action = scanner._action
    log.info("mcp: WebSocket bridge to %s", upstream_url)

    pending_requests = {}

    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(upstream_url) as ws:
            ws_transport = WebSocketClientTransport(ws)
            client = await StdioTransport.from_process_stdio()

            async def _relay_to_upstream():
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
                        msg_id = msg.get("id")

                        if method == "tools/call":
                            findings = scanner.scan_request(msg)
                            if findings and action == "block":
                                error_resp = {
                                    "jsonrpc": "2.0",
                                    "id": msg_id,
                                    "error": {
                                        "code": -32600,
                                        "message": "Request blocked by lumen-argus: sensitive data detected",
                                    },
                                }
                                sys.stdout.buffer.write(json.dumps(error_resp).encode() + b"\n")
                                sys.stdout.buffer.flush()
                                continue

                        if msg_id is not None and method:
                            pending_requests[msg_id] = method

                    await ws_transport.write_message(data)

                await ws_transport.close()

            async def _relay_from_upstream():
                """WebSocket -> scan -> stdout."""
                while True:
                    data = await ws_transport.read_message()
                    if data is None:
                        break
                    line_str = data.decode("utf-8", errors="ignore")

                    try:
                        msg = json.loads(line_str)
                        if isinstance(msg, dict) and "result" in msg:
                            msg_id = msg.get("id")
                            req_method = pending_requests.pop(msg_id, "")
                            if req_method == "tools/call":
                                findings = scanner.scan_response(msg, req_method)
                                if findings:
                                    log.debug("mcp response findings: %d", len(findings))
                            elif req_method == "tools/list":
                                tools = msg.get("result", {}).get("tools", [])
                                if isinstance(tools, list):
                                    log.debug("mcp: tools/list response: %d tools", len(tools))
                    except (json.JSONDecodeError, ValueError):
                        pass

                    sys.stdout.buffer.write(data + b"\n")
                    sys.stdout.buffer.flush()

            done, pending = await asyncio.wait(
                [
                    asyncio.create_task(_relay_to_upstream()),
                    asyncio.create_task(_relay_from_upstream()),
                ],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    log.info("mcp: WebSocket bridge closed")
    return 0
