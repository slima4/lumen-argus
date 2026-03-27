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
from typing import Any

from lumen_argus.mcp.scanner import MCPScanner
from lumen_argus.mcp.transport import (
    HTTPClientTransport,
    StdioTransport,
    WebSocketClientTransport,
)

log = logging.getLogger("argus.mcp")


def _run_policy_engine(policy_engine: Any, tool_name: str, arguments: dict[str, Any]) -> list[Any]:
    """Run Pro policy engine on a tools/call request. Returns findings list.

    Returns empty list if no engine registered or engine raises.
    """
    if policy_engine is None:
        return []
    try:
        return policy_engine.evaluate(tool_name, arguments)  # type: ignore[no-any-return]
    except Exception as exc:
        log.warning("mcp: policy engine raised %s", exc)
        return []


def _signal_escalation(
    escalation_fn: Any, signal_type: str, session_id: str, details: dict[str, Any] | None | None = None
) -> str | None:
    """Feed a threat signal to Pro's adaptive enforcement. Returns enforcement level.

    Returns None if no escalation function registered or it raises.
    The session_id may be empty for stdio-based modes that have no session
    concept — Pro's escalation engine should treat empty session_id as a
    single implicit session.
    """
    if escalation_fn is None:
        return None
    try:
        level = escalation_fn(signal_type, session_id, details or {})
        if level and level != "normal":
            log.info("mcp: session escalation level: %s (signal=%s)", level, signal_type)
        return str(level) if level else None
    except Exception as exc:
        log.warning("mcp: session escalation raised %s", exc)
        return None


def _jsonrpc_error(msg_id: Any, message: str) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 error response."""
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32600, "message": message},
    }


def _check_tools_call(
    msg: dict[str, Any],
    scanner: MCPScanner,
    action: str,
    policy_engine: Any,
    escalation_fn: Any,
    session_id: str = "",
) -> dict[str, Any] | None:
    """Validate a tools/call request: session binding → policy engine → scanner.

    Returns a JSON-RPC error dict if the call should be blocked, or None if
    it should be forwarded. Fires escalation signals as side effects.

    All 4 transport modes call this for tools/call requests.
    """
    msg_id = msg.get("id")
    tool_name = msg.get("params", {}).get("name", "")
    arguments = msg.get("params", {}).get("arguments", {})

    # Session binding check
    if scanner.session_binding and not scanner.session_binding.validate_tool(tool_name):
        _signal_escalation(escalation_fn, "unknown_tool", session_id, {"tool": tool_name})
        if scanner.session_binding.should_block:
            return _jsonrpc_error(msg_id, "Tool '%s' not in session baseline" % tool_name)

    # Pro policy engine check
    policy_findings = _run_policy_engine(policy_engine, tool_name, arguments)
    if policy_findings and any(f.action == "block" for f in policy_findings):
        _signal_escalation(escalation_fn, "block", session_id, {"tool": tool_name})
        return _jsonrpc_error(msg_id, "Request blocked by policy: %s" % policy_findings[0].type)

    # Scanner check
    findings = scanner.scan_request(msg)
    if findings and action == "block":
        _signal_escalation(escalation_fn, "block", session_id, {"tool": tool_name})
        return _jsonrpc_error(msg_id, "Request blocked by lumen-argus: sensitive data detected")

    # Not blocked — signal near_miss or clean
    if findings:
        _signal_escalation(escalation_fn, "near_miss", session_id, {"tool": tool_name})
    else:
        _signal_escalation(escalation_fn, "clean", session_id, {"tool": tool_name})
    return None


def _handle_response(
    msg: dict[str, Any],
    pending_requests: dict[Any, Any],
    scanner: MCPScanner,
    escalation_fn: Any,
    session_id: str = "",
) -> bool:
    """Process an MCP response: confused deputy check, response scan, tools/list handling.

    Returns True if the response should be forwarded, False if it should be dropped.

    All 4 transport modes call this for response messages.
    """
    msg_id = msg.get("id")

    # Confused deputy check
    if scanner.request_tracker and "result" in msg:
        if not scanner.request_tracker.validate(msg_id):
            if scanner.request_tracker.should_block:
                return False  # drop unsolicited response

    if "result" in msg:
        req_method = pending_requests.pop(msg_id, "")
        if req_method == "tools/call":
            findings = scanner.scan_response(msg, req_method)
            if findings:
                log.debug("mcp response findings: %d", len(findings))
        elif req_method == "tools/list":
            tools = msg.get("result", {}).get("tools", [])
            if isinstance(tools, list):
                log.debug("mcp: tools/list response: %d tools", len(tools))
                tl_findings = scanner.process_tools_list(tools)
                for f in tl_findings:
                    if f.type == "tool_drift":
                        _signal_escalation(escalation_fn, "drift", session_id, {"tool": f.location.rsplit(".", 1)[-1]})

    return True  # forward


def _track_outbound(msg: dict[str, Any], pending_requests: dict[Any, Any], scanner: MCPScanner) -> None:
    """Track an outbound request for confused deputy protection and method correlation."""
    method = msg.get("method", "")
    msg_id = msg.get("id")
    if msg_id is not None and method:
        pending_requests[msg_id] = method
    if scanner.request_tracker:
        scanner.request_tracker.track(msg_id)


# Maximum request body size for HTTP listener mode (10 MB).
_MAX_BODY_SIZE = 10 * 1024 * 1024


async def run_stdio_proxy(
    command: list[str],
    scanner: MCPScanner,
    env: dict[str, str] | None = None,
    policy_engine: Any = None,
    escalation_fn: Any = None,
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

    pending_requests: dict[Any, Any] = {}  # id -> method
    _stdout_lock = asyncio.Lock()

    async def _write_stdout(data: bytes) -> None:
        """Write to stdout with lock to prevent interleaved writes."""
        async with _stdout_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    async def _relay_stdin() -> None:
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
                if proc.stdin is None:
                    log.error("mcp: subprocess stdin pipe closed, cannot forward data")
                    break
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

                if method == "tools/call":
                    error = _check_tools_call(m, scanner, action, policy_engine, escalation_fn)
                    if error:
                        await _write_stdout(json.dumps(error).encode() + b"\n")
                        continue

                _track_outbound(m, pending_requests, scanner)
                forward.append(m)

            if forward:
                if proc.stdin is None:
                    log.error("mcp: subprocess stdin pipe closed, cannot forward messages")
                    break
                if len(forward) == 1 and not isinstance(msg, list):
                    proc.stdin.write(data + b"\n")
                else:
                    out = forward[0] if len(forward) == 1 else forward
                    proc.stdin.write(json.dumps(out).encode() + b"\n")
                await proc.stdin.drain()

        if proc.stdin is not None:
            proc.stdin.close()

    async def _relay_stdout() -> None:
        """Read from subprocess stdout, scan, forward to client."""
        if proc.stdout is None:
            log.error("mcp: subprocess stdout pipe not available")
            return
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

            # MCP uses single messages per line (not JSON-RPC batches)
            if not isinstance(msg, dict):
                await _write_stdout(line)
                continue

            if not _handle_response(msg, pending_requests, scanner, escalation_fn):
                continue  # drop unsolicited response

            await _write_stdout(line)

    async def _relay_stderr() -> None:
        """Pipe subprocess stderr to our stderr."""
        if proc.stderr is None:
            log.error("mcp: subprocess stderr pipe not available")
            return
        while True:
            line = await proc.stderr.readline()
            if not line:
                break
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()

    try:
        async with asyncio.TaskGroup() as tg:
            tg.create_task(_relay_stdin())
            tg.create_task(_relay_stdout())
            tg.create_task(_relay_stderr())
    except* Exception as eg:
        for exc in eg.exceptions:
            log.error("mcp relay error: %s", exc)

    await proc.wait()
    exit_code = proc.returncode or 1
    log.info("mcp: subprocess exited with code %d", exit_code)
    return exit_code


async def run_http_bridge(
    upstream_url: str,
    scanner: MCPScanner,
    policy_engine: Any = None,
    escalation_fn: Any = None,
) -> int:
    """Run MCP proxy in HTTP bridge mode (stdio client -> HTTP upstream).

    Reads JSON-RPC from stdin, POSTs to upstream, writes response to stdout.
    Handles Mcp-Session-Id for session correlation.
    """
    import aiohttp

    action = scanner._action
    log.info("mcp: HTTP bridge to %s", upstream_url)

    pending_requests: dict[Any, Any] = {}

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

                    if method == "tools/call":
                        error = _check_tools_call(msg, scanner, action, policy_engine, escalation_fn)
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
                except (json.JSONDecodeError, ValueError):
                    log.debug("MCP stdio: non-JSON response data, forwarding as-is")

                if should_forward:
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
    policy_engine: Any = None,
    escalation_fn: Any = None,
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
            error = _check_tools_call(msg, scanner, action, policy_engine, escalation_fn, session_id)
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
        except (json.JSONDecodeError, ValueError):
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


async def run_ws_bridge(
    upstream_url: str,
    scanner: MCPScanner,
    policy_engine: Any = None,
    escalation_fn: Any = None,
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
                            error = _check_tools_call(msg, scanner, action, policy_engine, escalation_fn)
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
                    except (json.JSONDecodeError, ValueError):
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

    log.info("mcp: WebSocket bridge closed")
    return 0
