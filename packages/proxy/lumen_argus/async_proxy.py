"""Async HTTP proxy server: aiohttp-based forwarding with scan integration.

Replaces ThreadingHTTPServer with aiohttp.web for:
- Non-blocking I/O (coroutine per request, not thread per request)
- Native SSE streaming via StreamResponse
- Built-in connection pooling via aiohttp.ClientSession
- WebSocket upgrade on the same port (Phase 2)

Scanning logic is unchanged — CPU-bound scanning runs in a thread pool
via asyncio.to_thread() to avoid blocking the event loop.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import logging
import os
import ssl
import threading
import time
import uuid
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.extensions import ExtensionRegistry

import aiohttp
from aiohttp import web

from lumen_argus.actions import build_block_response, should_forward, try_strip_blocked_history
from lumen_argus.audit import AuditLogger
from lumen_argus.display import TerminalDisplay
from lumen_argus.models import AuditEntry, Finding, ScanResult, SessionContext
from lumen_argus.pipeline import ScannerPipeline
from lumen_argus.provider import ProviderRouter
from lumen_argus.session import extract_session as _extract_session
from lumen_argus.stats import SessionStats
from lumen_argus_core.time_utils import now_iso_ms

log = logging.getLogger("argus.proxy")


def build_ssl_context(ca_bundle: str = "", verify_ssl: bool = True) -> ssl.SSLContext:
    """Build an SSL context for upstream connections.

    Args:
        ca_bundle: Path to a CA cert file or directory. Empty = system default.
        verify_ssl: If False, disable certificate verification (dev/testing only).
    """
    if not verify_ssl:
        log.warning("TLS certificate verification is disabled — do not use in production")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # NOSONAR — intentional: user explicitly set verify_ssl=false
        ctx.verify_mode = ssl.CERT_NONE  # NOSONAR
        return ctx

    ctx = ssl.create_default_context()
    if ca_bundle:
        ca_path = os.path.expanduser(ca_bundle)
        if os.path.isdir(ca_path):
            ctx.load_verify_locations(capath=ca_path)
        else:
            ctx.load_verify_locations(cafile=ca_path)
        log.info("loaded custom CA bundle: %s", ca_path)
    return ctx


# Typed app key for storing the proxy reference (avoids aiohttp AppKey warning).
_PROXY_KEY: Any = web.AppKey("proxy", t=str)

# Thread-safe request counter (shared with legacy proxy if both loaded).
_request_counter = itertools.count(1)

# Hop-by-hop headers that must not be forwarded.
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
)


def _log_audit(
    server: "AsyncArgusProxy",
    request_id: int,
    path: str,
    provider: str,
    model: str,
    result: ScanResult,
    body_size: int,
    passed: bool,
    session: SessionContext | None = None,
) -> None:
    """Write audit log entry."""
    entry = AuditEntry(
        timestamp=now_iso_ms(),
        request_id=request_id,
        provider=provider,
        model=model,
        endpoint=path,
        action=result.action,
        findings=result.findings,
        scan_duration_ms=result.scan_duration_ms,
        request_size_bytes=body_size,
        passed=passed,
        account_id=session.account_id if session else "",
        api_key_hash=session.api_key_hash if session else "",
        session_id=session.session_id if session else "",
        device_id=session.device_id if session else "",
        source_ip=session.source_ip if session else "",
        working_directory=session.working_directory if session else "",
        git_branch=session.git_branch if session else "",
        os_platform=session.os_platform if session else "",
        client_name=session.client_name if session else "",
        client_version=session.client_version if session else "",
    )
    server.audit.log(entry)


async def _handle_health(request: web.Request) -> web.Response:
    """Respond to /health endpoint.

    Returns 200 when ready, 503 when still starting (pipeline loading).
    The relay uses the HTTP status code to decide engine health.
    """
    server = request.app[_PROXY_KEY]
    ready = server.ready
    data = {
        "status": "ready" if ready else "starting",
        "version": __import__("lumen_argus").__version__,
        "uptime": round(time.monotonic() - server.start_time, 1),
        "requests": server.stats.total_requests,
    }
    health_hook = server.extensions.get_health_hook() if server.extensions else None
    if health_hook:
        try:
            extra = await asyncio.to_thread(health_hook)
            data.update(extra)
        except Exception:
            log.debug("health hook failed", exc_info=True)
    return web.json_response(data, status=200 if ready else 503)


async def _handle_metrics(request: web.Request) -> web.Response:
    """Respond to /metrics with Prometheus exposition format."""
    server = request.app[_PROXY_KEY]
    text = server.stats.prometheus_metrics(
        active_requests=server.active_requests,
        active_ws_connections=server.active_ws_connections,
    )
    metrics_hook = server.extensions.get_metrics_hook() if server.extensions else None
    if metrics_hook:
        try:
            extra = await asyncio.to_thread(metrics_hook)
            if extra:
                text += extra
        except Exception:
            log.debug("metrics hook failed", exc_info=True)
    resp = web.Response(body=text.encode("utf-8"))
    resp.content_type = "text/plain"
    resp.headers["Content-Type"] = "text/plain; version=0.0.4; charset=utf-8"
    return resp


async def _handle_websocket(request: web.Request, server: "AsyncArgusProxy") -> web.WebSocketResponse | web.Response:
    """Handle WebSocket upgrade — relay frames with scanning on same port.

    Client connects: ws://localhost:8080/ws?url=ws://real-server:3000/path
    Proxy connects to upstream, relays bidirectionally, scans text frames.
    """
    from urllib.parse import parse_qs, urlparse

    # Extract target URL from query params
    parsed = urlparse(request.path_qs)
    params = parse_qs(parsed.query)
    target_url = params.get("url", [None])[0]

    # Validate target URL (SSRF protection)
    if not target_url:
        log.warning("ws: missing 'url' parameter")
        return web.Response(text="Missing 'url' parameter. Use /ws?url=ws://target", status=400)
    target_parsed = urlparse(target_url)
    if target_parsed.scheme not in ("ws", "wss"):
        log.warning("ws: invalid scheme '%s' (must be ws:// or wss://)", target_parsed.scheme)
        return web.Response(text="Invalid URL scheme. Must be ws:// or wss://", status=400)
    if not target_parsed.hostname:
        log.warning("ws: missing hostname in target URL")
        return web.Response(text="Invalid target URL", status=400)

    # Origin check
    if server.ws_allowed_origins:
        origin = request.headers.get("Origin", "")
        if origin and origin not in server.ws_allowed_origins:
            log.warning("ws: rejected origin '%s'", origin)
            return web.Response(text="Origin not allowed", status=403)

    if not server.ws_scanner:
        log.warning("ws: WebSocket scanning not configured")
        return web.Response(text="WebSocket proxy not enabled", status=503)

    connection_id = str(uuid.uuid4())
    origin = request.headers.get("Origin", "")
    connect_time = time.time()
    with server._active_lock:
        server._active_ws_connections += 1
    frames_sent = 0
    frames_received = 0
    findings_total = 0

    # Get WS connection hook (community default or Pro override)
    ws_hook = server.extensions.get_ws_connection_hook() if server.extensions else None

    log.info("ws: relaying to %s (conn=%s)", target_url, connection_id[:8])

    # Accept WebSocket upgrade from client
    ws_client = web.WebSocketResponse()
    await ws_client.prepare(request)

    # Fire open hook AFTER upgrade succeeds — avoids orphaned DB rows if prepare() fails.
    # Hook runs in thread pool to avoid blocking event loop with SQLite I/O.
    if ws_hook:
        try:
            await asyncio.to_thread(
                ws_hook,
                "open",
                connection_id,
                {
                    "target_url": target_url,
                    "origin": origin,
                    "timestamp": connect_time,
                },
            )
        except Exception as e:
            log.debug("ws hook open error: %s", e)

    close_code = 1000
    # Connect to upstream via aiohttp client session
    try:
        if server.client_session is None:
            log.error("ws: client session not initialized, cannot connect to %s", target_url)
            return web.Response(text="Proxy client session not ready", status=502)
        async with server.client_session.ws_connect(target_url) as ws_upstream:
            log.debug("ws: upstream connected to %s (conn=%s)", target_url, connection_id[:8])

            # Snapshot policy under reload lock for thread safety.
            # Note: long-lived connections keep this snapshot — policy changes
            # via SIGHUP only take effect on new connections.
            with server.pipeline._reload_lock:
                ws_policy = server.pipeline._policy

            # Shared event: set on block to cancel both relay directions
            _blocked = asyncio.Event()

            async def _evaluate_ws_findings(findings: list[Finding], direction: str) -> bool:
                """Evaluate findings against policy. Returns True if connection should close."""
                decision = await asyncio.to_thread(ws_policy.evaluate, findings)
                if decision.action == "block":
                    log.warning(
                        "ws %s: BLOCKED — %d finding(s), closing connection (conn=%s)",
                        direction,
                        len(findings),
                        connection_id[:8],
                    )
                    _blocked.set()
                    return True
                # alert/log — findings are recorded, frame is forwarded
                log.info(
                    "ws %s: %s — %d finding(s) (conn=%s)",
                    direction,
                    decision.action.upper(),
                    len(findings),
                    connection_id[:8],
                )
                return False

            async def _fire_finding_hook(direction: str, frame_size: int, fc: int) -> None:
                """Fire finding_detected hook in thread pool."""
                if ws_hook:
                    try:
                        await asyncio.to_thread(
                            ws_hook,
                            "finding_detected",
                            connection_id,
                            {
                                "direction": direction,
                                "frame_size": frame_size,
                                "findings_count": fc,
                                "timestamp": time.time(),
                            },
                        )
                    except Exception as e:
                        log.debug("ws hook finding error: %s", e)

            async def _client_to_server() -> None:
                """Relay client → upstream with outbound scanning."""
                nonlocal frames_sent, findings_total
                try:
                    async for msg in ws_client:
                        if _blocked.is_set():
                            break
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            if server.mode != "passthrough":
                                try:
                                    findings = server.ws_scanner.scan_outbound_frame(msg.data)
                                except Exception:
                                    log.error("ws outbound scan failed (fail-open)", exc_info=True)
                                    findings = []
                            else:
                                findings = []
                            frames_sent += 1
                            fc = len(findings) if findings else 0
                            if fc:
                                findings_total += fc
                                await _fire_finding_hook("outbound", len(msg.data), fc)
                                if await _evaluate_ws_findings(findings, "outbound"):
                                    break  # block — stop relaying
                            await ws_upstream.send_str(msg.data)
                        elif msg.type == aiohttp.WSMsgType.BINARY:
                            frames_sent += 1
                            await ws_upstream.send_bytes(msg.data)
                        elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR):
                            break
                except Exception as e:
                    log.debug("ws client->server relay ended: %s", e)

            async def _server_to_client() -> None:
                """Relay upstream → client with inbound scanning."""
                nonlocal frames_received, findings_total
                try:
                    async for msg in ws_upstream:
                        if _blocked.is_set():
                            break
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            if server.mode != "passthrough":
                                try:
                                    findings = server.ws_scanner.scan_inbound_frame(msg.data)
                                except Exception:
                                    log.error("ws inbound scan failed (fail-open)", exc_info=True)
                                    findings = []
                            else:
                                findings = []
                            frames_received += 1
                            fc = len(findings) if findings else 0
                            if fc:
                                findings_total += fc
                                await _fire_finding_hook("inbound", len(msg.data), fc)
                                if await _evaluate_ws_findings(findings, "inbound"):
                                    break  # block — stop relaying
                            await ws_client.send_str(msg.data)
                        elif msg.type == aiohttp.WSMsgType.BINARY:
                            frames_received += 1
                            await ws_client.send_bytes(msg.data)
                        elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR):
                            break
                except Exception as e:
                    log.debug("ws server->client relay ended: %s", e)

            # Run both relay directions concurrently.
            # When one direction ends (client disconnect, block, error),
            # cancel the other to avoid hanging on the remaining async for.
            task_c2s = asyncio.create_task(_client_to_server())
            task_s2c = asyncio.create_task(_server_to_client())
            _done, pending = await asyncio.wait([task_c2s, task_s2c], return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            # On block: close both ends with policy violation code (1008)
            if _blocked.is_set():
                close_code = 1008
                log.warning(
                    "ws: closing both ends after block (conn=%s, %d/%d frames)",
                    connection_id[:8],
                    frames_sent,
                    frames_received,
                )
                if not ws_upstream.closed:
                    await ws_upstream.close()
                if not ws_client.closed:
                    await ws_client.close(code=1008, message=b"Policy violation")
            else:
                # Capture actual close code from upstream or client
                close_code = ws_upstream.close_code or ws_client.close_code or 1000

    except aiohttp.ClientError as e:
        log.error("ws upstream connection failed for %s: %s", target_url, e)
        close_code = 1011
        if not ws_client.closed:
            await ws_client.close(code=1011, message=b"Upstream connection failed")
    except Exception as e:
        log.error("ws relay error for %s: %s", target_url, e)
        close_code = 1011
        if not ws_client.closed:
            await ws_client.close(code=1011, message=b"Internal error")

    # Fire close hook in thread pool (SQLite I/O)
    duration = time.time() - connect_time
    if ws_hook:
        try:
            await asyncio.to_thread(
                ws_hook,
                "close",
                connection_id,
                {
                    "timestamp": time.time(),
                    "duration_seconds": duration,
                    "frames_sent": frames_sent,
                    "frames_received": frames_received,
                    "close_code": close_code,
                },
            )
        except Exception as e:
            log.debug("ws hook close error: %s", e)

    with server._active_lock:
        server._active_ws_connections -= 1
    log.debug(
        "ws: connection closed for %s (conn=%s, %.1fs, %d/%d frames, %d findings)",
        target_url,
        connection_id[:8],
        duration,
        frames_sent,
        frames_received,
        findings_total,
    )
    return ws_client


async def _handle_request(request: web.Request) -> web.StreamResponse:
    """Main request handler: read -> scan -> forward or block."""
    path = request.path_qs
    method = request.method

    if path == "/health":
        return await _handle_health(request)
    if path == "/metrics":
        return await _handle_metrics(request)

    # WebSocket upgrade — handle on same port
    if request.headers.get("Upgrade", "").lower() == "websocket" or path.startswith("/ws"):
        ws_server: AsyncArgusProxy = request.app[_PROXY_KEY]
        return await _handle_websocket(request, ws_server)

    request_id = next(_request_counter)
    server: AsyncArgusProxy = request.app[_PROXY_KEY]

    # OTel trace span wraps the full request lifecycle
    trace_hook = server.extensions.get_trace_request_hook() if server.extensions else None
    trace_ctx = None
    if trace_hook:
        try:
            trace_ctx = trace_hook(method, path)
        except Exception:
            trace_ctx = None

    with server._active_lock:
        server._active_requests += 1
    try:
        if trace_ctx:
            try:
                with trace_ctx as span:
                    return await _do_forward(request, request_id, server, span)
            except Exception:
                return await _do_forward(request, request_id, server, None)
        else:
            return await _do_forward(request, request_id, server, None)
    finally:
        with server._active_lock:
            server._active_requests -= 1


async def _do_forward(
    request: web.Request, request_id: int, server: "AsyncArgusProxy", span: Any = None
) -> web.StreamResponse:
    """Inner forwarding logic — separated for active request tracking."""
    # Pre-request hook
    pre_hook = server.pipeline._extensions.get_pre_request_hook() if server.pipeline._extensions else None
    if pre_hook:
        try:
            pre_hook(request_id)
        except Exception:
            log.debug("pre-request hook failed for #%d", request_id, exc_info=True)

    path = request.path_qs
    method = request.method
    t0 = time.monotonic()
    body = b""
    resp_size = 0
    resp_text = ""
    model = ""
    host = ""
    provider = "unknown"
    is_streaming = False
    session = SessionContext()
    scan_result = ScanResult()

    try:
        # Read request body
        body = await request.read()
        if not body:
            log.debug("#%d empty body — scan skipped", request_id)

        # Detect provider and determine upstream
        headers_dict = {k.lower(): v for k, v in request.headers.items()}
        host, port, use_ssl, provider = server.router.route(path, headers_dict)
        log.debug(
            "#%d %s %s -> %s:%d (ssl=%s, provider=%s, %d bytes)",
            request_id,
            method,
            path,
            host,
            port,
            use_ssl,
            provider,
            len(body),
        )
        if span and hasattr(span, "set_attribute"):
            span.set_attribute("provider", provider)
            span.set_attribute("body.size", len(body))

        # Parse body once
        req_data = None
        if body:
            try:
                req_data = json.loads(body)
                if isinstance(req_data, dict):
                    model = req_data.get("model", "")
                    is_streaming = req_data.get("stream", False)
                else:
                    is_streaming = False
            except (json.JSONDecodeError, UnicodeDecodeError):
                is_streaming = False
        else:
            is_streaming = False

        # Extract session context
        source_ip = request.remote or ""
        session = _extract_session(req_data, provider, headers_dict, source_ip, hmac_key=server.hmac_key)

        # Passthrough mode — skip all scanning, forward directly
        if server.mode == "passthrough":
            log.debug("#%d passthrough mode — scanning skipped", request_id)
            scan_result = ScanResult(action="pass", findings=[])

        # Scan request body (CPU-bound — run in thread pool)
        elif body and len(body) <= server.max_body_size:
            try:
                scan_result = await asyncio.to_thread(
                    server.pipeline.scan,
                    body,
                    provider,
                    model=model,
                    session=session,
                )
                log.debug(
                    "#%d scan: %d findings, action=%s, %.1fms",
                    request_id,
                    len(scan_result.findings),
                    scan_result.action,
                    scan_result.scan_duration_ms,
                )
                if span and hasattr(span, "set_attribute"):
                    span.set_attribute("findings.count", len(scan_result.findings))
                    span.set_attribute("action", scan_result.action)
                    span.set_attribute("scan.duration_ms", scan_result.scan_duration_ms)
                if scan_result.action in ("block", "redact") and scan_result.findings:
                    types = ", ".join(f.type for f in scan_result.findings)
                    log.info(
                        "#%d %s %s (%d findings)",
                        request_id,
                        scan_result.action.upper(),
                        types,
                        len(scan_result.findings),
                    )
            except Exception:
                log.error("#%d scan failed — forwarding request (fail-open)", request_id, exc_info=True)
                scan_result = ScanResult(
                    action="pass",
                    findings=[
                        Finding(
                            detector="proxy",
                            type="scan_error",
                            severity="critical",
                            location="pipeline",
                            value_preview="scan failed — request forwarded unscanned",
                            matched_value="",
                            action="log",
                        )
                    ],
                )
        elif len(body) > server.max_body_size:
            scan_result = ScanResult(
                action="pass",
                findings=[
                    Finding(
                        detector="proxy",
                        type="scan_skipped_oversized",
                        severity="warning",
                        location="request_body",
                        value_preview="%d bytes" % len(body),
                        matched_value="",
                        action="log",
                    )
                ],
            )
            log.warning(
                "#%d oversized body skipped scanning (%d bytes > %d limit)",
                request_id,
                len(body),
                server.max_body_size,
            )
            server.display.show_error(
                request_id,
                "body too large to scan (%d bytes > %d limit)" % (len(body), server.max_body_size),
            )

        # MCP-aware scanning (skipped in passthrough)
        _mcp_info = None
        _mcp_method = None
        if body and server.mcp_scanner and server.mode != "passthrough":
            from lumen_argus.mcp.scanner import detect_mcp_method, detect_mcp_request

            try:
                _mcp_method = detect_mcp_method(body)
                _mcp_info = detect_mcp_request(body) if _mcp_method == "tools/call" else None
            except Exception:
                log.error("#%d MCP detection failed (fail-open)", request_id, exc_info=True)
            if _mcp_info:
                tool_name = _mcp_info["tool_name"]
                log.debug("#%d MCP tools/call detected: %s", request_id, tool_name)

                # Track tool usage
                if server.extensions:
                    store = server.extensions.get_analytics_store()
                    if store:
                        try:
                            store.record_mcp_tool_seen(tool_name)
                        except Exception:
                            log.debug("failed to record MCP tool '%s'", tool_name, exc_info=True)

                # Check tool allow/block lists
                if not server.mcp_scanner.is_tool_allowed(tool_name):
                    log.info("#%d MCP tool '%s' blocked by policy", request_id, tool_name)
                    blocked_finding = Finding(
                        detector="mcp",
                        type="blocked_tool",
                        severity="high",
                        location="mcp.tools/call.%s" % tool_name,
                        value_preview=tool_name,
                        matched_value=tool_name,
                        action="block",
                    )
                    block_result = ScanResult(
                        action="block",
                        findings=[blocked_finding],
                        scan_duration_ms=scan_result.scan_duration_ms,
                    )
                    block_body = json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": _mcp_info["request_id"],
                            "error": {
                                "code": -32600,
                                "message": "Tool blocked by lumen-argus: %s" % tool_name,
                            },
                        }
                    ).encode()
                    server.display.show_request(
                        request_id,
                        method,
                        path,
                        model,
                        len(body),
                        len(block_body),
                        (time.monotonic() - t0) * 1000,
                        block_result,
                    )
                    _log_audit(server, request_id, path, provider, model, block_result, len(body), False, session)
                    server.stats.record(provider, len(body), block_result)
                    # Log tool call (blocked)
                    if server.extensions:
                        _s = server.extensions.get_analytics_store()
                        if _s:
                            try:
                                _s.record_mcp_tool_call(
                                    tool_name,
                                    session.session_id if session else "",
                                    status="blocked",
                                    finding_count=1,
                                    source="proxy",
                                )
                            except Exception:
                                log.debug("failed to record blocked MCP tool call '%s'", tool_name, exc_info=True)
                    return web.Response(body=block_body, status=400, content_type="application/json")

                # Scan tool arguments
                try:
                    mcp_findings = server.mcp_scanner.scan_arguments(tool_name, _mcp_info["arguments"])
                except Exception:
                    log.error("#%d MCP argument scan failed (fail-open)", request_id, exc_info=True)
                    mcp_findings = []
                if mcp_findings:
                    scan_result.findings.extend(mcp_findings)
                    log.info("#%d MCP argument scan: %d finding(s) in '%s'", request_id, len(mcp_findings), tool_name)

                # Record MCP argument findings to analytics store
                # (pipeline.scan() already called record_findings() before MCP scanning,
                # so MCP findings need their own explicit write)
                if mcp_findings and server.extensions:
                    _s = server.extensions.get_analytics_store()
                    if _s:
                        try:
                            _s.record_findings(
                                findings=mcp_findings,
                                provider=provider,
                                model=model,
                                session=session,
                            )
                        except Exception:
                            log.warning("failed to record MCP argument findings", exc_info=True)

                # Log tool call (allowed/alert)
                if server.extensions:
                    _s = server.extensions.get_analytics_store()
                    if _s:
                        try:
                            _s.record_mcp_tool_call(
                                tool_name,
                                session.session_id if session else "",
                                status="alert" if mcp_findings else "allowed",
                                finding_count=len(mcp_findings) if mcp_findings else 0,
                                source="proxy",
                            )
                        except Exception:
                            log.debug("failed to record MCP tool call '%s'", tool_name, exc_info=True)

        # Check if we should block
        if not should_forward(scan_result):
            stripped_body = (
                try_strip_blocked_history(req_data, scan_result.findings) if isinstance(req_data, dict) else None
            )
            if stripped_body is not None:
                types = ", ".join(f.type for f in scan_result.findings)
                log.info(
                    "#%d stripping %d blocked message(s) from history (%d→%d bytes): %s",
                    request_id,
                    len(scan_result.findings),
                    len(body),
                    len(stripped_body),
                    types,
                )
                _log_audit(
                    server,
                    request_id,
                    path,
                    provider,
                    model,
                    ScanResult(
                        action="strip", findings=scan_result.findings, scan_duration_ms=scan_result.scan_duration_ms
                    ),
                    len(body),
                    True,
                    session,
                )
                server.pipeline.commit_pending(scan_result)
                body = stripped_body
                scan_result = ScanResult(action="pass", findings=[], scan_duration_ms=scan_result.scan_duration_ms)
            else:
                types = ", ".join(f.type for f in scan_result.findings)
                block_body = build_block_response(scan_result)
                log.info(
                    "#%d blocking request (400, streaming=%s, %d bytes): %s",
                    request_id,
                    is_streaming,
                    len(block_body),
                    types,
                )
                server.display.show_request(
                    request_id,
                    method,
                    path,
                    model,
                    len(body),
                    len(block_body),
                    (time.monotonic() - t0) * 1000,
                    scan_result,
                )
                _log_audit(server, request_id, path, provider, model, scan_result, len(body), False, session)
                server.stats.record(provider, len(body), scan_result)
                return web.Response(body=block_body, status=400, content_type="application/json")

        # Apply redaction if action is "redact" and a hook is registered
        if scan_result.action == "redact":
            if server.redact_hook is not None:
                try:
                    original_len = len(body)
                    body = server.redact_hook(body, scan_result.findings)
                    types = ", ".join(f.type for f in scan_result.findings)
                    log.info(
                        "#%d REDACT %d finding(s) (%s), body %d→%d bytes",
                        request_id,
                        len(scan_result.findings),
                        types,
                        original_len,
                        len(body),
                    )
                except Exception as e:
                    log.error("#%d redaction hook failed, forwarding unmodified: %s", request_id, e)
            else:
                log.warning(
                    "#%d redact action but no redact hook registered — forwarding unmodified "
                    "(Pro redaction not loaded?)",
                    request_id,
                )

        # Build forwarding headers
        fwd_headers = {}
        for key, val in request.headers.items():
            lk = key.lower()
            if lk in _HOP_BY_HOP:
                continue
            if lk in ("host", "accept-encoding"):
                continue
            if lk == "content-length":
                fwd_headers[key] = str(len(body))
                continue
            fwd_headers[key] = val
        fwd_headers["Host"] = host

        # Build upstream URL
        scheme = "https" if use_ssl else "http"
        upstream_url = "%s://%s:%d%s" % (scheme, host, port, path)

        # Forward to upstream via aiohttp ClientSession
        if server.client_session is None:
            log.error("#%d client session not initialized", request_id)
            return web.Response(status=502, text="Proxy not ready")
        client_session = server.client_session
        try:
            async with client_session.request(
                method,
                upstream_url,
                data=body,
                headers=fwd_headers,
                timeout=aiohttp.ClientTimeout(total=server.timeout),
            ) as upstream_resp:
                # Determine response scanning strategy
                _should_scan_response = server.response_scanner is not None and server.mode != "passthrough"
                _should_accumulate = (
                    _should_scan_response
                    or (_mcp_info is not None and server.mcp_scanner is not None)
                    or (_mcp_method == "tools/list" and server.mcp_scanner is not None)
                )
                _response_hook = server.extensions.get_response_scan_hook() if server.extensions else None

                content_type = upstream_resp.headers.get("Content-Type", "")
                is_sse = is_streaming or "text/event-stream" in content_type

                # Collect response headers (filter hop-by-hop)
                resp_headers = {}
                for hdr, val in upstream_resp.headers.items():
                    lk = hdr.lower()
                    if lk in _HOP_BY_HOP:
                        continue
                    if lk == "content-length" and is_sse:
                        continue
                    resp_headers[hdr] = val

                # Buffered response scan hook (Pro) — for non-SSE only
                _response_blocked = False
                if _response_hook and _should_scan_response and not is_sse:
                    data = await upstream_resp.read()
                    resp_text = data.decode("utf-8", errors="ignore")
                    try:
                        hook_action, hook_findings = _response_hook(resp_text, provider, model, session)
                        if hook_action == "block" and hook_findings:
                            log.info(
                                "#%d response blocked by scan hook: %d finding(s)",
                                request_id,
                                len(hook_findings),
                            )
                            _response_blocked = True
                            hook_result = ScanResult(action="block", findings=hook_findings)
                            block_body_bytes = build_block_response(hook_result)
                            resp_size = len(block_body_bytes)
                            resp_text = ""
                            server.display.show_request(
                                request_id,
                                method,
                                path,
                                model,
                                len(body),
                                resp_size,
                                (time.monotonic() - t0) * 1000,
                                hook_result,
                            )
                            _log_audit(
                                server, request_id, path, provider, model, hook_result, len(body), False, session
                            )
                            server.stats.record(provider, len(body), hook_result)
                            return web.Response(
                                body=block_body_bytes,
                                status=400,
                                content_type="application/json",
                            )
                    except Exception as e:
                        log.warning("#%d response scan hook failed: %s", request_id, e)
                    # Hook passed — forward the response normally
                    resp_size = len(data)
                    resp_text = ""  # hook handled — skip async scan
                    response: web.StreamResponse = web.Response(
                        body=data,
                        status=upstream_resp.status,
                        headers=resp_headers,
                    )
                    # Fall through to audit/stats below (don't return early)

                elif is_sse:
                    # Stream SSE response
                    response = web.StreamResponse(
                        status=upstream_resp.status,
                        headers=resp_headers,
                    )
                    await response.prepare(request)

                    text_parts = []
                    async for chunk in upstream_resp.content.iter_any():
                        if not chunk:
                            continue
                        try:
                            await response.write(chunk)
                        except (ConnectionResetError, ConnectionAbortedError):
                            break
                        resp_size += len(chunk)
                        if _should_accumulate:
                            text_parts.append(chunk)

                    if _should_accumulate and text_parts:
                        resp_text = b"".join(text_parts).decode("utf-8", errors="ignore")

                    try:
                        await response.write_eof()
                    except (ConnectionResetError, BrokenPipeError, OSError):
                        log.debug("#%d client disconnected during write_eof", request_id)

                else:
                    # Non-streaming — read full response
                    data = await upstream_resp.read()
                    resp_size = len(data)
                    if _should_accumulate:
                        resp_text = data.decode("utf-8", errors="ignore")

                    response = web.Response(
                        body=data,
                        status=upstream_resp.status,
                        headers=resp_headers,
                    )

        except asyncio.TimeoutError:
            msg = (
                "Upstream timed out after %ds. "
                "Increase proxy.timeout in ~/.lumen-argus/config.yaml "
                "or the dashboard Settings page." % server.timeout
            )
            log.error("#%d upstream timeout after %ds", request_id, server.timeout)
            server.display.show_error(request_id, msg)
            server.stats.record(provider, len(body), scan_result)
            return web.json_response(
                {"error": {"type": "timeout", "message": msg}},
                status=504,
            )
        except aiohttp.ClientConnectionError as e:
            # Connection-level error — retry if attempts remain
            if server.retries > 0:
                log.debug("#%d connection error (attempt 1/%d): %s", request_id, server.retries + 1, e)
                for _attempt in range(server.retries):
                    try:
                        async with client_session.request(
                            method,
                            upstream_url,
                            data=body,
                            headers=fwd_headers,
                            timeout=aiohttp.ClientTimeout(total=server.timeout),
                        ) as upstream_resp:
                            # On successful retry, read and return full response
                            data = await upstream_resp.read()
                            resp_size = len(data)
                            resp_headers = {
                                hdr: val for hdr, val in upstream_resp.headers.items() if hdr.lower() not in _HOP_BY_HOP
                            }
                            response = web.Response(
                                body=data,
                                status=upstream_resp.status,
                                headers=resp_headers,
                            )
                            log.debug("#%d retry %d succeeded", request_id, _attempt + 1)
                            server.display.show_request(
                                request_id,
                                method,
                                path,
                                model,
                                len(body),
                                resp_size,
                                (time.monotonic() - t0) * 1000,
                                scan_result,
                            )
                            _log_audit(server, request_id, path, provider, model, scan_result, len(body), True, session)
                            server.stats.record(provider, len(body), scan_result)
                            return response
                    except (aiohttp.ClientConnectionError, asyncio.TimeoutError) as retry_err:
                        log.debug("#%d retry %d failed: %s", request_id, _attempt + 1, retry_err)
                        continue
            log.error("#%d upstream connection error: %s", request_id, e)
            server.display.show_error(request_id, str(e))
            server.stats.record(provider, len(body), scan_result)
            return web.json_response(
                {"error": {"type": "proxy_error", "message": str(e)}},
                status=502,
            )
        except aiohttp.ClientError as e:
            log.error("#%d upstream error: %s", request_id, e)
            server.display.show_error(request_id, str(e))
            server.stats.record(provider, len(body), scan_result)
            return web.json_response(
                {"error": {"type": "proxy_error", "message": str(e)}},
                status=502,
            )
        except ssl.SSLCertVerificationError as e:
            msg = (
                "TLS verification failed for %s — %s. "
                "If behind a corporate proxy, set proxy.ca_bundle in "
                "~/.lumen-argus/config.yaml" % (host, e)
            )
            log.error("#%d %s", request_id, msg)
            server.display.show_error(request_id, msg)
            server.stats.record(provider, len(body), scan_result)
            return web.json_response(
                {"error": {"type": "tls_error", "message": msg}},
                status=502,
            )

        # Display request line
        server.display.show_request(
            request_id,
            method,
            path,
            model,
            len(body),
            resp_size,
            (time.monotonic() - t0) * 1000,
            scan_result,
        )

        # Audit log + stats
        _log_audit(server, request_id, path, provider, model, scan_result, len(body), True, session)
        server.stats.record(provider, len(body), scan_result)

        # Async response scanning — scan after forwarding (no latency impact)
        if _should_scan_response and resp_text:
            _async_response_scan(server, request_id, resp_text, provider, model, session)

        # MCP response scanning
        if _mcp_info and server.mcp_scanner and resp_text:
            from lumen_argus.mcp.scanner import detect_mcp_response

            mcp_resp = detect_mcp_response(resp_text.encode("utf-8", errors="ignore"))
            if mcp_resp and mcp_resp.get("content"):
                mcp_resp_findings = server.mcp_scanner.scan_response_content(mcp_resp["content"])
                if mcp_resp_findings:
                    log.info("#%d MCP response scan: %d finding(s)", request_id, len(mcp_resp_findings))
                    if server.extensions:
                        _store = server.extensions.get_analytics_store()
                        if _store:
                            try:
                                _store.record_findings(
                                    findings=mcp_resp_findings,
                                    provider=provider,
                                    model=model,
                                    session=session,
                                )
                            except Exception:
                                log.warning("failed to record MCP response findings", exc_info=True)

        # MCP tools/list response — capture tool descriptions
        if _mcp_method == "tools/list" and server.mcp_scanner and resp_text:
            from lumen_argus.mcp.scanner import detect_mcp_tools_list_response

            tools_meta = detect_mcp_tools_list_response(resp_text.encode("utf-8", errors="ignore"))
            if tools_meta and server.extensions:
                _store = server.extensions.get_analytics_store()
                if _store:
                    for t in tools_meta:
                        try:
                            _store.record_mcp_tool_seen(
                                t["name"],
                                description=t.get("description", ""),
                                input_schema=json.dumps(t.get("inputSchema", {})),
                            )
                        except Exception:
                            log.debug("failed to record MCP tool '%s'", t.get("name"), exc_info=True)
                    log.debug("#%d MCP tools/list: captured %d tool descriptions", request_id, len(tools_meta))

        return response

    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        log.debug("#%d client disconnected", request_id)
        return web.Response(status=499)
    except Exception as e:
        log.error("#%d request error: %s", request_id, e)
        server.display.show_error(request_id, str(e))
        server.stats.record(provider, len(body), scan_result)
        return web.json_response(
            {"error": {"type": "proxy_error", "message": str(e)}},
            status=502,
        )


def _async_response_scan(
    server: "AsyncArgusProxy",
    request_id: int,
    text: str,
    provider: str,
    model: str,
    session: SessionContext | None = None,
) -> None:
    """Run response scanning in a background task (async mode)."""

    async def _scan() -> None:
        try:
            findings = await asyncio.to_thread(server.response_scanner.scan, text, provider, model)
            if not findings:
                return
            log.info("#%d response scan: %d finding(s)", request_id, len(findings))
            # DB write in thread pool — don't block event loop with SQLite I/O
            if server.extensions:
                store = server.extensions.get_analytics_store()
                if store:
                    await asyncio.to_thread(
                        store.record_findings,
                        findings,
                        provider=provider,
                        model=model,
                        session=session,
                    )
            # Post-scan hook in thread pool — may do CPU work (notifications)
            post_scan = server.extensions.get_post_scan_hook() if server.extensions else None
            if post_scan:
                resp_result = ScanResult(findings=findings, action="alert")
                try:
                    await asyncio.to_thread(
                        post_scan,
                        result=resp_result,
                        body=b"",
                        provider=provider,
                        session=session,
                        model=model,
                    )
                except Exception:
                    log.warning("#%d post-scan hook failed for response", request_id, exc_info=True)
        except Exception as e:
            log.warning("#%d response scan failed: %s", request_id, e)

    task = asyncio.ensure_future(_scan())
    # Store reference in set to prevent GC of pending tasks
    server._background_tasks.add(task)
    task.add_done_callback(server._background_tasks.discard)


class AsyncArgusProxy:
    """Async HTTP proxy server with scan pipeline integration.

    Uses aiohttp.web for non-blocking I/O and aiohttp.ClientSession for
    upstream connections. CPU-bound scanning runs in a thread pool.
    """

    def __init__(
        self,
        bind: str,
        port: int,
        pipeline: ScannerPipeline,
        router: ProviderRouter,
        audit: AuditLogger,
        display: TerminalDisplay,
        timeout: int = 30,
        retries: int = 1,
        max_body_size: int = 50 * 1024 * 1024,
        redact_hook: Any = None,
        ssl_context: ssl.SSLContext | None = None,
        max_connections: int = 10,
    ):
        if bind not in ("127.0.0.1", "localhost"):
            log.warning("binding to %s — proxy is accessible on the network", bind)

        self.bind = bind
        self.port = port
        self.pipeline = pipeline
        self.router = router
        self.audit = audit
        self.display = display
        self.timeout = timeout
        self.retries = retries
        self.max_body_size = max_body_size
        self.redact_hook = redact_hook
        self._ssl_context = ssl_context
        self.max_connections = max_connections
        self._active_requests = 0
        self._active_ws_connections = 0
        self._active_lock = threading.Lock()  # free-threaded Python safety
        self._background_tasks: set[asyncio.Task[Any]] = set()
        self.stats = SessionStats()
        self.start_time = time.monotonic()
        self.extensions: ExtensionRegistry | None = None
        self.response_scanner: Any = None
        self.mcp_scanner: Any = None
        self.ws_scanner: Any = None  # WebSocketScanner, set by cli.py
        self.ready: bool = False  # set True after pipeline is fully loaded
        self.ws_allowed_origins: list[str] = []  # set by cli.py
        self.mode: str = "active"  # "active" or "passthrough"
        self.hmac_key: bytes = b""  # set by cli.py for API key fingerprinting
        self.standalone: bool = True  # False when managed by tray app
        self.client_session: aiohttp.ClientSession | None = None
        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None

    @property
    def active_requests(self) -> int:
        with self._active_lock:
            return self._active_requests

    @property
    def active_ws_connections(self) -> int:
        with self._active_lock:
            return self._active_ws_connections

    @property
    def server_address(self) -> tuple[str, int]:
        """Compatible with ThreadingHTTPServer.server_address."""
        return (self.bind, self.port)

    def _create_app(self) -> web.Application:
        """Create the aiohttp Application with routes and middleware."""
        app = web.Application(
            client_max_size=self.max_body_size + 1024,  # allow slightly over for headers
        )
        app[_PROXY_KEY] = self

        # Catch-all route for proxy forwarding
        app.router.add_route("*", "/{path_info:.*}", _handle_request)

        # Lifecycle hooks for client session management
        app.on_startup.append(self._on_startup)
        app.on_cleanup.append(self._on_cleanup)

        self._app = app
        return app

    async def _on_startup(self, app: web.Application) -> None:
        """Create the aiohttp ClientSession for upstream connections."""
        connector = aiohttp.TCPConnector(
            limit=self.max_connections,
            ssl=self._ssl_context if self._ssl_context else False,
            enable_cleanup_closed=True,
        )
        self.client_session = aiohttp.ClientSession(
            connector=connector,
            auto_decompress=False,  # pass through encoding as-is
        )
        log.info("async proxy client session created (max_connections=%d)", self.max_connections)

    async def _on_cleanup(self, app: web.Application) -> None:
        """Close the client session on shutdown."""
        if self.client_session:
            await self.client_session.close()
            log.info("async proxy client session closed")

    async def start(self) -> None:
        """Start the async proxy server."""
        if self._app is None:
            self._create_app()
        if self._app is None:
            log.error("failed to create aiohttp application")
            raise RuntimeError("failed to create aiohttp application")

        self._runner = web.AppRunner(self._app, handle_signals=False)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self.bind, self.port)
        await self._site.start()
        self._loop = asyncio.get_running_loop()
        log.info("async proxy listening on http://%s:%d", self.bind, self.port)

    async def rebind(self, new_port: int | None = None, new_bind: str | None = None) -> None:
        """Rebind the proxy to a new address without full restart.

        Stops the listening socket and starts a new one on the target
        address.  In-flight requests on existing connections continue
        uninterrupted.  If the new port is unavailable, rolls back to the
        previous address and raises ``OSError``.
        """
        target_port = new_port if new_port is not None else self.port
        target_bind = new_bind if new_bind is not None else self.bind

        if target_port == self.port and target_bind == self.bind:
            log.debug("rebind: no change (already on %s:%d)", self.bind, self.port)
            return

        if self._runner is None:
            raise RuntimeError("cannot rebind: server not started")

        old_port, old_bind = self.port, self.bind
        log.info("rebind: %s:%d -> %s:%d", old_bind, old_port, target_bind, target_port)

        # Stop accepting new connections on the old address
        if self._site:
            await self._site.stop()

        # Try to bind to the new address
        self.port = target_port
        self.bind = target_bind
        try:
            self._site = web.TCPSite(self._runner, self.bind, self.port)
            await self._site.start()
            if self.bind not in ("127.0.0.1", "localhost"):
                log.warning("binding to %s — proxy is accessible on the network", self.bind)
            log.info("rebind complete: listening on http://%s:%d", self.bind, self.port)
        except OSError:
            # Rollback — restore the old address
            log.error(
                "rebind failed: could not bind to %s:%d, rolling back to %s:%d",
                target_bind,
                target_port,
                old_bind,
                old_port,
            )
            self.port = old_port
            self.bind = old_bind
            self._site = web.TCPSite(self._runner, self.bind, self.port)
            await self._site.start()
            raise

    async def stop(self) -> None:
        """Stop the async proxy server gracefully."""
        if self._runner:
            await self._runner.cleanup()
            log.info("async proxy stopped")

    def update_timeout(self, timeout: int) -> None:
        """Update request timeout."""
        self.timeout = timeout

    async def drain(self, timeout: int = 30) -> int:
        """Wait for in-flight requests to complete."""
        if timeout <= 0:
            return self.active_requests
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.active_requests == 0:
                return 0
            await asyncio.sleep(0.1)
        return self.active_requests
