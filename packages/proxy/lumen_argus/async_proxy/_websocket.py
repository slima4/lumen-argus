from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import TYPE_CHECKING

import aiohttp
from aiohttp import web

from lumen_argus.models import Finding

if TYPE_CHECKING:
    from lumen_argus.async_proxy._server import AsyncArgusProxy

log = logging.getLogger("argus.proxy")


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
