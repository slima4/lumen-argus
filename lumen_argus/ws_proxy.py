"""WebSocket proxy — bidirectional frame scanning.

Runs a standalone WebSocket server (default port 8083) alongside the HTTP
proxy. Clients connect with the target URL as a query parameter:

    ws://localhost:8083/?url=ws://real-server:3000/path

The proxy connects to the upstream server, relays frames bidirectionally,
and scans text frames for secrets, PII, and injection patterns. Binary
frames pass through without scanning.

Integrated into the proxy startup via start_ws_proxy() called from cli.py.
Supports dynamic start/stop on SIGHUP (Pipeline dashboard toggle).
"""

import asyncio
import logging
import threading
from typing import List, Optional
from urllib.parse import parse_qs, urlparse

from lumen_argus.models import Finding, ScanField
from lumen_argus.text_utils import sanitize_text

log = logging.getLogger("argus.ws")

# Graceful import — server doesn't crash if websockets not installed
try:
    import websockets

    _HAS_WEBSOCKETS = True
except ImportError:
    websockets = None  # type: ignore[assignment]
    _HAS_WEBSOCKETS = False
    log.warning("websockets package not installed — WebSocket proxy disabled")


class WebSocketScanner:
    """Scans WebSocket text frames for sensitive data.

    Reuses existing detectors for secret/PII detection.
    Reuses response scanner for injection detection on inbound frames.
    """

    def __init__(
        self,
        detectors: list = None,
        allowlist=None,
        response_scanner=None,
        scan_outbound: bool = True,
        scan_inbound: bool = True,
        max_frame_size: int = 1_048_576,
    ):
        self._detectors = detectors or []
        self._allowlist = allowlist
        self._response_scanner = response_scanner
        self._scan_outbound = scan_outbound
        self._scan_inbound = scan_inbound
        self._max_frame_size = max_frame_size

    def scan_outbound_frame(self, text: str) -> List[Finding]:
        """Scan an outbound text frame (client -> server)."""
        if not self._scan_outbound or not text:
            return []
        return self._scan_text(text, "ws.outbound")

    def scan_inbound_frame(self, text: str) -> List[Finding]:
        """Scan an inbound text frame (server -> client)."""
        if not self._scan_inbound or not text:
            return []

        findings = self._scan_text(text, "ws.inbound")

        # Injection detection on inbound frames
        if self._response_scanner:
            try:
                inj_findings = self._response_scanner._scan_injection_patterns(text)
                for f in inj_findings:
                    f.location = "ws.inbound"
                findings.extend(inj_findings)
            except Exception as e:
                log.warning("ws injection scan failed: %s", e)

        return findings

    def _scan_text(self, text: str, location_prefix: str) -> List[Finding]:
        """Scan text with all detectors."""
        if len(text) > self._max_frame_size:
            log.debug("ws frame truncated: %d -> %d", len(text), self._max_frame_size)
            text = text[: self._max_frame_size]

        text = sanitize_text(text)
        fields = [ScanField(path=location_prefix, text=text)]

        findings = []
        for detector in self._detectors:
            try:
                det_findings = detector.scan(fields, self._allowlist)
                for f in det_findings:
                    f.location = "%s.%s" % (location_prefix, f.location)
                findings.extend(det_findings)
            except Exception as e:
                log.warning("ws detector %s failed: %s", detector.__class__.__name__, e)

        return findings


def _validate_target_url(url: str) -> Optional[str]:
    """Validate and return the target URL, or None if invalid."""
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme not in ("ws", "wss"):
        return None
    if not parsed.hostname:
        return None
    return url


async def _handle_connection(websocket, scanner, allowed_origins):
    """Handle a single WebSocket client connection."""
    # Extract target URL from path query
    path = websocket.request.path if hasattr(websocket, "request") else "/"
    parsed = urlparse(path)
    params = parse_qs(parsed.query)
    target_url = params.get("url", [None])[0]

    target_url = _validate_target_url(target_url)
    if not target_url:
        log.warning("ws: missing or invalid 'url' parameter")
        await websocket.close(1008, "Missing or invalid 'url' parameter. Use ?url=ws://target")
        return

    # Origin check
    origin = ""
    if hasattr(websocket, "request") and hasattr(websocket.request, "headers"):
        origin = websocket.request.headers.get("Origin", "")
    if allowed_origins and origin and origin not in allowed_origins:
        log.warning("ws: rejected origin '%s'", origin)
        await websocket.close(1008, "Origin not allowed")
        return

    log.info("ws: relaying to %s", target_url)

    try:
        async with websockets.connect(target_url) as upstream:

            async def _client_to_server():
                try:
                    async for message in websocket:
                        if isinstance(message, str):
                            findings = scanner.scan_outbound_frame(message)
                            if findings:
                                log.info("ws outbound: %d finding(s)", len(findings))
                        await upstream.send(message)
                except websockets.ConnectionClosed:
                    pass

            async def _server_to_client():
                try:
                    async for message in upstream:
                        if isinstance(message, str):
                            findings = scanner.scan_inbound_frame(message)
                            if findings:
                                log.info("ws inbound: %d finding(s)", len(findings))
                        await websocket.send(message)
                except websockets.ConnectionClosed:
                    pass

            await asyncio.gather(
                _client_to_server(),
                _server_to_client(),
                return_exceptions=True,
            )

    except Exception as e:
        log.error("ws relay error for %s: %s", target_url, e)
        try:
            await websocket.close(1011, "Upstream connection failed")
        except Exception:
            pass


class WebSocketProxyHandle:
    """Handle for a running WebSocket proxy server. Supports stop() for SIGHUP."""

    def __init__(self):
        self._thread = None  # type: Optional[threading.Thread]
        self._loop = None  # type: Optional[asyncio.AbstractEventLoop]
        self._server = None  # type: Optional[object]
        self._stop_event = None  # type: Optional[asyncio.Event]

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def stop(self) -> None:
        """Stop the WebSocket proxy server gracefully."""
        if self._loop and self._stop_event:
            self._loop.call_soon_threadsafe(self._stop_event.set)
        if self._thread:
            self._thread.join(timeout=5)
            log.info("ws proxy stopped")
        self._thread = None
        self._loop = None
        self._server = None
        self._stop_event = None


def start_ws_proxy(
    bind: str,
    port: int,
    scanner: WebSocketScanner,
    allowed_origins: Optional[List[str]] = None,
) -> Optional[WebSocketProxyHandle]:
    """Start the WebSocket proxy server in a background daemon thread.

    Returns a handle with stop() for SIGHUP reload, or None if websockets
    is not installed.
    """
    if not _HAS_WEBSOCKETS:
        log.warning("cannot start ws proxy: websockets package not installed")
        return None

    handle = WebSocketProxyHandle()
    ready = threading.Event()

    async def _serve():
        handle._stop_event = asyncio.Event()
        handle._loop = asyncio.get_running_loop()
        ready.set()  # signal: loop + stop_event are live

        async def _handler(ws):
            await _handle_connection(ws, scanner, allowed_origins or [])

        srv = await websockets.serve(_handler, bind, port)
        handle._server = srv
        log.info("ws proxy listening on ws://%s:%d", bind, port)

        # Wait until stop is requested
        await handle._stop_event.wait()
        srv.close()
        await srv.wait_closed()
        log.debug("ws proxy server closed")

    def _run():
        try:
            asyncio.run(_serve())
        except Exception as e:
            log.error("ws proxy failed: %s", e)
            ready.set()  # unblock caller on error

    handle._thread = threading.Thread(target=_run, daemon=True, name="ws-proxy")
    handle._thread.start()
    ready.wait(timeout=5)  # wait for loop to be assigned before returning
    return handle
