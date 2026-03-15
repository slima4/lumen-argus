"""HTTP proxy server: transparent forwarding with scan integration.

Architecture follows the ClaudeTUI sniffer pattern:
- ThreadingHTTPServer with daemon threads
- Plain HTTP on localhost, HTTPS to upstream
- SSE streaming passthrough via read1()
- Full request body buffered for scanning before forwarding
"""

import http.client
import http.server
import itertools
import json
import ssl
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from lumen_argus.actions import build_block_response, build_sse_block_response, should_forward
from lumen_argus.audit import AuditLogger
from lumen_argus.display import TerminalDisplay
from lumen_argus.models import AuditEntry, Finding, ScanResult
from lumen_argus.pipeline import ScannerPipeline
from lumen_argus.provider import ProviderRouter

# Shared SSL context — created once, reused across all connections.
_SSL_CTX = ssl.create_default_context()

# Thread-safe request counter.
_request_counter = itertools.count(1)

# Hop-by-hop headers that must not be forwarded.
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "proxy-connection",
    "te", "trailers", "transfer-encoding", "upgrade",
})


class ArgusProxyHandler(http.server.BaseHTTPRequestHandler):
    """Handles proxied HTTP requests with scan integration."""

    # Suppress default log_message output — we use TerminalDisplay.
    def log_message(self, format, *args):
        pass

    def do_POST(self):
        self._forward()

    def do_GET(self):
        self._forward()

    def do_PUT(self):
        self._forward()

    def do_DELETE(self):
        self._forward()

    def do_OPTIONS(self):
        self._forward()

    def do_HEAD(self):
        self._forward()

    def do_PATCH(self):
        self._forward()

    def _forward(self):
        """Main request handling: read → scan → forward or block."""
        request_id = next(_request_counter)
        server = self.server  # type: ArgusProxyServer
        t0 = time.monotonic()
        body = b""
        resp_size = 0
        model = ""
        scan_result = ScanResult()

        try:
            # Read request body
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 0:
                body = self.rfile.read(content_length)

            # Detect provider and determine upstream (#1: use_ssl flag)
            headers_dict = {k.lower(): v for k, v in self.headers.items()}
            host, port, use_ssl, provider = server.router.route(self.path, headers_dict)

            # Extract model from request body for display
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

            # Scan request body (#5: oversized bodies get a finding)
            if body and len(body) <= server.max_body_size:
                scan_result = server.pipeline.scan(body, provider)
            elif len(body) > server.max_body_size:
                scan_result = ScanResult(
                    action="pass",
                    findings=[Finding(
                        detector="proxy",
                        type="scan_skipped_oversized",
                        severity="warning",
                        location="request_body",
                        value_preview="%d bytes" % len(body),
                        matched_value="",
                        action="log",
                    )],
                )
                server.display.show_error(
                    request_id,
                    "body too large to scan (%d bytes > %d limit)"
                    % (len(body), server.max_body_size),
                )

            # Check if we should block (#2: SSE-aware block response)
            if not should_forward(scan_result):
                if is_streaming:
                    block_body = build_sse_block_response(scan_result)
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-cache")
                else:
                    block_body = build_block_response(scan_result)
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(block_body)))
                self.end_headers()
                self.wfile.write(block_body)
                resp_size = len(block_body)

                server.display.show_request(
                    request_id, self.command, self.path, model,
                    len(body), resp_size,
                    (time.monotonic() - t0) * 1000, scan_result,
                )
                self._log_audit(
                    server, request_id, provider, model,
                    scan_result, len(body), False,
                )
                return

            # Forward to upstream (#1: use_ssl flag, #3: retry + timeout)
            last_err = None
            for attempt in range(server.retries + 1):
                conn = None
                try:
                    if use_ssl:
                        conn = http.client.HTTPSConnection(
                            host, port, context=_SSL_CTX, timeout=server.timeout,
                        )
                    else:
                        conn = http.client.HTTPConnection(
                            host, port, timeout=server.timeout,
                        )

                    # Build forwarding headers
                    fwd_headers = {}
                    for key, val in self.headers.items():
                        lk = key.lower()
                        if lk in _HOP_BY_HOP:
                            continue
                        if lk in ("host", "accept-encoding"):
                            continue
                        fwd_headers[key] = val
                    fwd_headers["Host"] = host

                    conn.request(self.command, self.path, body, fwd_headers)
                    resp = conn.getresponse()

                    # Forward response status and headers
                    self.send_response(resp.status)
                    content_type = ""
                    for hdr, val in resp.getheaders():
                        lk = hdr.lower()
                        if lk in _HOP_BY_HOP:
                            continue
                        if lk == "content-type":
                            content_type = val
                        if lk == "content-length" and (is_streaming or "text/event-stream" in content_type):
                            continue
                        self.send_header(hdr, val)
                    self.end_headers()

                    # Stream or read response body
                    is_sse = is_streaming or "text/event-stream" in content_type

                    if is_sse:
                        resp_size = self._stream_sse(resp)
                    else:
                        data = resp.read()
                        self.wfile.write(data)
                        resp_size = len(data)

                    conn.close()
                    last_err = None
                    break  # success

                except (ConnectionError, OSError, http.client.HTTPException) as e:
                    last_err = e
                    if conn:
                        conn.close()
                    if attempt < server.retries:
                        continue
                    raise

            # Display request line
            server.display.show_request(
                request_id, self.command, self.path, model,
                len(body), resp_size,
                (time.monotonic() - t0) * 1000, scan_result,
            )

            # Audit log
            self._log_audit(
                server, request_id, provider, model,
                scan_result, len(body), True,
            )

        except (BrokenPipeError, ConnectionResetError):
            pass  # Client disconnected
        except Exception as e:
            server.display.show_error(request_id, str(e))
            try:
                error_body = json.dumps({
                    "error": {"type": "proxy_error", "message": str(e)}
                }).encode("utf-8")
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(error_body)))
                self.end_headers()
                self.wfile.write(error_body)
            except Exception:
                pass

    def _stream_sse(self, resp: http.client.HTTPResponse) -> int:
        """Stream SSE response chunks using read1() for low latency."""
        total = 0
        while True:
            try:
                chunk = resp.read1(8192)
            except AttributeError:
                chunk = resp.read(8192)
            if not chunk:
                break
            try:
                self.wfile.write(chunk)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                break
            total += len(chunk)
        return total

    def _log_audit(
        self,
        server: "ArgusProxyServer",
        request_id: int,
        provider: str,
        model: str,
        result: ScanResult,
        body_size: int,
        passed: bool,
    ) -> None:
        """Write audit log entry."""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            request_id=request_id,
            provider=provider,
            model=model,
            endpoint=self.path,
            action=result.action,
            findings=result.findings,
            scan_duration_ms=result.scan_duration_ms,
            request_size_bytes=body_size,
            passed=passed,
        )
        server.audit.log(entry)


class ArgusProxyServer(http.server.ThreadingHTTPServer):
    """Threaded HTTP proxy server with scan pipeline integration."""

    daemon_threads = True
    allow_reuse_address = True

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
    ):
        # Hard safety invariant: never bind to 0.0.0.0
        if bind != "127.0.0.1" and bind != "localhost":
            raise ValueError(
                "lumen-argus must bind to 127.0.0.1 or localhost, got: %s" % bind
            )

        self.pipeline = pipeline
        self.router = router
        self.audit = audit
        self.display = display
        self.timeout = timeout
        self.retries = retries
        self.max_body_size = max_body_size

        super().__init__((bind, port), ArgusProxyHandler)
