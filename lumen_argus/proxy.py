"""HTTP proxy server: transparent forwarding with scan integration.

Architecture follows the ClaudeTUI sniffer pattern:
- ThreadingHTTPServer with daemon threads
- Plain HTTP on localhost, HTTPS to upstream
- SSE streaming passthrough via read1()
- Full request body buffered for scanning before forwarding
- Connection pool for upstream reuse (#12)
- Session statistics tracking (#14)
"""

import http.client
import http.server
import itertools
import json
import logging
import socket
import ssl
import threading
import time
from datetime import datetime, timezone

from lumen_argus.actions import build_block_response, build_sse_block_response, should_forward
from lumen_argus.audit import AuditLogger
from lumen_argus.display import TerminalDisplay
from lumen_argus.models import AuditEntry, Finding, ScanResult
from lumen_argus.pipeline import ScannerPipeline
from lumen_argus.pool import ConnectionPool
from lumen_argus.provider import ProviderRouter
from lumen_argus.stats import SessionStats

log = logging.getLogger("argus.proxy")

# Thread-safe request counter.
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

    def _handle_health(self):
        """Respond to /health endpoint with proxy status.

        No auth required — designed for container orchestrator probes
        (Kubernetes liveness/readiness, ECS, Docker HEALTHCHECK).
        Fast: no DB queries, no file reads.
        """
        server = self.server  # type: ArgusProxyServer
        data = {
            "status": "ok",
            "version": __import__("lumen_argus").__version__,
            "uptime": round(time.monotonic() - server.start_time, 1),
            "requests": server.stats.total_requests,
        }
        # Let Pro extend with license/notification/analytics health
        health_hook = server.extensions.get_health_hook() if server.extensions else None
        if health_hook:
            try:
                data.update(health_hook())
            except Exception:
                pass
        body = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_metrics(self):
        """Respond to /metrics with Prometheus exposition format."""
        server = self.server  # type: ArgusProxyServer
        text = server.stats.prometheus_metrics(
            active_requests=server.active_requests,
        )
        # Let Pro extend with additional metrics
        metrics_hook = server.extensions.get_metrics_hook() if server.extensions else None
        if metrics_hook:
            try:
                extra = metrics_hook()
                if extra:
                    text += extra
            except Exception:
                pass
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _forward(self):
        """Main request handling: read -> scan -> forward or block."""
        # Local endpoints — handled by proxy, not forwarded
        if self.path == "/health":
            self._handle_health()
            return
        if self.path == "/metrics":
            self._handle_metrics()
            return

        request_id = next(_request_counter)
        server = self.server  # type: ArgusProxyServer

        # OTel trace span wraps the full request lifecycle
        trace_hook = server.extensions.get_trace_request_hook() if server.extensions else None
        trace_ctx = None
        if trace_hook:
            try:
                trace_ctx = trace_hook(self.command, self.path)
            except Exception:
                trace_ctx = None

        with server._active_lock:
            server._active_requests += 1
        try:
            if trace_ctx:
                try:
                    with trace_ctx as span:
                        self._do_forward(request_id, server, span)
                except Exception:
                    pass  # trace failure must never break the request
            else:
                self._do_forward(request_id, server, None)
        finally:
            with server._active_lock:
                server._active_requests -= 1

    def _do_forward(self, request_id, server, span=None):
        """Inner forwarding logic — separated for active request tracking."""
        # Pre-request hook — sets correlation ID before any logging
        pre_hook = server.pipeline._extensions.get_pre_request_hook() if server.pipeline._extensions else None
        if pre_hook:
            try:
                pre_hook(request_id)
            except Exception:
                pass

        t0 = time.monotonic()
        body = b""
        resp_size = 0
        model = ""
        host = ""
        scan_result = ScanResult()

        try:
            # Read request body
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 0:
                body = self.rfile.read(content_length)

            # Detect provider and determine upstream
            headers_dict = {k.lower(): v for k, v in self.headers.items()}
            host, port, use_ssl, provider = server.router.route(self.path, headers_dict)
            log.debug(
                "#%d %s %s -> %s:%d (ssl=%s, provider=%s, %d bytes)",
                request_id,
                self.command,
                self.path,
                host,
                port,
                use_ssl,
                provider,
                len(body),
            )
            # Set provider on trace span (available after routing)
            if span and hasattr(span, "set_attribute"):
                span.set_attribute("provider", provider)
                span.set_attribute("body.size", len(body))

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

            # Scan request body
            if body and len(body) <= server.max_body_size:
                scan_result = server.pipeline.scan(body, provider, model=model)
                log.debug(
                    "#%d scan: %d findings, action=%s, %.1fms",
                    request_id,
                    len(scan_result.findings),
                    scan_result.action,
                    scan_result.scan_duration_ms,
                )
                # Enrich trace span with scan results
                if span and hasattr(span, "set_attribute"):
                    span.set_attribute("findings.count", len(scan_result.findings))
                    span.set_attribute("action", scan_result.action)
                    span.set_attribute("scan.duration_ms", scan_result.scan_duration_ms)
                # Block/redact always logged at INFO for the file log
                if scan_result.action in ("block", "redact") and scan_result.findings:
                    types = ", ".join(f.type for f in scan_result.findings)
                    log.info(
                        "#%d %s %s (%d findings)",
                        request_id,
                        scan_result.action.upper(),
                        types,
                        len(scan_result.findings),
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

            # Check if we should block (SSE-aware block response)
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
                    request_id,
                    self.command,
                    self.path,
                    model,
                    len(body),
                    resp_size,
                    (time.monotonic() - t0) * 1000,
                    scan_result,
                )
                self._log_audit(
                    server,
                    request_id,
                    provider,
                    model,
                    scan_result,
                    len(body),
                    False,
                )
                server.stats.record(provider, len(body), scan_result)
                return

            # Apply redaction if action is "redact" and a hook is registered
            if scan_result.action == "redact" and server.redact_hook is not None:
                try:
                    body = server.redact_hook(body, scan_result.findings)
                    log.debug("#%d redacted %d findings", request_id, len(scan_result.findings))
                except Exception as e:
                    log.warning("#%d redaction failed: %s", request_id, e)

            # Backpressure: limit concurrent upstream connections.
            # Semaphore blocks if max_connections is reached.
            _sem_acquired = False
            if not server._conn_semaphore.acquire(blocking=False):
                log.warning("#%d queued — max concurrent connections reached", request_id)
                server._conn_semaphore.acquire()
            _sem_acquired = True

            try:
                # Forward to upstream with retry and connection pooling.
                # On retry after a stale-connection failure, force a fresh
                # connection instead of pulling another potentially stale one
                # from the pool.
                force_fresh = False
                for attempt in range(server.retries + 1):
                    if force_fresh:
                        conn = server.pool.get_fresh(host, port, use_ssl)
                    else:
                        conn = server.pool.get(host, port, use_ssl)
                    try:
                        # Build forwarding headers
                        fwd_headers = {}
                        for key, val in self.headers.items():
                            lk = key.lower()
                            if lk in _HOP_BY_HOP:
                                continue
                            if lk in ("host", "accept-encoding"):
                                continue
                            # Recalculate Content-Length if body was modified (e.g. by redaction)
                            if lk == "content-length":
                                fwd_headers[key] = str(len(body))
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
                            # SSE connections cannot be reused
                            try:
                                resp_size = self._stream_sse(resp)
                            finally:
                                conn.close()
                        else:
                            data = resp.read()
                            self.wfile.write(data)
                            resp_size = len(data)
                            # Return non-streaming connection to pool for reuse
                            server.pool.put(host, port, use_ssl, conn)

                        break  # success

                    except (ConnectionError, OSError, http.client.HTTPException) as e:
                        conn.close()
                        if attempt < server.retries:
                            force_fresh = True  # don't pull stale from pool on retry
                            log.debug("#%d retry %d after %s", request_id, attempt + 1, e)
                            continue
                        raise
            finally:
                if _sem_acquired:
                    server._conn_semaphore.release()

            # Display request line
            server.display.show_request(
                request_id,
                self.command,
                self.path,
                model,
                len(body),
                resp_size,
                (time.monotonic() - t0) * 1000,
                scan_result,
            )

            # Audit log + stats
            self._log_audit(
                server,
                request_id,
                provider,
                model,
                scan_result,
                len(body),
                True,
            )
            server.stats.record(provider, len(body), scan_result)

        except (BrokenPipeError, ConnectionResetError):
            pass  # Client disconnected
        except socket.timeout:
            msg = (
                "Upstream timed out after %ds. "
                "Increase proxy.timeout in ~/.lumen-argus/config.yaml "
                "or the dashboard Settings page." % server.timeout
            )
            log.error("#%d upstream timeout after %ds", request_id, server.timeout)
            server.display.show_error(request_id, msg)
            server.stats.record(provider, len(body), scan_result)
            # Only send error response if headers haven't been sent yet
            if not resp_size:
                try:
                    error_body = json.dumps({"error": {"type": "timeout", "message": msg}}).encode("utf-8")
                    self.send_response(504)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(error_body)))
                    self.end_headers()
                    self.wfile.write(error_body)
                except Exception:
                    pass
            return
        except ssl.SSLCertVerificationError as e:
            msg = (
                "TLS verification failed for %s — %s. "
                "If behind a corporate proxy, set proxy.ca_bundle in "
                "~/.lumen-argus/config.yaml" % (host, e)
            )
            log.error("#%d %s", request_id, msg)
            server.display.show_error(request_id, msg)
            server.stats.record(provider, len(body), scan_result)
            try:
                error_body = json.dumps({"error": {"type": "tls_error", "message": msg}}).encode("utf-8")
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(error_body)))
                self.end_headers()
                self.wfile.write(error_body)
            except Exception:
                pass
            return
        except Exception as e:
            log.error("#%d upstream error: %s", request_id, e)
            server.display.show_error(request_id, str(e))
            server.stats.record(provider, len(body), scan_result)
            try:
                error_body = json.dumps({"error": {"type": "proxy_error", "message": str(e)}}).encode("utf-8")
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

    def handle_error(self, request, client_address):
        """Suppress connection reset errors from client disconnections."""
        import sys

        exc_type = sys.exc_info()[0]
        if exc_type in (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            return  # Normal — client closed the connection
        super().handle_error(request, client_address)

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
        pool_size: int = 4,
        redact_hook: object = None,
        ssl_context=None,
        max_connections: int = 10,
    ):
        # Safety: warn if binding to non-loopback (e.g. 0.0.0.0 in Docker).
        # The --host CLI flag is required to override the config default.
        if bind not in ("127.0.0.1", "localhost"):
            import logging as _logging

            _logging.getLogger("argus.proxy").warning(
                "binding to %s — proxy is accessible on the network",
                bind,
            )

        self.pipeline = pipeline
        self.router = router
        self.audit = audit
        self.display = display
        self.timeout = timeout
        self.retries = retries
        self.max_body_size = max_body_size
        self.redact_hook = redact_hook
        self._conn_semaphore = threading.Semaphore(max_connections)
        self._active_requests = 0
        self._active_lock = threading.Lock()
        self.pool = ConnectionPool(
            pool_size=pool_size,
            timeout=timeout,
            idle_timeout=timeout * 2,
            ssl_context=ssl_context,
        )
        self.stats = SessionStats()
        self.start_time = time.monotonic()
        self.extensions = None  # set by cli.py after creation

        super().__init__((bind, port), ArgusProxyHandler)

    @property
    def active_requests(self) -> int:
        with self._active_lock:
            return self._active_requests

    def drain(self, timeout: int = 30) -> int:
        """Wait for in-flight requests to complete.

        Args:
            timeout: Max seconds to wait. 0 = don't wait.

        Returns:
            Number of requests that were force-closed (still active after timeout).
        """
        if timeout <= 0:
            return self.active_requests
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._active_lock:
                if self._active_requests == 0:
                    return 0
            time.sleep(0.1)
        with self._active_lock:
            return self._active_requests

    def update_timeout(self, timeout: int) -> None:
        """Update request timeout for the proxy and its connection pool.

        Public API for plugins to change timeout at runtime without
        accessing private pool attributes.
        """
        self.timeout = timeout
        self.pool.set_timeout(timeout)
