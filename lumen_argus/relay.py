"""Lightweight relay — fault-isolated HTTP forwarder for lumen-argus.

Sits on the user-facing port and forwards traffic to the engine process
for inspection.  When the engine is down, applies fail-mode policy:
``open`` forwards directly to upstream LLM providers (unprotected),
``closed`` returns 503.

Design constraints:
- No scanning, detection, or analytics imports (near-zero crash risk)
- Only depends on aiohttp (already a project dependency) and ProviderRouter
- ~500 lines — small enough to audit by hand
"""

from __future__ import annotations

import asyncio
import enum
import itertools
import logging
import time
from typing import Any

import aiohttp
from aiohttp import web

from lumen_argus.provider import ProviderRouter

log = logging.getLogger("argus.relay")

# Hop-by-hop headers that must not be forwarded (RFC 2616 §13.5.1)
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

_RELAY_KEY: web.AppKey["ArgusRelay"] = web.AppKey("relay")
_request_counter = itertools.count(1)


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------


class RelayState(str, enum.Enum):
    """Engine health states."""

    STARTING = "starting"  # buffering requests while engine boots
    HEALTHY = "healthy"  # forwarding to engine
    UNHEALTHY = "unhealthy"  # engine down, apply fail_mode


# ---------------------------------------------------------------------------
# Relay server
# ---------------------------------------------------------------------------


class ArgusRelay:
    """Lightweight HTTP relay with engine health checking.

    Args:
        bind: Address to listen on (default ``127.0.0.1``).
        port: Port to listen on (default ``8080``).
        engine_url: Base URL of the engine process (default ``http://localhost:8090``).
        fail_mode: ``"open"`` (forward direct) or ``"closed"`` (return 503).
        router: :class:`ProviderRouter` for fail-open upstream resolution.
        health_interval: Seconds between engine health checks.
        health_timeout: Seconds before a health check times out.
        queue_timeout: Seconds to buffer requests while engine starts.
        timeout: Request forwarding timeout in seconds.
    """

    def __init__(
        self,
        bind: str = "127.0.0.1",
        port: int = 8080,
        engine_url: str = "http://localhost:8090",
        fail_mode: str = "open",
        router: ProviderRouter | None = None,
        health_interval: int = 2,
        health_timeout: int = 1,
        queue_timeout: int = 2,
        timeout: int = 120,
        max_connections: int = 20,
    ):
        self.bind = bind
        self.port = port
        self.engine_url = engine_url.rstrip("/")
        self.fail_mode = fail_mode
        self.router = router or ProviderRouter()
        self.health_interval = health_interval
        self.health_timeout = health_timeout
        self.queue_timeout = queue_timeout
        self.timeout = timeout
        self.max_connections = max_connections

        self.state = RelayState.STARTING
        self.start_time = time.monotonic()
        self._active_requests = 0
        self._engine_session: aiohttp.ClientSession | None = None
        self._upstream_session: aiohttp.ClientSession | None = None
        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self._health_task: asyncio.Task[Any] | None = None
        self._healthy_event = asyncio.Event()
        self._background_tasks: set[asyncio.Task[Any]] = set()

    # --- Lifecycle ---

    async def start(self) -> None:
        """Start the relay server and health checker."""
        self._engine_session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(limit=self.max_connections),
            auto_decompress=False,
        )
        self._upstream_session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(limit=self.max_connections),
            auto_decompress=False,
        )

        self._app = web.Application(middlewares=[_nosniff_middleware])
        self._app[_RELAY_KEY] = self
        self._app.router.add_route("*", "/{path_info:.*}", _handle_request)

        self._runner = web.AppRunner(self._app, handle_signals=False)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self.bind, self.port)
        await self._site.start()

        self._health_task = asyncio.ensure_future(self._health_loop())
        log.info(
            "relay listening on http://%s:%d → engine %s (fail_mode=%s)",
            self.bind,
            self.port,
            self.engine_url,
            self.fail_mode,
        )

    async def stop(self) -> None:
        """Stop the relay and clean up resources."""
        if self._health_task:
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass
        if self._engine_session:
            await self._engine_session.close()
        if self._upstream_session:
            await self._upstream_session.close()
        if self._runner:
            await self._runner.cleanup()
        log.info("relay stopped")

    async def drain(self, timeout: int = 10) -> int:
        """Wait for in-flight requests to complete."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._active_requests == 0:
                return 0
            await asyncio.sleep(0.1)
        return self._active_requests

    def reload(
        self,
        fail_mode: str | None = None,
        engine_url: str | None = None,
        health_interval: int | None = None,
        health_timeout: int | None = None,
        timeout: int | None = None,
    ) -> None:
        """Hot-reload relay configuration without restart."""
        if fail_mode is not None and fail_mode in ("open", "closed"):
            if self.fail_mode != fail_mode:
                log.info("relay config: fail_mode %s → %s", self.fail_mode, fail_mode)
            self.fail_mode = fail_mode
        if engine_url is not None:
            url = engine_url.rstrip("/")
            if self.engine_url != url:
                log.info("relay config: engine_url %s → %s", self.engine_url, url)
            self.engine_url = url
        if health_interval is not None:
            self.health_interval = max(1, health_interval)
        if health_timeout is not None:
            self.health_timeout = max(1, health_timeout)
        if timeout is not None:
            self.timeout = max(1, timeout)

    # --- Health checker ---

    async def _health_loop(self) -> None:
        """Periodically check engine health."""
        while True:
            try:
                await self._check_engine()
            except asyncio.CancelledError:
                return
            except Exception:
                log.debug("health check error", exc_info=True)
                self._transition(RelayState.UNHEALTHY)
            await asyncio.sleep(self.health_interval)

    async def _check_engine(self) -> None:
        """Single engine health check."""
        if self._engine_session is None:
            self._transition(RelayState.UNHEALTHY)
            return
        try:
            async with self._engine_session.get(
                "%s/health" % self.engine_url,
                timeout=aiohttp.ClientTimeout(total=self.health_timeout),
            ) as resp:
                if resp.status == 200:
                    self._transition(RelayState.HEALTHY)
                else:
                    self._transition(RelayState.UNHEALTHY)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            self._transition(RelayState.UNHEALTHY)

    def _transition(self, new_state: RelayState) -> None:
        """Transition to a new state, logging changes."""
        if self.state == new_state:
            return
        old = self.state
        self.state = new_state
        log.info("relay state: %s → %s", old.value, new_state.value)
        if new_state == RelayState.HEALTHY:
            self._healthy_event.set()
        else:
            self._healthy_event.clear()

    # --- Forwarding ---

    async def forward(self, request: web.Request) -> web.StreamResponse:
        """Forward a request based on current engine state."""
        request_id = next(_request_counter)
        request_id_str = "relay-%d" % request_id
        t0 = time.monotonic()
        path = request.path_qs
        method = request.method
        body = await request.read()

        # Propagate client IP and request ID for cross-process tracing
        existing_xff = request.headers.get("X-Forwarded-For", "")
        relay_ip = request.remote or "127.0.0.1"
        xff = "%s, %s" % (existing_xff, relay_ip) if existing_xff else relay_ip
        extra_headers = {
            "X-Forwarded-For": xff,
            "X-Request-ID": request_id_str,
        }

        # During startup, wait for engine to become healthy
        if self.state == RelayState.STARTING:
            try:
                await asyncio.wait_for(self._healthy_event.wait(), timeout=self.queue_timeout)
            except asyncio.TimeoutError:
                log.info("#%d engine not ready after %ds startup queue", request_id, self.queue_timeout)

        # Try engine first when healthy
        if self.state == RelayState.HEALTHY:
            try:
                resp = await self._forward_via(
                    self._engine_session,
                    "%s%s" % (self.engine_url, path),
                    method,
                    body,
                    request,
                    request_id,
                    "engine",
                    extra_headers=extra_headers,
                )
                elapsed_ms = (time.monotonic() - t0) * 1000
                log.info("#%d %s %s %dms via engine", request_id, method, path, elapsed_ms)
                return resp
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                # Don't flip state on a single request failure — the
                # health checker is the authority on engine state.
                # Trigger an immediate check and fall through to
                # fail_mode for THIS request only.
                log.warning("#%d engine forwarding failed: %s — applying fail_mode for this request", request_id, e)
                task = asyncio.ensure_future(self._check_engine())
                self._background_tasks.add(task)
                task.add_done_callback(self._background_tasks.discard)

        # Engine unavailable (unhealthy or single request failure) — apply fail_mode
        if self.fail_mode == "open":
            log.info("#%d forwarding direct to upstream (engine down, fail-open)", request_id)
            resp = await self._forward_direct(request_id, method, path, body, request, extra_headers)
            elapsed_ms = (time.monotonic() - t0) * 1000
            log.info("#%d %s %s %dms via direct (fail-open)", request_id, method, path, elapsed_ms)
            return resp

        elapsed_ms = (time.monotonic() - t0) * 1000
        log.info("#%d %s %s %dms → 503 (fail-closed)", request_id, method, path, elapsed_ms)
        return web.json_response(
            {"error": {"type": "service_unavailable", "message": "lumen-argus engine unavailable"}},
            status=503,
        )

    async def _forward_direct(
        self,
        request_id: int,
        method: str,
        path: str,
        body: bytes,
        request: web.Request,
        extra_headers: dict[str, str] | None = None,
    ) -> web.StreamResponse:
        """Forward request directly to upstream LLM provider (fail-open)."""
        headers_dict = {k.lower(): v for k, v in request.headers.items()}
        host, port, use_ssl, provider = self.router.route(path, headers_dict)
        scheme = "https" if use_ssl else "http"
        upstream_url = "%s://%s:%d%s" % (scheme, host, port, path)

        try:
            return await self._forward_via(
                self._upstream_session,
                upstream_url,
                method,
                body,
                request,
                request_id,
                "direct:%s" % provider,
                host=host,
                ssl=None if use_ssl else False,
                extra_headers=extra_headers,
            )
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            log.error("#%d direct upstream failed: %s", request_id, e)
            return web.json_response(
                {"error": {"type": "upstream_error", "message": "upstream provider unreachable"}},
                status=502,
            )

    async def _forward_via(
        self,
        session: aiohttp.ClientSession | None,
        url: str,
        method: str,
        body: bytes,
        request: web.Request,
        request_id: int,
        via: str,
        host: str = "",
        ssl: Any = None,
        extra_headers: dict[str, str] | None = None,
    ) -> web.StreamResponse:
        """Forward request via a session and relay the response (buffered or SSE)."""
        if session is None:
            return web.Response(status=502, text="Relay session not ready")

        fwd_headers = _build_forward_headers(request, body)
        if host:
            fwd_headers["Host"] = host
        if extra_headers:
            fwd_headers.update(extra_headers)

        kwargs: dict[str, Any] = {
            "data": body,
            "headers": fwd_headers,
            "timeout": aiohttp.ClientTimeout(total=self.timeout),
        }
        if ssl is not None:
            kwargs["ssl"] = ssl

        async with session.request(method, url, **kwargs) as resp:
            content_type = resp.headers.get("Content-Type", "")
            is_sse = "text/event-stream" in content_type

            # Collect response headers
            resp_headers: dict[str, str] = {}
            for hdr, val in resp.headers.items():
                lk = hdr.lower()
                if lk in _HOP_BY_HOP:
                    continue
                if lk == "content-length" and is_sse:
                    continue
                resp_headers[hdr] = val

            if is_sse:
                # Stream SSE chunks back to client
                stream_resp = web.StreamResponse(status=resp.status, headers=resp_headers)
                await stream_resp.prepare(request)
                async for chunk in resp.content.iter_any():
                    await stream_resp.write(chunk)
                await stream_resp.write_eof()
                log.debug("#%d streamed SSE via %s", request_id, via)
                return stream_resp

            # Buffered response
            data = await resp.read()
            log.debug("#%d relayed %d bytes via %s", request_id, len(data), via)
            return web.Response(body=data, status=resp.status, headers=resp_headers)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@web.middleware
async def _nosniff_middleware(request: web.Request, handler: Any) -> web.StreamResponse:
    """Add X-Content-Type-Options: nosniff to all responses."""
    resp: web.StreamResponse = await handler(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


def _build_forward_headers(request: web.Request, body: bytes) -> dict[str, str]:
    """Build forwarding headers, stripping hop-by-hop."""
    fwd: dict[str, str] = {}
    for key, val in request.headers.items():
        lk = key.lower()
        if lk in _HOP_BY_HOP:
            continue
        if lk in ("host", "accept-encoding"):
            continue
        if lk == "content-length":
            fwd[key] = str(len(body))
            continue
        fwd[key] = val
    return fwd


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------


async def _handle_request(request: web.Request) -> web.StreamResponse:
    """Main relay request handler."""
    relay: ArgusRelay = request.app[_RELAY_KEY]
    path = request.path_qs

    # Relay health endpoint
    if path == "/health":
        return web.json_response(
            {
                "status": "ok",
                "engine": relay.state.value,
                "fail_mode": relay.fail_mode,
                "uptime": round(time.monotonic() - relay.start_time, 1),
            }
        )

    relay._active_requests += 1
    try:
        return await relay.forward(request)
    finally:
        relay._active_requests -= 1
