from __future__ import annotations

import asyncio
import logging
import ssl
import threading
import time
from typing import TYPE_CHECKING, Any

import aiohttp
from aiohttp import web

from lumen_argus.audit import AuditLogger
from lumen_argus.display import TerminalDisplay
from lumen_argus.pipeline import ScannerPipeline
from lumen_argus.provider import ProviderRouter
from lumen_argus.stats import SessionStats

if TYPE_CHECKING:
    from lumen_argus.extensions import ExtensionRegistry

log = logging.getLogger("argus.proxy")

# Typed app key for storing the proxy reference (avoids aiohttp AppKey warning).
_PROXY_KEY: Any = web.AppKey("proxy", t=str)


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
        connect_timeout: int = 10,
        retries: int = 1,
        max_body_size: int = 50 * 1024 * 1024,
        redact_hook: Any = None,
        ssl_context: ssl.SSLContext | None = None,
        max_connections: int = 50,
    ):
        if bind not in ("127.0.0.1", "localhost", "::1"):
            log.warning("binding to %s — proxy is accessible on the network", bind)

        self.bind = bind
        self.port = port
        self.pipeline = pipeline
        self.router = router
        self.audit = audit
        self.display = display
        self.timeout = timeout
        self.connect_timeout = connect_timeout
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
        from lumen_argus.async_proxy._forward import _handle_request

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
            if self.bind not in ("127.0.0.1", "localhost", "::1"):
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
