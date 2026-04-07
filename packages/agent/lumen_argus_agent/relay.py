"""Agent relay — local forwarding proxy with identity enrichment.

Sits on the workstation between AI coding tools and the lumen-argus proxy.
Enriches every request with OS-level identity headers (X-Lumen-*) so the
proxy can attribute findings to a specific agent instance, project, machine,
and user.

Follows the CASB agent model (Netskope, Zscaler): local agent enriches
traffic, cloud/server proxy inspects it.

Design:
- aiohttp for async HTTP forwarding with SSE streaming support
- Lazy-imported: ``lumen-argus-agent detect`` never loads aiohttp
- No scanning or detection logic — relay only, proxy does all DLP
- Fail-open (default) or fail-closed when upstream proxy is unreachable
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import os
import time
from dataclasses import dataclass
from typing import Any

import aiohttp
from aiohttp import web

from lumen_argus_agent.context import CallerContext, resolve_context, static_context

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

_RELAY_KEY: web.AppKey["AgentRelay"] = web.AppKey("agent_relay")
_request_counter = itertools.count(1)

# Headers the relay injects — must NOT be forwarded to upstream API providers.
# The proxy strips them before forwarding; we also strip them here for direct mode.
LUMEN_HEADER_PREFIX = "x-lumen-argus-"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class RelayConfig:
    """Agent relay configuration."""

    bind: str = "127.0.0.1"
    port: int = 8070
    upstream_url: str = "http://localhost:8080"
    fail_mode: str = "open"  # "open" | "closed"
    agent_id: str = ""
    agent_token: str = ""
    machine_id: str = ""
    send_username: bool = True
    send_hostname: bool = True
    timeout: int = 150
    max_connections: int = 20
    health_interval: int = 5


# ---------------------------------------------------------------------------
# Direct-mode provider routing (minimal, for fail-open)
# ---------------------------------------------------------------------------

_PROVIDER_ROUTES: list[tuple[str, str, str]] = [
    # (path_prefix, header_check, upstream)
    # Checked in order; first match wins.
]


def _resolve_direct_upstream(path: str, headers: dict[str, str]) -> tuple[str, str]:
    """Resolve upstream API URL for direct forwarding (fail-open).

    Returns (upstream_base_url, provider_name).
    """
    # Anthropic
    if path.startswith(("/v1/messages", "/v1/complete")):
        if headers.get("x-api-key") or headers.get("anthropic-version"):
            return "https://api.anthropic.com", "anthropic"

    # OpenAI
    if path.startswith(("/v1/chat/completions", "/v1/completions", "/v1/embeddings")):
        return "https://api.openai.com", "openai"

    # Gemini
    if "/generateContent" in path or path.startswith("/v1beta/"):
        return "https://generativelanguage.googleapis.com", "gemini"

    # Header-based detection
    if "x-api-key" in headers:
        return "https://api.anthropic.com", "anthropic"
    auth = headers.get("authorization", "")
    if auth.startswith("Bearer sk-ant-"):
        return "https://api.anthropic.com", "anthropic"
    if auth.startswith("Bearer sk-"):
        return "https://api.openai.com", "openai"

    # Default
    return "https://api.anthropic.com", "anthropic"


# ---------------------------------------------------------------------------
# Relay server
# ---------------------------------------------------------------------------


class AgentRelay:
    """Local forwarding proxy with identity header injection.

    Args:
        config: Relay configuration.
    """

    def __init__(self, config: RelayConfig) -> None:
        self.config = config
        self.start_time = time.monotonic()
        self._upstream_healthy = False
        self._active_requests = 0
        self._upstream_session: aiohttp.ClientSession | None = None
        self._direct_session: aiohttp.ClientSession | None = None
        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self._health_task: asyncio.Task[Any] | None = None

    # --- Lifecycle ---

    async def start(self) -> None:
        """Start the relay server and upstream health checker."""
        connector_kwargs: dict[str, Any] = {"limit": self.config.max_connections}
        self._upstream_session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(**connector_kwargs),
            auto_decompress=False,
        )
        self._direct_session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(**connector_kwargs),
            auto_decompress=False,
        )

        self._app = web.Application()
        self._app[_RELAY_KEY] = self
        self._app.router.add_route("*", "/{path_info:.*}", _handle_request)

        self._runner = web.AppRunner(self._app, handle_signals=False)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self.config.bind, self.config.port)
        await self._site.start()

        self._health_task = asyncio.ensure_future(self._health_loop())
        log.info(
            "relay listening on %s:%d upstream=%s fail_mode=%s agent=%s",
            self.config.bind,
            self.config.port,
            self.config.upstream_url,
            self.config.fail_mode,
            self.config.agent_id or "(not enrolled)",
        )

    async def stop(self) -> None:
        """Stop relay and release resources."""
        if self._health_task:
            self._health_task.cancel()
            await asyncio.gather(self._health_task, return_exceptions=True)
        if self._upstream_session:
            await self._upstream_session.close()
        if self._direct_session:
            await self._direct_session.close()
        if self._runner:
            await self._runner.cleanup()
        log.info("relay stopped")

    async def drain(self, timeout: int = 10) -> int:
        """Wait for in-flight requests to complete. Returns remaining count."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._active_requests == 0:
                return 0
            await asyncio.sleep(0.1)
        return self._active_requests

    # --- Health checking ---

    async def _health_loop(self) -> None:
        """Periodically check upstream proxy health."""
        while True:
            try:
                await self._check_upstream()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.debug("health check error", exc_info=True)
                if self._upstream_healthy:
                    self._upstream_healthy = False
                    log.warning("upstream unhealthy: health check exception")
            await asyncio.sleep(self.config.health_interval)

    async def _check_upstream(self) -> None:
        """Single upstream health check."""
        if self._upstream_session is None:
            self._upstream_healthy = False
            return
        try:
            url = "%s/health" % self.config.upstream_url.rstrip("/")
            async with self._upstream_session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=3),
            ) as resp:
                was_healthy = self._upstream_healthy
                self._upstream_healthy = resp.status == 200
                if self._upstream_healthy and not was_healthy:
                    log.info("upstream healthy: %s", self.config.upstream_url)
                elif not self._upstream_healthy and was_healthy:
                    log.warning("upstream unhealthy: HTTP %d", resp.status)
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            if self._upstream_healthy:
                log.warning("upstream unhealthy: %s", exc)
            self._upstream_healthy = False

    # --- Forwarding ---

    async def forward(self, request: web.Request) -> web.StreamResponse:
        """Forward a request to upstream proxy or direct to API provider."""
        request_id = next(_request_counter)
        t0 = time.monotonic()
        path = request.path_qs
        method = request.method
        body = await request.read()
        headers_dict = {k.lower(): v for k, v in request.headers.items()}

        # Resolve caller context from OS
        source_port = 0
        peername = request.transport.get_extra_info("peername") if request.transport else None
        if peername and len(peername) >= 2:
            source_port = peername[1]
        ctx = resolve_context(self.config.port, source_port) if source_port else static_context()

        # Build forwarding headers
        fwd_headers = _build_forward_headers(request, body)

        # Inject X-Lumen-* identity headers
        _inject_identity_headers(fwd_headers, self.config, ctx)

        # Inject agent authentication for upstream proxy
        if self.config.agent_token:
            fwd_headers["X-Lumen-Argus-Agent-Token"] = self.config.agent_token

        # Try upstream proxy
        if self._upstream_healthy and self._upstream_session:
            upstream_url = "%s%s" % (self.config.upstream_url.rstrip("/"), path)
            try:
                resp = await self._forward_via(
                    self._upstream_session, upstream_url, method, body, request, fwd_headers, request_id
                )
                elapsed = (time.monotonic() - t0) * 1000
                log.info(
                    "#%d %s %s → %d (%dms) dir=%s pid=%d",
                    request_id,
                    method,
                    path,
                    resp.status if hasattr(resp, "status") else 0,
                    elapsed,
                    ctx.working_directory or "-",
                    ctx.client_pid,
                )
                return resp
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                log.warning("#%d upstream forwarding failed: %s", request_id, exc)
                # Fall through to fail mode

        # Upstream unavailable — apply fail mode
        if self.config.fail_mode == "open":
            return await self._forward_direct(request_id, method, path, body, request, fwd_headers, headers_dict, t0)

        elapsed = (time.monotonic() - t0) * 1000
        log.error("#%d upstream unreachable, fail-closed: %s %s → 503 (%dms)", request_id, method, path, elapsed)
        return web.json_response(
            {"error": {"type": "service_unavailable", "message": "lumen-argus proxy unreachable (fail-closed)"}},
            status=503,
        )

    async def _forward_direct(
        self,
        request_id: int,
        method: str,
        path: str,
        body: bytes,
        request: web.Request,
        fwd_headers: dict[str, str],
        original_headers: dict[str, str],
        t0: float,
    ) -> web.StreamResponse:
        """Forward directly to API provider (fail-open, no scanning)."""
        upstream_base, provider = _resolve_direct_upstream(path, original_headers)
        direct_url = "%s%s" % (upstream_base, path)

        # Strip X-Lumen-* headers — API providers don't need them
        clean_headers = {k: v for k, v in fwd_headers.items() if not k.lower().startswith(LUMEN_HEADER_PREFIX)}
        # Restore original Host header for the API provider
        if "://" in upstream_base:
            clean_headers["Host"] = upstream_base.split("://", 1)[1].rstrip("/")

        log.warning(
            "#%d proxy unreachable, forwarding directly (fail-open): %s %s → %s",
            request_id,
            method,
            path,
            provider,
        )

        try:
            resp = await self._forward_via(
                self._direct_session, direct_url, method, body, request, clean_headers, request_id
            )
            elapsed = (time.monotonic() - t0) * 1000
            log.info("#%d %s %s → %d (%dms) via direct:%s", request_id, method, path, resp.status, elapsed, provider)
            return resp
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            log.error("#%d direct upstream failed: %s", request_id, exc)
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
        headers: dict[str, str],
        request_id: int,
    ) -> web.StreamResponse:
        """Forward request and relay response (buffered or SSE streaming)."""
        if session is None:
            return web.Response(status=502, text="Relay session not ready")

        async with session.request(
            method,
            url,
            data=body,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=self.config.timeout),
        ) as resp:
            content_type = resp.headers.get("Content-Type", "")
            is_sse = "text/event-stream" in content_type

            # Collect response headers (filter hop-by-hop)
            resp_headers: dict[str, str] = {}
            for hdr, val in resp.headers.items():
                lk = hdr.lower()
                if lk in _HOP_BY_HOP:
                    continue
                if lk == "content-length" and is_sse:
                    continue
                resp_headers[hdr] = val

            if is_sse:
                stream_resp = web.StreamResponse(status=resp.status, headers=resp_headers)
                await stream_resp.prepare(request)
                async for chunk in resp.content.iter_any():
                    await stream_resp.write(chunk)
                await stream_resp.write_eof()
                log.debug("#%d streamed SSE response", request_id)
                return stream_resp

            # Buffered response
            data = await resp.read()
            log.debug("#%d relayed %d bytes", request_id, len(data))
            return web.Response(body=data, status=resp.status, headers=resp_headers)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


def _inject_identity_headers(headers: dict[str, str], config: RelayConfig, ctx: CallerContext) -> None:
    """Inject X-Lumen-* identity headers into forwarding headers."""
    if config.agent_id:
        headers["X-Lumen-Argus-Agent-Id"] = config.agent_id
    if config.machine_id:
        headers["X-Lumen-Argus-Device-Id"] = config.machine_id
    if ctx.working_directory and ctx.working_directory != "/":
        headers["X-Lumen-Argus-Working-Dir"] = ctx.working_directory
    if ctx.git_branch:
        headers["X-Lumen-Argus-Git-Branch"] = ctx.git_branch
    if ctx.os_platform:
        headers["X-Lumen-Argus-OS-Platform"] = ctx.os_platform
    if ctx.hostname and config.send_hostname:
        headers["X-Lumen-Argus-Hostname"] = ctx.hostname
    if ctx.username and config.send_username:
        headers["X-Lumen-Argus-Username"] = ctx.username
    if ctx.client_pid:
        headers["X-Lumen-Argus-Client-PID"] = str(ctx.client_pid)


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------


async def _handle_request(request: web.Request) -> web.StreamResponse:
    """Main relay request handler."""
    relay: AgentRelay = request.app[_RELAY_KEY]
    path = request.path_qs

    # Health endpoint
    if path == "/health":
        return web.json_response(
            {
                "status": "ok",
                "upstream": "healthy" if relay._upstream_healthy else "unhealthy",
                "upstream_url": relay.config.upstream_url,
                "fail_mode": relay.config.fail_mode,
                "agent_id": relay.config.agent_id or "",
                "enrolled": bool(relay.config.agent_id),
                "uptime": round(time.monotonic() - relay.start_time, 1),
            }
        )

    relay._active_requests += 1
    try:
        return await relay.forward(request)
    finally:
        relay._active_requests -= 1


# ---------------------------------------------------------------------------
# Relay state file
# ---------------------------------------------------------------------------

_ARGUS_DIR = os.path.expanduser("~/.lumen-argus")
_RELAY_STATE_PATH = os.path.join(_ARGUS_DIR, "relay.json")


def _write_relay_state(config: RelayConfig) -> None:
    """Write relay state file so the setup wizard can detect the relay."""
    import json

    from lumen_argus_core.time_utils import now_iso

    os.makedirs(_ARGUS_DIR, mode=0o700, exist_ok=True)
    state = {
        "port": config.port,
        "bind": config.bind,
        "upstream_url": config.upstream_url,
        "pid": os.getpid(),
        "started_at": now_iso(),
    }
    try:
        tmp = _RELAY_STATE_PATH + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp, _RELAY_STATE_PATH)
        log.info("relay state written to %s", _RELAY_STATE_PATH)
    except OSError as exc:
        log.warning("could not write relay state: %s", exc)


def _remove_relay_state() -> None:
    """Remove relay state file on shutdown."""
    try:
        os.remove(_RELAY_STATE_PATH)
        log.debug("relay state removed")
    except FileNotFoundError:
        pass
    except OSError as exc:
        log.warning("could not remove relay state: %s", exc)


def load_relay_state() -> dict[str, Any] | None:
    """Load relay state from disk. Returns None if relay is not running.

    Validates the PID — if the recorded process is dead, removes the stale
    state file and returns None.
    """
    import json

    try:
        with open(_RELAY_STATE_PATH, encoding="utf-8") as f:
            state: dict[str, Any] = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None

    # Check if the relay process is still alive
    pid = state.get("pid", 0)
    if pid and not _pid_alive(pid):
        log.debug("stale relay state (pid %d dead) — removing", pid)
        _remove_relay_state()
        return None

    return state


def _pid_alive(pid: int) -> bool:
    """Check if a PID is still running."""
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Entry point (called from CLI)
# ---------------------------------------------------------------------------


def _reload_enrollment_config(relay: AgentRelay) -> None:
    """Reload enrollment config and update relay settings.

    Called on SIGHUP to pick up rotated tokens, fail_mode changes,
    and privacy flag updates without restarting.
    """
    from lumen_argus_core.enrollment import load_enrollment

    enrollment = load_enrollment()
    if not enrollment:
        log.info("sighup reload: no enrollment found, config unchanged")
        return

    config = relay.config
    changed: list[str] = []

    new_token = enrollment.get("agent_token", "")
    if new_token and new_token != config.agent_token:
        config.agent_token = new_token
        changed.append("agent_token")

    policy = enrollment.get("policy", {})
    if isinstance(policy, dict):
        fm = policy.get("fail_mode", "")
        if fm in ("open", "closed") and fm != config.fail_mode:
            config.fail_mode = fm
            changed.append("fail_mode=%s" % fm)

        for flag_name, attr in (("relay_send_username", "send_username"), ("relay_send_hostname", "send_hostname")):
            if flag_name in policy:
                new_val = bool(policy[flag_name])
                if new_val != getattr(config, attr):
                    setattr(config, attr, new_val)
                    changed.append("%s=%s" % (attr, new_val))

    if changed:
        log.info("sighup reload: updated %s", ", ".join(changed))
    else:
        log.info("sighup reload: no changes detected")


async def run_relay(config: RelayConfig) -> None:
    """Start the relay and run until interrupted."""
    relay = AgentRelay(config)
    await relay.start()
    _write_relay_state(config)

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _signal_handler() -> None:
        log.info("shutdown signal received")
        stop_event.set()

    def _sighup_handler() -> None:
        log.info("sighup received — reloading enrollment config")
        _reload_enrollment_config(relay)

    import signal

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _signal_handler)
    loop.add_signal_handler(signal.SIGHUP, _sighup_handler)

    await stop_event.wait()

    remaining = await relay.drain(timeout=5)
    if remaining:
        log.warning("draining timed out with %d active requests", remaining)
    await relay.stop()
    _remove_relay_state()
