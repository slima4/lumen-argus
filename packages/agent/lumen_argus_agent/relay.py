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
import secrets
import time
from dataclasses import dataclass
from typing import Any

import aiohttp
from aiohttp import web
from multidict import CIMultiDict

from lumen_argus_agent.context import CallerContext, resolve_context, static_context
from lumen_argus_agent.upstream_health import UpstreamHealth
from lumen_argus_core.relay_state import (
    PROBE_MATCH,
    PROBE_MISMATCH,
    PROBE_REFUSED,
    loopback_host_for,
    probe_loopback_health,
    read_relay_state_file,
    validate_relay_state,
)

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
    connect_timeout: int = 10
    max_connections: int = 50


# ---------------------------------------------------------------------------
# Direct-mode provider routing (minimal, for fail-open)
# ---------------------------------------------------------------------------


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
# Passthrough session factory
# ---------------------------------------------------------------------------


def make_passthrough_session(*, limit: int) -> aiohttp.ClientSession:
    """Build a ClientSession for byte-identical response forwarding.

    ``auto_decompress=False`` is load-bearing: ``_forward_via`` propagates
    the upstream ``Content-Encoding`` header verbatim, so aiohttp must not
    silently gunzip the body — that would double-encode against the
    preserved header. Paired with the ``accept-encoding`` strip in
    ``_build_forward_headers`` (which normalizes the inbound value).
    """
    return aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(limit=limit),
        auto_decompress=False,
    )


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
        # Per-process identity (#77). Echoed by /health and persisted in
        # relay.json so adopters can detect a recycled PID claiming the
        # same record. Stable across SIGHUP rewrites.
        self.boot_token = secrets.token_hex(16)
        self._upstream_health = UpstreamHealth()
        self._active_requests = 0
        self._upstream_session: aiohttp.ClientSession | None = None
        self._direct_session: aiohttp.ClientSession | None = None
        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None

    # --- Lifecycle ---

    async def start(self) -> None:
        """Start the relay server."""
        self._upstream_session = make_passthrough_session(limit=self.config.max_connections)
        self._direct_session = make_passthrough_session(limit=self.config.max_connections)

        self._app = web.Application()
        self._app[_RELAY_KEY] = self
        self._app.router.add_route("*", "/{path_info:.*}", _handle_request)

        self._runner = web.AppRunner(self._app, handle_signals=False)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self.config.bind, self.config.port)
        await self._site.start()

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

        # Inject X-Lumen-* identity + agent-token headers (one strip pass
        # inside owns the entire x-lumen-argus-* namespace — keep token
        # injection here too so a future caller cannot reintroduce a write
        # outside the strip's protection window).
        _inject_identity_headers(fwd_headers, self.config, ctx)

        if self._upstream_session:
            upstream_url = "%s%s" % (self.config.upstream_url.rstrip("/"), path)
            try:
                resp = await self._forward_via(
                    self._upstream_session, upstream_url, method, body, request, fwd_headers, request_id
                )
                self._upstream_health.record(True)
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
                self._upstream_health.record(False)
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
        fwd_headers: CIMultiDict[str],
        original_headers: dict[str, str],
        t0: float,
    ) -> web.StreamResponse:
        """Forward directly to API provider (fail-open, no scanning)."""
        upstream_base, provider = _resolve_direct_upstream(path, original_headers)
        direct_url = "%s%s" % (upstream_base, path)

        # Strip X-Lumen-* headers — API providers don't need them
        clean_headers: CIMultiDict[str] = CIMultiDict(
            (k, v) for k, v in fwd_headers.items() if not k.lower().startswith(LUMEN_HEADER_PREFIX)
        )
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
        headers: CIMultiDict[str],
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
            timeout=aiohttp.ClientTimeout(sock_read=self.config.timeout, connect=self.config.connect_timeout),
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
                try:
                    async for chunk in resp.content.iter_any():
                        if not chunk:
                            continue
                        try:
                            await stream_resp.write(chunk)
                        except (ConnectionResetError, ConnectionAbortedError):
                            break
                except asyncio.TimeoutError:
                    # Headers already flushed — close stream cleanly instead
                    # of surfacing a second response the client can't parse.
                    log.error("#%d upstream SSE idle timeout", request_id)
                try:
                    await stream_resp.write_eof()
                except (ConnectionResetError, BrokenPipeError, OSError):
                    log.debug("#%d client disconnected during write_eof", request_id)
                log.debug("#%d streamed SSE response", request_id)
                return stream_resp

            # Buffered response
            data = await resp.read()
            log.debug("#%d relayed %d bytes", request_id, len(data))
            return web.Response(body=data, status=resp.status, headers=resp_headers)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_forward_headers(request: web.Request, body: bytes) -> CIMultiDict[str]:
    """Build forwarding headers, stripping hop-by-hop.

    Returns a ``CIMultiDict`` so that subsequent ``headers[name] = value``
    writes deduplicate case-insensitively. ``add()`` is used for non-special
    client headers to preserve legitimately repeated names (e.g. ``Set-Cookie``,
    ``Cache-Control``); only fields the relay actively sets switch to
    ``__setitem__``.
    """
    fwd: CIMultiDict[str] = CIMultiDict()
    for key, val in request.headers.items():
        lk = key.lower()
        if lk in _HOP_BY_HOP:
            continue
        # ``accept-encoding`` strip pairs with ``auto_decompress=False`` — see ``make_passthrough_session``.
        if lk in ("host", "accept-encoding"):
            continue
        if lk == "content-length":
            fwd[key] = str(len(body))
            continue
        fwd.add(key, val)
    return fwd


def _strip_lumen_headers(headers: CIMultiDict[str]) -> None:
    """Remove every ``x-lumen-argus-*`` header (case-insensitive).

    The relay owns the ``x-lumen-argus-*`` namespace end-to-end. Any
    incoming value with that prefix is a spoofing attempt by a local
    process targeting the relay's audit attribution. Strip unconditionally
    before injection so headers the relay *chooses not to set* (because
    the ctx field is empty or a privacy flag is off) cannot be inherited
    from the caller.

    ``CIMultiDict.__delitem__`` removes *all* case-insensitive matches in a
    single call, so we deduplicate the candidate names by their lowercased
    form before deleting — otherwise an attacker sending two case-distinct
    duplicates of the same header (e.g. ``x-lumen-argus-foo`` and
    ``X-LUMEN-ARGUS-FOO``) would cause the second ``del`` to raise
    ``KeyError``. Using ``popall(name, [])`` makes the operation idempotent
    even if the input dict already collapsed duplicates.
    """
    names = {key.lower() for key in headers.keys() if key.lower().startswith(LUMEN_HEADER_PREFIX)}
    for name in names:
        headers.popall(name, [])


def _inject_identity_headers(headers: CIMultiDict[str], config: RelayConfig, ctx: CallerContext) -> None:
    """Inject X-Lumen-* identity headers into forwarding headers.

    Two-layer integrity guarantee against header spoofing (#76):
    1. ``_strip_lumen_headers`` drops every caller-supplied
       ``x-lumen-argus-*`` header up front.
    2. Writes go through ``CIMultiDict.__setitem__``, which already
       deduplicates case-insensitively — even if a future change skips
       the strip pass, a duplicate-cased entry can't survive.
    """
    _strip_lumen_headers(headers)

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
    if config.agent_token:
        headers["X-Lumen-Argus-Agent-Token"] = config.agent_token


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------


async def _handle_request(request: web.Request) -> web.StreamResponse:
    """Main relay request handler."""
    relay: AgentRelay = request.app[_RELAY_KEY]
    path = request.path_qs

    if path == "/health":
        return web.json_response(
            {
                "status": "ok",
                "upstream": relay._upstream_health.state(),
                "upstream_url": relay.config.upstream_url,
                "fail_mode": relay.config.fail_mode,
                "agent_id": relay.config.agent_id or "",
                "enrolled": bool(relay.config.agent_id),
                "uptime": round(time.monotonic() - relay.start_time, 1),
                # Per-process identity (#77). Loopback-only — never leaves
                # the workstation. See AgentRelay.__init__.
                "boot_token": relay.boot_token,
            }
        )

    # Build identity (sidecar-build-identity-spec.md). Loopback-bound; no
    # inbound auth — same security model as /health.
    if path == "/api/v1/build" and request.method == "GET":
        from lumen_argus_agent import __version__
        from lumen_argus_core.build_info import get_build_info

        info = get_build_info("lumen-argus-agent", __version__)
        info["plugins"] = []
        return web.json_response(info)

    relay._active_requests += 1
    try:
        return await relay.forward(request)
    finally:
        relay._active_requests -= 1


# ---------------------------------------------------------------------------
# Relay state file
# ---------------------------------------------------------------------------

_ARGUS_DIR = os.path.expanduser("~/.lumen-argus")
RELAY_STATE_PATH = os.path.join(_ARGUS_DIR, "relay.json")


def _write_relay_state(config: RelayConfig, boot_token: str) -> None:
    """Write relay state file so the setup wizard can detect the relay.

    ``boot_token`` is a per-process identity minted in
    :class:`AgentRelay.__init__`; persisted here and echoed by ``/health``
    so adopters can prove the file refers to *this* process and not a
    PID-recycled successor (#77).
    """
    import json

    from lumen_argus_core.time_utils import now_iso

    os.makedirs(_ARGUS_DIR, mode=0o700, exist_ok=True)
    state = {
        "port": config.port,
        "bind": config.bind,
        "upstream_url": config.upstream_url,
        "fail_mode": config.fail_mode,
        "pid": os.getpid(),
        "started_at": now_iso(),
        "boot_token": boot_token,
    }
    try:
        tmp = RELAY_STATE_PATH + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp, RELAY_STATE_PATH)
        log.info("relay state written to %s", RELAY_STATE_PATH)
    except OSError as exc:
        log.warning("could not write relay state: %s", exc, exc_info=True)


def _remove_relay_state() -> None:
    """Remove relay state file on shutdown."""
    try:
        os.remove(RELAY_STATE_PATH)
        log.debug("relay state removed")
    except FileNotFoundError:
        pass
    except OSError as exc:
        log.warning("could not remove relay state: %s", exc, exc_info=True)


# Loopback /health probe budget. Generous for a localhost call (typically
# resolves in single-digit milliseconds) but tight enough that adopters
# making the legacy 3x200ms retry loop still complete inside ~1.5s.
_HEALTH_PROBE_TIMEOUT = 0.5


def _read_state_or_remove() -> dict[str, Any] | None:
    """Read the relay state file. Removes it on corruption; missing → None."""
    import json

    try:
        return read_relay_state_file(RELAY_STATE_PATH)
    except FileNotFoundError:
        return None
    except (json.JSONDecodeError, TypeError, OSError) as exc:
        log.warning("relay state unreadable: %s — removing", exc, exc_info=True)
        _remove_relay_state()
        return None


def _interpret_probe_outcome(
    outcome: str,
    state: dict[str, Any],
    pid: int,
    host: str,
    port: int,
) -> dict[str, Any] | None:
    """Apply the agent's removal policy to a probe outcome.

    Definitive failures (mismatch, refused) remove the file; ambiguous
    failures leave it alone so a transient-slow relay can recover on the
    next probe.
    """
    if outcome == PROBE_MATCH:
        return state
    if outcome == PROBE_MISMATCH:
        # Foreign process owns the port. Do not log the token value — it
        # is loopback-only but still a process-identity secret.
        log.info(
            "relay state stale: foreign process responding on %s:%d (pid=%d) — removing",
            host,
            port,
            pid,
        )
        _remove_relay_state()
        return None
    if outcome == PROBE_REFUSED:
        log.info(
            "relay state stale: %s:%d refused connection (pid=%d) — removing",
            host,
            port,
            pid,
        )
        _remove_relay_state()
        return None
    # INFO not DEBUG: a persistent ambiguous outcome means the relay is up
    # but its /health is broken — the worst-case silent-fleet condition
    # this whole change exists to defeat. Match telemetry's level so a
    # persistent issue leaves an audit trail on both call sites.
    log.info(
        "relay state probe ambiguous on %s:%d (pid=%d, outcome=%s) — leaving file",
        host,
        port,
        pid,
        outcome,
    )
    return None


def load_relay_state() -> dict[str, Any] | None:
    """Load relay state from disk. Returns None if the relay is not running.

    Composes three single-purpose helpers cheapest-first so a long-down
    relay never costs heartbeat latency:

    1. Read + parse — :func:`_read_state_or_remove`.
    2. Schema validate — :func:`validate_relay_state` (pure, in core).
    3. PID liveness — :func:`_pid_alive` short-circuits before network I/O.
    4. Loopback /health probe — :func:`probe_loopback_health` (in core),
       outcome interpreted by :func:`_interpret_probe_outcome`.
    """
    state = _read_state_or_remove()
    if state is None:
        return None

    fields = validate_relay_state(state)
    if isinstance(fields, str):
        log.info("relay state rejected: %s — removing", fields)
        _remove_relay_state()
        return None
    pid, port, bind, boot_token = fields

    if not _pid_alive(pid):
        log.debug("stale relay state (pid=%d not running) — removing", pid)
        _remove_relay_state()
        return None

    probe_host = loopback_host_for(bind)
    outcome = probe_loopback_health(probe_host, port, boot_token, _HEALTH_PROBE_TIMEOUT)
    return _interpret_probe_outcome(outcome, state, pid, probe_host, port)


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
        # Keep relay.json in sync so adopters comparing on-disk config
        # see the post-reload fail_mode, not the startup value. Token is
        # process-scoped, so it stays the same across rewrites.
        _write_relay_state(config, relay.boot_token)
    else:
        log.info("sighup reload: no changes detected")


async def run_relay(config: RelayConfig) -> None:
    """Start the relay and run until interrupted."""
    relay = AgentRelay(config)
    await relay.start()
    _write_relay_state(config, relay.boot_token)

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
