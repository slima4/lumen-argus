"""mitmproxy addon for lumen-argus forward proxy.

Intercepts HTTPS requests from AI tools that don't support custom base
URLs (e.g., Copilot CLI with GitHub auth).  For intercepted hosts:

1. Resolves OS-level caller context (PID → cwd, git branch, hostname)
2. Injects X-Lumen-* identity headers
3. Re-routes the request to the lumen-argus proxy via ``/_forward``
4. Proxy scans, applies policy, and forwards to the original destination

Non-AI hosts pass through without TLS interception (mitmproxy's
``ignore_hosts`` config).

Requires: ``mitmproxy >= 12.0`` (installed as agent dependency).
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from mitmproxy import http

log = logging.getLogger("argus.forward.addon")


# ---------------------------------------------------------------------------
# Hosts to intercept (AI API endpoints)
# ---------------------------------------------------------------------------

# Hosts containing AI traffic that we want to scan.
# Requests to these hosts are re-routed through the lumen-argus proxy.
SCAN_HOSTS: frozenset[str] = frozenset(
    {
        # GitHub Copilot
        "api.individual.githubcopilot.com",
        "api.business.githubcopilot.com",
        "copilot-proxy.githubusercontent.com",
        # Standard AI providers (if tool uses HTTPS_PROXY for all traffic)
        "api.anthropic.com",
        "api.openai.com",
        "generativelanguage.googleapis.com",
        # Warp (if BYOK mode makes direct calls)
        "app.warp.dev",
    }
)

# Headers injected by the addon — stripped before forwarding to upstream API.
_LUMEN_HEADER_PREFIX = "x-lumen-argus-"
_FORWARD_HOST_HEADER = "x-lumen-forward-host"
_FORWARD_SCHEME_HEADER = "x-lumen-forward-scheme"
_FORWARD_PORT_HEADER = "x-lumen-forward-port"

# Host → tool name for metrics tracking.
_HOST_PROVIDER_MAP: dict[str, str] = {
    "api.individual.githubcopilot.com": "copilot",
    "api.business.githubcopilot.com": "copilot",
    "copilot-proxy.githubusercontent.com": "copilot",
    "api.anthropic.com": "anthropic",
    "api.openai.com": "openai",
    "generativelanguage.googleapis.com": "gemini",
    "app.warp.dev": "warp",
}


class LumenArgusAddon:
    """mitmproxy addon that re-routes AI traffic through lumen-argus proxy.

    Args:
        upstream_proxy: URL of the lumen-argus proxy (e.g., ``http://localhost:8080``).
        extra_scan_hosts: Additional hosts to intercept beyond the default set.
        agent_token: Agent authentication token for the proxy.
        agent_id: Agent ID for the proxy.
        machine_id: Machine ID for device identification.
        send_username: Whether to send username in identity headers.
        send_hostname: Whether to send hostname in identity headers.
    """

    def __init__(
        self,
        upstream_proxy: str = "http://localhost:8080",
        extra_scan_hosts: frozenset[str] | None = None,
        agent_token: str = "",
        agent_id: str = "",
        machine_id: str = "",
        send_username: bool = True,
        send_hostname: bool = True,
        listen_port: int = 9090,
    ) -> None:
        parsed = urlparse(upstream_proxy)
        self._proxy_scheme = parsed.scheme or "http"
        self._proxy_host = parsed.hostname or "localhost"
        self._proxy_port = parsed.port or 8080
        self._listen_port = listen_port
        self._agent_token = agent_token
        self._agent_id = agent_id
        self._machine_id = machine_id
        self._send_username = send_username
        self._send_hostname = send_hostname

        self._scan_hosts = SCAN_HOSTS
        if extra_scan_hosts:
            self._scan_hosts = SCAN_HOSTS | extra_scan_hosts

        # Cached GitHub account ID from /copilot_internal/user response
        self._github_login: str = ""

        # Request counters for /health metrics
        self._requests_total = 0
        self._requests_intercepted = 0
        self._requests_passthrough = 0
        self._errors = 0
        self._active_tools: set[str] = set()

    def _should_intercept(self, host: str) -> bool:
        """Check if a host should be intercepted for scanning."""
        return host in self._scan_hosts

    def request(self, flow: http.HTTPFlow) -> None:
        """Intercept request: enrich with identity, re-route to proxy."""
        # Health endpoint — respond locally without forwarding.
        # Tray app sends GET http://127.0.0.1:9090/health to check status.
        if flow.request.path == "/health" and flow.request.pretty_host in ("127.0.0.1", "localhost", "::1"):
            import json
            import os

            ca_cert = os.path.expanduser("~/.lumen-argus/ca/ca-cert.pem")
            flow.response = http.Response.make(
                200,
                json.dumps(
                    {
                        "status": "ok",
                        "upstream": self._proxy_host + ":" + str(self._proxy_port),
                        "ca_loaded": os.path.isfile(ca_cert),
                        "scan_hosts": len(self._scan_hosts),
                        "requests_total": self._requests_total,
                        "requests_intercepted": self._requests_intercepted,
                        "requests_passthrough": self._requests_passthrough,
                        "errors": self._errors,
                        "active_tools": sorted(self._active_tools),
                    }
                ),
                {"Content-Type": "application/json"},
            )
            return

        original_host = flow.request.pretty_host
        original_port = flow.request.port
        original_scheme = flow.request.scheme

        self._requests_total += 1

        if not self._should_intercept(original_host):
            self._requests_passthrough += 1
            return

        self._requests_intercepted += 1

        # Track which tools are using the forward proxy (by host)
        tool = _HOST_PROVIDER_MAP.get(original_host, "")
        if tool:
            self._active_tools.add(tool)

        log.info(
            "intercepting %s %s://%s%s",
            flow.request.method,
            original_scheme,
            original_host,
            flow.request.path,
        )

        # Resolve caller context (OS-level identity)
        self._inject_identity_headers(flow)

        # Set forwarding headers (original destination)
        flow.request.headers[_FORWARD_HOST_HEADER] = original_host
        flow.request.headers[_FORWARD_SCHEME_HEADER] = original_scheme
        if original_port not in (80, 443):
            flow.request.headers[_FORWARD_PORT_HEADER] = str(original_port)

        # Agent authentication
        if self._agent_token:
            flow.request.headers["x-lumen-argus-agent-token"] = self._agent_token

        # Re-route to proxy's /_forward endpoint
        flow.request.scheme = self._proxy_scheme
        flow.request.host = self._proxy_host
        flow.request.port = self._proxy_port
        flow.request.path = "/_forward" + flow.request.path

    def response(self, flow: http.HTTPFlow) -> None:
        """Strip X-Lumen-* headers and extract GitHub account from responses."""
        if flow.response is None:
            return

        # Extract GitHub login from /copilot_internal/user response.
        # This endpoint is called on every Copilot CLI session start.
        if (
            not self._github_login
            and flow.request.pretty_host == "api.github.com"
            and flow.request.path == "/copilot_internal/user"
            and flow.response.status_code == 200
        ):
            try:
                import json

                data = json.loads(flow.response.content or b"")
                login = data.get("login", "")
                if login:
                    self._github_login = str(login)
                    log.info("GitHub account resolved: %s", self._github_login)
            except (ValueError, TypeError):
                log.debug("failed to parse /copilot_internal/user response")

        # Strip internal headers before returning to client
        headers_to_remove = [
            k
            for k in flow.response.headers
            if k.lower().startswith(_LUMEN_HEADER_PREFIX)
            or k.lower() in (_FORWARD_HOST_HEADER, _FORWARD_SCHEME_HEADER, _FORWARD_PORT_HEADER)
        ]
        for k in headers_to_remove:
            del flow.response.headers[k]

    def error(self, flow: http.HTTPFlow) -> None:
        """Track errors (connection failures, TLS issues, etc.)."""
        self._errors += 1

    def _inject_identity_headers(self, flow: http.HTTPFlow) -> None:
        """Inject X-Lumen-* identity headers from OS-level context."""
        # Lazy import to avoid loading context module until needed
        from lumen_argus_agent.context import resolve_context, static_context

        # Strip every caller-supplied x-lumen-argus-* header before
        # injection (#76). The agent owns this namespace; any pre-existing
        # value is a spoofing attempt by a local process. mitmproxy's
        # ``Headers`` is case-insensitive, so __setitem__ later replaces
        # cleanly, but we still drop fields the agent chooses not to set
        # (empty ctx, privacy flags, no GitHub login) — those would
        # otherwise be inherited from the caller.
        for key in list(flow.request.headers.keys()):
            if key.lower().startswith(_LUMEN_HEADER_PREFIX):
                del flow.request.headers[key]

        # Attempt PID-level resolution from client address
        # mitmproxy provides client connection info
        client_port = 0
        if flow.client_conn and flow.client_conn.peername:
            client_port = flow.client_conn.peername[1]

        if client_port:
            ctx_info = resolve_context(self._listen_port, client_port)
            log.debug(
                "PID resolution: listen=%d client_port=%d pid=%d cwd=%s",
                self._listen_port,
                client_port,
                ctx_info.client_pid,
                ctx_info.working_directory or "-",
            )
        else:
            ctx_info = static_context()

        if self._agent_id:
            flow.request.headers["x-lumen-argus-agent-id"] = self._agent_id
        if self._machine_id:
            flow.request.headers["x-lumen-argus-device-id"] = self._machine_id
        if ctx_info.working_directory and ctx_info.working_directory != "/":
            flow.request.headers["x-lumen-argus-working-dir"] = ctx_info.working_directory
        if ctx_info.git_branch:
            flow.request.headers["x-lumen-argus-git-branch"] = ctx_info.git_branch
        if ctx_info.os_platform:
            flow.request.headers["x-lumen-argus-os-platform"] = ctx_info.os_platform
        if ctx_info.hostname and self._send_hostname:
            flow.request.headers["x-lumen-argus-hostname"] = ctx_info.hostname
        if ctx_info.username and self._send_username:
            flow.request.headers["x-lumen-argus-username"] = ctx_info.username
        if ctx_info.client_pid:
            flow.request.headers["x-lumen-argus-client-pid"] = str(ctx_info.client_pid)
        if self._github_login:
            flow.request.headers["x-lumen-argus-account-id"] = self._github_login
