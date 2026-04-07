"""Agent telemetry — heartbeat to central proxy.

Sends periodic heartbeats with tool status and agent health.
Uses only stdlib (json, urllib) — no external dependencies.
"""

from __future__ import annotations

import json
import logging
import platform
import urllib.error
import urllib.request

from lumen_argus_core.enrollment import load_enrollment, ssl_context_for_proxy, update_agent_token
from lumen_argus_core.time_utils import now_iso

log = logging.getLogger("argus.telemetry")

# Loopback hostnames where HTTP is safe (no network exposure)
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "[::1]"}


def _is_loopback_url(url: str) -> bool:
    """Return True if the URL targets a loopback address."""
    from urllib.parse import urlparse

    host = urlparse(url).hostname or ""
    return host in _LOOPBACK_HOSTS


def send_heartbeat() -> bool:
    """Send a heartbeat to the central proxy.

    Reads enrollment state, runs detection, and POSTs tool status.
    Returns True on success, False on failure.
    """
    enrollment = load_enrollment()
    if not enrollment:
        log.debug("not enrolled — skipping heartbeat")
        return False

    # Import detect here to avoid circular imports and keep telemetry lightweight
    from lumen_argus_core.detect import detect_installed_clients
    from lumen_argus_core.setup_wizard import protection_status

    proxy_url = enrollment.get("proxy_url") or enrollment["server"]
    # When relay is active, tools are configured against the relay URL,
    # not the remote proxy URL. Use relay URL for accurate detection.
    detection_url = _relay_url_or(proxy_url)
    log.info("heartbeat: detecting tools against %s (proxy=%s)", detection_url, proxy_url)
    report = detect_installed_clients(proxy_url=detection_url)
    prot_status = protection_status()

    tools = [
        {
            "client_id": c.client_id,
            "display_name": c.display_name,
            "installed": c.installed,
            "version": c.version,
            "install_method": c.install_method,
            "proxy_configured": c.proxy_configured,
            "routing_active": c.routing_active,
            "proxy_config_type": c.proxy_config_type,
        }
        for c in report.clients
        if c.installed
    ]

    mcp_servers = _detect_mcp_for_heartbeat()

    payload = json.dumps(
        {
            "agent_id": enrollment["agent_id"],
            "agent_version": _get_version(),
            "os": platform.system().lower(),
            "arch": platform.machine(),
            "hostname": platform.node(),
            "protection_enabled": prot_status.get("enabled", False),
            "tools": tools,
            "mcp_servers": mcp_servers,
            "policy_version": enrollment.get("enrolled_at", ""),
            "watch_daemon_running": _check_watch_daemon(),
            "heartbeat_at": now_iso(),
        }
    ).encode()

    dashboard_url = enrollment.get("dashboard_url") or enrollment["server"]
    url = dashboard_url.rstrip("/") + "/api/v1/enrollment/heartbeat"

    headers = {"Content-Type": "application/json"}
    agent_token = enrollment.get("agent_token", "")
    if agent_token:
        if not url.startswith("https://") and not _is_loopback_url(url):
            log.warning("bearer token not sent — dashboard_url is not HTTPS")
        else:
            headers["Authorization"] = f"Bearer {agent_token}"

    req = urllib.request.Request(
        url,
        data=payload,
        headers=headers,
        method="POST",
    )

    try:
        ctx = ssl_context_for_proxy()
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            try:
                response_data = json.loads(resp.read())
            except ValueError:
                response_data = {}
        log.debug("heartbeat sent to %s", dashboard_url)
        # Handle token rotation — proxy may issue a new token
        new_token = response_data.get("new_token", "")
        if new_token:
            update_agent_token(new_token)
        return True
    except urllib.error.HTTPError as e:
        log.warning("heartbeat failed: HTTP %d", e.code)
        return False
    except urllib.error.URLError as e:
        log.warning("heartbeat failed: %s", e.reason)
        return False


def _relay_url_or(fallback: str) -> str:
    """Return the relay URL if the agent relay is running, otherwise fallback.

    Reads ~/.lumen-argus/relay.json directly (no agent package import —
    core must not depend on agent).  Validates PID liveness to avoid
    stale state.
    """
    import os

    state_path = os.path.join(os.path.expanduser("~"), ".lumen-argus", "relay.json")
    try:
        with open(state_path, encoding="utf-8") as f:
            state = json.load(f)
        pid = state.get("pid", 0)
        if pid:
            try:
                os.kill(pid, 0)
            except OSError:
                log.debug("relay state file has stale pid=%d — using fallback", pid)
                return fallback
        bind = state.get("bind")
        port = state.get("port")
        if not bind or not port:
            log.warning("relay state file missing bind/port — using fallback")
            return fallback
        url = "http://%s:%d" % (bind, port)
        log.debug("heartbeat detection using relay url=%s (pid=%d)", url, pid)
        return url
    except FileNotFoundError:
        log.debug("no relay state file — using proxy url for detection")
        return fallback
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        log.warning("failed to read relay state: %s — using fallback", exc)
        return fallback


def _check_watch_daemon() -> bool:
    """Check if the watch daemon service is installed."""
    try:
        from lumen_argus_core.watch import get_service_status

        status = get_service_status()
        return bool(status.get("installed", False))
    except Exception:
        return False


def _detect_mcp_for_heartbeat() -> list[dict[str, object]]:
    """Detect MCP servers and return a safe subset for heartbeat payload.

    Only includes name, transport, source_tool, scope, and scanning_enabled.
    Never sends command, args, env, or urls — they may contain secrets or paths.
    """
    try:
        from lumen_argus_core.detect import detect_mcp_servers

        report = detect_mcp_servers()
        return [
            {
                "name": s.name,
                "transport": s.transport,
                "source_tool": s.source_tool,
                "scope": s.scope,
                "scanning_enabled": s.scanning_enabled,
            }
            for s in report.servers
        ]
    except Exception:
        log.debug("MCP detection failed during heartbeat — skipping", exc_info=True)
        return []


def _get_version() -> str:
    """Get the agent version."""
    try:
        from importlib.metadata import version

        return version("lumen-argus-agent")
    except Exception:
        return "0.0.0"
