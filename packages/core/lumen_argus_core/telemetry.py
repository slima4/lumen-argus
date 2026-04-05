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
    report = detect_installed_clients(proxy_url=proxy_url)
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

    payload = json.dumps(
        {
            "agent_id": enrollment["agent_id"],
            "agent_version": _get_version(),
            "os": platform.system().lower(),
            "arch": platform.machine(),
            "hostname": platform.node(),
            "protection_enabled": prot_status.get("enabled", False),
            "tools": tools,
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


def _check_watch_daemon() -> bool:
    """Check if the watch daemon service is installed."""
    try:
        from lumen_argus_core.watch import get_service_status

        status = get_service_status()
        return bool(status.get("installed", False))
    except Exception:
        return False


def _get_version() -> str:
    """Get the agent version."""
    try:
        from importlib.metadata import version

        return version("lumen-argus-agent")
    except Exception:
        return "0.0.0"
