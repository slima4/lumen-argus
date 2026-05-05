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
from typing import Any

from lumen_argus_core.enrollment import (
    EnrollmentError,
    fetch_policy,
    load_enrollment,
    policy_diff_fields,
    ssl_context_for_proxy,
    update_agent_token,
    update_enrollment_policy,
)
from lumen_argus_core.time_utils import now_iso

log = logging.getLogger("argus.telemetry")


def _is_loopback_url(url: str) -> bool:
    """Return True if the URL targets a loopback address."""
    from urllib.parse import urlparse

    # Share the single source of truth with the enrollment module so the
    # two call sites cannot drift on which hosts count as loopback (e.g.
    # ::1 vs [::1]).
    from lumen_argus_core.enrollment import _LOOPBACK_HOSTS

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
    from lumen_argus_core.setup.protection import protection_status

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

    heartbeat_ok = False
    try:
        ctx = ssl_context_for_proxy()
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            try:
                response_data = json.loads(resp.read())
            except ValueError:
                response_data = {}
        log.debug("heartbeat sent to %s", dashboard_url)
        # Handle token rotation — proxy may issue a new token.
        # Refresh below will then read the rotated token from enrollment.json.
        new_token = response_data.get("new_token", "")
        if new_token:
            update_agent_token(new_token)
        heartbeat_ok = True
    except urllib.error.HTTPError as e:
        log.warning("heartbeat failed: HTTP %d", e.code)
    except urllib.error.URLError as e:
        log.warning("heartbeat failed: %s", e.reason)
    except Exception:
        # SSLError, TimeoutError, and other OSError subclasses can escape
        # urlopen in edge cases the urllib wrappers do not catch. Swallow
        # them so the refresh step below still runs — the spec makes policy
        # propagation independent of heartbeat success.
        log.warning("heartbeat failed with unexpected error", exc_info=True)

    # Policy refresh runs regardless of heartbeat outcome so admin-side
    # policy changes can still propagate when dashboard POSTs are flaky.
    # Failures here never influence the heartbeat return value.
    _refresh_policy_silent(dashboard_url)
    return heartbeat_ok


def _refresh_policy_silent(dashboard_url: str) -> None:
    """Re-fetch and persist enrollment policy. Never raises.

    Reads the (possibly rotated) enrollment state fresh so the bearer
    token matches whatever the heartbeat response just wrote. Logs changed
    field names — never values, since policy payloads can carry sensitive
    operational settings.
    """
    try:
        enrollment = load_enrollment()
        if not enrollment:
            # Can happen if a concurrent unenroll wiped the file between
            # the heartbeat's own load_enrollment and this point.
            log.debug("policy refresh skipped — enrollment state missing")
            return
        agent_token = enrollment.get("agent_token", "")
        if not agent_token:
            log.debug("policy refresh skipped — no agent bearer token")
            return
        old_policy = enrollment.get("policy") if isinstance(enrollment.get("policy"), dict) else {}
        new_policy = fetch_policy(dashboard_url, agent_token)
        if update_enrollment_policy(new_policy):
            fields = policy_diff_fields(old_policy or {}, new_policy)
            log.info("policy_refresh: changed=true fields=%s", fields)
        else:
            log.debug("policy_refresh: changed=false")
    except EnrollmentError as e:
        log.warning("policy refresh failed: %s", e)
    except Exception:  # defensive — never fail heartbeat on unexpected errors
        log.warning("policy refresh raised unexpectedly", exc_info=True)


def _relay_state_or_fallback() -> dict[str, Any] | None:
    """Read relay.json for the heartbeat path. Read-only — never mutates.

    Returns the parsed state dict, or ``None`` if the file is missing or
    unreadable. File lifecycle is owned by the agent's
    ``load_relay_state``; the heartbeat must not race the agent on
    removals.
    """
    import os

    state_path = os.path.join(os.path.expanduser("~"), ".lumen-argus", "relay.json")
    try:
        from lumen_argus_core.relay_state import read_relay_state_file

        return read_relay_state_file(state_path)
    except FileNotFoundError:
        log.debug("no relay state file — using proxy url for detection")
        return None
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        log.warning("failed to read relay state: %s — using fallback", exc, exc_info=True)
        return None


def _relay_url_or(fallback: str) -> str:
    """Return the relay URL if the agent relay is running, otherwise fallback.

    Validates PID liveness AND probes ``/health`` for the per-process
    ``boot_token`` to defeat PID recycling (#77). Read-only: file lifecycle
    stays owned by the agent's ``load_relay_state``.

    Composes the same pure helpers used by the agent (defined in
    :mod:`lumen_argus_core.relay_state`) so any future tightening of the
    schema or probe semantics applies to both call sites.
    """
    import os

    from lumen_argus_core.relay_state import (
        PROBE_MATCH,
        loopback_host_for,
        probe_loopback_health,
        validate_relay_state,
    )

    state = _relay_state_or_fallback()
    if state is None:
        return fallback

    fields = validate_relay_state(state)
    if isinstance(fields, str):
        log.info("relay state rejected by heartbeat: %s — using fallback", fields)
        return fallback
    pid, port, bind, boot_token = fields

    try:
        os.kill(pid, 0)
    except OSError:
        log.debug("relay state file has stale pid=%d — using fallback", pid)
        return fallback

    probe_host = loopback_host_for(bind)
    outcome = probe_loopback_health(probe_host, port, boot_token, timeout=0.5)
    if outcome != PROBE_MATCH:
        log.info(
            "relay /health probe outcome=%s (pid=%d host=%s port=%d) — using fallback",
            outcome,
            pid,
            probe_host,
            port,
        )
        return fallback

    url = "http://%s:%d" % (bind, port)
    log.debug("heartbeat detection using relay url=%s (pid=%d)", url, pid)
    return url


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
