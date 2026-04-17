"""Enrollment state management — agent-side enrollment lifecycle.

Manages the enrollment state file at ~/.lumen-argus/enrollment.json.
Uses only stdlib (json, os, urllib) — no external dependencies.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import secrets
import ssl
import urllib.error
import urllib.request
from typing import Any

from lumen_argus_core.time_utils import now_iso

log = logging.getLogger("argus.enrollment")

_ARGUS_DIR = os.path.expanduser("~/.lumen-argus")
ENROLLMENT_FILE = os.path.join(_ARGUS_DIR, "enrollment.json")
_CA_CERT_FILE = os.path.join(_ARGUS_DIR, "ca.pem")


_ssl_ctx_cache: ssl.SSLContext | None = None
_ssl_ctx_mtime: float = 0.0


def ssl_context_for_proxy() -> ssl.SSLContext | None:
    """Build an SSL context using the enrolled CA cert, if available.

    Returns None if no CA cert is installed (default system CA will be used).
    Called by enrollment and telemetry for all proxy HTTPS requests.
    Caches the context and only rebuilds when the CA file changes on disk.
    """
    global _ssl_ctx_cache, _ssl_ctx_mtime
    if not os.path.isfile(_CA_CERT_FILE):
        _ssl_ctx_cache = None
        return None
    mtime = os.path.getmtime(_CA_CERT_FILE)
    if _ssl_ctx_cache is None or mtime != _ssl_ctx_mtime:
        _ssl_ctx_cache = ssl.create_default_context(cafile=_CA_CERT_FILE)
        _ssl_ctx_mtime = mtime
        log.debug("loaded CA cert %s for proxy TLS", _CA_CERT_FILE)
    return _ssl_ctx_cache


def _generate_agent_id() -> str:
    """Generate a unique agent ID."""
    return "agent_" + secrets.token_hex(8)


def _generate_machine_id() -> str:
    """Generate a stable machine identifier from hostname + platform."""
    raw = f"{platform.node()}:{platform.system()}:{platform.machine()}"
    return "mac_" + hashlib.sha256(raw.encode()).hexdigest()[:16]


def fetch_enrollment_config(server_url: str, token: str = "") -> dict[str, Any]:
    """Fetch enrollment configuration from the central proxy.

    Args:
        server_url: Base URL of the central proxy (e.g., https://argus.corp.io)
        token: Optional enrollment token for authentication

    Returns:
        Parsed enrollment config dict.

    Raises:
        EnrollmentError: If the fetch fails or the response is invalid.
    """
    url = server_url.rstrip("/") + "/api/v1/enrollment/config"
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        ctx = ssl_context_for_proxy()
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            data: dict[str, Any] = json.loads(resp.read())
            return data
    except urllib.error.HTTPError as e:
        if e.code == 402:
            raise EnrollmentError("Server does not support enrollment (Pro license required)") from e
        raise EnrollmentError(f"Failed to fetch enrollment config: HTTP {e.code}") from e
    except urllib.error.URLError as e:
        raise EnrollmentError(f"Cannot reach server: {e.reason}") from e
    except json.JSONDecodeError as e:
        raise EnrollmentError(f"Invalid enrollment config response: {e}") from e


def register_agent(server_url: str, agent_id: str, machine_id: str, token: str = "") -> dict[str, Any]:
    """Register this agent with the central proxy.

    Args:
        server_url: Base URL of the central proxy.
        agent_id: Unique agent identifier.
        machine_id: Stable machine identifier.
        token: Enrollment token for authentication.

    Returns:
        Registration response dict. May contain 'agent_token' (show-once bearer token).

    Raises:
        EnrollmentError: If registration fails.
    """
    url = server_url.rstrip("/") + "/api/v1/enrollment/register"
    payload = json.dumps(
        {
            "agent_id": agent_id,
            "machine_id": machine_id,
            "hostname": platform.node(),
            "os": platform.system().lower(),
            "arch": platform.machine(),
            "agent_version": _get_version(),
            "enrollment_token": token,
        }
    ).encode()

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        ctx = ssl_context_for_proxy()
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            try:
                response_data: dict[str, Any] = json.loads(resp.read())
            except ValueError:
                response_data = {}
    except urllib.error.HTTPError as e:
        if e.code == 402:
            raise EnrollmentError("Server does not support enrollment (Pro license required)") from e
        if e.code == 401:
            raise EnrollmentError("Invalid enrollment token") from e
        raise EnrollmentError(f"Registration failed: HTTP {e.code}") from e
    except urllib.error.URLError as e:
        raise EnrollmentError(f"Cannot reach server: {e.reason}") from e

    log.info("agent registered with %s", server_url)
    return response_data


def deregister_agent(server_url: str, agent_id: str) -> None:
    """Deregister this agent from the central proxy."""
    url = server_url.rstrip("/") + "/api/v1/enrollment/deregister"
    payload = json.dumps({"agent_id": agent_id}).encode()
    headers = {"Content-Type": "application/json"}

    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        ctx = ssl_context_for_proxy()
        urllib.request.urlopen(req, timeout=15, context=ctx)
    except urllib.error.URLError:
        log.warning("failed to deregister agent — server may be unreachable")


def enroll(server_url: str, token: str = "") -> dict[str, Any]:
    """Full enrollment flow: fetch config, register, save state.

    Returns:
        The saved enrollment state dict.

    Raises:
        EnrollmentError: If any step fails.
    """
    config = fetch_enrollment_config(server_url, token=token)

    agent_id = _generate_agent_id()
    machine_id = _generate_machine_id()

    reg_response = register_agent(server_url, agent_id, machine_id, token=token)

    state: dict[str, Any] = {
        "server": server_url,
        "proxy_url": config.get("proxy_url", server_url),
        "dashboard_url": config.get("dashboard_url", server_url),
        "organization": config.get("organization", ""),
        "policy": config.get("policy", {}),
        "enrolled_at": now_iso(),
        "agent_id": agent_id,
        "machine_id": machine_id,
    }

    # Store agent bearer token if proxy issued one (Pro feature)
    agent_token = reg_response.get("agent_token", "")
    if agent_token:
        state["agent_token"] = agent_token
        log.info("agent bearer token received and stored")

    # Save CA cert if provided
    ca_cert = config.get("ca_cert", "")
    if ca_cert:
        _write_file(_CA_CERT_FILE, ca_cert)
        log.info("CA certificate saved to %s", _CA_CERT_FILE)

    # Save enrollment state
    _save_enrollment(state)
    log.info("enrolled with %s (org: %s)", server_url, state["organization"])

    return state


def unenroll() -> bool:
    """Remove enrollment state and clean up.

    Returns:
        True if was enrolled, False if not enrolled.
    """
    state = load_enrollment()
    if not state:
        return False

    # Notify proxy (best effort)
    deregister_agent(state["server"], state["agent_id"])

    # Remove files
    for path in (ENROLLMENT_FILE, _CA_CERT_FILE):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass

    log.info("unenrolled from %s", state["server"])
    return True


def load_enrollment() -> dict[str, Any] | None:
    """Load enrollment state from disk. Returns None if not enrolled."""
    try:
        with open(ENROLLMENT_FILE, encoding="utf-8") as f:
            state: dict[str, Any] = json.load(f)
            return state
    except (FileNotFoundError, PermissionError, json.JSONDecodeError):
        return None


def is_enrolled() -> bool:
    """Check if this machine is enrolled."""
    return os.path.isfile(ENROLLMENT_FILE)


def update_agent_token(new_token: str) -> bool:
    """Update the agent bearer token in enrollment.json.

    Called by telemetry on token rotation. Loads current state,
    updates the token, and writes atomically.

    Returns True if updated, False if not enrolled.
    """
    state = load_enrollment()
    if not state:
        log.warning("cannot update agent token — not enrolled")
        return False
    state["agent_token"] = new_token
    _save_enrollment(state)
    log.info("agent token rotated")
    return True


def _save_enrollment(state: dict[str, Any]) -> None:
    """Write enrollment state atomically with 0o600 permissions."""
    os.makedirs(_ARGUS_DIR, mode=0o700, exist_ok=True)
    tmp_path = ENROLLMENT_FILE + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, ENROLLMENT_FILE)


def _write_file(path: str, content: str) -> None:
    """Write a file atomically with 0o600 permissions."""
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)


def _get_version() -> str:
    """Get the agent/core version."""
    try:
        from importlib.metadata import version

        return version("lumen-argus-agent")
    except Exception:
        return "0.0.0"


class EnrollmentError(Exception):
    """Raised when enrollment fails."""
