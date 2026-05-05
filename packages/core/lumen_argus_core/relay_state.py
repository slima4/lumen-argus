"""Relay runtime-state provider registry.

:func:`lumen_argus_core.relay_service.get_service_status` needs the
running relay's port / upstream / PID without importing from the agent
package — core must not depend on agent (see ``test_module_boundaries``).
The agent package implements :class:`RelayStateProvider` and registers
it at import time; core reads through :func:`get_provider` and treats a
missing provider as "relay not installed".

Matches the inversion pattern used by
:mod:`lumen_argus_core.forward_proxy` for the setup-adapter registry.
"""

from __future__ import annotations

import json
import logging
import socket
import urllib.error
import urllib.request
from typing import Any, Protocol, runtime_checkable

log = logging.getLogger("argus.core.relay_state")


@runtime_checkable
class RelayStateProvider(Protocol):
    """Contract for reading the agent relay's runtime state from disk."""

    def load(self) -> dict[str, Any] | None:
        """Return the running relay's state dict, or ``None`` if not running.

        The provider is expected to validate the recorded PID and drop
        stale state so callers never observe a phantom relay.
        """


_provider: RelayStateProvider | None = None


def register_provider(provider: RelayStateProvider) -> None:
    """Register the relay-state provider.

    Called once at agent-package import time. Re-registration replaces
    the previous provider and logs the swap at DEBUG — normal during
    tests, a smell in production.
    """
    global _provider
    if _provider is not None and _provider is not provider:
        log.debug(
            "replacing relay-state provider: previous=%s new=%s",
            type(_provider).__name__,
            type(provider).__name__,
        )
    else:
        log.info("relay-state provider registered: %s", type(provider).__name__)
    _provider = provider


def unregister_provider() -> None:
    """Remove the registered provider. Intended for test teardown."""
    global _provider
    if _provider is not None:
        log.debug("relay-state provider unregistered: %s", type(_provider).__name__)
    _provider = None


def get_provider() -> RelayStateProvider | None:
    """Return the registered provider, or ``None`` when the agent is absent."""
    return _provider


# ---------------------------------------------------------------------------
# Pure helpers for relay.json (issue #77)
#
# Split out so the agent's ``load_relay_state`` (which removes the file on
# definitive staleness) and ``telemetry._relay_url_or`` (read-only — must
# never mutate the file) can share parsing/validation/probe logic without
# duplicating it. Each function does one thing; orchestrators in the agent
# and telemetry compose them with their own removal policy.
# ---------------------------------------------------------------------------


def read_relay_state_file(path: str) -> dict[str, Any]:
    """Read and parse a relay state file.

    Returns the parsed dict on success. Raises :class:`FileNotFoundError`
    when the file is absent, :class:`OSError` for other I/O failures,
    :class:`json.JSONDecodeError` on corruption, and :class:`TypeError`
    when the file's top-level value is not a JSON object — the caller
    decides whether to remove the file (the agent does, telemetry does
    not).
    """
    with open(path, encoding="utf-8") as f:
        parsed = json.load(f)
    if not isinstance(parsed, dict):
        raise TypeError("relay state must be a JSON object, got %s" % type(parsed).__name__)
    return parsed


def validate_relay_state(state: dict[str, Any]) -> tuple[int, int, str, str] | str:
    """Validate the shape of a parsed relay state dict.

    Returns ``(pid, port, bind, boot_token)`` on success, or a short reason
    string naming the offending field on failure. Pure — no I/O, no
    logging — so callers can attach their own observability and removal
    policy.
    """
    boot_token = state.get("boot_token")
    if not isinstance(boot_token, str) or not boot_token:
        return "missing or invalid boot_token"
    pid = state.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return "missing or invalid pid"
    port = state.get("port")
    # Reject out-of-range ports here so ``probe_loopback_health`` never
    # sees a value ``urllib`` would refuse with ``OverflowError`` — that
    # exception would escape the probe and break its always-returns-a-
    # string contract.
    if not isinstance(port, int) or port <= 0 or port > 65535:
        return "missing or invalid port"
    bind = state.get("bind") or "127.0.0.1"
    return pid, port, bind, boot_token


def loopback_host_for(bind: str) -> str:
    """Resolve the host to use when probing /health.

    A relay bound to ``0.0.0.0`` is reachable via ``127.0.0.1``; any other
    bind value is used verbatim.
    """
    return "127.0.0.1" if bind == "0.0.0.0" else bind


# ---------------------------------------------------------------------------
# Loopback /health probe (issue #77)
# ---------------------------------------------------------------------------

# Probe outcomes. Definitive ones authorise a caller to remove relay.json;
# ambiguous ones must leave the file alone so a transient-slow relay can
# recover on the next probe.
PROBE_MATCH = "match"
PROBE_MISMATCH = "mismatch"
PROBE_REFUSED = "refused"
PROBE_AMBIGUOUS = "ambiguous"


def probe_loopback_health(
    host: str,
    port: int,
    expected_boot_token: str,
    timeout: float,
) -> str:
    """Probe a relay's /health endpoint and classify the outcome.

    Used by both :func:`lumen_argus_agent.relay.load_relay_state` and
    :func:`lumen_argus_core.telemetry._relay_url_or` to defeat PID recycling:
    a recycled PID may pass ``os.kill(pid, 0)`` but only the real relay
    process echoes the per-process ``boot_token`` it wrote into
    ``relay.json`` at startup.

    Returns one of :data:`PROBE_MATCH`, :data:`PROBE_MISMATCH`,
    :data:`PROBE_REFUSED`, :data:`PROBE_AMBIGUOUS`.
    """
    url = "http://%s:%d/health" % (host, port)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            if resp.status != 200:
                return PROBE_AMBIGUOUS
            try:
                payload = json.loads(resp.read())
            except (ValueError, OSError):
                return PROBE_AMBIGUOUS
    except urllib.error.HTTPError:
        return PROBE_AMBIGUOUS
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, ConnectionRefusedError):
            return PROBE_REFUSED
        if isinstance(reason, (socket.timeout, TimeoutError)):
            return PROBE_AMBIGUOUS
        # OSError covers the bulk of network failures wrapped by URLError;
        # treat as ambiguous so we don't churn relay.json on transient
        # failures (DNS hiccup, ENETUNREACH on a flaky stack).
        return PROBE_AMBIGUOUS
    except ConnectionRefusedError:
        return PROBE_REFUSED
    except (socket.timeout, TimeoutError):
        return PROBE_AMBIGUOUS
    except OSError:
        return PROBE_AMBIGUOUS

    if not isinstance(payload, dict):
        # 200 with a body that isn't our /health shape — foreign service.
        return PROBE_MISMATCH
    actual = payload.get("boot_token")
    if not isinstance(actual, str) or not actual:
        # 200 + JSON object but no boot_token: definitely not our relay.
        return PROBE_MISMATCH
    return PROBE_MATCH if actual == expected_boot_token else PROBE_MISMATCH
