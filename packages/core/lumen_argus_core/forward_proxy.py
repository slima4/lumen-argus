"""Forward proxy setup adapter registry.

Forward-proxy tool setup (Copilot CLI, Warp, etc.) requires CA cert
generation and trust-store interaction, which depends on mitmproxy. That
belongs in ``lumen-argus-agent`` — not in this zero-dependency core package.

The registry here lets the agent package supply a concrete adapter at
import time while the core setup wizard dispatches through a stable
interface. When no adapter is registered (e.g. the proxy-only PyInstaller
bundle), callers receive :class:`ForwardProxyUnavailable` with clear
install guidance instead of a misleading ``ImportError``.
"""

from __future__ import annotations

import logging
import os
from typing import Protocol, runtime_checkable

log = logging.getLogger("argus.core.forward_proxy")

# Shared path for forward-proxy shell aliases. Written by
# ``setup_wizard._write_aliases`` and read by ``detect._check_forward_proxy_aliases``;
# lives here because this module is already the neutral forward-proxy seam
# (detect ↔ setup_wizard have a circular-import hazard).
ALIASES_PATH = os.path.expanduser("~/.lumen-argus/forward-proxy-aliases.sh")


class ForwardProxyUnavailable(RuntimeError):
    """Raised when forward-proxy setup is requested without an adapter.

    The error message names the binary the user should run instead so the
    CLI surface can forward it verbatim without further formatting.
    """


@runtime_checkable
class ForwardProxySetupAdapter(Protocol):
    """Contract the agent package implements to enable forward-proxy setup."""

    def ca_exists(self) -> bool:
        """Return True if the CA certificate is already on disk."""

    def ensure_ca(self) -> str:
        """Generate the CA if missing and return its certificate path."""

    def get_ca_cert_path(self) -> str:
        """Return the path to the CA certificate (may not exist yet)."""

    def is_ca_trusted(self) -> bool:
        """Return True if the CA is installed in the system trust store."""

    def install_ca_system(self) -> bool:
        """Install the CA to the system trust store. Returns True on success."""


_adapter: ForwardProxySetupAdapter | None = None


def register_adapter(adapter: ForwardProxySetupAdapter) -> None:
    """Register the forward-proxy adapter.

    Called once at agent package import time. Re-registration replaces the
    previous adapter and logs the swap at DEBUG — normal during tests, a
    smell in production.
    """
    global _adapter
    if _adapter is not None and _adapter is not adapter:
        log.debug(
            "replacing forward-proxy adapter: previous=%s new=%s",
            type(_adapter).__name__,
            type(adapter).__name__,
        )
    else:
        log.info("forward-proxy adapter registered: %s", type(adapter).__name__)
    _adapter = adapter


def unregister_adapter() -> None:
    """Remove the registered adapter. Intended for test teardown."""
    global _adapter
    if _adapter is not None:
        log.debug("forward-proxy adapter unregistered: %s", type(_adapter).__name__)
    _adapter = None


def get_adapter() -> ForwardProxySetupAdapter | None:
    """Return the registered adapter or None.

    Callers that need a client-specific error message when the adapter is
    missing (e.g. the setup wizard) handle the ``None`` case themselves
    and raise :class:`ForwardProxyUnavailable` with their own context. No
    generic ``require_adapter`` helper is provided — every current caller
    wants different error text.
    """
    return _adapter
