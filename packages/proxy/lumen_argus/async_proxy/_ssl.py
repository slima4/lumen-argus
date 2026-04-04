from __future__ import annotations

import logging
import os
import ssl

log = logging.getLogger("argus.proxy")


def build_ssl_context(ca_bundle: str = "", verify_ssl: bool = True) -> ssl.SSLContext:
    """Build an SSL context for upstream connections.

    Args:
        ca_bundle: Path to a CA cert file or directory. Empty = system default.
        verify_ssl: If False, disable certificate verification (dev/testing only).
    """
    if not verify_ssl:
        log.warning("TLS certificate verification is disabled — do not use in production")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # NOSONAR — intentional: user explicitly set verify_ssl=false
        ctx.verify_mode = ssl.CERT_NONE  # NOSONAR
        return ctx

    ctx = ssl.create_default_context()
    if ca_bundle:
        ca_path = os.path.expanduser(ca_bundle)
        if os.path.isdir(ca_path):
            ctx.load_verify_locations(capath=ca_path)
        else:
            ctx.load_verify_locations(cafile=ca_path)
        log.info("loaded custom CA bundle: %s", ca_path)
    return ctx


# Hop-by-hop headers that must not be forwarded.
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
