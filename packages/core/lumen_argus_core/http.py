"""Shared HTTP helpers for proxy and agent.

Lives in core so proxy and agent agree on load-bearing aiohttp session
settings. ``aiohttp`` is imported lazily inside helpers so importing this
module does not pull aiohttp into core's dependency surface — both
consumers (proxy, agent) already declare aiohttp.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import aiohttp


def make_passthrough_session(*, limit: int, ssl: Any = None) -> aiohttp.ClientSession:
    """Build a ClientSession for byte-identical response forwarding.

    ``auto_decompress=False`` is load-bearing: relay/proxy forwarders
    propagate the upstream ``Content-Encoding`` response header verbatim,
    so aiohttp must not silently gunzip the body — that would double-encode
    against the preserved header. Companion ``accept-encoding`` request
    strip in each forwarder normalizes the inbound value.

    Args:
        limit: ``TCPConnector(limit=...)`` — max simultaneous connections.
        ssl: Optional ``ssl=`` for ``TCPConnector``. ``None`` (default)
            uses aiohttp's default TLS verification; pass ``False`` to
            disable verification or an ``SSLContext`` for custom config.
    """
    import aiohttp

    connector_kwargs: dict[str, Any] = {"limit": limit}
    if ssl is not None:
        connector_kwargs["ssl"] = ssl
    return aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(**connector_kwargs),
        auto_decompress=False,
    )
