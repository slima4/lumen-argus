"""Shared helpers for dashboard API handlers.

JSON encoding, pagination, body parsing, store validation, SSE broadcast.
All handler modules import from here — not from api.py.
"""

from __future__ import annotations

import json
import logging
import os
import signal
from datetime import date, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore
    from lumen_argus.extensions import ExtensionRegistry

from lumen_argus.log_utils import sanitize_user_input

log = logging.getLogger("argus.dashboard.api")

SENSITIVE_FIELDS = frozenset(
    {
        "webhook_url",
        "routing_key",
        "password",
        "url",
        "username",
        "api_key",
        "token",
        "api_token",
    }
)


class _DateTimeEncoder(json.JSONEncoder):
    """JSON encoder that handles datetime objects from PostgreSQL TIMESTAMPTZ columns."""

    def default(self, o: Any) -> Any:
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, date):
            return o.isoformat()
        return super().default(o)


def json_response(status: int, data: object) -> tuple[int, bytes]:
    """Return (status, body_bytes) JSON response."""
    body = json.dumps(data, cls=_DateTimeEncoder).encode("utf-8")
    return status, body


class StoreUnavailable(Exception):
    """Raised by require_store when the analytics store is not available."""


def require_store(store: AnalyticsStore | None, context: str = "") -> AnalyticsStore:
    """Check that the analytics store is available.

    Returns the store if available, raises StoreUnavailable if not.
    """
    if not store:
        if context:
            log.error("%s: analytics store not available", context)
        raise StoreUnavailable()
    return store


def parse_pagination(
    params: dict[str, str], default_limit: int = 50, max_limit: int = 100
) -> tuple[int, bytes] | tuple[int, int]:
    """Parse limit/offset from query params with bounds.

    Returns (limit, offset) or a (status, body) error response tuple.
    """
    try:
        limit = min(int(params.get("limit", default_limit)), max_limit)
        offset = max(int(params.get("offset", 0)), 0)
    except (ValueError, TypeError):
        return json_response(400, {"error": "invalid pagination parameters"})
    return limit, offset


def parse_json_body(body: bytes, context: str = "") -> dict[str, Any] | tuple[int, bytes]:
    """Parse JSON body with sanitization and error handling.

    Returns parsed dict or a (status, body) error response tuple.
    """
    try:
        data = sanitize_user_input(json.loads(body))
    except (UnicodeDecodeError, ValueError):
        if context:
            log.debug("%s: invalid JSON body", context)
        return json_response(400, {"error": "invalid JSON"})
    if not isinstance(data, dict):
        return json_response(400, {"error": "invalid JSON"})
    return data


def parse_days(params: dict[str, str], default: int = 30) -> int:
    """Parse a 'days' query parameter with fallback to default."""
    val = params.get("days")
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def broadcast_sse(extensions: ExtensionRegistry | None, event_type: str, data: dict[str, Any] | None = None) -> None:
    """Broadcast an SSE event if a broadcaster is available."""
    if not extensions:
        return
    broadcaster = extensions.get_sse_broadcaster()
    if broadcaster:
        try:
            broadcaster.broadcast(event_type, data or {})
        except Exception:
            log.debug("SSE %s broadcast failed", event_type, exc_info=True)


def send_sighup() -> bool:
    """Send SIGHUP to self for config reload. Returns True if sent."""
    if not hasattr(signal, "SIGHUP"):
        return False
    current_handler = signal.getsignal(signal.SIGHUP)
    if current_handler in (signal.SIG_DFL, signal.SIG_IGN, None):
        return False
    try:
        os.kill(os.getpid(), signal.SIGHUP)
        log.debug("SIGHUP sent for config reload")
        return True
    except OSError:
        log.warning("could not send SIGHUP for config reload")
        return False


def parse_query(path: str) -> tuple[str, dict[str, str]]:
    """Split path and query string, return (path, params_dict)."""
    from urllib.parse import unquote_plus

    query = ""
    if "?" in path:
        path, query = path.split("?", 1)
    params: dict[str, str] = {}
    if query:
        for part in query.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                params[unquote_plus(k)] = unquote_plus(v)
    return path, params


def mask_channel(channel: dict[str, Any]) -> dict[str, Any]:
    """Mask sensitive fields in channel config for API responses."""
    ch = dict(channel)
    config = ch.get("config", {})
    if isinstance(config, str):
        config = json.loads(config)
    masked = dict(config)
    for key in SENSITIVE_FIELDS:
        if masked.get(key):
            val = str(masked[key])
            masked[key] = val[:4] + "****" + val[-4:] if len(val) > 8 else "****"
    ch["config_masked"] = masked
    ch.pop("config", None)
    return ch
