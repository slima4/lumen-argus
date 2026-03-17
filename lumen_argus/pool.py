"""Thread-safe HTTP/HTTPS connection pool for upstream providers."""

import http.client
import logging
import os
import ssl
import threading
import time
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("argus.pool")

# Key type: (host, port, use_ssl)
_PoolKey = Tuple[str, int, bool]


def build_ssl_context(ca_bundle: str = "", verify_ssl: bool = True) -> ssl.SSLContext:
    """Build an SSL context from config.

    Args:
        ca_bundle: Path to a CA cert file or directory. Empty = system default.
        verify_ssl: If False, disable certificate verification (dev/testing only).

    Returns:
        Configured ssl.SSLContext.
    """
    if not verify_ssl:
        log.warning("TLS certificate verification is disabled — do not use in production")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
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


class ConnectionPool:
    """Per-host connection pool with idle timeout and thread-safe access.

    Connections are returned to the pool after non-streaming responses.
    SSE streaming connections are NOT returned (stream must be fully consumed
    before the connection can be reused, and we don't buffer the full stream).
    """

    def __init__(self, pool_size: int = 4, timeout: int = 30, idle_timeout: int = 60,
                 ssl_context: ssl.SSLContext = None):
        """
        Args:
            pool_size: Max idle connections per host.
            timeout: Socket timeout for connections (seconds).
            idle_timeout: Evict connections idle longer than this (seconds).
            ssl_context: SSL context for HTTPS connections. If None, uses system default.
        """
        self._pool_size = pool_size
        self._timeout = timeout
        self._idle_timeout = idle_timeout
        self._ssl_ctx = ssl_context or ssl.create_default_context()
        self._lock = threading.Lock()
        # pool_key -> list of (connection, last_used_timestamp)
        self._idle = {}  # type: Dict[_PoolKey, List[Tuple[http.client.HTTPConnection, float]]]

    def get(self, host: str, port: int, use_ssl: bool) -> http.client.HTTPConnection:
        """Get a connection from the pool or create a new one."""
        key = (host, port, use_ssl)
        now = time.monotonic()

        with self._lock:
            conns = self._idle.get(key, [])
            while conns:
                conn, last_used = conns.pop()
                # Check if connection is still alive (not idle too long)
                if now - last_used > self._idle_timeout:
                    self._close_quiet(conn)
                    log.info("evicted idle connection to %s:%d", host, port)
                    continue
                log.debug("reusing pooled connection to %s:%d", host, port)
                return conn

        # No pooled connection available — create new one
        if use_ssl:
            conn = http.client.HTTPSConnection(
                host, port, context=self._ssl_ctx, timeout=self._timeout,
            )
        else:
            conn = http.client.HTTPConnection(
                host, port, timeout=self._timeout,
            )
        log.debug("new connection to %s:%d (ssl=%s)", host, port, use_ssl)
        return conn

    def get_fresh(self, host: str, port: int, use_ssl: bool) -> http.client.HTTPConnection:
        """Create a new connection, bypassing the pool. Used on retry after stale failure."""
        if use_ssl:
            conn = http.client.HTTPSConnection(
                host, port, context=self._ssl_ctx, timeout=self._timeout,
            )
        else:
            conn = http.client.HTTPConnection(
                host, port, timeout=self._timeout,
            )
        log.debug("fresh connection to %s:%d (ssl=%s, retry)", host, port, use_ssl)
        return conn

    def put(self, host: str, port: int, use_ssl: bool, conn: http.client.HTTPConnection) -> None:
        """Return a connection to the pool for reuse.

        Only call this for non-streaming responses where the response body
        has been fully read. Do NOT return SSE streaming connections.
        """
        key = (host, port, use_ssl)

        with self._lock:
            conns = self._idle.setdefault(key, [])
            if len(conns) >= self._pool_size:
                # Pool full — close the connection
                self._close_quiet(conn)
                return
            conns.append((conn, time.monotonic()))

    def set_timeout(self, timeout: int) -> None:
        """Update pool timeout and recycle existing connections."""
        with self._lock:
            self._timeout = timeout
        self.close_all()

    def close_all(self) -> None:
        """Close all idle connections in the pool."""
        with self._lock:
            for key, conns in self._idle.items():
                for conn, _ in conns:
                    self._close_quiet(conn)
            self._idle.clear()

    def _close_quiet(self, conn: http.client.HTTPConnection) -> None:
        """Close a connection, ignoring errors."""
        try:
            conn.close()
        except Exception:
            pass
