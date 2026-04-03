"""Database adapter abstraction — pluggable backend for analytics storage.

Community ships SQLiteAdapter (stdlib sqlite3, zero dependencies).
Pro can inject PostgresAdapter via extensions.set_database_adapter().

The adapter handles:
- Connection lifecycle (thread-local for SQLite, pooled for PostgreSQL)
- SQL dialect differences (7 syntax points)
- Schema setup (WAL/pragmas for SQLite, PL/pgSQL for PostgreSQL)
- Write locking (required for SQLite, no-op for PostgreSQL MVCC)
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from contextlib import contextmanager
from pathlib import Path
from typing import Any

log = logging.getLogger("argus.analytics")

# No-op lock for adapters that don't need write serialization (PostgreSQL MVCC).
_NOOP_LOCK = type("_NoopLock", (), {"__enter__": lambda self: self, "__exit__": lambda *a: None})()


class DatabaseAdapter(ABC):
    """Abstract database connection and dialect adapter.

    Community provides SQLiteAdapter. Pro provides PostgresAdapter.
    Repositories access connections via store._connect() and serialize
    writes via store._lock (which delegates to adapter.lock).
    """

    # --- Connection lifecycle ---

    @abstractmethod
    def connect(self) -> Any:
        """Get a database connection.

        SQLite: thread-local, reused across calls.
        PostgreSQL: from connection pool, returned after use.
        """

    @abstractmethod
    def ensure_schema(self, schema_sql: str) -> None:
        """Execute schema DDL with engine-specific setup.

        SQLite: PRAGMA WAL, PRAGMA foreign_keys, executescript.
        PostgreSQL: execute within transaction.
        """

    @abstractmethod
    def close(self) -> None:
        """Release all connections / close pool."""

    # --- Write locking ---

    @property
    def lock(self) -> Any:
        """Lock object for write serialization.

        Repositories use `with self._store._lock:` which is bound to this.
        SQLite: real threading.Lock (single-writer).
        PostgreSQL: no-op lock (MVCC handles concurrency).
        """
        return _NOOP_LOCK

    @contextmanager
    def write_lock(self) -> Any:
        """Context manager for write serialization.

        Default: no-op (PostgreSQL MVCC).
        SQLiteAdapter overrides with threading.Lock.
        """
        yield

    # --- SQL dialect ---

    @abstractmethod
    def now_sql(self) -> str:
        """SQL expression for current timestamp.

        SQLite: datetime('now')
        PostgreSQL: now()
        """

    @abstractmethod
    def date_trunc_sql(self, field: str, column: str) -> str:
        """SQL expression for date truncation.

        SQLite: DATE(column)
        PostgreSQL: date_trunc('day', column)
        """

    @abstractmethod
    def date_diff_sql(self, column: str, days: int) -> str:
        """SQL expression for 'column >= N days ago'.

        SQLite: column >= DATE('now', '-N days')
        PostgreSQL: column >= now() - interval 'N days'
        """

    @abstractmethod
    def auto_id_type(self) -> str:
        """Column type for auto-incrementing primary key.

        SQLite: INTEGER PRIMARY KEY AUTOINCREMENT
        PostgreSQL: SERIAL PRIMARY KEY
        """

    @abstractmethod
    def timestamp_type(self) -> str:
        """Column type for timestamps.

        SQLite: TEXT
        PostgreSQL: TIMESTAMPTZ
        """

    @property
    @abstractmethod
    def engine_name(self) -> str:
        """Engine identifier: 'sqlite' or 'postgresql'."""

    @property
    def supports_returning(self) -> bool:
        """Whether INSERT ... RETURNING is supported."""
        return False


class SQLiteAdapter(DatabaseAdapter):
    """SQLite adapter using stdlib sqlite3.

    Thread-local connections, WAL mode, 0o600 file permissions.
    Extracted from AnalyticsStore._connect() — same behavior, now behind
    the adapter interface so Pro can swap it for PostgresAdapter.
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = os.path.expanduser(db_path)
        self._local = threading.local()
        self._lock = threading.Lock()

    def connect(self) -> sqlite3.Connection:
        """Return a thread-local SQLite connection.

        Each thread gets its own connection, reused across method calls.
        Health check after 60s of inactivity.
        """
        conn: sqlite3.Connection | None = getattr(self._local, "conn", None)
        if conn is not None:
            now = time.monotonic()
            last_used: float = getattr(self._local, "conn_last_used", 0)
            if now - last_used > 60:
                try:
                    conn.execute("SELECT 1")
                except (sqlite3.ProgrammingError, sqlite3.OperationalError):
                    log.warning("stale SQLite connection detected, reconnecting")
                    self._local.conn = None
                    conn = None
            if conn is not None:
                self._local.conn_last_used = now
                return conn
        conn = sqlite3.connect(self._db_path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        self._local.conn = conn
        self._local.conn_last_used = time.monotonic()
        log.debug("new SQLite connection for thread %s", threading.current_thread().name)
        return conn

    def ensure_schema(self, schema_sql: str) -> None:
        """Execute schema DDL with SQLite pragmas."""
        db_dir = Path(self._db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(schema_sql)
        try:
            os.chmod(self._db_path, 0o600)
        except OSError as exc:
            log.warning("could not set DB file permissions to 0o600: %s", exc)

    def close(self) -> None:
        """Close the thread-local connection if open."""
        conn: sqlite3.Connection | None = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
                log.debug("SQLite connection closed for thread %s", threading.current_thread().name)
            except Exception as exc:
                log.warning("error closing SQLite connection: %s", exc)
            self._local.conn = None

    @property
    def lock(self) -> threading.Lock:
        """Real threading.Lock for SQLite single-writer serialization."""
        return self._lock

    @contextmanager
    def write_lock(self) -> Any:
        """Acquire threading.Lock for SQLite single-writer serialization."""
        with self._lock:
            yield

    # --- SQL dialect ---

    def now_sql(self) -> str:
        return "datetime('now')"

    def date_trunc_sql(self, field: str, column: str) -> str:
        if field == "day":
            return f"DATE({column})"
        if field == "hour":
            return f"strftime('%Y-%m-%d %H:00:00', {column})"
        return f"DATE({column})"

    def date_diff_sql(self, column: str, days: int) -> str:
        return f"{column} >= DATE('now', '-{days} days')"

    def auto_id_type(self) -> str:
        return "INTEGER PRIMARY KEY AUTOINCREMENT"

    def timestamp_type(self) -> str:
        return "TEXT"

    @property
    def engine_name(self) -> str:
        return "sqlite"

    @property
    def supports_returning(self) -> bool:
        return sqlite3.sqlite_version_info >= (3, 35, 0)
