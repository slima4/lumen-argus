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
from typing import Any, Protocol, Sequence, runtime_checkable

log = logging.getLogger("argus.analytics")

# No-op lock for adapters that don't need write serialization (PostgreSQL MVCC).
_NOOP_LOCK = type("_NoopLock", (), {"__enter__": lambda self: self, "__exit__": lambda *a: None})()


@runtime_checkable
class DBCursor(Protocol):
    """Structural type for database cursors (DB-API 2.0 subset).

    Both sqlite3.Cursor and psycopg.Cursor satisfy this protocol.
    """

    @property
    def rowcount(self) -> int: ...
    @property
    def lastrowid(self) -> int | None: ...
    @property
    def description(self) -> Any: ...
    def fetchone(self) -> Any: ...
    def fetchall(self) -> list[Any]: ...
    def __iter__(self) -> Any: ...
    def __next__(self) -> Any: ...


@runtime_checkable
class DBConnection(Protocol):
    """Structural type for database connections (DB-API 2.0 subset).

    Both sqlite3.Connection and psycopg.Connection satisfy this protocol.
    Repositories type their connection variables as DBConnection instead of
    coupling to a specific engine.
    """

    def execute(self, sql: str, parameters: Sequence[Any] = ...) -> DBCursor:
        """Execute a single SQL statement. Returns a cursor."""
        ...

    def executemany(self, sql: str, parameters: Sequence[Sequence[Any]]) -> DBCursor:
        """Execute a SQL statement with multiple parameter sets."""
        ...

    def executescript(self, sql: str) -> DBCursor:
        """Execute multiple SQL statements (SQLite-specific, used in schema setup)."""
        ...

    def commit(self) -> None:
        """Commit the current transaction."""
        ...

    def rollback(self) -> None:
        """Roll back the current transaction.

        Required by AnalyticsStore.write_transaction for exception-safe
        atomicity. Both sqlite3.Connection and psycopg.Connection
        implement this (DB-API 2.0), so the protocol just declares it.
        """
        ...

    def close(self) -> None:
        """Close the connection."""
        ...

    def __enter__(self) -> DBConnection:
        """Context manager entry (transaction begin)."""
        ...

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> Any:
        """Context manager exit (commit on success, rollback on exception)."""
        ...


class DatabaseAdapter(ABC):
    """Abstract database connection and dialect adapter.

    Community provides SQLiteAdapter. Pro provides PostgresAdapter.
    Repositories access connections via store._connect() and serialize
    writes via store._adapter.write_lock().
    """

    # --- Connection lifecycle ---

    @abstractmethod
    def connect(self) -> DBConnection:
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
    def hours_ago_sql(self, column: str, hours: int) -> str:
        """SQL expression for 'column >= N hours ago'.

        SQLite: column >= DATETIME('now', '-N hours')
        PostgreSQL: column >= now() - interval 'N hours'
        """

    @abstractmethod
    def is_today_sql(self, column: str) -> str:
        """SQL expression for 'column is today'.

        SQLite: DATE(column) = DATE('now')
        PostgreSQL: column::date = CURRENT_DATE
        """

    @abstractmethod
    def extract_weekday_sql(self, column: str) -> str:
        """SQL expression for weekday as integer (0=Sunday for SQLite, 0=Sunday for PG).

        SQLite: CAST(strftime('%w', column) AS INTEGER)
        PostgreSQL: EXTRACT(DOW FROM column)::INTEGER
        """

    @abstractmethod
    def extract_hour_sql(self, column: str) -> str:
        """SQL expression for hour as integer.

        SQLite: CAST(strftime('%H', column) AS INTEGER)
        PostgreSQL: EXTRACT(HOUR FROM column)::INTEGER
        """

    @abstractmethod
    def date_subtract_literal_sql(self, interval_param: str = "?") -> str:
        """SQL expression for date subtraction with a literal interval parameter.

        The bound value is a pre-formatted interval string like '-365 days'.
        SQLite: DATE('now', ?)
        PostgreSQL: now() + ?::interval
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

    def connect(self) -> DBConnection:
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

    def hours_ago_sql(self, column: str, hours: int) -> str:
        return f"{column} >= DATETIME('now', '-{hours} hours')"

    def is_today_sql(self, column: str) -> str:
        return f"DATE({column}) = DATE('now')"

    def extract_weekday_sql(self, column: str) -> str:
        return f"CAST(strftime('%w', {column}) AS INTEGER)"

    def extract_hour_sql(self, column: str) -> str:
        return f"CAST(strftime('%H', {column}) AS INTEGER)"

    def date_subtract_literal_sql(self, interval_param: str = "?") -> str:
        return f"DATE('now', {interval_param})"

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
