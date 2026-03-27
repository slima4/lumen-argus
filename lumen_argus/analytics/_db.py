"""Shared SQLite utilities for analytics repositories."""

import sqlite3


def scalar(conn: sqlite3.Connection, sql: str, params: tuple[object, ...] = ()) -> int:
    """Execute a query expected to return a single integer value (e.g. COUNT(*)).

    Returns 0 if the query returns no rows or a NULL value.
    """
    row = conn.execute(sql, params).fetchone()
    return int(row[0]) if row and row[0] is not None else 0
