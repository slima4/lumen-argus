"""Enrollment agents repository — tracks registered workstation agents."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore

log = logging.getLogger("argus.analytics")

_ENROLLMENT_SCHEMA = """\
CREATE TABLE IF NOT EXISTS enrollment_agents (
    agent_id TEXT PRIMARY KEY,
    machine_id TEXT NOT NULL,
    hostname TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL DEFAULT '',
    arch TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    enrolled_at TEXT NOT NULL,
    last_heartbeat TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    tools_configured INTEGER NOT NULL DEFAULT 0,
    tools_detected INTEGER NOT NULL DEFAULT 0,
    UNIQUE(machine_id)
);
CREATE INDEX IF NOT EXISTS idx_enrollment_status ON enrollment_agents(status);
"""


class EnrollmentRepository:
    """Repository for enrollment agent operations."""

    def __init__(self, store: AnalyticsStore) -> None:
        self._store = store

    def register(
        self,
        agent_id: str,
        machine_id: str,
        hostname: str,
        os: str,
        arch: str,
        agent_version: str,
        enrolled_at: str,
    ) -> None:
        """Register a new agent or update an existing one."""
        with self._store._lock:
            with self._store._connect() as conn:
                conn.execute(
                    """INSERT INTO enrollment_agents
                    (agent_id, machine_id, hostname, os, arch, agent_version, enrolled_at, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
                    ON CONFLICT(machine_id) DO UPDATE SET
                        agent_id = excluded.agent_id,
                        hostname = excluded.hostname,
                        os = excluded.os,
                        arch = excluded.arch,
                        agent_version = excluded.agent_version,
                        enrolled_at = excluded.enrolled_at,
                        status = 'active'
                    """,
                    (agent_id, machine_id, hostname, os, arch, agent_version, enrolled_at),
                )
        log.info("agent registered: %s (%s)", agent_id[:12], hostname)

    def deregister(self, agent_id: str) -> bool:
        """Mark an agent as deregistered. Returns True if found."""
        with self._store._lock:
            with self._store._connect() as conn:
                cur = conn.execute(
                    "UPDATE enrollment_agents SET status = 'deregistered' WHERE agent_id = ?",
                    (agent_id,),
                )
                found = cur.rowcount > 0
        if found:
            log.info("agent deregistered: %s", agent_id[:12])
        return found

    def heartbeat(
        self,
        agent_id: str,
        agent_version: str,
        tools_configured: int,
        tools_detected: int,
        heartbeat_at: str,
    ) -> bool:
        """Update agent heartbeat. Returns True if agent exists."""
        with self._store._lock:
            with self._store._connect() as conn:
                cur = conn.execute(
                    """UPDATE enrollment_agents SET
                        last_heartbeat = ?,
                        agent_version = ?,
                        tools_configured = ?,
                        tools_detected = ?,
                        status = 'active'
                    WHERE agent_id = ? AND status != 'deregistered'
                    """,
                    (heartbeat_at, agent_version, tools_configured, tools_detected, agent_id),
                )
                return cur.rowcount > 0

    def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        """Get a single agent by ID."""
        with self._store._lock:
            with self._store._connect() as conn:
                conn.row_factory = _dict_factory
                row = conn.execute(
                    "SELECT * FROM enrollment_agents WHERE agent_id = ?",
                    (agent_id,),
                ).fetchone()
                result: dict[str, Any] | None = row
                return result

    def list_agents(
        self,
        status: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List enrolled agents with optional status filter."""
        with self._store._lock:
            with self._store._connect() as conn:
                conn.row_factory = _dict_factory
                if status:
                    rows = conn.execute(
                        "SELECT * FROM enrollment_agents WHERE status = ? ORDER BY enrolled_at DESC LIMIT ? OFFSET ?",
                        (status, limit, offset),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM enrollment_agents WHERE status != 'deregistered' "
                        "ORDER BY enrolled_at DESC LIMIT ? OFFSET ?",
                        (limit, offset),
                    ).fetchall()
                return rows

    def count_agents(self, status: str = "") -> int:
        """Count agents by status."""
        with self._store._lock:
            with self._store._connect() as conn:
                if status:
                    row = conn.execute(
                        "SELECT COUNT(*) FROM enrollment_agents WHERE status = ?",
                        (status,),
                    ).fetchone()
                else:
                    row = conn.execute(
                        "SELECT COUNT(*) FROM enrollment_agents WHERE status != 'deregistered'",
                    ).fetchone()
                return row[0] if row else 0

    def mark_stale(self, stale_before: str) -> int:
        """Mark agents as stale if last heartbeat is before the given timestamp.

        Returns the number of agents marked stale.
        """
        with self._store._lock:
            with self._store._connect() as conn:
                cur = conn.execute(
                    """UPDATE enrollment_agents SET status = 'stale'
                    WHERE status = 'active'
                    AND last_heartbeat IS NOT NULL
                    AND last_heartbeat < ?
                    """,
                    (stale_before,),
                )
                count = cur.rowcount
        if count:
            log.info("marked %d agents as stale (heartbeat before %s)", count, stale_before)
        return count


def _dict_factory(cursor: Any, row: Any) -> dict[str, Any]:
    """SQLite row factory that returns dicts."""
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}
