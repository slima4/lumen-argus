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

CREATE TABLE IF NOT EXISTS enrollment_agent_tools (
    agent_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    install_method TEXT NOT NULL DEFAULT '',
    proxy_configured INTEGER NOT NULL DEFAULT 0,
    routing_active INTEGER NOT NULL DEFAULT 0,
    proxy_config_type TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (agent_id, client_id),
    FOREIGN KEY (agent_id) REFERENCES enrollment_agents(agent_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_agent_tools_unconfigured
    ON enrollment_agent_tools(proxy_configured) WHERE proxy_configured = 0;
"""

_GAPS_LIMIT = 500


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
                row = conn.execute(
                    "SELECT * FROM enrollment_agents WHERE agent_id = ?",
                    (agent_id,),
                ).fetchone()
                return dict(row) if row else None

    def list_agents(
        self,
        status: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List enrolled agents with optional status filter."""
        with self._store._lock:
            with self._store._connect() as conn:
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
                return [dict(r) for r in rows]

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

    def list_and_count(
        self,
        status: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        """List agents and count total in a single lock acquisition.

        Prevents race conditions where an agent registers between
        separate list_agents() and count_agents() calls.
        """
        with self._store._lock:
            with self._store._connect() as conn:
                if status:
                    rows = conn.execute(
                        "SELECT * FROM enrollment_agents WHERE status = ? ORDER BY enrolled_at DESC LIMIT ? OFFSET ?",
                        (status, limit, offset),
                    ).fetchall()
                    count_row = conn.execute(
                        "SELECT COUNT(*) FROM enrollment_agents WHERE status = ?",
                        (status,),
                    ).fetchone()
                else:
                    rows = conn.execute(
                        "SELECT * FROM enrollment_agents WHERE status != 'deregistered' "
                        "ORDER BY enrolled_at DESC LIMIT ? OFFSET ?",
                        (limit, offset),
                    ).fetchall()
                    count_row = conn.execute(
                        "SELECT COUNT(*) FROM enrollment_agents WHERE status != 'deregistered'",
                    ).fetchone()
                total = count_row[0] if count_row else 0
                return [dict(r) for r in rows], total

    def upsert_tools(self, agent_id: str, tools: list[dict[str, Any]], updated_at: str) -> None:
        """Replace all tools for an agent from heartbeat data.

        Deletes tools no longer present (agent uninstalled) and upserts current ones.
        """
        current_ids = [t.get("client_id", "") for t in tools]
        current_ids = [cid for cid in current_ids if cid]
        with self._store._lock:
            with self._store._connect() as conn:
                if current_ids:
                    placeholders = ",".join("?" for _ in current_ids)
                    cur = conn.execute(
                        f"DELETE FROM enrollment_agent_tools WHERE agent_id = ? AND client_id NOT IN ({placeholders})",
                        [agent_id, *current_ids],
                    )
                else:
                    cur = conn.execute(
                        "DELETE FROM enrollment_agent_tools WHERE agent_id = ?",
                        (agent_id,),
                    )
                if cur.rowcount:
                    log.info(
                        "agent %s: removed %d uninstalled tool(s)",
                        agent_id[:12],
                        cur.rowcount,
                    )

                params = [
                    (
                        agent_id,
                        t.get("client_id", ""),
                        t.get("display_name", ""),
                        t.get("version", ""),
                        t.get("install_method", ""),
                        int(t.get("proxy_configured", False)),
                        int(t.get("routing_active", False)),
                        t.get("proxy_config_type", ""),
                        updated_at,
                    )
                    for t in tools
                    if t.get("client_id")
                ]
                conn.executemany(
                    """INSERT INTO enrollment_agent_tools
                    (agent_id, client_id, display_name, version, install_method,
                     proxy_configured, routing_active, proxy_config_type, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(agent_id, client_id) DO UPDATE SET
                        display_name = excluded.display_name,
                        version = excluded.version,
                        install_method = excluded.install_method,
                        proxy_configured = excluded.proxy_configured,
                        routing_active = excluded.routing_active,
                        proxy_config_type = excluded.proxy_config_type,
                        updated_at = excluded.updated_at
                    """,
                    params,
                )

        unconfigured_count = sum(1 for t in tools if not t.get("proxy_configured"))
        log.debug(
            "agent %s: upserted %d tool(s) at %s",
            agent_id[:12],
            len(params),
            updated_at,
        )
        if unconfigured_count:
            log.info(
                "agent %s: %d/%d tool(s) unconfigured",
                agent_id[:12],
                unconfigured_count,
                len(params),
            )

    def get_agent_tools(self, agent_id: str) -> list[dict[str, Any]]:
        """Get all tools for a specific agent."""
        with self._store._lock:
            with self._store._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM enrollment_agent_tools WHERE agent_id = ? ORDER BY client_id",
                    (agent_id,),
                ).fetchall()
        log.debug("agent %s: %d tool(s) found", agent_id[:12], len(rows))
        return [dict(r) for r in rows]

    def get_fleet_tools_summary(self) -> dict[str, Any]:
        """Aggregate tool status across the fleet.

        Returns per-tool install/configured/routing counts and a list of
        unconfigured tools (capped at _GAPS_LIMIT) with agent context.
        """
        with self._store._lock:
            with self._store._connect() as conn:
                by_tool = [
                    dict(r)
                    for r in conn.execute(
                        """SELECT
                            client_id,
                            display_name,
                            COUNT(*) AS installed,
                            SUM(proxy_configured) AS configured,
                            SUM(routing_active) AS routing
                        FROM enrollment_agent_tools t
                        JOIN enrollment_agents a USING(agent_id)
                        WHERE a.status != 'deregistered'
                        GROUP BY client_id
                        ORDER BY installed DESC
                        """,
                    ).fetchall()
                ]

                gaps = [
                    dict(r)
                    for r in conn.execute(
                        """SELECT
                            t.agent_id,
                            a.hostname,
                            t.client_id,
                            t.display_name,
                            t.proxy_config_type,
                            CASE WHEN t.proxy_config_type != 'unsupported' THEN 1 ELSE 0 END AS actionable
                        FROM enrollment_agent_tools t
                        JOIN enrollment_agents a USING(agent_id)
                        WHERE t.proxy_configured = 0
                        AND a.status != 'deregistered'
                        ORDER BY a.hostname, t.client_id
                        LIMIT ?
                        """,
                        (_GAPS_LIMIT,),
                    ).fetchall()
                ]

        # SQLite returns actionable as int; convert to bool for API consumers
        for gap in gaps:
            gap["actionable"] = bool(gap["actionable"])

        actionable_count = sum(1 for g in gaps if g["actionable"])
        log.debug(
            "fleet tools summary: %d tool type(s), %d gap(s) (%d actionable)",
            len(by_tool),
            len(gaps),
            actionable_count,
        )

        return {"by_tool": by_tool, "gaps": gaps}

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
