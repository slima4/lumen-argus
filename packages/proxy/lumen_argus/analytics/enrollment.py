"""Enrollment agents repository — tracks registered workstation agents."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from lumen_argus.analytics.base import BaseRepository

if TYPE_CHECKING:
    from lumen_argus.analytics.adapter import DatabaseAdapter

log = logging.getLogger("argus.analytics")

_GAPS_LIMIT = 500


class AgentStatus:
    """Canonical agent lifecycle status values — single source of truth for SQL."""

    ACTIVE = "active"
    DEREGISTERED = "deregistered"
    STALE = "stale"


class SeatCapExceeded(Exception):
    """Raised by EnrollmentRepository.register when seat_cap would be exceeded
    by a new machine_id. Carries .current and .cap so callers can surface them
    in an error response."""

    def __init__(self, current: int, cap: int) -> None:
        super().__init__("seat cap exceeded: %d/%d" % (current, cap))
        self.current = current
        self.cap = cap


class EnrollmentRepository(BaseRepository):
    """Repository for enrollment agent operations."""

    def __init__(self, adapter: DatabaseAdapter) -> None:
        super().__init__(adapter)

    def _count_agents_locked(self, conn: Any, status: str = "") -> int:
        # Caller must already hold write_lock. Empty status means "not deregistered".
        if status:
            row = conn.execute(
                "SELECT COUNT(*) FROM enrollment_agents WHERE status = ?",
                (status,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT COUNT(*) FROM enrollment_agents WHERE status != ?",
                (AgentStatus.DEREGISTERED,),
            ).fetchone()
        return row[0] if row else 0

    def register(
        self,
        agent_id: str,
        machine_id: str,
        hostname: str,
        os: str,
        arch: str,
        agent_version: str,
        enrolled_at: str,
        *,
        seat_cap: int | None = None,
    ) -> None:
        """Register a new agent or replace the existing enrollment for this machine.

        Re-enrolling the same machine generates a fresh agent_id (the PK), so we
        can't UPSERT — PostgreSQL refuses to update a PK referenced by
        enrollment_agent_tools.agent_id. Delete the prior row (cascades to
        agent_tools) and insert anew.

        If seat_cap is not None and the registering machine_id is not already
        on file, refuse with SeatCapExceeded when the count of active agents
        would exceed the cap. Re-enrolling an existing machine_id is always
        allowed (it replaces its own row — no net seat change). The check
        runs inside the adapter's write_lock alongside the DELETE/INSERT;
        atomicity against concurrent registrations depends on the adapter's
        lock semantics.
        """
        with self._adapter.write_lock():
            with self._connect() as conn:
                if seat_cap is not None:
                    # Re-registration of the same machine_id is a no-op for
                    # the seat count because the DELETE below removes its
                    # old row before the INSERT.
                    existing = conn.execute(
                        "SELECT 1 FROM enrollment_agents WHERE machine_id = ? AND status != ? LIMIT 1",
                        (machine_id, AgentStatus.DEREGISTERED),
                    ).fetchone()
                    if existing is None:
                        current = self._count_agents_locked(conn)
                        if current >= seat_cap:
                            raise SeatCapExceeded(current=current, cap=seat_cap)

                conn.execute(
                    "DELETE FROM enrollment_agents WHERE machine_id = ?",
                    (machine_id,),
                )
                conn.execute(
                    """INSERT INTO enrollment_agents
                    (agent_id, machine_id, hostname, os, arch, agent_version, enrolled_at, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (agent_id, machine_id, hostname, os, arch, agent_version, enrolled_at, AgentStatus.ACTIVE),
                )
        log.info("agent registered: %s (%s)", agent_id[:12], hostname)

    def deregister(self, agent_id: str) -> bool:
        """Mark an agent as deregistered. Returns True if found."""
        with self._adapter.write_lock():
            with self._connect() as conn:
                cur = conn.execute(
                    "UPDATE enrollment_agents SET status = ? WHERE agent_id = ?",
                    (AgentStatus.DEREGISTERED, agent_id),
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
        with self._adapter.write_lock():
            with self._connect() as conn:
                cur = conn.execute(
                    """UPDATE enrollment_agents SET
                        last_heartbeat = ?,
                        agent_version = ?,
                        tools_configured = ?,
                        tools_detected = ?,
                        status = ?
                    WHERE agent_id = ? AND status != ?
                    """,
                    (
                        heartbeat_at,
                        agent_version,
                        tools_configured,
                        tools_detected,
                        AgentStatus.ACTIVE,
                        agent_id,
                        AgentStatus.DEREGISTERED,
                    ),
                )
                return cur.rowcount > 0

    def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        """Get a single agent by ID."""
        with self._adapter.write_lock():
            with self._connect() as conn:
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
        with self._adapter.write_lock():
            with self._connect() as conn:
                if status:
                    rows = conn.execute(
                        "SELECT * FROM enrollment_agents WHERE status = ? ORDER BY enrolled_at DESC LIMIT ? OFFSET ?",
                        (status, limit, offset),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM enrollment_agents WHERE status != ? ORDER BY enrolled_at DESC LIMIT ? OFFSET ?",
                        (AgentStatus.DEREGISTERED, limit, offset),
                    ).fetchall()
                return [dict(r) for r in rows]

    def count_agents(self, status: str = "") -> int:
        """Count agents by status."""
        with self._adapter.write_lock():
            with self._connect() as conn:
                return self._count_agents_locked(conn, status)

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
        with self._adapter.write_lock():
            with self._connect() as conn:
                if status:
                    rows = conn.execute(
                        "SELECT * FROM enrollment_agents WHERE status = ? ORDER BY enrolled_at DESC LIMIT ? OFFSET ?",
                        (status, limit, offset),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM enrollment_agents WHERE status != ? ORDER BY enrolled_at DESC LIMIT ? OFFSET ?",
                        (AgentStatus.DEREGISTERED, limit, offset),
                    ).fetchall()
                total = self._count_agents_locked(conn, status)
                return [dict(r) for r in rows], total

    def upsert_tools(self, agent_id: str, tools: list[dict[str, Any]], updated_at: str) -> None:
        """Replace all tools for an agent from heartbeat data.

        Deletes tools no longer present (agent uninstalled) and upserts current ones.
        """
        current_ids = [t.get("client_id", "") for t in tools]
        current_ids = [cid for cid in current_ids if cid]
        with self._adapter.write_lock():
            with self._connect() as conn:
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
        with self._adapter.write_lock():
            with self._connect() as conn:
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
        with self._adapter.write_lock():
            with self._connect() as conn:
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
                        WHERE a.status != ?
                        GROUP BY client_id, display_name
                        ORDER BY installed DESC
                        """,
                        (AgentStatus.DEREGISTERED,),
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
                        AND a.status != ?
                        ORDER BY a.hostname, t.client_id
                        LIMIT ?
                        """,
                        (AgentStatus.DEREGISTERED, _GAPS_LIMIT),
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
        with self._adapter.write_lock():
            with self._connect() as conn:
                cur = conn.execute(
                    """UPDATE enrollment_agents SET status = ?
                    WHERE status = ?
                    AND last_heartbeat IS NOT NULL
                    AND last_heartbeat < ?
                    """,
                    (AgentStatus.STALE, AgentStatus.ACTIVE, stale_before),
                )
                count = cur.rowcount
        if count:
            log.info("marked %d agents as stale (heartbeat before %s)", count, stale_before)
        return count
