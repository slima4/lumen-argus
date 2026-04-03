"""MCP tool lists repository — extracted from AnalyticsStore."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore

log = logging.getLogger("argus.analytics")


class MCPToolListsRepository:
    """Repository for MCP tool allow/block list operations."""

    def __init__(self, store: AnalyticsStore) -> None:
        self._store = store

    def get_lists(self) -> dict[str, list[dict[str, Any]]]:
        """Return MCP tool lists: {"allowed": [...], "blocked": [...]}."""
        log.debug("loading MCP tool lists from DB")
        with self._store._connect() as conn:
            rows = conn.execute(
                "SELECT id, list_type, tool_name, source, created_at FROM mcp_tool_lists ORDER BY id"
            ).fetchall()
        result: dict[str, list[dict[str, Any]]] = {"allowed": [], "blocked": []}
        for row in rows:
            entry = {
                "id": row["id"],
                "tool_name": row["tool_name"],
                "source": row["source"],
                "created_at": row["created_at"],
            }
            lt = row["list_type"]
            if lt in result:
                result[lt].append(entry)
        return result

    def add_entry(self, list_type: str, tool_name: str) -> int | None:
        """Add a tool to the allowed or blocked list. Returns the new entry ID."""
        if list_type not in ("allowed", "blocked"):
            raise ValueError("list_type must be 'allowed' or 'blocked'")
        if not tool_name or not tool_name.strip():
            raise ValueError("tool_name must not be empty")
        tool_name = tool_name.strip()
        now = self._store._now()
        with self._store._adapter.write_lock():
            with self._store._connect() as conn:
                cursor = conn.execute(
                    "INSERT OR IGNORE INTO mcp_tool_lists (list_type, tool_name, source, created_at) "
                    "VALUES (?, ?, 'api', ?)",
                    (list_type, tool_name, now),
                )
                entry_id = cursor.lastrowid if cursor.rowcount > 0 else None
        if entry_id:
            log.info("mcp tool list: added '%s' to %s list (id=%d)", tool_name, list_type, entry_id)
        else:
            log.debug("mcp tool list: '%s' already in %s list (ignored)", tool_name, list_type)
        return entry_id

    def delete_entry(self, entry_id: int) -> bool:
        """Remove an MCP tool list entry by ID. Returns True if deleted."""
        with self._store._adapter.write_lock():
            with self._store._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM mcp_tool_lists WHERE id = ? AND source = 'api'",
                    (entry_id,),
                )
                deleted = cursor.rowcount > 0
        if deleted:
            log.info("mcp tool list: deleted entry %d", entry_id)
        return deleted

    def reconcile(self, yaml_allowed: list[Any] | None, yaml_blocked: list[Any] | None) -> dict[str, int]:
        """Reconcile YAML tool lists with DB entries.

        YAML entries are authoritative for source='config'. API entries untouched.
        Same pattern as reconcile_yaml_channels.
        """
        now = self._store._now()
        created = 0
        deleted = 0
        with self._store._adapter.write_lock():
            with self._store._connect() as conn:
                # Get current config-sourced entries
                existing = conn.execute(
                    "SELECT id, list_type, tool_name FROM mcp_tool_lists WHERE source = 'config'"
                ).fetchall()
                existing_set = {(r["list_type"], r["tool_name"]): r["id"] for r in existing}

                # Build target set from YAML
                target: set[tuple[str, str]] = set()
                for t in yaml_allowed or []:
                    target.add(("allowed", str(t)))
                for t in yaml_blocked or []:
                    target.add(("blocked", str(t)))

                # Delete entries not in YAML
                for key, eid in existing_set.items():
                    if key not in target:
                        conn.execute("DELETE FROM mcp_tool_lists WHERE id = ?", (eid,))
                        deleted += 1

                # Create entries in YAML but not in DB
                for lt, tn in target:
                    if (lt, tn) not in existing_set:
                        conn.execute(
                            "INSERT OR IGNORE INTO mcp_tool_lists "
                            "(list_type, tool_name, source, created_at) VALUES (?, ?, 'config', ?)",
                            (lt, tn, now),
                        )
                        created += 1

        if created or deleted:
            log.info("mcp tool lists reconciled: %d created, %d deleted", created, deleted)
        return {"created": created, "deleted": deleted}
