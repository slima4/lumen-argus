"""Allowlist entries repository — DB-backed allowlist patterns."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from lumen_argus.analytics.base import BaseRepository

if TYPE_CHECKING:
    from lumen_argus.analytics.adapter import DatabaseAdapter

log = logging.getLogger("argus.analytics")

_ALLOWLIST_COLUMNS = (
    "id, list_type, pattern, description, source, enabled, created_at, updated_at, created_by, updated_by"
)


class AllowlistRepository(BaseRepository):
    """Repository for allowlist entry CRUD operations."""

    def __init__(self, adapter: DatabaseAdapter) -> None:
        super().__init__(adapter)

    def _row_to_dict(self, row: Any) -> dict[str, Any]:
        d = dict(row)
        d["enabled"] = bool(d.get("enabled", 1))
        return d

    def add(
        self, list_type: str, pattern: str, description: str = "", created_by: str = "", namespace_id: int = 1
    ) -> dict[str, Any]:
        """Add an allowlist entry. list_type: 'secrets', 'pii', or 'paths'."""
        if list_type not in ("secrets", "pii", "paths"):
            raise ValueError("invalid list_type: %s" % list_type)
        pattern = (pattern or "").strip()
        if not pattern:
            raise ValueError("pattern is required")
        now = self._now()
        with self._adapter.write_lock():
            with self._connect() as conn:
                cursor = conn.execute(
                    "INSERT INTO allowlist_entries "
                    "(namespace_id, list_type, pattern, description, source, enabled, "
                    "created_at, updated_at, created_by, updated_by) "
                    "VALUES (?, ?, ?, ?, 'api', 1, ?, ?, ?, ?)",
                    (namespace_id, list_type, pattern, description, now, now, created_by, created_by),
                )
                entry_id = cursor.lastrowid
        return {
            "id": entry_id,
            "list_type": list_type,
            "pattern": pattern,
            "description": description,
            "source": "api",
            "enabled": True,
            "created_at": now,
            "updated_at": now,
            "created_by": created_by,
            "updated_by": created_by,
        }

    def update(self, entry_id: int, data: dict[str, Any], namespace_id: int = 1) -> dict[str, Any] | None:
        """Update an API-managed allowlist entry. Returns updated entry or None."""
        updates: list[str] = []
        params: list[Any] = []
        for key in ("pattern", "description", "list_type"):
            if key in data:
                updates.append("%s = ?" % key)
                params.append(data[key])
        if "enabled" in data:
            updates.append("enabled = ?")
            params.append(1 if data["enabled"] else 0)
        if not updates:
            return self.get(entry_id, namespace_id=namespace_id)
        updates.append("updated_at = ?")
        params.append(self._now())
        if "updated_by" in data:
            updates.append("updated_by = ?")
            params.append(data["updated_by"])
        params.extend([int(entry_id), namespace_id])
        with self._adapter.write_lock():
            with self._connect() as conn:
                cursor = conn.execute(
                    "UPDATE allowlist_entries SET %s WHERE id = ? AND namespace_id = ? AND source = 'api'"
                    % ", ".join(updates),
                    params,
                )
                if cursor.rowcount == 0:
                    return None
        return self.get(entry_id, namespace_id=namespace_id)

    def get(self, entry_id: int, namespace_id: int = 1) -> dict[str, Any] | None:
        """Get a single entry by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT " + _ALLOWLIST_COLUMNS + " FROM allowlist_entries WHERE id = ? AND namespace_id = ?",
                (int(entry_id), namespace_id),
            ).fetchone()
        if not row:
            return None
        return self._row_to_dict(row)

    def delete(self, entry_id: int, namespace_id: int = 1) -> bool:
        """Delete an API-managed allowlist entry by ID. Returns True if deleted."""
        with self._adapter.write_lock():
            with self._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM allowlist_entries WHERE id = ? AND namespace_id = ? AND source = 'api'",
                    (int(entry_id), namespace_id),
                )
                return cursor.rowcount > 0

    def list_all(self, list_type: str | None = None, namespace_id: int = 1) -> list[dict[str, Any]]:
        """List allowlist entries, optionally filtered by type."""
        query = "SELECT " + _ALLOWLIST_COLUMNS + " FROM allowlist_entries WHERE namespace_id = ?"
        params: list[Any] = [namespace_id]
        if list_type:
            query += " AND list_type = ?"
            params.append(list_type)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def list_enabled(self, list_type: str | None = None, namespace_id: int = 1) -> list[dict[str, Any]]:
        """List only enabled entries (for scan-time integration)."""
        query = "SELECT " + _ALLOWLIST_COLUMNS + " FROM allowlist_entries WHERE enabled = 1 AND namespace_id = ?"
        params: list[Any] = [namespace_id]
        if list_type:
            query += " AND list_type = ?"
            params.append(list_type)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]
