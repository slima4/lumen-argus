"""Allowlist entries repository — DB-backed allowlist patterns."""

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore

log = logging.getLogger("argus.analytics")

_ALLOWLIST_SCHEMA = """\
CREATE TABLE IF NOT EXISTS allowlist_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    list_type TEXT NOT NULL,
    pattern TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'api',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_allowlist_type ON allowlist_entries(list_type);
CREATE INDEX IF NOT EXISTS idx_allowlist_enabled ON allowlist_entries(enabled);
"""

_ALLOWLIST_COLUMNS = (
    "id, list_type, pattern, description, source, enabled, created_at, updated_at, created_by, updated_by"
)


class AllowlistRepository:
    """Repository for allowlist entry CRUD operations."""

    def __init__(self, store: AnalyticsStore) -> None:
        self._store = store

    def _row_to_dict(self, row: Any) -> dict[str, Any]:
        d = dict(row)
        d["enabled"] = bool(d.get("enabled", 1))
        return d

    def add(self, list_type: str, pattern: str, description: str = "", created_by: str = "") -> dict[str, Any]:
        """Add an allowlist entry. list_type: 'secrets', 'pii', or 'paths'."""
        if list_type not in ("secrets", "pii", "paths"):
            raise ValueError("invalid list_type: %s" % list_type)
        pattern = (pattern or "").strip()
        if not pattern:
            raise ValueError("pattern is required")
        now = self._store._now()
        with self._store._lock:
            with self._store._connect() as conn:
                cursor = conn.execute(
                    "INSERT INTO allowlist_entries "
                    "(list_type, pattern, description, source, enabled, "
                    "created_at, updated_at, created_by, updated_by) "
                    "VALUES (?, ?, ?, 'api', 1, ?, ?, ?, ?)",
                    (list_type, pattern, description, now, now, created_by, created_by),
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

    def update(self, entry_id: int, data: dict[str, Any]) -> dict[str, Any] | None:
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
            return self.get(entry_id)
        updates.append("updated_at = ?")
        params.append(self._store._now())
        if "updated_by" in data:
            updates.append("updated_by = ?")
            params.append(data["updated_by"])
        params.append(int(entry_id))
        with self._store._lock:
            with self._store._connect() as conn:
                cursor = conn.execute(
                    "UPDATE allowlist_entries SET %s WHERE id = ? AND source = 'api'" % ", ".join(updates),
                    params,
                )
                if cursor.rowcount == 0:
                    return None
        return self.get(entry_id)

    def get(self, entry_id: int) -> dict[str, Any] | None:
        """Get a single entry by ID."""
        with self._store._connect() as conn:
            row = conn.execute(
                "SELECT " + _ALLOWLIST_COLUMNS + " FROM allowlist_entries WHERE id = ?",
                (int(entry_id),),
            ).fetchone()
        if not row:
            return None
        return self._row_to_dict(row)

    def delete(self, entry_id: int) -> bool:
        """Delete an API-managed allowlist entry by ID. Returns True if deleted."""
        with self._store._lock:
            with self._store._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM allowlist_entries WHERE id = ? AND source = 'api'",
                    (int(entry_id),),
                )
                return cursor.rowcount > 0

    def list_all(self, list_type: str | None = None) -> list[dict[str, Any]]:
        """List allowlist entries, optionally filtered by type."""
        query = "SELECT " + _ALLOWLIST_COLUMNS + " FROM allowlist_entries"
        params: list[str] = []
        if list_type:
            query += " WHERE list_type = ?"
            params.append(list_type)
        query += " ORDER BY created_at DESC"
        with self._store._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def list_enabled(self, list_type: str | None = None) -> list[dict[str, Any]]:
        """List only enabled entries (for scan-time integration)."""
        query = "SELECT " + _ALLOWLIST_COLUMNS + " FROM allowlist_entries WHERE enabled = 1"
        params: list[str] = []
        if list_type:
            query += " AND list_type = ?"
            params.append(list_type)
        query += " ORDER BY created_at DESC"
        with self._store._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]
