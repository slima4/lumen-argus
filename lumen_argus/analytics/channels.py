"""Notification channels repository — extracted from AnalyticsStore."""

import json
import logging
import sqlite3
from typing import TYPE_CHECKING, Any

from lumen_argus.analytics._db import scalar

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore

log = logging.getLogger("argus.analytics")

_NOTIFICATION_SCHEMA = """\
CREATE TABLE IF NOT EXISTS notification_channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    config TEXT NOT NULL DEFAULT '{}',
    enabled INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL DEFAULT 'dashboard',
    events TEXT NOT NULL DEFAULT '["block","alert"]',
    min_severity TEXT NOT NULL DEFAULT 'warning',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT ''
);
"""

_CHANNEL_COLUMNS = (
    "id, name, type, config, enabled, source, events, min_severity, created_at, updated_at, created_by, updated_by"
)


class ChannelsRepository:
    """Repository for notification channel CRUD operations."""

    def __init__(self, store: AnalyticsStore) -> None:
        self._store = store

    def _parse_row(self, row: sqlite3.Row) -> dict[str, Any]:
        """Convert a DB row to a dict with parsed JSON fields."""
        d = dict(row)
        for key in ("config", "events"):
            if key in d and isinstance(d[key], str):
                try:
                    d[key] = json.loads(d[key])
                except (json.JSONDecodeError, ValueError):
                    d[key] = {} if key == "config" else []
        d["enabled"] = bool(d.get("enabled", 1))
        return d

    def list_all(self, source: str | None = None) -> list[dict[str, Any]]:
        """Return all channels, optionally filtered by source."""
        query = (
            "SELECT "
            + _CHANNEL_COLUMNS
            + " FROM notification_channels"
            + (" WHERE source = ?" if source else "")
            + " ORDER BY id"
        )
        params: list[str | None] = [source] if source else []
        with self._store._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._parse_row(r) for r in rows]

    def get(self, channel_id: int) -> dict[str, Any] | None:
        """Return a single channel by ID (with full config)."""
        with self._store._connect() as conn:
            row = conn.execute(
                "SELECT " + _CHANNEL_COLUMNS + " FROM notification_channels WHERE id = ?",
                (channel_id,),
            ).fetchone()
        return self._parse_row(row) if row else None

    def count(self) -> int:
        """Return total channel count (for limit enforcement)."""
        with self._store._connect() as conn:
            return scalar(conn, "SELECT COUNT(*) FROM notification_channels")

    def create(
        self,
        data: dict[str, Any],
        channel_limit: int | None = None,
    ) -> dict[str, Any] | None:
        """Create a channel. Raises ValueError on validation failure.

        channel_limit: if set, count check + insert runs under the same
        lock to prevent race conditions on concurrent creates.
        """
        name = data.get("name", "").strip()
        if not name:
            raise ValueError("name is required")
        ch_type = data.get("type", "").strip()
        if not ch_type:
            raise ValueError("type is required")

        config = data.get("config", {})
        if isinstance(config, str):
            config = json.loads(config)
        events = data.get("events", ["block", "alert"])
        if isinstance(events, str):
            events = json.loads(events)

        now = self._store._now()
        with self._store._lock:
            with self._store._connect() as conn:
                # Atomic limit check under the same lock as insert
                if channel_limit is not None:
                    current = scalar(conn, "SELECT COUNT(*) FROM notification_channels")
                    if current >= channel_limit:
                        raise ValueError("channel_limit_reached")
                created_by = data.get("created_by", "")
                try:
                    conn.execute(
                        "INSERT INTO notification_channels "
                        "(name, type, config, enabled, source, events, "
                        "min_severity, created_at, updated_at, created_by, updated_by) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            name,
                            ch_type,
                            json.dumps(config),
                            1 if data.get("enabled", True) else 0,
                            data.get("source", "dashboard"),
                            json.dumps(events),
                            data.get("min_severity", "warning"),
                            now,
                            now,
                            created_by,
                            created_by,
                        ),
                    )
                    channel_id: Any = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                except sqlite3.IntegrityError:
                    raise ValueError("channel name '%s' already exists" % name)

        return self.get(channel_id)

    def update(self, channel_id: int, data: dict[str, Any]) -> dict[str, Any] | None:
        """Update channel fields. Only updates provided keys."""
        updates: list[str] = []
        params: list[Any] = []
        for key in ("name", "type", "min_severity", "source"):
            if key in data:
                updates.append("%s = ?" % key)
                params.append(data[key])
        if "enabled" in data:
            updates.append("enabled = ?")
            params.append(1 if data["enabled"] else 0)
        if "config" in data:
            config = data["config"]
            if isinstance(config, str):
                config = json.loads(config)
            updates.append("config = ?")
            params.append(json.dumps(config))
        if "events" in data:
            events = data["events"]
            if isinstance(events, str):
                events = json.loads(events)
            updates.append("events = ?")
            params.append(json.dumps(events))

        if not updates:
            return self.get(channel_id)

        updates.append("updated_at = ?")
        params.append(self._store._now())
        if "updated_by" in data:
            updates.append("updated_by = ?")
            params.append(data["updated_by"])
        params.append(channel_id)

        with self._store._lock:
            with self._store._connect() as conn:
                try:
                    cursor = conn.execute(
                        "UPDATE notification_channels SET %s WHERE id = ?" % ", ".join(updates),
                        params,
                    )
                except sqlite3.IntegrityError:
                    raise ValueError("channel name '%s' already exists" % data.get("name", ""))
                if cursor.rowcount == 0:
                    return None

        return self.get(channel_id)

    def delete(self, channel_id: int) -> bool:
        """Delete a channel by ID. Returns True if deleted."""
        with self._store._lock:
            with self._store._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM notification_channels WHERE id = ?",
                    (channel_id,),
                )
                return cursor.rowcount > 0

    def bulk_update(self, ids: list[int], action: str) -> int:
        """Bulk enable/disable/delete. Returns count affected."""
        if not ids:
            return 0
        placeholders = ",".join("?" for _ in ids)
        with self._store._lock:
            with self._store._connect() as conn:
                if action == "delete":
                    # Only delete dashboard-managed channels
                    cursor = conn.execute(
                        "DELETE FROM notification_channels WHERE id IN (%s) AND source = 'dashboard'" % placeholders,
                        ids,
                    )
                elif action in ("enable", "disable"):
                    enabled = 1 if action == "enable" else 0
                    cursor = conn.execute(
                        "UPDATE notification_channels SET enabled = ?, updated_at = ? WHERE id IN (%s)" % placeholders,
                        [enabled, self._store._now(), *ids],
                    )
                else:
                    return 0
                return cursor.rowcount

    def reconcile_yaml(
        self,
        yaml_channels: list[Any],
        channel_limit: int | None = None,
    ) -> dict[str, list[str]]:
        """Kubernetes-style declarative reconciliation of YAML channels.

        YAML is fully authoritative for source='yaml' channels: all fields
        (including enabled) overwrite DB values on every reconcile.

        channel_limit: max total channels (None = unlimited). Only blocks
        new creates — existing YAML channels are always updated.
        """
        result: dict[str, list[str]] = {"created": [], "updated": [], "deleted": []}

        # Build lookup of YAML channels by name
        yaml_by_name: dict[str, Any] = {}
        for ch in yaml_channels:
            if not isinstance(ch, dict):
                continue
            name = ch.get("name", "")
            if name:
                yaml_by_name[name] = ch

        # Get current DB state
        db_yaml = {ch["name"]: ch for ch in self.list_all(source="yaml")}
        db_dashboard_names = {ch["name"] for ch in self.list_all(source="dashboard")}
        current_total = self.count()

        # Delete YAML channels no longer in config
        for name, db_ch in db_yaml.items():
            if name not in yaml_by_name:
                self.delete(db_ch["id"])
                current_total -= 1
                result["deleted"].append(name)

        # Create or update YAML channels
        for name, yaml_ch in yaml_by_name.items():
            # Skip if name collides with a dashboard-managed channel
            if name in db_dashboard_names:
                log.warning(
                    "notification channel '%s' in config conflicts with dashboard-managed channel — skipping",
                    name,
                )
                continue

            ch_type = yaml_ch.get("type", "")
            # Build config from all keys except top-level ones
            _top_keys = {"name", "type", "events", "min_severity", "enabled"}
            config = {k: v for k, v in yaml_ch.items() if k not in _top_keys}
            # Normalize to_addrs: comma-separated string → list
            if "to_addrs" in config and isinstance(config["to_addrs"], str):
                config["to_addrs"] = [a.strip() for a in config["to_addrs"].split(",") if a.strip()]

            channel_data = {
                "name": name,
                "type": ch_type,
                "config": config,
                "source": "yaml",
                "events": yaml_ch.get("events", ["block", "alert"]),
                "min_severity": yaml_ch.get("min_severity", "warning"),
                "enabled": yaml_ch.get("enabled", True),
                "created_by": "config",
                "updated_by": "config",
            }

            if name in db_yaml:
                # Update existing — always allowed (already counts toward limit)
                self.update(db_yaml[name]["id"], channel_data)
                result["updated"].append(name)
            else:
                # New create — check limit
                if channel_limit is not None and current_total >= channel_limit:
                    log.warning(
                        "notification channel '%s' skipped — channel limit reached (%d)",
                        name,
                        channel_limit,
                    )
                    continue
                self.create(channel_data)
                current_total += 1
                result["created"].append(name)

        return result
