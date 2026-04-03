"""Notification channels repository — extracted from AnalyticsStore."""

from __future__ import annotations

import json
import logging
import sqlite3
from typing import TYPE_CHECKING, Any

from lumen_argus.analytics._db import scalar
from lumen_argus.analytics.base import BaseRepository

if TYPE_CHECKING:
    from lumen_argus.analytics.adapter import DatabaseAdapter

log = logging.getLogger("argus.analytics")

_CHANNEL_COLUMNS = (
    "id, name, type, config, enabled, source, events, min_severity, created_at, updated_at, created_by, updated_by"
)


class ChannelsRepository(BaseRepository):
    """Repository for notification channel CRUD operations."""

    def __init__(self, adapter: DatabaseAdapter) -> None:
        super().__init__(adapter)

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

    def list_all(self, source: str | None = None, namespace_id: int = 1) -> list[dict[str, Any]]:
        """Return all channels, optionally filtered by source."""
        conditions = ["namespace_id = ?"]
        params: list[Any] = [namespace_id]
        if source:
            conditions.append("source = ?")
            params.append(source)
        query = (
            "SELECT "
            + _CHANNEL_COLUMNS
            + " FROM notification_channels WHERE "
            + " AND ".join(conditions)
            + " ORDER BY id"
        )
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._parse_row(r) for r in rows]

    def get(self, channel_id: int, namespace_id: int = 1) -> dict[str, Any] | None:
        """Return a single channel by ID (with full config)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT " + _CHANNEL_COLUMNS + " FROM notification_channels WHERE id = ? AND namespace_id = ?",
                (channel_id, namespace_id),
            ).fetchone()
        return self._parse_row(row) if row else None

    def count(self, namespace_id: int = 1) -> int:
        """Return total channel count (for limit enforcement)."""
        with self._connect() as conn:
            return scalar(conn, "SELECT COUNT(*) FROM notification_channels WHERE namespace_id = ?", (namespace_id,))

    def create(
        self,
        data: dict[str, Any],
        channel_limit: int | None = None,
        namespace_id: int = 1,
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

        now = self._now()
        with self._adapter.write_lock():
            with self._connect() as conn:
                # Atomic limit check under the same lock as insert
                if channel_limit is not None:
                    current = scalar(
                        conn,
                        "SELECT COUNT(*) FROM notification_channels WHERE namespace_id = ?",
                        (namespace_id,),
                    )
                    if current >= channel_limit:
                        raise ValueError("channel_limit_reached")
                created_by = data.get("created_by", "")
                try:
                    conn.execute(
                        "INSERT INTO notification_channels "
                        "(namespace_id, name, type, config, enabled, source, events, "
                        "min_severity, created_at, updated_at, created_by, updated_by) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            namespace_id,
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

        return self.get(channel_id, namespace_id=namespace_id)

    def update(self, channel_id: int, data: dict[str, Any], namespace_id: int = 1) -> dict[str, Any] | None:
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
            return self.get(channel_id, namespace_id=namespace_id)

        updates.append("updated_at = ?")
        params.append(self._now())
        if "updated_by" in data:
            updates.append("updated_by = ?")
            params.append(data["updated_by"])
        params.extend([channel_id, namespace_id])

        with self._adapter.write_lock():
            with self._connect() as conn:
                try:
                    cursor = conn.execute(
                        "UPDATE notification_channels SET %s WHERE id = ? AND namespace_id = ?" % ", ".join(updates),
                        params,
                    )
                except sqlite3.IntegrityError:
                    raise ValueError("channel name '%s' already exists" % data.get("name", ""))
                if cursor.rowcount == 0:
                    return None

        return self.get(channel_id, namespace_id=namespace_id)

    def delete(self, channel_id: int, namespace_id: int = 1) -> bool:
        """Delete a channel by ID. Returns True if deleted."""
        with self._adapter.write_lock():
            with self._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM notification_channels WHERE id = ? AND namespace_id = ?",
                    (channel_id, namespace_id),
                )
                return cursor.rowcount > 0

    def bulk_update(self, ids: list[int], action: str, namespace_id: int = 1) -> int:
        """Bulk enable/disable/delete. Returns count affected."""
        if not ids:
            return 0
        placeholders = ",".join("?" for _ in ids)
        with self._adapter.write_lock():
            with self._connect() as conn:
                if action == "delete":
                    cursor = conn.execute(
                        "DELETE FROM notification_channels "
                        "WHERE id IN (%s) AND namespace_id = ? AND source = 'dashboard'" % placeholders,
                        [*ids, namespace_id],
                    )
                elif action in ("enable", "disable"):
                    enabled = 1 if action == "enable" else 0
                    cursor = conn.execute(
                        "UPDATE notification_channels SET enabled = ?, updated_at = ? "
                        "WHERE id IN (%s) AND namespace_id = ?" % placeholders,
                        [enabled, self._now(), *ids, namespace_id],
                    )
                else:
                    return 0
                return cursor.rowcount

    def reconcile_yaml(
        self,
        yaml_channels: list[Any],
        channel_limit: int | None = None,
        namespace_id: int = 1,
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
        db_yaml = {ch["name"]: ch for ch in self.list_all(source="yaml", namespace_id=namespace_id)}
        db_dashboard_names = {ch["name"] for ch in self.list_all(source="dashboard", namespace_id=namespace_id)}
        current_total = self.count(namespace_id=namespace_id)

        # Delete YAML channels no longer in config
        for name, db_ch in db_yaml.items():
            if name not in yaml_by_name:
                self.delete(db_ch["id"], namespace_id=namespace_id)
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
                self.update(db_yaml[name]["id"], channel_data, namespace_id=namespace_id)
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
                self.create(channel_data, namespace_id=namespace_id)
                current_total += 1
                result["created"].append(name)

        return result
