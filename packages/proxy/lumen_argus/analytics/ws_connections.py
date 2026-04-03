"""WebSocket connections repository — extracted from AnalyticsStore."""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore

log = logging.getLogger("argus.analytics")


class WebSocketConnectionsRepository:
    """Repository for WebSocket connection lifecycle operations."""

    def __init__(self, store: AnalyticsStore) -> None:
        self._store = store

    def record_open(self, connection_id: str, target_url: str, origin: str, timestamp: float) -> None:
        """Record a new WebSocket connection."""
        with self._store._adapter.write_lock():
            with self._store._connect() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO ws_connections (id, target_url, origin, connected_at) VALUES (?, ?, ?, ?)",
                    (connection_id, target_url, origin or "", timestamp),
                )
        log.debug("ws connection open: %s -> %s", connection_id[:8], target_url)

    def record_close(
        self,
        connection_id: str,
        timestamp: float,
        duration: float,
        frames_sent: int,
        frames_received: int,
        findings_count: int,
        close_code: int | None,
    ) -> None:
        """Update a WebSocket connection record on close."""
        with self._store._adapter.write_lock():
            with self._store._connect() as conn:
                conn.execute(
                    "UPDATE ws_connections SET disconnected_at = ?, duration_seconds = ?, "
                    "frames_sent = ?, frames_received = ?, findings_count = findings_count + ?, "
                    "close_code = ? WHERE id = ?",
                    (timestamp, duration, frames_sent, frames_received, findings_count, close_code, connection_id),
                )
        log.debug(
            "ws connection close: %s (%.1fs, %d/%d frames)", connection_id[:8], duration, frames_sent, frames_received
        )

    def increment_findings(self, connection_id: str, count: int) -> None:
        """Increment findings count for a WebSocket connection."""
        if count <= 0:
            return
        with self._store._adapter.write_lock():
            with self._store._connect() as conn:
                conn.execute(
                    "UPDATE ws_connections SET findings_count = findings_count + ? WHERE id = ?",
                    (count, connection_id),
                )

    def get_connections(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """Return recent WebSocket connections, newest first."""
        with self._store._connect() as conn:
            rows = conn.execute(
                "SELECT id, target_url, origin, connected_at, disconnected_at, "
                "duration_seconds, frames_sent, frames_received, findings_count, close_code "
                "FROM ws_connections ORDER BY connected_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self, days: int = 7) -> dict[str, Any]:
        """Return aggregate WebSocket stats for the given period."""
        cutoff = time.time() - (days * 86400)
        with self._store._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as total_connections, "
                "COALESCE(SUM(frames_sent), 0) as total_frames_sent, "
                "COALESCE(SUM(frames_received), 0) as total_frames_received, "
                "COALESCE(AVG(duration_seconds), 0) as avg_duration, "
                "COALESCE(SUM(findings_count), 0) as total_findings "
                "FROM ws_connections WHERE connected_at >= ?",
                (cutoff,),
            ).fetchone()
        return (
            dict(row)
            if row
            else {
                "total_connections": 0,
                "total_frames_sent": 0,
                "total_frames_received": 0,
                "avg_duration": 0,
                "total_findings": 0,
            }
        )

    def cleanup(self, retention_days: int = 365) -> int:
        """Delete WebSocket connection records older than retention_days."""
        cutoff = time.time() - (retention_days * 86400)
        with self._store._adapter.write_lock():
            with self._store._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM ws_connections WHERE connected_at < ?",
                    (cutoff,),
                )
                deleted = cursor.rowcount
        if deleted:
            log.info("ws connections cleanup: %d entries deleted (older than %d days)", deleted, retention_days)
        return deleted
