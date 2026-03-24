"""WebSocket connections repository — extracted from AnalyticsStore."""

import logging
import time

log = logging.getLogger("argus.analytics")

_WS_CONNECTIONS_SCHEMA = """\
CREATE TABLE IF NOT EXISTS ws_connections (
    id TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    origin TEXT NOT NULL DEFAULT '',
    connected_at REAL NOT NULL,
    disconnected_at REAL,
    duration_seconds REAL,
    frames_sent INTEGER NOT NULL DEFAULT 0,
    frames_received INTEGER NOT NULL DEFAULT 0,
    findings_count INTEGER NOT NULL DEFAULT 0,
    close_code INTEGER
);
CREATE INDEX IF NOT EXISTS idx_ws_conn_at ON ws_connections(connected_at);
"""


class WebSocketConnectionsRepository:
    """Repository for WebSocket connection lifecycle operations."""

    def __init__(self, store):
        self._store = store

    def record_open(self, connection_id, target_url, origin, timestamp):
        """Record a new WebSocket connection."""
        with self._store._lock:
            with self._store._connect() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO ws_connections (id, target_url, origin, connected_at) VALUES (?, ?, ?, ?)",
                    (connection_id, target_url, origin or "", timestamp),
                )
        log.debug("ws connection open: %s -> %s", connection_id[:8], target_url)

    def record_close(
        self, connection_id, timestamp, duration, frames_sent, frames_received, findings_count, close_code
    ):
        """Update a WebSocket connection record on close."""
        with self._store._lock:
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

    def increment_findings(self, connection_id, count):
        """Increment findings count for a WebSocket connection."""
        if count <= 0:
            return
        with self._store._lock:
            with self._store._connect() as conn:
                conn.execute(
                    "UPDATE ws_connections SET findings_count = findings_count + ? WHERE id = ?",
                    (count, connection_id),
                )

    def get_connections(self, limit=50, offset=0):
        """Return recent WebSocket connections, newest first."""
        with self._store._connect() as conn:
            rows = conn.execute(
                "SELECT id, target_url, origin, connected_at, disconnected_at, "
                "duration_seconds, frames_sent, frames_received, findings_count, close_code "
                "FROM ws_connections ORDER BY connected_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self, days=7):
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

    def cleanup(self, retention_days=365):
        """Delete WebSocket connection records older than retention_days."""
        cutoff = time.time() - (retention_days * 86400)
        with self._store._lock:
            with self._store._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM ws_connections WHERE connected_at < ?",
                    (cutoff,),
                )
                deleted = cursor.rowcount
        if deleted:
            log.info("ws connections cleanup: %d entries deleted (older than %d days)", deleted, retention_days)
        return deleted
