"""SQLite-backed analytics store for community dashboard.

Stores summarized finding data (no raw secrets/PII values) with
aggregation queries for dashboard charts. Includes scheduled cleanup
for retention enforcement.

sqlite3 is Python stdlib — zero external dependencies.
"""

import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from lumen_argus.models import Finding

log = logging.getLogger("argus.analytics")

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    detector TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    location TEXT NOT NULL,
    action_taken TEXT NOT NULL DEFAULT '',
    provider TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    value_preview TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TEXT NOT NULL
);
"""

_COMMUNITY_SCHEMA_VERSION = 1


class AnalyticsStore:
    """Thread-safe SQLite store for finding history and trend queries.

    Uses thread-local connection pooling — one connection per thread,
    reused across method calls. WAL mode allows concurrent readers.
    Write serialization: single Lock wraps all writes; reads don't acquire it.
    """

    def __init__(self, db_path: str = "~/.lumen-argus/analytics.db"):
        self._db_path = os.path.expanduser(db_path)
        self._lock = threading.Lock()
        self._local = threading.local()
        self._ensure_db()

    def _ensure_db(self) -> None:
        """Create the database and schema if they don't exist."""
        db_dir = Path(self._db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
        new_db = not os.path.exists(self._db_path)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            # Record schema version if not present
            existing = conn.execute(
                "SELECT version FROM schema_version WHERE version = ?",
                (_COMMUNITY_SCHEMA_VERSION,),
            ).fetchone()
            if not existing:
                now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                conn.execute(
                    "INSERT INTO schema_version (version, description, applied_at) "
                    "VALUES (?, ?, ?)",
                    (_COMMUNITY_SCHEMA_VERSION, "community findings table", now),
                )
        # Secure file permissions — same 0o600 as audit JSONL files
        try:
            os.chmod(self._db_path, 0o600)
        except OSError:
            pass

    def _connect(self) -> sqlite3.Connection:
        """Return a thread-local SQLite connection.

        Each thread gets its own connection, reused across method calls.
        Health check after 60s of inactivity.
        """
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            now = time.monotonic()
            last_used = getattr(self._local, "conn_last_used", 0)
            if now - last_used > 60:
                try:
                    conn.execute("SELECT 1")
                except (sqlite3.ProgrammingError, sqlite3.OperationalError):
                    self._local.conn = None
                    conn = None
            if conn is not None:
                self._local.conn_last_used = now
                return conn
        conn = sqlite3.connect(self._db_path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        self._local.conn = conn
        self._local.conn_last_used = time.monotonic()
        return conn

    def record_findings(
        self,
        findings: List[Finding],
        provider: str = "",
        model: str = "",
    ) -> None:
        """Insert findings into the store. Thread-safe.

        Only stores summarized data — matched_value is never persisted.
        """
        if not findings:
            return

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        rows = [
            (now, f.detector, f.type, f.severity, f.location,
             f.action, provider, model, f.value_preview)
            for f in findings
        ]

        with self._lock:
            with self._connect() as conn:
                conn.executemany(
                    "INSERT INTO findings "
                    "(timestamp, detector, finding_type, severity, location, "
                    "action_taken, provider, model, value_preview) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    rows,
                )

    def get_findings_page(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: Optional[str] = None,
        detector: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> tuple:
        """Return (findings_list, total_count) for consistency."""
        where = ""
        conditions = []
        params = []  # type: list
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if detector:
            conditions.append("detector = ?")
            params.append(detector)
        if provider:
            conditions.append("provider = ?")
            params.append(provider)
        if conditions:
            where = " WHERE " + " AND ".join(conditions)

        with self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM findings" + where, params,
            ).fetchone()[0]
            rows = conn.execute(
                "SELECT id, timestamp, detector, finding_type, severity, "
                "location, action_taken, provider, model, value_preview "
                "FROM findings" + where +
                " ORDER BY id DESC LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()
        return [dict(r) for r in rows], total

    def get_finding_by_id(self, finding_id: int) -> Optional[dict]:
        """Return a single finding by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, timestamp, detector, finding_type, severity, "
                "location, action_taken, provider, model, value_preview "
                "FROM findings WHERE id = ?",
                (finding_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_stats(self) -> dict:
        """Return aggregate statistics for the dashboard."""
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]

            by_severity = {}
            for row in conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"
            ):
                by_severity[row["severity"]] = row["cnt"]

            by_detector = {}
            for row in conn.execute(
                "SELECT detector, COUNT(*) as cnt FROM findings GROUP BY detector"
            ):
                by_detector[row["detector"]] = row["cnt"]

            top_types = {}
            for row in conn.execute(
                "SELECT finding_type, COUNT(*) as cnt FROM findings "
                "GROUP BY finding_type ORDER BY cnt DESC LIMIT 20"
            ):
                top_types[row["finding_type"]] = row["cnt"]

            by_action = {}
            for row in conn.execute(
                "SELECT action_taken, COUNT(*) as cnt FROM findings "
                "GROUP BY action_taken"
            ):
                by_action[row["action_taken"]] = row["cnt"]

            by_provider = {}
            for row in conn.execute(
                "SELECT provider, COUNT(*) as cnt FROM findings GROUP BY provider"
            ):
                by_provider[row["provider"] or "unknown"] = row["cnt"]

            by_model = {}
            for row in conn.execute(
                "SELECT model, COUNT(*) as cnt FROM findings "
                "GROUP BY model ORDER BY cnt DESC LIMIT 20"
            ):
                by_model[row["model"] or "unknown"] = row["cnt"]

            # Findings per day (last 30 days)
            daily = []
            for row in conn.execute(
                "SELECT DATE(timestamp) as day, COUNT(*) as cnt "
                "FROM findings "
                "WHERE timestamp >= DATE('now', '-30 days') "
                "GROUP BY day ORDER BY day"
            ):
                daily.append({"date": row["day"], "count": row["cnt"]})

        return {
            "total_findings": total,
            "by_severity": by_severity,
            "by_detector": by_detector,
            "top_finding_types": top_types,
            "by_action": by_action,
            "by_provider": by_provider,
            "by_model": by_model,
            "daily_trend": daily,
        }

    def get_total_count(
        self,
        severity: Optional[str] = None,
        detector: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> int:
        """Return total number of findings, optionally filtered."""
        query = "SELECT COUNT(*) FROM findings"
        conditions = []
        params = []  # type: list
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if detector:
            conditions.append("detector = ?")
            params.append(detector)
        if provider:
            conditions.append("provider = ?")
            params.append(provider)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        with self._connect() as conn:
            return conn.execute(query, params).fetchone()[0]

    def cleanup(self, retention_days: int = 365) -> int:
        """Delete findings older than retention_days. Returns count deleted."""
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM findings WHERE timestamp < DATE('now', ?)",
                    ("-%d days" % retention_days,),
                )
                deleted = cursor.rowcount
        if deleted:
            log.info("analytics cleanup: deleted %d findings older than %d days",
                     deleted, retention_days)
        return deleted

    def start_cleanup_scheduler(self, retention_days: int = 365) -> None:
        """Start a background thread that runs cleanup daily."""
        def _cleanup_loop():
            while True:
                time.sleep(86400)  # 24 hours
                try:
                    self.cleanup(retention_days)
                except Exception as e:
                    log.error("analytics cleanup failed: %s", e)

        t = threading.Thread(target=_cleanup_loop, daemon=True, name="analytics-cleanup")
        t.start()
