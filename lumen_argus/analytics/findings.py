"""Findings repository — extracted from AnalyticsStore."""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import logging
from typing import TYPE_CHECKING, Any

from lumen_argus_core.time_utils import now_iso_ms

from lumen_argus.analytics._db import scalar
from lumen_argus.models import Finding, SessionContext

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore

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
    value_preview TEXT NOT NULL DEFAULT '',
    account_id TEXT NOT NULL DEFAULT '',
    session_id TEXT NOT NULL DEFAULT '',
    device_id TEXT NOT NULL DEFAULT '',
    source_ip TEXT NOT NULL DEFAULT '',
    working_directory TEXT NOT NULL DEFAULT '',
    git_branch TEXT NOT NULL DEFAULT '',
    os_platform TEXT NOT NULL DEFAULT '',
    client_name TEXT NOT NULL DEFAULT '',
    client_version TEXT NOT NULL DEFAULT '',
    api_key_hash TEXT NOT NULL DEFAULT '',
    content_hash TEXT NOT NULL DEFAULT '',
    seen_count INTEGER NOT NULL DEFAULT 1,
    value_hash TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_account ON findings(account_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedup
ON findings(content_hash, session_id)
WHERE content_hash != '';
"""

_FINDINGS_COLUMNS = (
    "id, timestamp, detector, finding_type, severity, location, action_taken, "
    "provider, model, value_preview, account_id, session_id, device_id, "
    "source_ip, working_directory, git_branch, os_platform, client_name, "
    "client_version, api_key_hash, content_hash, seen_count, value_hash"
)


class FindingsRepository:
    """Repository for findings CRUD operations."""

    def __init__(self, store: AnalyticsStore) -> None:
        self._store = store

    def record(
        self,
        findings: list[Finding],
        provider: str = "",
        model: str = "",
        session: SessionContext | None = None,
    ) -> None:
        """Insert findings into the store. Thread-safe.

        Only stores summarized data — matched_value is never persisted.
        """
        if not findings:
            return

        now = now_iso_ms()
        s = session  # shorthand

        rows = []
        for f in findings:
            # Content hash: deterministic fingerprint for store-level dedup.
            # Uses detector + type + hash(matched_value). The matched_value
            # is only used transiently for hashing — never stored in the DB.
            # This avoids collisions between different secrets with the same
            # masked preview (e.g. two stripe keys both showing "sk_l****").
            mv_hash = hashlib.sha256(f.matched_value.encode()).hexdigest()[:16]
            hash_input = "%s|%s|%s" % (f.detector, f.type, mv_hash)
            content_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]
            # HMAC-SHA-256 of matched_value for cross-session secret tracking.
            # Full 64 hex chars (256 bits), keyed — useless without the key file.
            if self._store._hmac_key:
                vh = hmac_mod.new(self._store._hmac_key, f.matched_value.encode(), hashlib.sha256).hexdigest()
            else:
                vh = ""
            rows.append(
                (
                    now,
                    f.detector,
                    f.type,
                    f.severity,
                    f.location,
                    f.action,
                    provider,
                    model,
                    f.value_preview,
                    s.account_id if s else "",
                    s.session_id if s else "",
                    s.device_id if s else "",
                    s.source_ip if s else "",
                    s.working_directory if s else "",
                    s.git_branch if s else "",
                    s.os_platform if s else "",
                    s.client_name if s else "",
                    s.client_version if s else "",
                    s.api_key_hash if s else "",
                    content_hash,
                    vh,
                )
            )

        with self._store._lock:
            with self._store._connect() as conn:
                conn.executemany(
                    "INSERT INTO findings "
                    "(timestamp, detector, finding_type, severity, location, "
                    "action_taken, provider, model, value_preview, "
                    "account_id, session_id, device_id, source_ip, "
                    "working_directory, git_branch, os_platform, "
                    "client_name, client_version, api_key_hash, content_hash, value_hash) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(content_hash, session_id) "
                    "WHERE content_hash != '' "
                    "DO UPDATE SET seen_count = seen_count + 1, "
                    "timestamp = excluded.timestamp",
                    rows,
                )

    def bump_seen_counts(self, session_id: str) -> None:
        """Increment seen_count for all findings in a session.

        Called when Layer 1 skips fields (conversation history re-sent).
        LLM APIs send the full history on each request, so all previously
        found secrets are present in the re-sent content.
        """
        if not session_id:
            return
        with self._store._lock:
            with self._store._connect() as conn:
                conn.execute(
                    "UPDATE findings SET seen_count = seen_count + 1 WHERE session_id = ?",
                    (session_id,),
                )

    def get_page(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: str | None = None,
        detector: str | None = None,
        provider: str | None = None,
        session_id: str | None = None,
        account_id: str | None = None,
        action: str | None = None,
        finding_type: str | None = None,
        client_name: str | None = None,
        days: int | None = None,
    ) -> tuple[list[dict[str, Any]], Any]:
        """Return (findings_list, total_count) with optional filters."""
        where = ""
        conditions: list[str] = []
        params: list[Any] = []
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if detector:
            conditions.append("detector = ?")
            params.append(detector)
        if provider:
            conditions.append("provider = ?")
            params.append(provider)
        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)
        if account_id:
            conditions.append("account_id = ?")
            params.append(account_id)
        if action:
            conditions.append("action_taken = ?")
            params.append(action)
        if finding_type:
            conditions.append("finding_type = ?")
            params.append(finding_type)
        if client_name:
            conditions.append("client_name = ?")
            params.append(client_name)
        if days and days > 0:
            conditions.append("timestamp >= DATE('now', '-%d days')" % min(days, 365))
        if conditions:
            where = " WHERE " + " AND ".join(conditions)

        with self._store._connect() as conn:
            total = scalar(conn, "SELECT COUNT(*) FROM findings" + where, tuple(params))
            rows = conn.execute(
                "SELECT " + _FINDINGS_COLUMNS + " FROM findings" + where + " ORDER BY id DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        return [dict(r) for r in rows], total

    def get_by_id(self, finding_id: int) -> dict[str, Any] | None:
        """Return a single finding by ID."""
        with self._store._connect() as conn:
            row = conn.execute(
                "SELECT " + _FINDINGS_COLUMNS + " FROM findings WHERE id = ?",
                (finding_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_account_stats(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return top accounts by finding count.

        Returns list of dicts with account_id, finding_count, session_count.
        Sorted by finding_count descending. Excludes empty account_id.
        Read-only — no write lock needed.
        """
        with self._store._connect() as conn:
            rows = conn.execute(
                "SELECT account_id, "
                "COUNT(*) as finding_count, "
                "COUNT(DISTINCT session_id) as session_count "
                "FROM findings WHERE account_id != '' "
                "GROUP BY account_id "
                "ORDER BY finding_count DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self, days: int = 30) -> dict[str, Any]:
        """Return aggregate statistics for the dashboard.

        Args:
            days: Number of days for daily_trend (default 30, max 365).
                  Totals and breakdowns are always all-time.
        """
        days = max(1, min(days, 365))
        with self._store._connect() as conn:
            agg = conn.execute(
                "SELECT COUNT(*) as total, "
                "SUM(CASE WHEN DATE(timestamp) = DATE('now') THEN 1 ELSE 0 END) as today_count, "
                "MAX(timestamp) as last_finding_time "
                "FROM findings"
            ).fetchone()
            total = agg["total"]
            today_count = agg["today_count"] or 0
            last_finding_time = agg["last_finding_time"]

            by_severity = {}
            for row in conn.execute("SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"):
                by_severity[row["severity"]] = row["cnt"]

            by_detector = {}
            for row in conn.execute("SELECT detector, COUNT(*) as cnt FROM findings GROUP BY detector"):
                by_detector[row["detector"]] = row["cnt"]

            top_types = {}
            for row in conn.execute(
                "SELECT finding_type, COUNT(*) as cnt FROM findings GROUP BY finding_type ORDER BY cnt DESC LIMIT 20"
            ):
                top_types[row["finding_type"]] = row["cnt"]

            by_action = {}
            for row in conn.execute("SELECT action_taken, COUNT(*) as cnt FROM findings GROUP BY action_taken"):
                by_action[row["action_taken"]] = row["cnt"]

            by_provider = {}
            for row in conn.execute("SELECT provider, COUNT(*) as cnt FROM findings GROUP BY provider"):
                by_provider[row["provider"] or "unknown"] = row["cnt"]

            by_model = {}
            for row in conn.execute(
                "SELECT model, COUNT(*) as cnt FROM findings GROUP BY model ORDER BY cnt DESC LIMIT 20"
            ):
                by_model[row["model"] or "unknown"] = row["cnt"]

            by_client = {}
            for row in conn.execute(
                "SELECT client_name, COUNT(*) as cnt FROM findings "
                "WHERE client_name != '' GROUP BY client_name ORDER BY cnt DESC LIMIT 50"
            ):
                by_client[row["client_name"]] = row["cnt"]

            daily = [
                {"date": row["day"], "count": row["cnt"]}
                for row in conn.execute(
                    "SELECT DATE(timestamp) as day, COUNT(*) as cnt "
                    "FROM findings "
                    "WHERE timestamp >= DATE('now', '-' || ? || ' days') "
                    "GROUP BY day ORDER BY day",
                    (days,),
                )
            ]

        return {
            "total_findings": total,
            "today_count": today_count,
            "last_finding_time": last_finding_time,
            "by_severity": by_severity,
            "by_detector": by_detector,
            "top_finding_types": top_types,
            "by_action": by_action,
            "by_provider": by_provider,
            "by_model": by_model,
            "by_client": by_client,
            "daily_trend": daily,
        }

    def get_action_trend(self, days: int = 30) -> list[dict[str, Any]]:
        """Daily findings grouped by action_taken for stacked area chart."""
        days = max(1, min(days, 365))
        with self._store._connect() as conn:
            rows = conn.execute(
                "SELECT DATE(timestamp) as day, action_taken, COUNT(*) as cnt "
                "FROM findings "
                "WHERE timestamp >= DATE('now', '-' || ? || ' days') "
                "GROUP BY day, action_taken ORDER BY day",
                (days,),
            ).fetchall()
        # Pivot into {date, block, redact, alert, log} per day
        by_day: dict[str, dict[str, Any]] = {}
        for row in rows:
            day = row["day"]
            if day not in by_day:
                by_day[day] = {"date": day, "block": 0, "redact": 0, "alert": 0, "log": 0}
            action = row["action_taken"] or "log"
            if action in by_day[day]:
                by_day[day][action] = row["cnt"]
        return sorted(by_day.values(), key=lambda d: d["date"])

    def get_activity_matrix(self, days: int = 30) -> list[dict[str, Any]]:
        """Pre-shaped 7x24 activity matrix for heatmap chart.

        Returns list of 7 objects (Mon-Sun), each with a 24-element hours array.
        SQLite strftime('%w') returns 0=Sunday, so we remap to Mon-first order.
        """
        days = max(1, min(days, 365))
        # Build empty 7x24 grid (indexed by strftime %w: 0=Sun, 1=Mon, ...)
        grid = [[0] * 24 for _ in range(7)]
        with self._store._connect() as conn:
            rows = conn.execute(
                "SELECT CAST(strftime('%w', timestamp) AS INTEGER) as weekday, "
                "CAST(strftime('%H', timestamp) AS INTEGER) as hour, "
                "COUNT(*) as cnt "
                "FROM findings "
                "WHERE timestamp >= DATE('now', '-' || ? || ' days') "
                "GROUP BY weekday, hour",
                (days,),
            ).fetchall()
        for r in rows:
            grid[r["weekday"]][r["hour"]] = r["cnt"]
        # Remap to Mon-first: Mon(1), Tue(2), ..., Sat(6), Sun(0)
        day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        day_order = [1, 2, 3, 4, 5, 6, 0]  # strftime %w indices
        return [{"weekday": day_names[i], "hours": grid[day_order[i]]} for i in range(7)]

    def get_top_accounts(self, days: int = 30, limit: int = 8) -> list[dict[str, Any]]:
        """Top accounts by finding count."""
        days = max(1, min(days, 365))
        with self._store._connect() as conn:
            rows = conn.execute(
                "SELECT account_id, COUNT(*) as cnt "
                "FROM findings "
                "WHERE account_id IS NOT NULL AND account_id != '' "
                "AND timestamp >= DATE('now', '-' || ? || ' days') "
                "GROUP BY account_id ORDER BY cnt DESC LIMIT ?",
                (days, limit),
            ).fetchall()
        return [{"account_id": r["account_id"], "count": r["cnt"]} for r in rows]

    def get_top_projects(self, days: int = 30, limit: int = 8) -> list[dict[str, Any]]:
        """Top working directories by finding count."""
        days = max(1, min(days, 365))
        with self._store._connect() as conn:
            rows = conn.execute(
                "SELECT working_directory, COUNT(*) as cnt "
                "FROM findings "
                "WHERE working_directory IS NOT NULL AND working_directory != '' "
                "AND timestamp >= DATE('now', '-' || ? || ' days') "
                "GROUP BY working_directory ORDER BY cnt DESC LIMIT ?",
                (days, limit),
            ).fetchall()
        return [{"working_directory": r["working_directory"], "count": r["cnt"]} for r in rows]

    def get_total_count(
        self,
        severity: str | None = None,
        detector: str | None = None,
        provider: str | None = None,
    ) -> int:
        """Return total number of findings, optionally filtered."""
        query = "SELECT COUNT(*) FROM findings"
        conditions: list[str] = []
        params: list[Any] = []
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
        with self._store._connect() as conn:
            return scalar(conn, query, tuple(params))

    def get_sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent sessions with finding counts and metadata.

        Groups findings by session_id, returns aggregate info per session.
        Only includes rows where session_id is non-empty.

        Note: MAX() on text fields returns the lexicographically largest value,
        not the most recent. This is acceptable for display metadata — if a
        field changes mid-session (e.g., branch switch), the shown value may
        not be the latest. Exact-latest would require a correlated subquery.
        """
        with self._store._connect() as conn:
            rows = conn.execute(
                "SELECT session_id, MIN(timestamp) as first_seen, "
                "MAX(timestamp) as last_seen, COUNT(*) as finding_count, "
                "MAX(provider) as provider, MAX(model) as model, "
                "MAX(account_id) as account_id, "
                "MAX(device_id) as device_id, "
                "MAX(working_directory) as working_directory, "
                "MAX(git_branch) as git_branch "
                "FROM findings WHERE session_id != '' "
                "GROUP BY session_id "
                "ORDER BY last_seen DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_dashboard_sessions(self, limit: int = 5, hours: int = 24) -> dict[str, Any]:
        """Return active sessions with severity breakdown for dashboard.

        Only includes sessions with findings in the last ``hours`` hours.
        Returns both the session list and total count (uncapped by limit)
        so the quick-stat card can show the real active session count.
        """
        hours = max(1, min(hours, 168))  # 1h-7d
        time_filter = "AND timestamp >= DATETIME('now', '-%d hours')" % hours
        with self._store._connect() as conn:
            # Fetch limit+1 to detect if there are more sessions than limit
            rows = conn.execute(
                "SELECT session_id, MIN(timestamp) as first_seen, "
                "MAX(timestamp) as last_seen, COUNT(*) as finding_count, "
                "MAX(account_id) as account_id, "
                "MAX(client_name) as client_name, "
                "MAX(working_directory) as working_directory, "
                "SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_count, "
                "SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_count, "
                "SUM(CASE WHEN severity = 'warning' THEN 1 ELSE 0 END) as warning_count, "
                "SUM(CASE WHEN severity = 'info' THEN 1 ELSE 0 END) as info_count "
                "FROM findings WHERE session_id != '' " + time_filter + " "
                "GROUP BY session_id "
                "ORDER BY last_seen DESC LIMIT ?",
                (limit + 1,),
            ).fetchall()
            if len(rows) <= limit:
                total = len(rows)
            else:
                rows = rows[:limit]
                total = scalar(
                    conn, "SELECT COUNT(DISTINCT session_id) FROM findings WHERE session_id != '' " + time_filter
                )
        return {"sessions": [dict(r) for r in rows], "total": total}

    def cleanup(self, retention_days: int = 365) -> int:
        """Delete findings older than retention_days. Returns count deleted."""
        with self._store._lock:
            with self._store._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM findings WHERE timestamp < DATE('now', ?)",
                    ("-%d days" % retention_days,),
                )
                deleted = cursor.rowcount
        if deleted:
            log.info("analytics cleanup: deleted %d findings older than %d days", deleted, retention_days)
        return deleted
