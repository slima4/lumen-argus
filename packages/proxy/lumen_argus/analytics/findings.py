"""Findings repository — extracted from AnalyticsStore."""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import logging
from typing import TYPE_CHECKING, Any

from lumen_argus.analytics._db import scalar
from lumen_argus.analytics.base import BaseRepository
from lumen_argus.models import Finding, SessionContext
from lumen_argus_core.time_utils import now_iso_ms

if TYPE_CHECKING:
    from lumen_argus.analytics.adapter import DatabaseAdapter

log = logging.getLogger("argus.analytics")

_FINDINGS_COLUMNS = (
    "id, timestamp, detector, finding_type, severity, location, action_taken, "
    "provider, model, value_preview, account_id, session_id, device_id, "
    "source_ip, working_directory, git_branch, os_platform, hostname, username, "
    "client_name, client_version, api_key_hash, content_hash, seen_count, value_hash"
)


class FindingsRepository(BaseRepository):
    """Repository for findings CRUD operations."""

    def __init__(self, adapter: DatabaseAdapter, hmac_key: bytes | None = None) -> None:
        super().__init__(adapter)
        self._hmac_key = hmac_key

    def record(
        self,
        findings: list[Finding],
        provider: str = "",
        model: str = "",
        session: SessionContext | None = None,
        namespace_id: int = 1,
    ) -> None:
        """Insert findings into the store. Thread-safe.

        Only stores summarized data — matched_value is never persisted.
        """
        if not findings:
            return

        now = now_iso_ms()
        s = session  # shorthand

        sess = (
            (
                s.account_id,
                s.session_id,
                s.device_id,
                s.source_ip,
                s.working_directory,
                s.git_branch,
                s.os_platform,
                s.hostname,
                s.username,
                s.client_name,
                s.client_version,
                s.api_key_hash,
            )
            if s
            else ("",) * 12
        )

        rows = []
        for f in findings:
            mv_hash = hashlib.sha256(f.matched_value.encode()).hexdigest()[:16]
            hash_input = "%s|%s|%s" % (f.detector, f.type, mv_hash)
            content_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]
            vh = (
                hmac_mod.new(self._hmac_key, f.matched_value.encode(), hashlib.sha256).hexdigest()
                if self._hmac_key
                else ""
            )
            rows.append(
                (
                    namespace_id,
                    now,
                    f.detector,
                    f.type,
                    f.severity,
                    f.location,
                    f.action,
                    provider,
                    model,
                    f.value_preview,
                    *sess,
                    content_hash,
                    vh,
                )
            )

        with self._adapter.write_lock():
            with self._connect() as conn:
                conn.executemany(
                    "INSERT INTO findings "
                    "(namespace_id, timestamp, detector, finding_type, severity, location, "
                    "action_taken, provider, model, value_preview, "
                    "account_id, session_id, device_id, source_ip, "
                    "working_directory, git_branch, os_platform, hostname, username, "
                    "client_name, client_version, api_key_hash, content_hash, value_hash) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(content_hash, session_id, namespace_id) "
                    "WHERE content_hash != '' "
                    "DO UPDATE SET seen_count = findings.seen_count + 1, "
                    "timestamp = excluded.timestamp",
                    rows,
                )

    def bump_seen_counts(self, session_id: str, namespace_id: int = 1) -> None:
        """Increment seen_count for all findings in a session.

        Called when Layer 1 skips fields (conversation history re-sent).
        LLM APIs send the full history on each request, so all previously
        found secrets are present in the re-sent content.
        """
        if not session_id:
            return
        with self._adapter.write_lock():
            with self._connect() as conn:
                conn.execute(
                    "UPDATE findings SET seen_count = seen_count + 1 WHERE session_id = ? AND namespace_id = ?",
                    (session_id, namespace_id),
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
        working_directory: str | None = None,
        hostname: str | None = None,
        username: str | None = None,
        days: int | None = None,
        namespace_id: int = 1,
    ) -> tuple[list[dict[str, Any]], Any]:
        """Return (findings_list, total_count) with optional filters."""
        where = ""
        conditions: list[str] = ["namespace_id = ?"]
        params: list[Any] = [namespace_id]
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
        if working_directory:
            escaped_wd = working_directory.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            conditions.append("working_directory LIKE ? ESCAPE '\\'")
            params.append("%%%s%%" % escaped_wd)
        if hostname:
            conditions.append("hostname = ?")
            params.append(hostname)
        if username:
            conditions.append("username = ?")
            params.append(username)
        if days and days > 0:
            conditions.append(self._adapter.date_diff_sql("timestamp", min(days, 365)))
        where = " WHERE " + " AND ".join(conditions)

        with self._connect() as conn:
            total = scalar(conn, "SELECT COUNT(*) FROM findings" + where, tuple(params))
            rows = conn.execute(
                "SELECT " + _FINDINGS_COLUMNS + " FROM findings" + where + " ORDER BY id DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        return [dict(r) for r in rows], total

    def get_by_id(self, finding_id: int, namespace_id: int = 1) -> dict[str, Any] | None:
        """Return a single finding by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT " + _FINDINGS_COLUMNS + " FROM findings WHERE id = ? AND namespace_id = ?",
                (finding_id, namespace_id),
            ).fetchone()
        return dict(row) if row else None

    def get_account_stats(self, limit: int = 10, namespace_id: int = 1) -> list[dict[str, Any]]:
        """Return top accounts by finding count.

        Returns list of dicts with account_id, finding_count, session_count.
        Sorted by finding_count descending. Excludes empty account_id.
        Read-only — no write lock needed.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT account_id, "
                "COUNT(*) as finding_count, "
                "COUNT(DISTINCT session_id) as session_count "
                "FROM findings WHERE account_id != '' AND namespace_id = ? "
                "GROUP BY account_id "
                "ORDER BY finding_count DESC LIMIT ?",
                (namespace_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self, days: int = 30, namespace_id: int = 1) -> dict[str, Any]:
        """Return aggregate statistics for the dashboard.

        Args:
            days: Number of days for daily_trend (default 30, max 365).
                  Totals and breakdowns are always all-time.
        """
        days = max(1, min(days, 365))
        ns_filter = "WHERE namespace_id = ?"
        ns_and = "AND namespace_id = ?"

        with self._connect() as conn:
            agg = conn.execute(
                "SELECT COUNT(*) as total, "
                f"SUM(CASE WHEN {self._adapter.is_today_sql('timestamp')} THEN 1 ELSE 0 END) as today_count, "
                "MAX(timestamp) as last_finding_time "
                f"FROM findings {ns_filter}",
                (namespace_id,),
            ).fetchone()
            total = agg["total"]
            today_count = agg["today_count"] or 0
            last_finding_time = agg["last_finding_time"]

            by_severity = {}
            for row in conn.execute(
                f"SELECT severity, COUNT(*) as cnt FROM findings {ns_filter} GROUP BY severity",
                (namespace_id,),
            ):
                by_severity[row["severity"]] = row["cnt"]

            by_detector = {}
            for row in conn.execute(
                f"SELECT detector, COUNT(*) as cnt FROM findings {ns_filter} GROUP BY detector",
                (namespace_id,),
            ):
                by_detector[row["detector"]] = row["cnt"]

            top_types = {}
            for row in conn.execute(
                f"SELECT finding_type, COUNT(*) as cnt FROM findings {ns_filter} "
                "GROUP BY finding_type ORDER BY cnt DESC LIMIT 20",
                (namespace_id,),
            ):
                top_types[row["finding_type"]] = row["cnt"]

            by_action = {}
            for row in conn.execute(
                f"SELECT action_taken, COUNT(*) as cnt FROM findings {ns_filter} GROUP BY action_taken",
                (namespace_id,),
            ):
                by_action[row["action_taken"]] = row["cnt"]

            by_provider = {}
            for row in conn.execute(
                f"SELECT provider, COUNT(*) as cnt FROM findings {ns_filter} GROUP BY provider",
                (namespace_id,),
            ):
                by_provider[row["provider"] or "unknown"] = row["cnt"]

            by_model = {}
            for row in conn.execute(
                f"SELECT model, COUNT(*) as cnt FROM findings {ns_filter} GROUP BY model ORDER BY cnt DESC LIMIT 20",
                (namespace_id,),
            ):
                by_model[row["model"] or "unknown"] = row["cnt"]

            by_client = {}
            for row in conn.execute(
                "SELECT client_name, COUNT(*) as cnt FROM findings "
                f"WHERE client_name != '' {ns_and} "
                "GROUP BY client_name ORDER BY cnt DESC LIMIT 50",
                (namespace_id,),
            ):
                by_client[row["client_name"]] = row["cnt"]

            daily = [
                {"date": row["day"], "count": row["cnt"]}
                for row in conn.execute(
                    f"SELECT {self._adapter.date_trunc_sql('day', 'timestamp')} as day, COUNT(*) as cnt "
                    "FROM findings "
                    f"WHERE {self._adapter.date_diff_sql('timestamp', days)} {ns_and} "
                    "GROUP BY day ORDER BY day",
                    (namespace_id,),
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

    def get_action_trend(self, days: int = 30, namespace_id: int = 1) -> list[dict[str, Any]]:
        """Daily findings grouped by action_taken for stacked area chart."""
        days = max(1, min(days, 365))

        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {self._adapter.date_trunc_sql('day', 'timestamp')} as day, action_taken, COUNT(*) as cnt "
                "FROM findings "
                f"WHERE {self._adapter.date_diff_sql('timestamp', days)} AND namespace_id = ? "
                "GROUP BY day, action_taken ORDER BY day",
                (namespace_id,),
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

    def get_activity_matrix(self, days: int = 30, namespace_id: int = 1) -> list[dict[str, Any]]:
        """Pre-shaped 7x24 activity matrix for heatmap chart.

        Returns list of 7 objects (Mon-Sun), each with a 24-element hours array.
        SQLite strftime('%w') returns 0=Sunday, so we remap to Mon-first order.
        """
        days = max(1, min(days, 365))

        # Build empty 7x24 grid (indexed by DOW: 0=Sun, 1=Mon, ...)
        grid = [[0] * 24 for _ in range(7)]
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {self._adapter.extract_weekday_sql('timestamp')} as weekday, "
                f"{self._adapter.extract_hour_sql('timestamp')} as hour, "
                "COUNT(*) as cnt "
                "FROM findings "
                f"WHERE {self._adapter.date_diff_sql('timestamp', days)} AND namespace_id = ? "
                "GROUP BY weekday, hour",
                (namespace_id,),
            ).fetchall()
        for r in rows:
            grid[r["weekday"]][r["hour"]] = r["cnt"]
        # Remap to Mon-first: Mon(1), Tue(2), ..., Sat(6), Sun(0)
        day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        day_order = [1, 2, 3, 4, 5, 6, 0]  # strftime %w indices
        return [{"weekday": day_names[i], "hours": grid[day_order[i]]} for i in range(7)]

    def get_top_accounts(self, days: int = 30, limit: int = 8, namespace_id: int = 1) -> list[dict[str, Any]]:
        """Top accounts by finding count."""
        days = max(1, min(days, 365))

        with self._connect() as conn:
            rows = conn.execute(
                "SELECT account_id, COUNT(*) as cnt "
                "FROM findings "
                "WHERE account_id IS NOT NULL AND account_id != '' "
                f"AND {self._adapter.date_diff_sql('timestamp', days)} AND namespace_id = ? "
                "GROUP BY account_id ORDER BY cnt DESC LIMIT ?",
                (namespace_id, limit),
            ).fetchall()
        return [{"account_id": r["account_id"], "count": r["cnt"]} for r in rows]

    def get_top_projects(self, days: int = 30, limit: int = 8, namespace_id: int = 1) -> list[dict[str, Any]]:
        """Top working directories by finding count."""
        days = max(1, min(days, 365))

        with self._connect() as conn:
            rows = conn.execute(
                "SELECT working_directory, COUNT(*) as cnt "
                "FROM findings "
                "WHERE working_directory IS NOT NULL AND working_directory != '' "
                f"AND {self._adapter.date_diff_sql('timestamp', days)} AND namespace_id = ? "
                "GROUP BY working_directory ORDER BY cnt DESC LIMIT ?",
                (namespace_id, limit),
            ).fetchall()
        return [{"working_directory": r["working_directory"], "count": r["cnt"]} for r in rows]

    def get_by_project(self, days: int = 30, limit: int = 20, namespace_id: int = 1) -> list[dict[str, Any]]:
        """Return findings grouped by working_directory with severity breakdown.

        Each entry includes project name (last path component), finding count,
        critical count, last finding time, and distinct agent list.
        """
        days = max(1, min(days, 365))

        with self._connect() as conn:
            rows = conn.execute(
                "SELECT working_directory, "
                "COUNT(*) as finding_count, "
                "SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_count, "
                "MAX(timestamp) as last_finding_at "
                "FROM findings "
                "WHERE working_directory IS NOT NULL AND working_directory != '' "
                f"AND {self._adapter.date_diff_sql('timestamp', days)} AND namespace_id = ? "
                "GROUP BY working_directory "
                "ORDER BY finding_count DESC LIMIT ?",
                (namespace_id, limit),
            ).fetchall()

            projects = []
            for r in rows:
                wd = r["working_directory"]
                # Get distinct agents for this project
                agent_rows = conn.execute(
                    "SELECT DISTINCT client_name FROM findings "
                    "WHERE working_directory = ? AND client_name != '' AND namespace_id = ? "
                    f"AND {self._adapter.date_diff_sql('timestamp', days)}",
                    (wd, namespace_id),
                ).fetchall()
                agents = [a["client_name"] for a in agent_rows]

                project_name = wd.rsplit("/", 1)[-1] if "/" in wd else wd.rsplit("\\", 1)[-1] if "\\" in wd else wd
                projects.append(
                    {
                        "working_directory": wd,
                        "project_name": project_name,
                        "finding_count": r["finding_count"],
                        "critical_count": r["critical_count"] or 0,
                        "last_finding_at": r["last_finding_at"],
                        "agents": agents,
                    }
                )

        return projects

    def get_total_count(
        self,
        severity: str | None = None,
        detector: str | None = None,
        provider: str | None = None,
        namespace_id: int = 1,
    ) -> int:
        """Return total number of findings, optionally filtered."""
        query = "SELECT COUNT(*) FROM findings"
        conditions: list[str] = ["namespace_id = ?"]
        params: list[Any] = [namespace_id]
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if detector:
            conditions.append("detector = ?")
            params.append(detector)
        if provider:
            conditions.append("provider = ?")
            params.append(provider)
        query += " WHERE " + " AND ".join(conditions)
        with self._connect() as conn:
            return scalar(conn, query, tuple(params))

    def get_sessions(self, limit: int = 50, namespace_id: int = 1) -> list[dict[str, Any]]:
        """Return recent sessions with finding counts and metadata.

        Groups findings by session_id, returns aggregate info per session.
        Only includes rows where session_id is non-empty.

        Note: MAX() on text fields returns the lexicographically largest value,
        not the most recent. This is acceptable for display metadata — if a
        field changes mid-session (e.g., branch switch), the shown value may
        not be the latest. Exact-latest would require a correlated subquery.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT session_id, MIN(timestamp) as first_seen, "
                "MAX(timestamp) as last_seen, COUNT(*) as finding_count, "
                "MAX(provider) as provider, MAX(model) as model, "
                "MAX(account_id) as account_id, "
                "MAX(device_id) as device_id, "
                "MAX(working_directory) as working_directory, "
                "MAX(git_branch) as git_branch "
                "FROM findings WHERE session_id != '' AND namespace_id = ? "
                "GROUP BY session_id "
                "ORDER BY last_seen DESC LIMIT ?",
                (namespace_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_dashboard_sessions(self, limit: int = 5, hours: int = 24, namespace_id: int = 1) -> dict[str, Any]:
        """Return active sessions with severity breakdown for dashboard.

        Only includes sessions with findings in the last ``hours`` hours.
        Returns both the session list and total count (uncapped by limit)
        so the quick-stat card can show the real active session count.
        """
        hours = max(1, min(hours, 168))  # 1h-7d
        time_filter = "AND " + self._adapter.hours_ago_sql("timestamp", hours)
        ns_filter = "AND namespace_id = ?"
        with self._connect() as conn:
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
                "FROM findings WHERE session_id != '' " + time_filter + " " + ns_filter + " "
                "GROUP BY session_id "
                "ORDER BY last_seen DESC LIMIT ?",
                (namespace_id, limit + 1),
            ).fetchall()
            if len(rows) <= limit:
                total = len(rows)
            else:
                rows = rows[:limit]
                total = scalar(
                    conn,
                    "SELECT COUNT(DISTINCT session_id) FROM findings "
                    "WHERE session_id != '' " + time_filter + " " + ns_filter,
                    (namespace_id,),
                )
        return {"sessions": [dict(r) for r in rows], "total": total}

    def cleanup(self, retention_days: int = 365, namespace_id: int = 1) -> int:
        """Delete findings older than retention_days. Returns count deleted."""

        with self._adapter.write_lock():
            with self._connect() as conn:
                cursor = conn.execute(
                    f"DELETE FROM findings WHERE namespace_id = ? "
                    f"AND timestamp < {self._adapter.date_subtract_literal_sql()}",
                    (namespace_id, "-%d days" % retention_days),
                )
                deleted = cursor.rowcount
        if deleted:
            log.info("analytics cleanup: deleted %d findings older than %d days", deleted, retention_days)
        return deleted
