"""SQLite-backed analytics store for community dashboard.

Stores summarized finding data (no raw secrets/PII values) with
aggregation queries for dashboard charts. Includes scheduled cleanup
for retention enforcement.

sqlite3 is Python stdlib — zero external dependencies.
"""

import hashlib
import hmac as hmac_mod
import json
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from lumen_argus.models import Finding, SessionContext

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

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TEXT NOT NULL
);
"""

_RULES_SCHEMA = """\
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    pattern TEXT NOT NULL,
    detector TEXT NOT NULL DEFAULT 'secrets',
    severity TEXT NOT NULL DEFAULT 'high',
    action TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    tier TEXT NOT NULL DEFAULT 'community',
    source TEXT NOT NULL DEFAULT 'import',
    description TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '[]',
    validator TEXT NOT NULL DEFAULT '',
    entropy_context INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_rules_detector ON rules(detector);
CREATE INDEX IF NOT EXISTS idx_rules_tier ON rules(tier);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);
"""

_RULES_COLUMNS = (
    "id, name, pattern, detector, severity, action, enabled, tier, source, "
    "description, tags, validator, entropy_context, created_at, updated_at, "
    "created_by, updated_by"
)

_FINDINGS_COLUMNS = (
    "id, timestamp, detector, finding_type, severity, location, action_taken, "
    "provider, model, value_preview, account_id, session_id, device_id, "
    "source_ip, working_directory, git_branch, os_platform, client_name, "
    "api_key_hash, content_hash, seen_count, value_hash"
)

_CHANNEL_COLUMNS = (
    "id, name, type, config, enabled, source, events, min_severity, created_at, updated_at, created_by, updated_by"
)

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


class AnalyticsStore:
    """Thread-safe SQLite store for finding history and trend queries.

    Uses thread-local connection pooling — one connection per thread,
    reused across method calls. WAL mode allows concurrent readers.
    Write serialization: single Lock wraps all writes; reads don't acquire it.
    """

    def __init__(self, db_path: str = "~/.lumen-argus/analytics.db", hmac_key: bytes = None):
        self._db_path = os.path.expanduser(db_path)
        self._hmac_key = hmac_key
        self._lock = threading.Lock()
        self._local = threading.local()
        self._ensure_db()

    def _ensure_db(self) -> None:
        """Create the database and schema if they don't exist."""
        db_dir = Path(self._db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            conn.executescript(_RULES_SCHEMA)
            conn.executescript(_NOTIFICATION_SCHEMA)
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
        session: "SessionContext" = None,
    ) -> None:
        """Insert findings into the store. Thread-safe.

        Only stores summarized data — matched_value is never persisted.
        """
        if not findings:
            return

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
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
            if self._hmac_key:
                vh = hmac_mod.new(self._hmac_key, f.matched_value.encode(), hashlib.sha256).hexdigest()
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
                    s.api_key_hash if s else "",
                    content_hash,
                    vh,
                )
            )

        with self._lock:
            with self._connect() as conn:
                conn.executemany(
                    "INSERT INTO findings "
                    "(timestamp, detector, finding_type, severity, location, "
                    "action_taken, provider, model, value_preview, "
                    "account_id, session_id, device_id, source_ip, "
                    "working_directory, git_branch, os_platform, "
                    "client_name, api_key_hash, content_hash, value_hash) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
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
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE findings SET seen_count = seen_count + 1 WHERE session_id = ?",
                    (session_id,),
                )

    def get_findings_page(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: Optional[str] = None,
        detector: Optional[str] = None,
        provider: Optional[str] = None,
        session_id: Optional[str] = None,
        account_id: Optional[str] = None,
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
        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)
        if account_id:
            conditions.append("account_id = ?")
            params.append(account_id)
        if conditions:
            where = " WHERE " + " AND ".join(conditions)

        with self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM findings" + where,
                params,
            ).fetchone()[0]
            rows = conn.execute(
                "SELECT " + _FINDINGS_COLUMNS + " FROM findings" + where + " ORDER BY id DESC LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()
        return [dict(r) for r in rows], total

    def get_finding_by_id(self, finding_id: int) -> Optional[dict]:
        """Return a single finding by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT " + _FINDINGS_COLUMNS + " FROM findings WHERE id = ?",
                (finding_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_account_stats(self, limit: int = 10) -> list:
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
                "FROM findings WHERE account_id != '' "
                "GROUP BY account_id "
                "ORDER BY finding_count DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> dict:
        """Return aggregate statistics for the dashboard."""
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]

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

    def get_sessions(self, limit: int = 50) -> list:
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
                "FROM findings WHERE session_id != '' "
                "GROUP BY session_id "
                "ORDER BY last_seen DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

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
            log.info("analytics cleanup: deleted %d findings older than %d days", deleted, retention_days)
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

    # --- Rules ---

    def get_rules_count(self) -> int:
        """Return total number of rules in the DB."""
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM rules").fetchone()[0]

    def get_active_rules(self, detector: Optional[str] = None, tier: Optional[str] = None) -> list:
        """Return enabled rules, optionally filtered by detector/tier."""
        query = "SELECT " + _RULES_COLUMNS + " FROM rules WHERE enabled = 1"
        params = []  # type: list
        if detector:
            query += " AND detector = ?"
            params.append(detector)
        if tier:
            query += " AND tier = ?"
            params.append(tier)
        query += " ORDER BY id"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["enabled"] = bool(d.get("enabled", 1))
            if "tags" in d and isinstance(d["tags"], str):
                try:
                    d["tags"] = json.loads(d["tags"])
                except (json.JSONDecodeError, ValueError):
                    d["tags"] = []
            result.append(d)
        return result

    def get_rules_page(
        self,
        limit: int = 50,
        offset: int = 0,
        search: Optional[str] = None,
        detector: Optional[str] = None,
        tier: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> tuple:
        """Paginated rules for dashboard. Returns (rules_list, total_count)."""
        conditions = []
        params = []  # type: list
        if search:
            conditions.append("(name LIKE ? OR description LIKE ?)")
            params.extend(["%" + search + "%", "%" + search + "%"])
        if detector:
            conditions.append("detector = ?")
            params.append(detector)
        if tier:
            conditions.append("tier = ?")
            params.append(tier)
        if enabled is not None:
            conditions.append("enabled = ?")
            params.append(1 if enabled else 0)
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""

        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM rules" + where, params).fetchone()[0]
            rows = conn.execute(
                "SELECT " + _RULES_COLUMNS + " FROM rules" + where + " ORDER BY id LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["enabled"] = bool(d.get("enabled", 1))
            if "tags" in d and isinstance(d["tags"], str):
                try:
                    d["tags"] = json.loads(d["tags"])
                except (json.JSONDecodeError, ValueError):
                    d["tags"] = []
            result.append(d)
        return result, total

    def get_rule_by_name(self, name: str) -> Optional[dict]:
        """Return a single rule by name."""
        with self._connect() as conn:
            row = conn.execute("SELECT " + _RULES_COLUMNS + " FROM rules WHERE name = ?", (name,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["enabled"] = bool(d.get("enabled", 1))
        if isinstance(d.get("tags"), str):
            try:
                d["tags"] = json.loads(d["tags"])
            except (json.JSONDecodeError, ValueError):
                d["tags"] = []
        return d

    def create_rule(self, data: dict) -> dict:
        """Create a custom rule. Validates pattern regex. Returns created rule."""
        import re as re_mod

        name = data.get("name", "").strip()
        if not name:
            raise ValueError("name is required")
        pattern = data.get("pattern", "").strip()
        if not pattern:
            raise ValueError("pattern is required")
        try:
            re_mod.compile(pattern)
        except re_mod.error as e:
            raise ValueError("invalid regex: %s" % e)

        now = self._now()
        with self._lock:
            with self._connect() as conn:
                try:
                    conn.execute(
                        "INSERT INTO rules "
                        "(name, pattern, detector, severity, action, enabled, "
                        "tier, source, description, tags, validator, entropy_context, "
                        "created_at, updated_at, created_by, updated_by) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            name,
                            pattern,
                            data.get("detector", "custom"),
                            data.get("severity", "high"),
                            data.get("action", ""),
                            1 if data.get("enabled", True) else 0,
                            data.get("tier", "custom"),
                            data.get("source", "dashboard"),
                            data.get("description", ""),
                            json.dumps(data.get("tags", [])),
                            data.get("validator", ""),
                            1 if data.get("entropy_context", False) else 0,
                            now,
                            now,
                            data.get("created_by", ""),
                            data.get("created_by", ""),
                        ),
                    )
                except sqlite3.IntegrityError:
                    raise ValueError("rule '%s' already exists" % name)
        return self.get_rule_by_name(name)

    def update_rule(self, name: str, data: dict) -> Optional[dict]:
        """Update rule fields. Returns updated rule or None if not found."""
        updates = []  # type: List[str]
        params = []  # type: list
        for key in ("pattern", "detector", "severity", "action", "description", "validator"):
            if key in data:
                updates.append("%s = ?" % key)
                params.append(data[key])
        if "enabled" in data:
            updates.append("enabled = ?")
            params.append(1 if data["enabled"] else 0)
        if "tags" in data:
            updates.append("tags = ?")
            params.append(json.dumps(data["tags"]) if isinstance(data["tags"], list) else data["tags"])
        if "entropy_context" in data:
            updates.append("entropy_context = ?")
            params.append(1 if data["entropy_context"] else 0)
        if not updates:
            return self.get_rule_by_name(name)
        updates.append("updated_at = ?")
        params.append(self._now())
        if "updated_by" in data:
            updates.append("updated_by = ?")
            params.append(data["updated_by"])
        params.append(name)

        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "UPDATE rules SET %s WHERE name = ?" % ", ".join(updates),
                    params,
                )
                if cursor.rowcount == 0:
                    return None
        return self.get_rule_by_name(name)

    def delete_rule(self, name: str) -> bool:
        """Delete a dashboard-created rule. Returns True if deleted."""
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM rules WHERE name = ? AND source = 'dashboard'",
                    (name,),
                )
                return cursor.rowcount > 0

    def clone_rule(self, name: str, new_name: str) -> dict:
        """Clone a rule as source='dashboard', tier='custom'."""
        original = self.get_rule_by_name(name)
        if not original:
            raise ValueError("rule '%s' not found" % name)
        return self.create_rule(
            {
                "name": new_name,
                "pattern": original["pattern"],
                "detector": original["detector"],
                "severity": original["severity"],
                "action": original["action"],
                "description": original.get("description", ""),
                "tags": original.get("tags", []),
                "validator": original.get("validator", ""),
                "entropy_context": original.get("entropy_context", False),
                "tier": "custom",
                "source": "dashboard",
                "created_by": "dashboard",
            }
        )

    def import_rules(self, rules: list, tier: str = "community", force: bool = False) -> dict:
        """Bulk import rules from a JSON bundle.

        Returns {"created": N, "updated": N, "skipped": N}.
        Existing import rules: updates pattern/description/tags (preserves action/enabled).
        Dashboard/YAML rules: skipped (user-owned).
        --force: resets action/enabled to defaults for import rules.
        """
        import re as re_mod

        result = {"created": 0, "updated": 0, "skipped": 0}
        now = self._now()

        with self._lock:
            with self._connect() as conn:
                for r in rules:
                    name = r.get("name", "").strip()
                    if not name:
                        continue
                    # Validate regex before storing
                    pattern = r.get("pattern", "")
                    if pattern:
                        try:
                            re_mod.compile(pattern)
                        except re_mod.error:
                            log.warning("rule '%s': invalid regex, skipping import", name)
                            result["skipped"] += 1
                            continue
                    existing = conn.execute("SELECT source, id FROM rules WHERE name = ?", (name,)).fetchone()

                    if existing:
                        source = existing[0]
                        if source in ("dashboard", "yaml"):
                            result["skipped"] += 1
                            continue
                        # Update existing import rule
                        if force:
                            conn.execute(
                                "UPDATE rules SET pattern=?, detector=?, severity=?, "
                                "action=?, enabled=1, description=?, tags=?, "
                                "validator=?, entropy_context=?, "
                                "updated_at=?, updated_by=? WHERE name=?",
                                (
                                    r.get("pattern", ""),
                                    r.get("detector", "secrets"),
                                    r.get("severity", "high"),
                                    r.get("action", ""),
                                    r.get("description", ""),
                                    json.dumps(r.get("tags", [])),
                                    r.get("validator", ""),
                                    1 if r.get("entropy_context", False) else 0,
                                    now,
                                    "cli",
                                    name,
                                ),
                            )
                        else:
                            # Preserve action and enabled
                            conn.execute(
                                "UPDATE rules SET pattern=?, detector=?, severity=?, "
                                "description=?, tags=?, validator=?, entropy_context=?, "
                                "updated_at=?, updated_by=? WHERE name=?",
                                (
                                    r.get("pattern", ""),
                                    r.get("detector", "secrets"),
                                    r.get("severity", "high"),
                                    r.get("description", ""),
                                    json.dumps(r.get("tags", [])),
                                    r.get("validator", ""),
                                    1 if r.get("entropy_context", False) else 0,
                                    now,
                                    "cli",
                                    name,
                                ),
                            )
                        result["updated"] += 1
                    else:
                        conn.execute(
                            "INSERT INTO rules "
                            "(name, pattern, detector, severity, action, enabled, "
                            "tier, source, description, tags, validator, entropy_context, "
                            "created_at, updated_at, created_by, updated_by) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                name,
                                r.get("pattern", ""),
                                r.get("detector", "secrets"),
                                r.get("severity", "high"),
                                r.get("action", ""),
                                1,
                                tier,
                                "import",
                                r.get("description", ""),
                                json.dumps(r.get("tags", [])),
                                r.get("validator", ""),
                                1 if r.get("entropy_context", False) else 0,
                                now,
                                now,
                                "cli",
                                "cli",
                            ),
                        )
                        result["created"] += 1

        return result

    def export_rules(self, tier: Optional[str] = None, detector: Optional[str] = None) -> list:
        """Export rules as dicts for JSON serialization."""
        query = "SELECT " + _RULES_COLUMNS + " FROM rules"
        conditions = []
        params = []  # type: list
        if tier:
            conditions.append("tier = ?")
            params.append(tier)
        if detector:
            conditions.append("detector = ?")
            params.append(detector)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY id"

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["enabled"] = bool(d.get("enabled", 1))
            if isinstance(d.get("tags"), str):
                try:
                    d["tags"] = json.loads(d["tags"])
                except (json.JSONDecodeError, ValueError):
                    d["tags"] = []
            result.append(d)
        return result

    def get_rule_stats(self) -> dict:
        """Rule counts by tier, detector, enabled."""
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
            by_tier = {}
            for row in conn.execute("SELECT tier, COUNT(*) as cnt FROM rules GROUP BY tier"):
                by_tier[row["tier"]] = row["cnt"]
            by_detector = {}
            for row in conn.execute("SELECT detector, COUNT(*) as cnt FROM rules GROUP BY detector"):
                by_detector[row["detector"]] = row["cnt"]
            enabled = conn.execute("SELECT COUNT(*) FROM rules WHERE enabled = 1").fetchone()[0]
        return {
            "total": total,
            "enabled": enabled,
            "disabled": total - enabled,
            "by_tier": by_tier,
            "by_detector": by_detector,
        }

    def reconcile_yaml_rules(self, custom_rules: list) -> dict:
        """Kubernetes-style reconciliation of YAML custom_rules to DB.

        YAML is authoritative for source='yaml' rules: all fields overwrite.
        Dashboard-created and import rules are never touched.

        Returns {"created": [...], "updated": [...], "deleted": [...]}.
        """
        import re as re_mod

        result = {"created": [], "updated": [], "deleted": []}  # type: dict
        now = self._now()

        yaml_by_name = {}
        for rule in custom_rules:
            if not isinstance(rule, dict):
                continue
            name = rule.get("name", "")
            if not name:
                log.warning("custom_rules: rule with missing 'name' skipped")
                continue
            yaml_by_name[name] = rule

        with self._lock:
            with self._connect() as conn:
                # Snapshot YAML-sourced rules inside the lock to avoid TOCTOU
                db_yaml = {}
                for row in conn.execute("SELECT name FROM rules WHERE source = 'yaml'").fetchall():
                    db_yaml[row[0]] = True

                # Delete YAML rules no longer in config
                for name in db_yaml:
                    if name not in yaml_by_name:
                        conn.execute("DELETE FROM rules WHERE name = ? AND source = 'yaml'", (name,))
                        result["deleted"].append(name)

                # Create or update YAML rules
                for name, rule in yaml_by_name.items():
                    pattern = str(rule.get("pattern", ""))
                    if not pattern:
                        continue
                    try:
                        re_mod.compile(pattern)
                    except re_mod.error:
                        log.warning("custom_rules '%s': invalid regex, skipping", name)
                        continue

                    if name in db_yaml:
                        conn.execute(
                            "UPDATE rules SET pattern=?, detector=?, severity=?, "
                            "action=?, description=?, updated_at=?, updated_by=? "
                            "WHERE name=? AND source='yaml'",
                            (
                                pattern,
                                str(rule.get("detector", "custom")),
                                str(rule.get("severity", "high")),
                                str(rule.get("action", "")),
                                str(rule.get("description", "")),
                                now,
                                "config",
                                name,
                            ),
                        )
                        result["updated"].append(name)
                    else:
                        # Check if name conflicts with non-yaml rule
                        existing = conn.execute("SELECT source FROM rules WHERE name = ?", (name,)).fetchone()
                        if existing:
                            log.warning(
                                "custom_rules '%s' conflicts with %s rule — skipping",
                                name,
                                existing[0],
                            )
                            continue
                        conn.execute(
                            "INSERT INTO rules "
                            "(name, pattern, detector, severity, action, enabled, "
                            "tier, source, description, tags, validator, entropy_context, "
                            "created_at, updated_at, created_by, updated_by) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                name,
                                pattern,
                                str(rule.get("detector", "custom")),
                                str(rule.get("severity", "high")),
                                str(rule.get("action", "")),
                                1,
                                "custom",
                                "yaml",
                                str(rule.get("description", "")),
                                "[]",
                                "",
                                0,
                                now,
                                now,
                                "config",
                                "config",
                            ),
                        )
                        result["created"].append(name)

        return result

    # --- Notification channels ---

    def _now(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _parse_channel_row(self, row: sqlite3.Row) -> dict:
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

    def list_notification_channels(self, source: Optional[str] = None) -> list:
        """Return all channels, optionally filtered by source."""
        query = (
            "SELECT "
            + _CHANNEL_COLUMNS
            + " FROM notification_channels"
            + (" WHERE source = ?" if source else "")
            + " ORDER BY id"
        )
        params = [source] if source else []
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._parse_channel_row(r) for r in rows]

    def get_notification_channel(self, channel_id: int) -> Optional[dict]:
        """Return a single channel by ID (with full config)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT " + _CHANNEL_COLUMNS + " FROM notification_channels WHERE id = ?",
                (channel_id,),
            ).fetchone()
        return self._parse_channel_row(row) if row else None

    def count_notification_channels(self) -> int:
        """Return total channel count (for limit enforcement)."""
        with self._connect() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM notification_channels",
            ).fetchone()[0]

    def create_notification_channel(
        self,
        data: dict,
        channel_limit: "Optional[int]" = None,
    ) -> dict:
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
        with self._lock:
            with self._connect() as conn:
                # Atomic limit check under the same lock as insert
                if channel_limit is not None:
                    current = conn.execute("SELECT COUNT(*) FROM notification_channels").fetchone()[0]
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
                    channel_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                except sqlite3.IntegrityError:
                    raise ValueError("channel name '%s' already exists" % name)

        return self.get_notification_channel(channel_id)

    def update_notification_channel(self, channel_id: int, data: dict) -> Optional[dict]:
        """Update channel fields. Only updates provided keys."""
        updates = []  # type: List[str]
        params = []  # type: list
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
            return self.get_notification_channel(channel_id)

        updates.append("updated_at = ?")
        params.append(self._now())
        if "updated_by" in data:
            updates.append("updated_by = ?")
            params.append(data["updated_by"])
        params.append(channel_id)

        with self._lock:
            with self._connect() as conn:
                try:
                    cursor = conn.execute(
                        "UPDATE notification_channels SET %s WHERE id = ?" % ", ".join(updates),
                        params,
                    )
                except sqlite3.IntegrityError:
                    raise ValueError("channel name '%s' already exists" % data.get("name", ""))
                if cursor.rowcount == 0:
                    return None

        return self.get_notification_channel(channel_id)

    def delete_notification_channel(self, channel_id: int) -> bool:
        """Delete a channel by ID. Returns True if deleted."""
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM notification_channels WHERE id = ?",
                    (channel_id,),
                )
                return cursor.rowcount > 0

    def bulk_update_channels(self, ids: list, action: str) -> int:
        """Bulk enable/disable/delete. Returns count affected."""
        if not ids:
            return 0
        placeholders = ",".join("?" for _ in ids)
        with self._lock:
            with self._connect() as conn:
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
                        [enabled, self._now()] + ids,
                    )
                else:
                    return 0
                return cursor.rowcount

    def reconcile_yaml_channels(
        self,
        yaml_channels: list,
        channel_limit: Optional[int] = None,
    ) -> dict:
        """Kubernetes-style declarative reconciliation of YAML channels.

        YAML is fully authoritative for source='yaml' channels: all fields
        (including enabled) overwrite DB values on every reconcile.

        channel_limit: max total channels (None = unlimited). Only blocks
        new creates — existing YAML channels are always updated.
        """
        result = {"created": [], "updated": [], "deleted": []}  # type: dict

        # Build lookup of YAML channels by name
        yaml_by_name = {}
        for ch in yaml_channels:
            if not isinstance(ch, dict):
                continue
            name = ch.get("name", "")
            if name:
                yaml_by_name[name] = ch

        # Get current DB state
        db_yaml = {ch["name"]: ch for ch in self.list_notification_channels(source="yaml")}
        db_dashboard_names = {ch["name"] for ch in self.list_notification_channels(source="dashboard")}
        current_total = self.count_notification_channels()

        # Delete YAML channels no longer in config
        for name, db_ch in db_yaml.items():
            if name not in yaml_by_name:
                self.delete_notification_channel(db_ch["id"])
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
                self.update_notification_channel(db_yaml[name]["id"], channel_data)
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
                self.create_notification_channel(channel_data)
                current_total += 1
                result["created"].append(name)

        return result
