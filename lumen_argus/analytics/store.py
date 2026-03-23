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


from lumen_argus.analytics.findings import FindingsRepository, _SCHEMA
from lumen_argus.analytics.rules import RulesRepository, _RULES_SCHEMA
from lumen_argus.analytics.channels import ChannelsRepository, _NOTIFICATION_SCHEMA

log = logging.getLogger("argus.analytics")

_SCHEMA_VERSION = """\
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TEXT NOT NULL
);
"""

_CONFIG_OVERRIDES_SCHEMA = """\
CREATE TABLE IF NOT EXISTS config_overrides (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

_MCP_TOOL_LISTS_SCHEMA = """\
CREATE TABLE IF NOT EXISTS mcp_tool_lists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    list_type TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'api',
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_tool_unique
    ON mcp_tool_lists(list_type, tool_name);
"""

_MCP_DETECTED_TOOLS_SCHEMA = """\
CREATE TABLE IF NOT EXISTS mcp_detected_tools (
    tool_name TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    input_schema TEXT NOT NULL DEFAULT '{}',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    call_count INTEGER NOT NULL DEFAULT 1
);
"""

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

_MCP_TOOL_CALLS_SCHEMA = """\
CREATE TABLE IF NOT EXISTS mcp_tool_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT NOT NULL,
    session_id TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'allowed',
    finding_count INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL DEFAULT 'proxy'
);
CREATE INDEX IF NOT EXISTS idx_mcp_calls_session ON mcp_tool_calls(session_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_mcp_calls_ts ON mcp_tool_calls(timestamp);
"""

# Community-editable config keys with validation rules
_VALID_CONFIG_KEYS = {
    "proxy.timeout",
    "proxy.retries",
    "default_action",
    "detectors.secrets.enabled",
    "detectors.pii.enabled",
    "detectors.proprietary.enabled",
    "detectors.secrets.action",
    "detectors.pii.action",
    "detectors.proprietary.action",
    "pipeline.stages.outbound_dlp.enabled",
    "pipeline.stages.encoding_decode.enabled",
    "pipeline.stages.encoding_decode.base64",
    "pipeline.stages.encoding_decode.hex",
    "pipeline.stages.encoding_decode.url",
    "pipeline.stages.encoding_decode.unicode",
    "pipeline.stages.encoding_decode.max_depth",
    "pipeline.stages.encoding_decode.min_decoded_length",
    "pipeline.stages.encoding_decode.max_decoded_length",
    "pipeline.stages.response_secrets.enabled",
    "pipeline.stages.response_injection.enabled",
    "pipeline.stages.mcp_arguments.enabled",
    "pipeline.stages.mcp_responses.enabled",
    "pipeline.stages.websocket_outbound.enabled",
    "pipeline.stages.websocket_inbound.enabled",
    "pipeline.parallel_batching",
}

_VALID_ACTIONS = {"log", "alert", "block"}


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
        self._rules_change_callback = None
        self._ensure_db()
        self.findings = FindingsRepository(self)
        self.rules = RulesRepository(self)
        self.channels = ChannelsRepository(self)

    def _ensure_db(self) -> None:
        """Create the database and schema if they don't exist."""
        db_dir = Path(self._db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            conn.executescript(_RULES_SCHEMA)
            conn.executescript(_NOTIFICATION_SCHEMA)
            conn.executescript(_SCHEMA_VERSION)
            conn.executescript(_CONFIG_OVERRIDES_SCHEMA)
            conn.executescript(_MCP_TOOL_LISTS_SCHEMA)
            conn.executescript(_MCP_DETECTED_TOOLS_SCHEMA)
            conn.executescript(_MCP_TOOL_CALLS_SCHEMA)
            conn.executescript(_WS_CONNECTIONS_SCHEMA)
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

    def _now(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def set_rules_change_callback(self, callback) -> None:
        """Register callback for rule changes.

        callback(change_type, rule_name=None)
        - change_type: "update" | "create" | "delete" | "bulk"
        - rule_name: specific rule name for single-rule changes, None for bulk
        """
        self._rules_change_callback = callback

    def _notify_rules_changed(self, change_type, rule_name=None):
        if self._rules_change_callback:
            try:
                self._rules_change_callback(change_type, rule_name=rule_name)
            except Exception:
                pass

    def start_cleanup_scheduler(self, retention_days: int = 365) -> None:
        """Start a background thread that runs cleanup daily."""

        def _cleanup_loop():
            while True:
                time.sleep(86400)  # 24 hours
                try:
                    self.cleanup(retention_days)
                    self.cleanup_ws_connections(retention_days)
                except Exception as e:
                    log.error("analytics cleanup failed: %s", e)

        t = threading.Thread(target=_cleanup_loop, daemon=True, name="analytics-cleanup")
        t.start()

    # --- Findings facade ---

    def record_findings(self, findings, provider="", model="", session=None):
        return self.findings.record(findings, provider=provider, model=model, session=session)

    def get_findings_page(
        self, limit=50, offset=0, severity=None, detector=None, provider=None, session_id=None, account_id=None
    ):
        return self.findings.get_page(
            limit=limit,
            offset=offset,
            severity=severity,
            detector=detector,
            provider=provider,
            session_id=session_id,
            account_id=account_id,
        )

    def get_finding_by_id(self, finding_id):
        return self.findings.get_by_id(finding_id)

    def get_stats(self, days: int = 30):
        return self.findings.get_stats(days=days)

    def get_total_count(self, severity=None, detector=None, provider=None):
        return self.findings.get_total_count(severity=severity, detector=detector, provider=provider)

    def get_sessions(self, limit=50):
        return self.findings.get_sessions(limit=limit)

    def get_account_stats(self, limit=10):
        return self.findings.get_account_stats(limit=limit)

    def bump_seen_counts(self, session_id):
        return self.findings.bump_seen_counts(session_id)

    def get_action_trend(self, days=30):
        return self.findings.get_action_trend(days=days)

    def get_activity_matrix(self, days=30):
        return self.findings.get_activity_matrix(days=days)

    def get_top_accounts(self, days=30, limit=8):
        return self.findings.get_top_accounts(days=days, limit=limit)

    def get_top_projects(self, days=30, limit=8):
        return self.findings.get_top_projects(days=days, limit=limit)

    def cleanup(self, retention_days=365):
        return self.findings.cleanup(retention_days)

    # --- Rules facade ---

    def get_rules_count(self):
        return self.rules.get_count()

    def get_rules_coverage(self):
        return self.rules.get_coverage()

    def get_active_rules(self, detector=None, tier=None):
        return self.rules.get_active(detector=detector, tier=tier)

    def get_rules_page(
        self, limit=50, offset=0, search=None, detector=None, tier=None, enabled=None, severity=None, tag=None
    ):
        return self.rules.get_page(
            limit=limit,
            offset=offset,
            search=search,
            detector=detector,
            tier=tier,
            enabled=enabled,
            severity=severity,
            tag=tag,
        )

    def get_rule_tag_stats(self):
        return self.rules.get_tag_stats()

    def get_rule_by_name(self, name):
        return self.rules.get_by_name(name)

    def create_rule(self, data):
        return self.rules.create(data)

    def update_rule(self, name, data):
        return self.rules.update(name, data)

    def delete_rule(self, name):
        return self.rules.delete(name)

    def clone_rule(self, name, new_name):
        return self.rules.clone(name, new_name)

    def import_rules(self, rules, tier="community", force=False):
        return self.rules.import_bulk(rules, tier=tier, force=force)

    def export_rules(self, tier=None, detector=None):
        return self.rules.export(tier=tier, detector=detector)

    def get_rule_stats(self):
        return self.rules.get_stats()

    def reconcile_yaml_rules(self, custom_rules):
        return self.rules.reconcile_yaml(custom_rules)

    # --- Channels facade ---

    def list_notification_channels(self, source=None):
        return self.channels.list(source=source)

    def get_notification_channel(self, channel_id):
        return self.channels.get(channel_id)

    def count_notification_channels(self):
        return self.channels.count()

    def create_notification_channel(self, data, channel_limit=None):
        return self.channels.create(data, channel_limit=channel_limit)

    def update_notification_channel(self, channel_id, data):
        return self.channels.update(channel_id, data)

    def delete_notification_channel(self, channel_id):
        return self.channels.delete(channel_id)

    def bulk_update_channels(self, ids, action):
        return self.channels.bulk_update(ids, action)

    def reconcile_yaml_channels(self, yaml_channels, channel_limit=None):
        return self.channels.reconcile_yaml(yaml_channels, channel_limit=channel_limit)

    # --- WebSocket connections ---

    def record_ws_connection_open(self, connection_id, target_url, origin, timestamp):
        """Record a new WebSocket connection."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO ws_connections (id, target_url, origin, connected_at) VALUES (?, ?, ?, ?)",
                    (connection_id, target_url, origin or "", timestamp),
                )
        log.debug("ws connection open: %s -> %s", connection_id[:8], target_url)

    def record_ws_connection_close(
        self, connection_id, timestamp, duration, frames_sent, frames_received, findings_count, close_code
    ):
        """Update a WebSocket connection record on close."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE ws_connections SET disconnected_at = ?, duration_seconds = ?, "
                    "frames_sent = ?, frames_received = ?, findings_count = findings_count + ?, "
                    "close_code = ? WHERE id = ?",
                    (timestamp, duration, frames_sent, frames_received, findings_count, close_code, connection_id),
                )
        log.debug(
            "ws connection close: %s (%.1fs, %d/%d frames)", connection_id[:8], duration, frames_sent, frames_received
        )

    def increment_ws_findings(self, connection_id, count):
        """Increment findings count for a WebSocket connection."""
        if count <= 0:
            return
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE ws_connections SET findings_count = findings_count + ? WHERE id = ?",
                    (count, connection_id),
                )

    def get_ws_connections(self, limit=50, offset=0):
        """Return recent WebSocket connections, newest first."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, target_url, origin, connected_at, disconnected_at, "
                "duration_seconds, frames_sent, frames_received, findings_count, close_code "
                "FROM ws_connections ORDER BY connected_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_ws_stats(self, days=7):
        """Return aggregate WebSocket stats for the given period."""
        cutoff = time.time() - (days * 86400)
        with self._connect() as conn:
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

    def cleanup_ws_connections(self, retention_days=365):
        """Delete WebSocket connection records older than retention_days."""
        cutoff = time.time() - (retention_days * 86400)
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM ws_connections WHERE connected_at < ?",
                    (cutoff,),
                )
                deleted = cursor.rowcount
        if deleted:
            log.info("ws connections cleanup: %d entries deleted (older than %d days)", deleted, retention_days)
        return deleted

    # --- Config overrides ---

    def get_config_overrides(self):
        """Return all config overrides as a dict."""
        with self._connect() as conn:
            rows = conn.execute("SELECT key, value FROM config_overrides").fetchall()
        overrides = {row["key"]: row["value"] for row in rows}
        log.debug("loaded %d config override(s) from DB", len(overrides))
        return overrides

    def set_config_override(self, key, value):
        """Set a config override. Validates key and value."""
        if key not in _VALID_CONFIG_KEYS:
            raise ValueError("Invalid config key: %s" % key)

        value = str(value)
        if key == "proxy.timeout":
            try:
                v = int(value)
            except (ValueError, TypeError):
                raise ValueError("timeout must be an integer (1-300)")
            if v < 1 or v > 300:
                raise ValueError("timeout must be 1-300")
        elif key == "proxy.retries":
            try:
                v = int(value)
            except (ValueError, TypeError):
                raise ValueError("retries must be an integer (0-10)")
            if v < 0 or v > 10:
                raise ValueError("retries must be 0-10")
        elif key in (
            "default_action",
            "detectors.secrets.action",
            "detectors.pii.action",
            "detectors.proprietary.action",
        ):
            if value not in _VALID_ACTIONS:
                raise ValueError("action must be one of: %s" % ", ".join(sorted(_VALID_ACTIONS)))
        elif key == "pipeline.parallel_batching":
            if value.lower() not in ("true", "false"):
                raise ValueError("parallel_batching must be true or false")
            value = value.lower()
        elif key.endswith(".enabled") or key.endswith((".base64", ".hex", ".url", ".unicode")):
            if value.lower() not in ("true", "false"):
                raise ValueError("%s must be true or false" % key)
            value = value.lower()  # normalize
        elif key == "pipeline.stages.encoding_decode.max_depth":
            try:
                v = int(value)
            except (ValueError, TypeError):
                raise ValueError("max_depth must be an integer (1-5)")
            if v < 1 or v > 5:
                raise ValueError("max_depth must be 1-5")
        elif key == "pipeline.stages.encoding_decode.min_decoded_length":
            try:
                v = int(value)
            except (ValueError, TypeError):
                raise ValueError("min_decoded_length must be an integer (1-100)")
            if v < 1 or v > 100:
                raise ValueError("min_decoded_length must be 1-100")
        elif key == "pipeline.stages.encoding_decode.max_decoded_length":
            try:
                v = int(value)
            except (ValueError, TypeError):
                raise ValueError("max_decoded_length must be an integer (100-1000000)")
            if v < 100 or v > 1_000_000:
                raise ValueError("max_decoded_length must be 100-1000000")

        now = self._now()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO config_overrides (key, value, updated_at) VALUES (?, ?, ?)",
                    (key, value, now),
                )
        log.debug("config override stored: %s = %s", key, value)

    def delete_config_override(self, key):
        """Delete a config override (revert to YAML default)."""
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM config_overrides WHERE key = ?",
                    (key,),
                )
                deleted = cursor.rowcount > 0
        if deleted:
            log.info("config override deleted: %s (reverted to YAML default)", key)
        return deleted

    # --- MCP tool lists ---

    def get_mcp_tool_lists(self):
        """Return MCP tool lists: {"allowed": [...], "blocked": [...]}."""
        log.debug("loading MCP tool lists from DB")
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, list_type, tool_name, source, created_at FROM mcp_tool_lists ORDER BY id"
            ).fetchall()
        result = {"allowed": [], "blocked": []}
        for row in rows:
            entry = {
                "id": row["id"],
                "tool_name": row["tool_name"],
                "source": row["source"],
                "created_at": row["created_at"],
            }
            lt = row["list_type"]
            if lt in result:
                result[lt].append(entry)
        return result

    def add_mcp_tool_entry(self, list_type, tool_name):
        """Add a tool to the allowed or blocked list. Returns the new entry ID."""
        if list_type not in ("allowed", "blocked"):
            raise ValueError("list_type must be 'allowed' or 'blocked'")
        if not tool_name or not tool_name.strip():
            raise ValueError("tool_name must not be empty")
        tool_name = tool_name.strip()
        now = self._now()
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "INSERT OR IGNORE INTO mcp_tool_lists (list_type, tool_name, source, created_at) "
                    "VALUES (?, ?, 'api', ?)",
                    (list_type, tool_name, now),
                )
                entry_id = cursor.lastrowid if cursor.rowcount > 0 else None
        if entry_id:
            log.info("mcp tool list: added '%s' to %s list (id=%d)", tool_name, list_type, entry_id)
        else:
            log.debug("mcp tool list: '%s' already in %s list (ignored)", tool_name, list_type)
        return entry_id

    def delete_mcp_tool_entry(self, entry_id):
        """Remove an MCP tool list entry by ID. Returns True if deleted."""
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM mcp_tool_lists WHERE id = ? AND source = 'api'",
                    (entry_id,),
                )
                deleted = cursor.rowcount > 0
        if deleted:
            log.info("mcp tool list: deleted entry %d", entry_id)
        return deleted

    def reconcile_mcp_tool_lists(self, yaml_allowed, yaml_blocked):
        """Reconcile YAML tool lists with DB entries.

        YAML entries are authoritative for source='config'. API entries untouched.
        Same pattern as reconcile_yaml_channels.
        """
        now = self._now()
        created = 0
        deleted = 0
        with self._lock:
            with self._connect() as conn:
                # Get current config-sourced entries
                existing = conn.execute(
                    "SELECT id, list_type, tool_name FROM mcp_tool_lists WHERE source = 'config'"
                ).fetchall()
                existing_set = {(r["list_type"], r["tool_name"]): r["id"] for r in existing}

                # Build target set from YAML
                target = set()
                for t in yaml_allowed or []:
                    target.add(("allowed", str(t)))
                for t in yaml_blocked or []:
                    target.add(("blocked", str(t)))

                # Delete entries not in YAML
                for key, eid in existing_set.items():
                    if key not in target:
                        conn.execute("DELETE FROM mcp_tool_lists WHERE id = ?", (eid,))
                        deleted += 1

                # Create entries in YAML but not in DB
                for lt, tn in target:
                    if (lt, tn) not in existing_set:
                        conn.execute(
                            "INSERT OR IGNORE INTO mcp_tool_lists "
                            "(list_type, tool_name, source, created_at) VALUES (?, ?, 'config', ?)",
                            (lt, tn, now),
                        )
                        created += 1

        if created or deleted:
            log.info("mcp tool lists reconciled: %d created, %d deleted", created, deleted)
        return {"created": created, "deleted": deleted}

    # --- MCP detected tools tracking ---

    def record_mcp_tool_seen(self, tool_name, description="", input_schema=""):
        """Record a tool seen. Upserts call_count, conditionally updates metadata."""
        if not tool_name:
            return
        now = self._now()
        # Build dynamic UPDATE clause — only overwrite metadata if new values provided
        update_parts = ["last_seen = excluded.last_seen", "call_count = call_count + 1"]
        if description:
            update_parts.append("description = excluded.description")
        if input_schema:
            update_parts.append("input_schema = excluded.input_schema")
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO mcp_detected_tools "
                    "(tool_name, description, input_schema, first_seen, last_seen, call_count) "
                    "VALUES (?, ?, ?, ?, ?, 1) "
                    "ON CONFLICT(tool_name) DO UPDATE SET " + ", ".join(update_parts),
                    (tool_name, description or "", input_schema or "{}", now, now),
                )
        log.debug("mcp tool seen: %s", tool_name)

    def get_mcp_detected_tools(self):
        """Return all detected MCP tools with metadata and call counts."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT tool_name, description, input_schema, first_seen, last_seen, call_count "
                "FROM mcp_detected_tools ORDER BY call_count DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    # --- MCP tool call logging ---

    def record_mcp_tool_call(self, tool_name, session_id="", status="allowed", finding_count=0, source="proxy"):
        """Log an MCP tool call for chain analysis."""
        if not tool_name:
            return
        now = self._now()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO mcp_tool_calls "
                    "(tool_name, session_id, timestamp, status, finding_count, source) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (tool_name, session_id, now, status, finding_count, source),
                )
        log.debug("mcp tool call: %s status=%s findings=%d source=%s", tool_name, status, finding_count, source)

    def get_mcp_tool_calls(self, session_id=None, limit=100):
        """Return recent MCP tool calls, optionally filtered by session."""
        query = "SELECT id, tool_name, session_id, timestamp, status, finding_count, source FROM mcp_tool_calls"
        params = []  # type: list
        if session_id:
            query += " WHERE session_id = ?"
            params.append(session_id)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def cleanup_mcp_tool_calls(self, retention_days=30):
        """Delete MCP tool calls older than retention_days."""
        from datetime import datetime, timedelta, timezone

        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute("DELETE FROM mcp_tool_calls WHERE timestamp < ?", (cutoff,))
                deleted = cursor.rowcount
        if deleted:
            log.info("mcp tool calls cleanup: %d entries deleted (older than %d days)", deleted, retention_days)
        return deleted

    # --- Private helper kept for backward compat (used by channels internally) ---

    def _parse_channel_row(self, row):
        return self.channels._parse_row(row)
