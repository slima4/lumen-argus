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
from lumen_argus.analytics.config_overrides import ConfigOverridesRepository, _CONFIG_OVERRIDES_SCHEMA
from lumen_argus.analytics.mcp_tool_lists import MCPToolListsRepository, _MCP_TOOL_LISTS_SCHEMA
from lumen_argus.analytics.ws_connections import WebSocketConnectionsRepository, _WS_CONNECTIONS_SCHEMA

log = logging.getLogger("argus.analytics")

_SCHEMA_VERSION = """\
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TEXT NOT NULL
);
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

_MCP_TOOL_BASELINES_SCHEMA = """\
CREATE TABLE IF NOT EXISTS mcp_tool_baselines (
    tool_name TEXT PRIMARY KEY,
    definition_hash TEXT NOT NULL,
    description TEXT,
    param_names TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    drift_count INTEGER DEFAULT 0
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
        self._rules_change_callback = None
        self._ensure_db()
        self.findings = FindingsRepository(self)
        self.rules = RulesRepository(self)
        self.channels = ChannelsRepository(self)
        self.config_overrides = ConfigOverridesRepository(self)
        self.mcp_tool_lists = MCPToolListsRepository(self)
        self.ws_connections = WebSocketConnectionsRepository(self)

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
            conn.executescript(_MCP_TOOL_BASELINES_SCHEMA)
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

    # --- WebSocket connections facade ---

    def record_ws_connection_open(self, connection_id, target_url, origin, timestamp):
        return self.ws_connections.record_open(connection_id, target_url, origin, timestamp)

    def record_ws_connection_close(
        self, connection_id, timestamp, duration, frames_sent, frames_received, findings_count, close_code
    ):
        return self.ws_connections.record_close(
            connection_id, timestamp, duration, frames_sent, frames_received, findings_count, close_code
        )

    def increment_ws_findings(self, connection_id, count):
        return self.ws_connections.increment_findings(connection_id, count)

    def get_ws_connections(self, limit=50, offset=0):
        return self.ws_connections.get_connections(limit=limit, offset=offset)

    def get_ws_stats(self, days=7):
        return self.ws_connections.get_stats(days=days)

    def cleanup_ws_connections(self, retention_days=365):
        return self.ws_connections.cleanup(retention_days=retention_days)

    # --- Config overrides facade ---

    def get_config_overrides(self):
        return self.config_overrides.get_all()

    def set_config_override(self, key, value):
        return self.config_overrides.set(key, value)

    def delete_config_override(self, key):
        return self.config_overrides.delete(key)

    # --- MCP tool lists facade ---

    def get_mcp_tool_lists(self):
        return self.mcp_tool_lists.get_lists()

    def add_mcp_tool_entry(self, list_type, tool_name):
        return self.mcp_tool_lists.add_entry(list_type, tool_name)

    def delete_mcp_tool_entry(self, entry_id):
        return self.mcp_tool_lists.delete_entry(entry_id)

    def reconcile_mcp_tool_lists(self, yaml_allowed, yaml_blocked):
        return self.mcp_tool_lists.reconcile(yaml_allowed, yaml_blocked)

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

    # --- MCP Tool Baselines (drift detection) ---

    def get_mcp_tool_baseline(self, tool_name):
        """Get stored baseline for a tool. Returns dict or None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT tool_name, definition_hash, description, param_names, "
                "first_seen, last_seen, drift_count FROM mcp_tool_baselines WHERE tool_name = ?",
                (tool_name,),
            ).fetchone()
        return dict(row) if row else None

    def record_mcp_tool_baseline(self, tool_name, definition_hash, description, param_names):
        """Insert or replace a tool baseline."""
        import json as _json

        now = self._now()
        params_json = _json.dumps(param_names)
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO mcp_tool_baselines (tool_name, definition_hash, description, "
                    "param_names, first_seen, last_seen, drift_count) VALUES (?, ?, ?, ?, ?, ?, 0) "
                    "ON CONFLICT(tool_name) DO UPDATE SET definition_hash=excluded.definition_hash, "
                    "description=excluded.description, param_names=excluded.param_names, last_seen=excluded.last_seen",
                    (tool_name, definition_hash, description, params_json, now, now),
                )

    def update_mcp_tool_baseline_seen(self, tool_name):
        """Update last_seen timestamp for a tool baseline."""
        now = self._now()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE mcp_tool_baselines SET last_seen = ? WHERE tool_name = ?",
                    (now, tool_name),
                )

    def increment_mcp_tool_drift_count(self, tool_name):
        """Increment drift_count for a tool that changed."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE mcp_tool_baselines SET drift_count = drift_count + 1 WHERE tool_name = ?",
                    (tool_name,),
                )

    # --- Private helper kept for backward compat (used by channels internally) ---

    def _parse_channel_row(self, row):
        return self.channels._parse_row(row)
