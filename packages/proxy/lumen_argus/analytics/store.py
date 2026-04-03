"""Analytics store for community dashboard.

Stores summarized finding data (no raw secrets/PII values) with
aggregation queries for dashboard charts. Includes scheduled cleanup
for retention enforcement.

Database-agnostic via DatabaseAdapter — defaults to SQLiteAdapter
(stdlib sqlite3, zero dependencies). Pro can inject PostgresAdapter
via extensions.set_database_adapter().
"""

import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Callable

from lumen_argus.analytics.adapter import DatabaseAdapter, SQLiteAdapter
from lumen_argus.analytics.allowlists import _ALLOWLIST_SCHEMA, AllowlistRepository
from lumen_argus.analytics.channels import _NOTIFICATION_SCHEMA, ChannelsRepository
from lumen_argus.analytics.config_overrides import _CONFIG_OVERRIDES_SCHEMA, ConfigOverridesRepository
from lumen_argus.analytics.enrollment import _ENROLLMENT_SCHEMA, EnrollmentRepository
from lumen_argus.analytics.findings import _SCHEMA, FindingsRepository
from lumen_argus.analytics.mcp_tool_lists import _MCP_TOOL_LISTS_SCHEMA, MCPToolListsRepository
from lumen_argus.analytics.rule_analysis_repo import _RULE_ANALYSIS_SCHEMA, RuleAnalysisRepository
from lumen_argus.analytics.rules import _RULES_SCHEMA, RulesRepository
from lumen_argus.analytics.ws_connections import _WS_CONNECTIONS_SCHEMA, WebSocketConnectionsRepository
from lumen_argus.models import Finding, SessionContext
from lumen_argus_core.time_utils import now_iso

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
    """Database-agnostic analytics store for finding history and trend queries.

    Delegates connection management and SQL dialect to a DatabaseAdapter.
    Defaults to SQLiteAdapter (thread-local connections, WAL mode).
    Pro can inject PostgresAdapter (connection pool, MVCC).
    """

    def __init__(
        self,
        db_path: str = "~/.lumen-argus/analytics.db",
        hmac_key: bytes | None = None,
        adapter: DatabaseAdapter | None = None,
    ) -> None:
        if adapter:
            self._adapter = adapter
        else:
            self._adapter = SQLiteAdapter(db_path)
        self._hmac_key = hmac_key
        # Repositories use `with self._store._lock:` for write serialization.
        # SQLite: real threading.Lock. PostgreSQL: no-op lock (MVCC).
        self._lock = self._adapter.lock
        self._rules_change_callback: Callable[..., Any] | None = None
        self._ensure_db()
        self.findings = FindingsRepository(self)
        self.rules = RulesRepository(self)
        self.channels = ChannelsRepository(self)
        self.config_overrides = ConfigOverridesRepository(self)
        self.mcp_tool_lists = MCPToolListsRepository(self)
        self.ws_connections = WebSocketConnectionsRepository(self)
        self.allowlists = AllowlistRepository(self)
        self.rule_analysis = RuleAnalysisRepository(self)
        self.enrollment = EnrollmentRepository(self)

    def _ensure_db(self) -> None:
        """Create the database and schema if they don't exist."""
        all_schemas = "\n".join(
            [
                _SCHEMA,
                _RULES_SCHEMA,
                _NOTIFICATION_SCHEMA,
                _SCHEMA_VERSION,
                _CONFIG_OVERRIDES_SCHEMA,
                _MCP_TOOL_LISTS_SCHEMA,
                _MCP_DETECTED_TOOLS_SCHEMA,
                _MCP_TOOL_CALLS_SCHEMA,
                _MCP_TOOL_BASELINES_SCHEMA,
                _WS_CONNECTIONS_SCHEMA,
                _ALLOWLIST_SCHEMA,
                _RULE_ANALYSIS_SCHEMA,
                _ENROLLMENT_SCHEMA,
            ]
        )
        self._adapter.ensure_schema(all_schemas)

    def _connect(self) -> sqlite3.Connection:
        """Return a database connection via the adapter.

        Repositories call this — the adapter handles the lifecycle
        (thread-local for SQLite, pooled for PostgreSQL).

        Typed as sqlite3.Connection for community (all repos expect DB-API 2.0).
        Pro widens this when PostgresAdapter is active.
        """
        conn: sqlite3.Connection = self._adapter.connect()
        return conn

    @contextmanager
    def _write_lock(self) -> Any:
        """Acquire write lock via the adapter.

        SQLite: threading.Lock (single-writer serialization).
        PostgreSQL: no-op (MVCC handles concurrency).
        """
        with self._adapter.write_lock():
            yield

    def _now(self) -> str:
        return now_iso()

    def set_rules_change_callback(self, callback: Callable[..., Any] | None) -> None:
        """Register callback for rule changes.

        callback(change_type, rule_name=None)
        - change_type: "update" | "create" | "delete" | "bulk"
        - rule_name: specific rule name for single-rule changes, None for bulk
        """
        self._rules_change_callback = callback

    def _notify_rules_changed(self, change_type: str, rule_name: str | None = None) -> None:
        if self._rules_change_callback:
            try:
                self._rules_change_callback(change_type, rule_name=rule_name)
            except Exception:
                log.warning("rules change callback failed for %s (rule=%s)", change_type, rule_name, exc_info=True)

    def start_cleanup_scheduler(self, retention_days: int = 365) -> None:
        """Start a background thread that runs cleanup daily."""

        def _cleanup_loop() -> None:
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

    def record_findings(
        self,
        findings: list[Finding],
        provider: str = "",
        model: str = "",
        session: SessionContext | None = None,
    ) -> None:
        return self.findings.record(findings, provider=provider, model=model, session=session)

    def get_findings_page(
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
        return self.findings.get_page(
            limit=limit,
            offset=offset,
            severity=severity,
            detector=detector,
            provider=provider,
            session_id=session_id,
            account_id=account_id,
            action=action,
            finding_type=finding_type,
            client_name=client_name,
            days=days,
        )

    def get_finding_by_id(self, finding_id: int) -> dict[str, Any] | None:
        return self.findings.get_by_id(finding_id)

    def get_stats(self, days: int = 30) -> dict[str, Any]:
        return self.findings.get_stats(days=days)

    def get_total_count(
        self,
        severity: str | None = None,
        detector: str | None = None,
        provider: str | None = None,
    ) -> int:
        return self.findings.get_total_count(severity=severity, detector=detector, provider=provider)

    def get_sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.findings.get_sessions(limit=limit)

    def get_dashboard_sessions(self, limit: int = 5, hours: int = 24) -> dict[str, Any]:
        return self.findings.get_dashboard_sessions(limit=limit, hours=hours)

    def get_account_stats(self, limit: int = 10) -> list[dict[str, Any]]:
        return self.findings.get_account_stats(limit=limit)

    def bump_seen_counts(self, session_id: str) -> None:
        return self.findings.bump_seen_counts(session_id)

    def get_action_trend(self, days: int = 30) -> list[dict[str, Any]]:
        return self.findings.get_action_trend(days=days)

    def get_activity_matrix(self, days: int = 30) -> list[dict[str, Any]]:
        return self.findings.get_activity_matrix(days=days)

    def get_top_accounts(self, days: int = 30, limit: int = 8) -> list[dict[str, Any]]:
        return self.findings.get_top_accounts(days=days, limit=limit)

    def get_top_projects(self, days: int = 30, limit: int = 8) -> list[dict[str, Any]]:
        return self.findings.get_top_projects(days=days, limit=limit)

    def cleanup(self, retention_days: int = 365) -> int:
        return self.findings.cleanup(retention_days)

    # --- Rules facade ---

    def get_rules_count(self) -> int:
        return self.rules.get_count()

    def get_rules_coverage(self) -> dict[str, int]:
        return self.rules.get_coverage()

    def get_active_rules(
        self,
        detector: str | None = None,
        tier: str | None = None,
    ) -> list[dict[str, Any]]:
        return self.rules.get_active(detector=detector, tier=tier)

    def get_rules_page(
        self,
        limit: int = 50,
        offset: int = 0,
        search: str | None = None,
        detector: str | None = None,
        tier: str | None = None,
        enabled: bool | None = None,
        severity: str | None = None,
        tag: str | None = None,
    ) -> tuple[list[dict[str, Any]], Any]:
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

    def get_rule_tag_stats(self) -> list[dict[str, Any]]:
        return self.rules.get_tag_stats()

    def get_rule_by_name(self, name: str) -> dict[str, Any] | None:
        return self.rules.get_by_name(name)

    def create_rule(self, data: dict[str, Any]) -> dict[str, Any] | None:
        return self.rules.create(data)

    def update_rule(self, name: str, data: dict[str, Any]) -> dict[str, Any] | None:
        return self.rules.update(name, data)

    def delete_rule(self, name: str) -> bool:
        return self.rules.delete(name)

    def clone_rule(self, name: str, new_name: str) -> dict[str, Any] | None:
        return self.rules.clone(name, new_name)

    def import_rules(
        self,
        rules: list[dict[str, Any]],
        tier: str = "community",
        force: bool = False,
    ) -> dict[str, int]:
        return self.rules.import_bulk(rules, tier=tier, force=force)

    def export_rules(
        self,
        tier: str | None = None,
        detector: str | None = None,
    ) -> list[dict[str, Any]]:
        return self.rules.export(tier=tier, detector=detector)

    def get_rule_stats(self) -> dict[str, Any]:
        return self.rules.get_stats()

    def reconcile_yaml_rules(self, custom_rules: list[Any]) -> dict[str, list[str]]:
        return self.rules.reconcile_yaml(custom_rules)

    # --- Channels facade ---

    def list_notification_channels(self, source: str | None = None) -> list[dict[str, Any]]:
        return self.channels.list_all(source=source)

    def get_notification_channel(self, channel_id: int) -> dict[str, Any] | None:
        return self.channels.get(channel_id)

    def count_notification_channels(self) -> int:
        return self.channels.count()

    def create_notification_channel(
        self,
        data: dict[str, Any],
        channel_limit: int | None = None,
    ) -> dict[str, Any] | None:
        return self.channels.create(data, channel_limit=channel_limit)

    def update_notification_channel(self, channel_id: int, data: dict[str, Any]) -> dict[str, Any] | None:
        return self.channels.update(channel_id, data)

    def delete_notification_channel(self, channel_id: int) -> bool:
        return self.channels.delete(channel_id)

    def bulk_update_channels(self, ids: list[int], action: str) -> int:
        return self.channels.bulk_update(ids, action)

    def reconcile_yaml_channels(
        self,
        yaml_channels: list[Any],
        channel_limit: int | None = None,
    ) -> dict[str, list[str]]:
        return self.channels.reconcile_yaml(yaml_channels, channel_limit=channel_limit)

    # --- WebSocket connections facade ---

    def record_ws_connection_open(
        self,
        connection_id: str,
        target_url: str,
        origin: str,
        timestamp: float,
    ) -> None:
        return self.ws_connections.record_open(connection_id, target_url, origin, timestamp)

    def record_ws_connection_close(
        self,
        connection_id: str,
        timestamp: float,
        duration: float,
        frames_sent: int,
        frames_received: int,
        findings_count: int,
        close_code: int | None,
    ) -> None:
        return self.ws_connections.record_close(
            connection_id, timestamp, duration, frames_sent, frames_received, findings_count, close_code
        )

    def increment_ws_findings(self, connection_id: str, count: int) -> None:
        return self.ws_connections.increment_findings(connection_id, count)

    def get_ws_connections(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        return self.ws_connections.get_connections(limit=limit, offset=offset)

    def get_ws_stats(self, days: int = 7) -> dict[str, Any]:
        return self.ws_connections.get_stats(days=days)

    def cleanup_ws_connections(self, retention_days: int = 365) -> int:
        return self.ws_connections.cleanup(retention_days=retention_days)

    # --- Allowlists facade ---

    def add_allowlist_entry(
        self,
        list_type: str,
        pattern: str,
        description: str = "",
        created_by: str = "",
    ) -> dict[str, Any]:
        return self.allowlists.add(list_type, pattern, description=description, created_by=created_by)

    def update_allowlist_entry(self, entry_id: int, data: dict[str, Any]) -> dict[str, Any] | None:
        return self.allowlists.update(entry_id, data)

    def get_allowlist_entry(self, entry_id: int) -> dict[str, Any] | None:
        return self.allowlists.get(entry_id)

    def delete_allowlist_entry(self, entry_id: int) -> bool:
        return self.allowlists.delete(entry_id)

    def list_allowlist_entries(self, list_type: str | None = None) -> list[dict[str, Any]]:
        return self.allowlists.list_all(list_type=list_type)

    def list_enabled_allowlist_entries(self, list_type: str | None = None) -> list[dict[str, Any]]:
        return self.allowlists.list_enabled(list_type=list_type)

    # --- Config overrides facade ---

    def get_config_overrides(self) -> dict[str, Any]:
        return self.config_overrides.get_all()

    def set_config_override(self, key: str, value: Any) -> None:
        return self.config_overrides.set(key, value)

    def delete_config_override(self, key: str) -> bool:
        return self.config_overrides.delete(key)

    # --- MCP tool lists facade ---

    def get_mcp_tool_lists(self) -> dict[str, list[dict[str, Any]]]:
        return self.mcp_tool_lists.get_lists()

    def add_mcp_tool_entry(self, list_type: str, tool_name: str) -> int | None:
        return self.mcp_tool_lists.add_entry(list_type, tool_name)

    def delete_mcp_tool_entry(self, entry_id: int) -> bool:
        return self.mcp_tool_lists.delete_entry(entry_id)

    def reconcile_mcp_tool_lists(
        self,
        yaml_allowed: list[Any] | None,
        yaml_blocked: list[Any] | None,
    ) -> dict[str, int]:
        return self.mcp_tool_lists.reconcile(yaml_allowed, yaml_blocked)

    # --- MCP detected tools tracking ---

    def record_mcp_tool_seen(self, tool_name: str, description: str = "", input_schema: str = "") -> None:
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

    def get_mcp_detected_tools(self) -> list[dict[str, Any]]:
        """Return all detected MCP tools with metadata and call counts."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT tool_name, description, input_schema, first_seen, last_seen, call_count "
                "FROM mcp_detected_tools ORDER BY call_count DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    # --- MCP tool call logging ---

    def record_mcp_tool_call(
        self,
        tool_name: str,
        session_id: str = "",
        status: str = "allowed",
        finding_count: int = 0,
        source: str = "proxy",
    ) -> None:
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

    def get_mcp_tool_calls(
        self,
        session_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return recent MCP tool calls, optionally filtered by session."""
        query = "SELECT id, tool_name, session_id, timestamp, status, finding_count, source FROM mcp_tool_calls"
        params: list[Any] = []
        if session_id:
            query += " WHERE session_id = ?"
            params.append(session_id)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def cleanup_mcp_tool_calls(self, retention_days: int = 30) -> int:
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

    def get_mcp_tool_baseline(self, tool_name: str) -> dict[str, Any] | None:
        """Get stored baseline for a tool. Returns dict or None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT tool_name, definition_hash, description, param_names, "
                "first_seen, last_seen, drift_count FROM mcp_tool_baselines WHERE tool_name = ?",
                (tool_name,),
            ).fetchone()
        return dict(row) if row else None

    def record_mcp_tool_baseline(
        self,
        tool_name: str,
        definition_hash: str,
        description: str,
        param_names: list[str],
    ) -> None:
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

    def update_mcp_tool_baseline_seen(self, tool_name: str) -> None:
        """Update last_seen timestamp for a tool baseline."""
        now = self._now()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE mcp_tool_baselines SET last_seen = ? WHERE tool_name = ?",
                    (now, tool_name),
                )

    def increment_mcp_tool_drift_count(self, tool_name: str) -> None:
        """Increment drift_count for a tool that changed."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE mcp_tool_baselines SET drift_count = drift_count + 1 WHERE tool_name = ?",
                    (tool_name,),
                )

    # --- Private helper kept for backward compat (used by channels internally) ---

    def _parse_channel_row(self, row: Any) -> dict[str, Any]:
        return self.channels._parse_row(row)
