"""Analytics store for community dashboard.

Stores summarized finding data (no raw secrets/PII values) with
aggregation queries for dashboard charts. Includes scheduled cleanup
for retention enforcement.

Database-agnostic via DatabaseAdapter — defaults to SQLiteAdapter
(stdlib sqlite3, zero dependencies). Pro can inject PostgresAdapter
via extensions.set_database_adapter().
"""

import logging
import threading
import time
from typing import Any, Callable

from lumen_argus.analytics.adapter import DatabaseAdapter, DBConnection, SQLiteAdapter
from lumen_argus.analytics.allowlists import AllowlistRepository
from lumen_argus.analytics.channels import ChannelsRepository
from lumen_argus.analytics.config_overrides import ConfigOverridesRepository
from lumen_argus.analytics.enrollment import EnrollmentRepository
from lumen_argus.analytics.findings import FindingsRepository
from lumen_argus.analytics.mcp_policies import MCPPoliciesRepository
from lumen_argus.analytics.mcp_tool_lists import MCPToolListsRepository
from lumen_argus.analytics.mcp_tool_tracking import MCPToolTrackingRepository
from lumen_argus.analytics.rule_analysis_repo import RuleAnalysisRepository
from lumen_argus.analytics.rules import RulesRepository
from lumen_argus.analytics.schema import build_all_schemas
from lumen_argus.analytics.ws_connections import WebSocketConnectionsRepository
from lumen_argus.models import Finding, SessionContext

log = logging.getLogger("argus.analytics")


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
        self._rules_change_callback: Callable[..., Any] | None = None
        self._ensure_db()
        # Repositories receive adapter directly (DDD repository pattern)
        self.findings = FindingsRepository(self._adapter, hmac_key=hmac_key)
        self.rules = RulesRepository(self._adapter, on_rules_changed=self._notify_rules_changed)
        self.channels = ChannelsRepository(self._adapter)
        self.config_overrides = ConfigOverridesRepository(self._adapter)
        self.mcp_tool_lists = MCPToolListsRepository(self._adapter)
        self.ws_connections = WebSocketConnectionsRepository(self._adapter)
        self.allowlists = AllowlistRepository(self._adapter)
        self.rule_analysis = RuleAnalysisRepository(self._adapter)
        self.enrollment = EnrollmentRepository(self._adapter)
        self.mcp_tool_tracking = MCPToolTrackingRepository(self._adapter)
        self.mcp_policies = MCPPoliciesRepository(self._adapter)

    def _ensure_db(self) -> None:
        """Create the database and schema if they don't exist."""
        self._adapter.ensure_schema(build_all_schemas(self._adapter))

    def _connect(self) -> DBConnection:
        """Return a database connection via the adapter.

        Used by detectors/rules.py for hit-count flush and by tests.
        Repositories use BaseRepository._connect() directly.
        """
        return self._adapter.connect()

    def set_rules_change_callback(self, callback: Callable[..., Any] | None) -> None:
        """Register callback for rule changes.

        callback(change_type, rule_name=None)
        - change_type: "update" | "create" | "delete" | "bulk"
        - rule_name: specific rule name for single-rule changes, None for bulk
        """
        self._rules_change_callback = callback

    def _notify_rules_changed(self, change_type: str, rule_name: str | None = None) -> None:
        """Bridge to the registered callback. Error handling is in RulesRepository."""
        if self._rules_change_callback:
            self._rules_change_callback(change_type, rule_name=rule_name)

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
        namespace_id: int = 1,
    ) -> None:
        return self.findings.record(
            findings, provider=provider, model=model, session=session, namespace_id=namespace_id
        )

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
        working_directory: str | None = None,
        hostname: str | None = None,
        username: str | None = None,
        sdk_name: str | None = None,
        runtime: str | None = None,
        intercept_mode: str | None = None,
        original_host: str | None = None,
        days: int | None = None,
        namespace_id: int = 1,
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
            working_directory=working_directory,
            hostname=hostname,
            username=username,
            sdk_name=sdk_name,
            runtime=runtime,
            intercept_mode=intercept_mode,
            original_host=original_host,
            days=days,
            namespace_id=namespace_id,
        )

    def get_finding_by_id(self, finding_id: int, namespace_id: int = 1) -> dict[str, Any] | None:
        return self.findings.get_by_id(finding_id, namespace_id=namespace_id)

    def get_stats(self, days: int = 30, namespace_id: int = 1) -> dict[str, Any]:
        return self.findings.get_stats(days=days, namespace_id=namespace_id)

    def get_total_count(
        self,
        severity: str | None = None,
        detector: str | None = None,
        provider: str | None = None,
        namespace_id: int = 1,
    ) -> int:
        return self.findings.get_total_count(
            severity=severity,
            detector=detector,
            provider=provider,
            namespace_id=namespace_id,
        )

    def get_sessions(self, limit: int = 50, namespace_id: int = 1) -> list[dict[str, Any]]:
        return self.findings.get_sessions(limit=limit, namespace_id=namespace_id)

    def get_dashboard_sessions(self, limit: int = 5, hours: int = 24, namespace_id: int = 1) -> dict[str, Any]:
        return self.findings.get_dashboard_sessions(limit=limit, hours=hours, namespace_id=namespace_id)

    def get_account_stats(self, limit: int = 10, namespace_id: int = 1) -> list[dict[str, Any]]:
        return self.findings.get_account_stats(limit=limit, namespace_id=namespace_id)

    def bump_seen_counts(self, session_id: str, namespace_id: int = 1) -> None:
        return self.findings.bump_seen_counts(session_id, namespace_id=namespace_id)

    def get_action_trend(self, days: int = 30, namespace_id: int = 1) -> list[dict[str, Any]]:
        return self.findings.get_action_trend(days=days, namespace_id=namespace_id)

    def get_activity_matrix(self, days: int = 30, namespace_id: int = 1) -> list[dict[str, Any]]:
        return self.findings.get_activity_matrix(days=days, namespace_id=namespace_id)

    def get_top_accounts(self, days: int = 30, limit: int = 8, namespace_id: int = 1) -> list[dict[str, Any]]:
        return self.findings.get_top_accounts(days=days, limit=limit, namespace_id=namespace_id)

    def get_top_projects(self, days: int = 30, limit: int = 8, namespace_id: int = 1) -> list[dict[str, Any]]:
        return self.findings.get_top_projects(days=days, limit=limit, namespace_id=namespace_id)

    def get_by_project(self, days: int = 30, limit: int = 20, namespace_id: int = 1) -> list[dict[str, Any]]:
        return self.findings.get_by_project(days=days, limit=limit, namespace_id=namespace_id)

    def cleanup(self, retention_days: int = 365, namespace_id: int = 1) -> int:
        return self.findings.cleanup(retention_days, namespace_id=namespace_id)

    # --- Rules facade ---

    def get_rules_count(self, namespace_id: int = 1) -> int:
        return self.rules.get_count(namespace_id=namespace_id)

    def get_rules_coverage(self, namespace_id: int = 1) -> dict[str, int]:
        return self.rules.get_coverage(namespace_id=namespace_id)

    def get_active_rules(
        self,
        detector: str | None = None,
        tier: str | None = None,
        namespace_id: int = 1,
    ) -> list[dict[str, Any]]:
        return self.rules.get_active(detector=detector, tier=tier, namespace_id=namespace_id)

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
        namespace_id: int = 1,
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
            namespace_id=namespace_id,
        )

    def get_rule_tag_stats(self, namespace_id: int = 1) -> list[dict[str, Any]]:
        return self.rules.get_tag_stats(namespace_id=namespace_id)

    def get_rule_by_name(self, name: str, namespace_id: int = 1) -> dict[str, Any] | None:
        return self.rules.get_by_name(name, namespace_id=namespace_id)

    def create_rule(self, data: dict[str, Any], namespace_id: int = 1) -> dict[str, Any] | None:
        return self.rules.create(data, namespace_id=namespace_id)

    def update_rule(self, name: str, data: dict[str, Any], namespace_id: int = 1) -> dict[str, Any] | None:
        return self.rules.update(name, data, namespace_id=namespace_id)

    def delete_rule(self, name: str, namespace_id: int = 1) -> bool:
        return self.rules.delete(name, namespace_id=namespace_id)

    def clone_rule(self, name: str, new_name: str, namespace_id: int = 1) -> dict[str, Any] | None:
        return self.rules.clone(name, new_name, namespace_id=namespace_id)

    def import_rules(
        self,
        rules: list[dict[str, Any]],
        tier: str = "community",
        force: bool = False,
        namespace_id: int = 1,
    ) -> dict[str, int]:
        return self.rules.import_bulk(rules, tier=tier, force=force, namespace_id=namespace_id)

    def export_rules(
        self,
        tier: str | None = None,
        detector: str | None = None,
        namespace_id: int = 1,
    ) -> list[dict[str, Any]]:
        return self.rules.export(tier=tier, detector=detector, namespace_id=namespace_id)

    def get_rule_stats(self, namespace_id: int = 1) -> dict[str, Any]:
        return self.rules.get_stats(namespace_id=namespace_id)

    def reconcile_yaml_rules(self, custom_rules: list[Any], namespace_id: int = 1) -> dict[str, list[str]]:
        return self.rules.reconcile_yaml(custom_rules, namespace_id=namespace_id)

    # --- Channels facade ---

    def list_notification_channels(self, source: str | None = None, namespace_id: int = 1) -> list[dict[str, Any]]:
        return self.channels.list_all(source=source, namespace_id=namespace_id)

    def get_notification_channel(self, channel_id: int, namespace_id: int = 1) -> dict[str, Any] | None:
        return self.channels.get(channel_id, namespace_id=namespace_id)

    def count_notification_channels(self, namespace_id: int = 1) -> int:
        return self.channels.count(namespace_id=namespace_id)

    def create_notification_channel(
        self,
        data: dict[str, Any],
        channel_limit: int | None = None,
        namespace_id: int = 1,
    ) -> dict[str, Any] | None:
        return self.channels.create(data, channel_limit=channel_limit, namespace_id=namespace_id)

    def update_notification_channel(
        self, channel_id: int, data: dict[str, Any], namespace_id: int = 1
    ) -> dict[str, Any] | None:
        return self.channels.update(channel_id, data, namespace_id=namespace_id)

    def delete_notification_channel(self, channel_id: int, namespace_id: int = 1) -> bool:
        return self.channels.delete(channel_id, namespace_id=namespace_id)

    def bulk_update_channels(self, ids: list[int], action: str, namespace_id: int = 1) -> int:
        return self.channels.bulk_update(ids, action, namespace_id=namespace_id)

    def reconcile_yaml_channels(
        self,
        yaml_channels: list[Any],
        channel_limit: int | None = None,
        namespace_id: int = 1,
    ) -> dict[str, list[str]]:
        return self.channels.reconcile_yaml(yaml_channels, channel_limit=channel_limit, namespace_id=namespace_id)

    # --- WebSocket connections facade ---

    def record_ws_connection_open(
        self,
        connection_id: str,
        target_url: str,
        origin: str,
        timestamp: float,
        namespace_id: int = 1,
    ) -> None:
        return self.ws_connections.record_open(connection_id, target_url, origin, timestamp, namespace_id=namespace_id)

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

    def get_ws_connections(self, limit: int = 50, offset: int = 0, namespace_id: int = 1) -> list[dict[str, Any]]:
        return self.ws_connections.get_connections(limit=limit, offset=offset, namespace_id=namespace_id)

    def get_ws_stats(self, days: int = 7, namespace_id: int = 1) -> dict[str, Any]:
        return self.ws_connections.get_stats(days=days, namespace_id=namespace_id)

    def cleanup_ws_connections(self, retention_days: int = 365, namespace_id: int = 1) -> int:
        return self.ws_connections.cleanup(retention_days=retention_days, namespace_id=namespace_id)

    # --- Allowlists facade ---

    def add_allowlist_entry(
        self,
        list_type: str,
        pattern: str,
        description: str = "",
        created_by: str = "",
        namespace_id: int = 1,
    ) -> dict[str, Any]:
        return self.allowlists.add(
            list_type,
            pattern,
            description=description,
            created_by=created_by,
            namespace_id=namespace_id,
        )

    def update_allowlist_entry(
        self, entry_id: int, data: dict[str, Any], namespace_id: int = 1
    ) -> dict[str, Any] | None:
        return self.allowlists.update(entry_id, data, namespace_id=namespace_id)

    def get_allowlist_entry(self, entry_id: int, namespace_id: int = 1) -> dict[str, Any] | None:
        return self.allowlists.get(entry_id, namespace_id=namespace_id)

    def delete_allowlist_entry(self, entry_id: int, namespace_id: int = 1) -> bool:
        return self.allowlists.delete(entry_id, namespace_id=namespace_id)

    def list_allowlist_entries(self, list_type: str | None = None, namespace_id: int = 1) -> list[dict[str, Any]]:
        return self.allowlists.list_all(list_type=list_type, namespace_id=namespace_id)

    def list_enabled_allowlist_entries(
        self, list_type: str | None = None, namespace_id: int = 1
    ) -> list[dict[str, Any]]:
        return self.allowlists.list_enabled(list_type=list_type, namespace_id=namespace_id)

    # --- Config overrides facade ---

    def get_config_overrides(self, namespace_id: int = 1) -> dict[str, Any]:
        return self.config_overrides.get_all(namespace_id=namespace_id)

    def set_config_override(self, key: str, value: Any, namespace_id: int = 1) -> None:
        return self.config_overrides.set(key, value, namespace_id=namespace_id)

    def delete_config_override(self, key: str, namespace_id: int = 1) -> bool:
        return self.config_overrides.delete(key, namespace_id=namespace_id)

    # --- MCP tool lists facade ---

    def get_mcp_tool_lists(self, namespace_id: int = 1) -> dict[str, list[dict[str, Any]]]:
        return self.mcp_tool_lists.get_lists(namespace_id=namespace_id)

    def add_mcp_tool_entry(self, list_type: str, tool_name: str, namespace_id: int = 1) -> int | None:
        return self.mcp_tool_lists.add_entry(list_type, tool_name, namespace_id=namespace_id)

    def delete_mcp_tool_entry(self, entry_id: int, namespace_id: int = 1) -> bool:
        return self.mcp_tool_lists.delete_entry(entry_id, namespace_id=namespace_id)

    def reconcile_mcp_tool_lists(
        self,
        yaml_allowed: list[Any] | None,
        yaml_blocked: list[Any] | None,
        namespace_id: int = 1,
    ) -> dict[str, int]:
        return self.mcp_tool_lists.reconcile(yaml_allowed, yaml_blocked, namespace_id=namespace_id)

    # --- MCP detected tools facade ---

    def record_mcp_tool_seen(
        self, tool_name: str, description: str = "", input_schema: str = "", namespace_id: int = 1
    ) -> None:
        return self.mcp_tool_tracking.record_tool_seen(
            tool_name,
            description=description,
            input_schema=input_schema,
            namespace_id=namespace_id,
        )

    def get_mcp_detected_tools(self, namespace_id: int = 1) -> list[dict[str, Any]]:
        return self.mcp_tool_tracking.get_detected_tools(namespace_id=namespace_id)

    # --- MCP tool call facade ---

    def record_mcp_tool_call(
        self,
        tool_name: str,
        session_id: str = "",
        status: str = "allowed",
        finding_count: int = 0,
        source: str = "proxy",
        namespace_id: int = 1,
    ) -> None:
        return self.mcp_tool_tracking.record_tool_call(
            tool_name,
            session_id=session_id,
            status=status,
            finding_count=finding_count,
            source=source,
            namespace_id=namespace_id,
        )

    def get_mcp_tool_calls(
        self, session_id: str | None = None, limit: int = 100, namespace_id: int = 1
    ) -> list[dict[str, Any]]:
        return self.mcp_tool_tracking.get_tool_calls(session_id=session_id, limit=limit, namespace_id=namespace_id)

    def cleanup_mcp_tool_calls(self, retention_days: int = 30, namespace_id: int = 1) -> int:
        return self.mcp_tool_tracking.cleanup_tool_calls(retention_days=retention_days, namespace_id=namespace_id)

    # --- MCP baselines facade ---

    def get_mcp_tool_baseline(self, tool_name: str, namespace_id: int = 1) -> dict[str, Any] | None:
        return self.mcp_tool_tracking.get_baseline(tool_name, namespace_id=namespace_id)

    def get_all_mcp_baselines(self, namespace_id: int = 1) -> list[dict[str, Any]]:
        return self.mcp_tool_tracking.get_all_baselines(namespace_id=namespace_id)

    def record_mcp_tool_baseline(
        self,
        tool_name: str,
        definition_hash: str,
        description: str,
        param_names: list[str],
        namespace_id: int = 1,
    ) -> None:
        return self.mcp_tool_tracking.record_baseline(
            tool_name,
            definition_hash,
            description,
            param_names,
            namespace_id=namespace_id,
        )

    def update_mcp_tool_baseline_seen(self, tool_name: str, namespace_id: int = 1) -> None:
        return self.mcp_tool_tracking.update_baseline_seen(tool_name, namespace_id=namespace_id)

    def increment_mcp_tool_drift_count(self, tool_name: str, namespace_id: int = 1) -> None:
        return self.mcp_tool_tracking.increment_drift_count(tool_name, namespace_id=namespace_id)

    # --- Private helper (used by channels internally) ---

    def _parse_channel_row(self, row: Any) -> dict[str, Any]:
        return self.channels._parse_row(row)
