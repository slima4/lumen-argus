"""Analytics store for community dashboard.

Stores summarized finding data (no raw secrets/PII values) with
aggregation queries for dashboard charts. Includes scheduled cleanup
for retention enforcement.

Database-agnostic via DatabaseAdapter — defaults to SQLiteAdapter
(stdlib sqlite3, zero dependencies). Plugins can inject an
alternative adapter (e.g. PostgreSQL) via
``extensions.set_database_adapter()``.
"""

import logging
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Sequence

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


@dataclass(frozen=True)
class WriteResult:
    """Result of a single-statement write via AnalyticsStore.execute_write."""

    rowcount: int
    lastrowid: int | None


class AnalyticsStore:
    """Database-agnostic analytics store for finding history and trend queries.

    Delegates connection management and SQL dialect to a DatabaseAdapter.
    Defaults to SQLiteAdapter (thread-local connections, WAL mode).
    Plugins can inject an alternative adapter (e.g. a PostgreSQL
    adapter with a connection pool + MVCC).
    """

    def __init__(
        self,
        db_path: str = "~/.lumen-argus/analytics.db",
        hmac_key: bytes | None = None,
        adapter: DatabaseAdapter | None = None,
        schema_extensions: list[str] | None = None,
    ) -> None:
        if adapter:
            self._adapter = adapter
        else:
            self._adapter = SQLiteAdapter(db_path)
        self._hmac_key = hmac_key
        self._rules_change_callback: Callable[..., Any] | None = None
        self._ensure_db()
        # Plugin-registered DDL runs after the community schema. Accepted as
        # a constructor arg (rather than reaching into the ExtensionRegistry
        # from here) to keep analytics/ free of upward dependencies. Callers
        # that adopt an already-constructed store (e.g. a plugin-provided
        # subclass returned via ExtensionRegistry.set_analytics_store) must
        # call ``apply_schema_extensions`` themselves after load_plugins().
        if schema_extensions:
            self.apply_schema_extensions(schema_extensions)
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
        """Create the database and community schema if they don't exist."""
        self._adapter.ensure_schema(build_all_schemas(self._adapter))

    def apply_schema_extensions(self, ddls: list[str]) -> None:
        """Apply plugin-registered DDL against this store's database.

        Each DDL string must be idempotent (``CREATE TABLE IF NOT EXISTS``
        / ``CREATE INDEX IF NOT EXISTS``) and may use the ``{auto_id}`` /
        ``{ts}`` dialect placeholders, which we resolve via the adapter
        before executing.

        Extensions are applied one at a time: a failure in one does not
        prevent the others from running. Both placeholder-resolution
        errors (``KeyError`` / ``IndexError``) and DDL execution errors
        are logged at ``ERROR`` level with ``exc_info`` but never raised —
        a broken plugin schema should degrade that plugin's features, not
        bring the proxy down. Log messages include only the extension
        index, never the raw DDL, to avoid leaking plugin internals.

        Called from ``__init__`` when ``schema_extensions=`` is passed,
        and from ``config_loader._create_or_get_store`` for stores
        adopted via ``ExtensionRegistry.set_analytics_store`` (e.g. a
        plugin-provided subclass). Safe to call multiple times: every
        DDL is idempotent.
        """
        if not ddls:
            return
        auto_id = self._adapter.auto_id_type()
        ts = self._adapter.timestamp_type()
        applied = 0
        for idx, ddl in enumerate(ddls):
            try:
                resolved = ddl.format(auto_id=auto_id, ts=ts)
            except (KeyError, IndexError) as e:
                log.error(
                    "schema extension #%d: placeholder resolution failed: %s",
                    idx,
                    e,
                    exc_info=True,
                )
                continue
            try:
                self._adapter.ensure_schema(resolved)
                applied += 1
            except Exception as e:
                # Log without DDL body to avoid leaking plugin internals;
                # the adapter exception itself carries the SQL error text.
                log.error(
                    "schema extension #%d: DDL failed: %s",
                    idx,
                    e,
                    exc_info=True,
                )
        # Summary log level reflects outcome so operators scanning for
        # failures don't mistake "applied 0 of N" for a successful no-op.
        total = len(ddls)
        if applied == total:
            log.info("applied %d plugin schema extension(s)", applied)
        elif applied > 0:
            log.warning(
                "applied %d of %d plugin schema extension(s) — %d failed",
                applied,
                total,
                total - applied,
            )
        else:
            log.warning("all %d plugin schema extension(s) failed", total)

    def _connect(self) -> DBConnection:
        """Return a database connection via the adapter.

        Used by detectors/rules.py for hit-count flush and by tests.
        Repositories use BaseRepository._connect() directly.
        """
        return self._adapter.connect()

    # --- Public SQL execution API (for plugin-owned tables) ---

    def execute(self, sql: str, params: Sequence[Any] | None = None) -> list[dict[str, Any]]:
        """Run a read-only SQL statement and return rows as dicts.

        Plugins that own their own tables (registered via
        ``ExtensionRegistry.register_schema_extension``) use this as a
        stable, public alternative to reaching into ``store._connect()``
        and ``store._adapter`` directly. Reads run on the thread-local
        connection — no locking needed for SELECTs.

        Use ``?`` placeholders; the adapter will translate to ``%s`` for
        PostgreSQL if/when a PostgreSQL adapter is wired up.

        Returns a list of ``dict[str, Any]`` — one per row — so callers do
        not depend on the underlying cursor's row type (``sqlite3.Row`` vs
        ``psycopg`` tuples).
        """
        conn = self._adapter.connect()
        cur = conn.execute(sql, tuple(params or ()))
        rows = cur.fetchall()
        if not rows:
            return []
        # sqlite3.Row exposes .keys(); psycopg rows use cursor.description.
        if hasattr(rows[0], "keys"):
            return [{k: row[k] for k in row.keys()} for row in rows]
        columns = [d[0] for d in cur.description or []]
        return [dict(zip(columns, row)) for row in rows]

    def execute_write(self, sql: str, params: Sequence[Any] | None = None) -> WriteResult:
        """Run a single-statement write under the adapter write lock.

        Writes are serialized by the adapter's ``write_lock()`` — a real
        ``threading.Lock`` for SQLite (single-writer), a no-op for
        PostgreSQL (MVCC). Commits before returning.

        Returns the ``rowcount`` and ``lastrowid`` from the cursor so
        callers can distinguish insert/update/delete semantics without
        re-querying.

        .. warning::
            Not reentrant on SQLite. Do **not** call ``execute_write`` or
            ``write_transaction`` from a thread that already holds the
            adapter write lock — that would self-deadlock on the
            non-reentrant ``threading.Lock``. If you need multiple
            statements under one lock, use ``write_transaction`` as the
            outermost call.
        """
        with self._adapter.write_lock():
            conn = self._adapter.connect()
            cur = conn.execute(sql, tuple(params or ()))
            conn.commit()
            return WriteResult(rowcount=cur.rowcount, lastrowid=cur.lastrowid)

    @contextmanager
    def write_transaction(self) -> Iterator[DBConnection]:
        """Yield a connection under the write lock for multi-statement writes.

        Example::

            with store.write_transaction() as conn:
                conn.execute("DELETE FROM my_table WHERE expired = 1")
                conn.execute("INSERT INTO my_table (name) VALUES (?)", ("x",))

        The block executes atomically — either all statements commit or
        (on exception) none do. Commit happens on successful exit;
        exceptions propagate and the connection rolls back.

        .. warning::
            Not reentrant on SQLite. Do **not** call ``execute_write`` or
            a nested ``write_transaction`` from inside the ``with`` block
            — the adapter write lock is a plain ``threading.Lock`` and
            the nested call will self-deadlock. Put all your writes
            inside this one block instead.
        """
        with self._adapter.write_lock():
            conn = self._adapter.connect()
            try:
                yield conn
                conn.commit()
            except Exception:
                # Attempt rollback; log (don't swallow) any rollback failure
                # so a broken connection is still diagnosable. Never log
                # SQL parameters — callers may pass sensitive values.
                try:
                    conn.rollback()
                except Exception as rollback_exc:
                    log.warning("write_transaction rollback failed: %s", rollback_exc)
                raise

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
                except Exception:
                    log.error("analytics cleanup failed", exc_info=True)

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
        origin: str | None = None,
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
            origin=origin,
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
