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

    # --- Private helper kept for backward compat (used by channels internally) ---

    def _parse_channel_row(self, row):
        return self.channels._parse_row(row)
