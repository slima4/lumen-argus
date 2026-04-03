"""Centralized database schema definitions — all DDL in one place.

Each table's schema is generated via a builder function that uses
DatabaseAdapter dialect methods for engine-portable types:
- adapter.auto_id_type() → INTEGER PRIMARY KEY AUTOINCREMENT (SQLite) / SERIAL PRIMARY KEY (PG)
- adapter.timestamp_type() → TEXT (SQLite) / TIMESTAMPTZ (PG)

Repos import their schema from here. Store._ensure_db() joins them all
and passes to adapter.ensure_schema().
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lumen_argus.analytics.adapter import DatabaseAdapter


def build_findings_schema(a: DatabaseAdapter) -> str:
    auto_id = a.auto_id_type()
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS findings (
    id {auto_id},
    timestamp {ts} NOT NULL,
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


def build_rules_schema(a: DatabaseAdapter) -> str:
    auto_id = a.auto_id_type()
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS rules (
    id {auto_id},
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
    hit_count INTEGER NOT NULL DEFAULT 0,
    created_at {ts} NOT NULL,
    updated_at {ts} NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_rules_detector ON rules(detector);
CREATE INDEX IF NOT EXISTS idx_rules_tier ON rules(tier);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);
"""


def build_notification_channels_schema(a: DatabaseAdapter) -> str:
    auto_id = a.auto_id_type()
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS notification_channels (
    id {auto_id},
    name TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    config TEXT NOT NULL DEFAULT '{{}}',
    enabled INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL DEFAULT 'dashboard',
    events TEXT NOT NULL DEFAULT '["block","alert"]',
    min_severity TEXT NOT NULL DEFAULT 'warning',
    created_at {ts} NOT NULL,
    updated_at {ts} NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT ''
);
"""


def build_enrollment_schema(a: DatabaseAdapter) -> str:
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS enrollment_agents (
    agent_id TEXT PRIMARY KEY,
    machine_id TEXT NOT NULL,
    hostname TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL DEFAULT '',
    arch TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    enrolled_at {ts} NOT NULL,
    last_heartbeat {ts},
    status TEXT NOT NULL DEFAULT 'active',
    tools_configured INTEGER NOT NULL DEFAULT 0,
    tools_detected INTEGER NOT NULL DEFAULT 0,
    UNIQUE(machine_id)
);
CREATE INDEX IF NOT EXISTS idx_enrollment_status ON enrollment_agents(status);

CREATE TABLE IF NOT EXISTS enrollment_agent_tools (
    agent_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    install_method TEXT NOT NULL DEFAULT '',
    proxy_configured INTEGER NOT NULL DEFAULT 0,
    routing_active INTEGER NOT NULL DEFAULT 0,
    proxy_config_type TEXT NOT NULL DEFAULT '',
    updated_at {ts} NOT NULL,
    PRIMARY KEY (agent_id, client_id),
    FOREIGN KEY (agent_id) REFERENCES enrollment_agents(agent_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_agent_tools_unconfigured
    ON enrollment_agent_tools(proxy_configured) WHERE proxy_configured = 0;
"""


def build_allowlist_schema(a: DatabaseAdapter) -> str:
    auto_id = a.auto_id_type()
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS allowlist_entries (
    id {auto_id},
    list_type TEXT NOT NULL,
    pattern TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'api',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at {ts} NOT NULL,
    updated_at {ts} NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_allowlist_type ON allowlist_entries(list_type);
CREATE INDEX IF NOT EXISTS idx_allowlist_enabled ON allowlist_entries(enabled);
"""


def build_config_overrides_schema(a: DatabaseAdapter) -> str:
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS config_overrides (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at {ts} NOT NULL
);
"""


def build_mcp_tool_lists_schema(a: DatabaseAdapter) -> str:
    auto_id = a.auto_id_type()
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS mcp_tool_lists (
    id {auto_id},
    list_type TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'api',
    created_at {ts} NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_tool_unique
    ON mcp_tool_lists(list_type, tool_name);
"""


def build_rule_analysis_schema(a: DatabaseAdapter) -> str:
    auto_id = a.auto_id_type()
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS rule_analysis (
    id {auto_id},
    timestamp {ts} NOT NULL,
    duration_s REAL NOT NULL DEFAULT 0,
    total_rules INTEGER NOT NULL DEFAULT 0,
    duplicates INTEGER NOT NULL DEFAULT 0,
    subsets INTEGER NOT NULL DEFAULT 0,
    overlaps INTEGER NOT NULL DEFAULT 0,
    results_json TEXT NOT NULL DEFAULT '{{}}',
    dismissed_json TEXT NOT NULL DEFAULT '[]'
);
"""


def build_ws_connections_schema(a: DatabaseAdapter) -> str:
    # ws_connections uses REAL for timestamps (Unix epoch), not TEXT/TIMESTAMPTZ
    return """\
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


def build_schema_version_schema(a: DatabaseAdapter) -> str:
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at {ts} NOT NULL
);
"""


def build_mcp_detected_tools_schema(a: DatabaseAdapter) -> str:
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS mcp_detected_tools (
    tool_name TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    input_schema TEXT NOT NULL DEFAULT '{{}}',
    first_seen {ts} NOT NULL,
    last_seen {ts} NOT NULL,
    call_count INTEGER NOT NULL DEFAULT 1
);
"""


def build_mcp_tool_calls_schema(a: DatabaseAdapter) -> str:
    auto_id = a.auto_id_type()
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS mcp_tool_calls (
    id {auto_id},
    tool_name TEXT NOT NULL,
    session_id TEXT NOT NULL DEFAULT '',
    timestamp {ts} NOT NULL,
    status TEXT NOT NULL DEFAULT 'allowed',
    finding_count INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL DEFAULT 'proxy'
);
CREATE INDEX IF NOT EXISTS idx_mcp_calls_session ON mcp_tool_calls(session_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_mcp_calls_ts ON mcp_tool_calls(timestamp);
"""


def build_mcp_tool_baselines_schema(a: DatabaseAdapter) -> str:
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS mcp_tool_baselines (
    tool_name TEXT PRIMARY KEY,
    definition_hash TEXT NOT NULL,
    description TEXT,
    param_names TEXT,
    first_seen {ts} NOT NULL,
    last_seen {ts} NOT NULL,
    drift_count INTEGER DEFAULT 0
);
"""


def build_all_schemas(adapter: DatabaseAdapter) -> str:
    """Build the complete community schema DDL for the given adapter."""
    return "\n".join(
        [
            build_findings_schema(adapter),
            build_rules_schema(adapter),
            build_notification_channels_schema(adapter),
            build_schema_version_schema(adapter),
            build_config_overrides_schema(adapter),
            build_mcp_tool_lists_schema(adapter),
            build_mcp_detected_tools_schema(adapter),
            build_mcp_tool_calls_schema(adapter),
            build_mcp_tool_baselines_schema(adapter),
            build_ws_connections_schema(adapter),
            build_allowlist_schema(adapter),
            build_rule_analysis_schema(adapter),
            build_enrollment_schema(adapter),
        ]
    )
