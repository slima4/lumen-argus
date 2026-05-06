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


def build_namespaces_schema(a: DatabaseAdapter) -> str:
    auto_id = a.auto_id_type()
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS namespaces (
    id {auto_id},
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    tier TEXT NOT NULL DEFAULT 'free',
    status TEXT NOT NULL DEFAULT 'active',
    created_at {ts} NOT NULL DEFAULT ({a.now_sql()}),
    updated_at {ts} NOT NULL DEFAULT ({a.now_sql()}),
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT ''
);

INSERT INTO namespaces (id, slug, display_name, tier, created_at, updated_at)
VALUES (1, 'default', 'Default', 'free', {a.now_sql()}, {a.now_sql()})
ON CONFLICT (id) DO NOTHING;
"""


def build_findings_schema(a: DatabaseAdapter) -> str:
    auto_id = a.auto_id_type()
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS findings (
    id {auto_id},
    namespace_id INTEGER NOT NULL DEFAULT 1 REFERENCES namespaces(id),
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
    hostname TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    client_name TEXT NOT NULL DEFAULT '',
    client_version TEXT NOT NULL DEFAULT '',
    client_type TEXT NOT NULL DEFAULT '',
    raw_user_agent TEXT NOT NULL DEFAULT '',
    api_format TEXT NOT NULL DEFAULT '',
    sdk_name TEXT NOT NULL DEFAULT '',
    sdk_version TEXT NOT NULL DEFAULT '',
    runtime TEXT NOT NULL DEFAULT '',
    intercept_mode TEXT NOT NULL DEFAULT 'reverse',
    original_host TEXT NOT NULL DEFAULT '',
    api_key_hash TEXT NOT NULL DEFAULT '',
    content_hash TEXT NOT NULL DEFAULT '',
    seen_count INTEGER NOT NULL DEFAULT 1,
    value_hash TEXT NOT NULL DEFAULT '',
    origin TEXT NOT NULL DEFAULT 'detector'
);

CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_account ON findings(account_id);
CREATE INDEX IF NOT EXISTS idx_findings_namespace ON findings(namespace_id);
CREATE INDEX IF NOT EXISTS idx_findings_provider ON findings(provider);
CREATE INDEX IF NOT EXISTS idx_findings_detector ON findings(detector);
CREATE INDEX IF NOT EXISTS idx_findings_client ON findings(client_name);
CREATE INDEX IF NOT EXISTS idx_findings_action ON findings(action_taken);
CREATE INDEX IF NOT EXISTS idx_findings_intercept ON findings(intercept_mode);
CREATE INDEX IF NOT EXISTS idx_findings_origin ON findings(origin);
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedup
ON findings(content_hash, session_id, namespace_id)
WHERE content_hash != '' AND session_id != '';
"""


def build_rules_schema(a: DatabaseAdapter) -> str:
    auto_id = a.auto_id_type()
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS rules (
    id {auto_id},
    namespace_id INTEGER NOT NULL DEFAULT 1 REFERENCES namespaces(id),
    name TEXT NOT NULL,
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
    updated_by TEXT NOT NULL DEFAULT '',
    UNIQUE(name, namespace_id)
);

CREATE INDEX IF NOT EXISTS idx_rules_detector ON rules(detector);
CREATE INDEX IF NOT EXISTS idx_rules_tier ON rules(tier);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);
CREATE INDEX IF NOT EXISTS idx_rules_namespace ON rules(namespace_id);
"""


def build_notification_channels_schema(a: DatabaseAdapter) -> str:
    auto_id = a.auto_id_type()
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS notification_channels (
    id {auto_id},
    namespace_id INTEGER NOT NULL DEFAULT 1 REFERENCES namespaces(id),
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    config TEXT NOT NULL DEFAULT '{{}}',
    enabled INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL DEFAULT 'dashboard',
    events TEXT NOT NULL DEFAULT '["block","alert"]',
    min_severity TEXT NOT NULL DEFAULT 'warning',
    created_at {ts} NOT NULL,
    updated_at {ts} NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    UNIQUE(name, namespace_id)
);
CREATE INDEX IF NOT EXISTS idx_channels_namespace ON notification_channels(namespace_id);
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
    namespace_id INTEGER NOT NULL DEFAULT 1 REFERENCES namespaces(id),
    token_hash TEXT NOT NULL DEFAULT '',
    previous_token_hash TEXT NOT NULL DEFAULT '',
    token_issued_at {ts},
    token_expires_at {ts},
    last_token_used_at {ts},
    created_at {ts} NOT NULL DEFAULT ({a.now_sql()}),
    updated_at {ts} NOT NULL DEFAULT ({a.now_sql()}),
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    UNIQUE(machine_id)
);
CREATE INDEX IF NOT EXISTS idx_enrollment_status ON enrollment_agents(status);
CREATE INDEX IF NOT EXISTS idx_enrollment_token_hash
    ON enrollment_agents(token_hash) WHERE token_hash != '';
CREATE INDEX IF NOT EXISTS idx_enrollment_prev_token_hash
    ON enrollment_agents(previous_token_hash) WHERE previous_token_hash != '';
CREATE INDEX IF NOT EXISTS idx_enrollment_namespace
    ON enrollment_agents(namespace_id);

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


def build_enrollment_tokens_schema(a: DatabaseAdapter) -> str:
    auto_id = a.auto_id_type()
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id {auto_id},
    token_hash TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    namespace_id INTEGER NOT NULL DEFAULT 1 REFERENCES namespaces(id),
    expires_at {ts} NOT NULL,
    used_at {ts},
    used_by_agent TEXT,
    max_uses INTEGER NOT NULL DEFAULT 1,
    use_count INTEGER NOT NULL DEFAULT 0,
    created_at {ts} NOT NULL DEFAULT ({a.now_sql()}),
    updated_at {ts} NOT NULL DEFAULT ({a.now_sql()}),
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_namespace
    ON enrollment_tokens(namespace_id);
"""


def build_allowlist_schema(a: DatabaseAdapter) -> str:
    auto_id = a.auto_id_type()
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS allowlist_entries (
    id {auto_id},
    namespace_id INTEGER NOT NULL DEFAULT 1 REFERENCES namespaces(id),
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
CREATE INDEX IF NOT EXISTS idx_allowlist_namespace ON allowlist_entries(namespace_id);
"""


def build_config_overrides_schema(a: DatabaseAdapter) -> str:
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS config_overrides (
    namespace_id INTEGER NOT NULL DEFAULT 1 REFERENCES namespaces(id),
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    updated_at {ts} NOT NULL,
    PRIMARY KEY (namespace_id, key)
);
"""


def build_mcp_tool_lists_schema(a: DatabaseAdapter) -> str:
    auto_id = a.auto_id_type()
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS mcp_tool_lists (
    id {auto_id},
    namespace_id INTEGER NOT NULL DEFAULT 1 REFERENCES namespaces(id),
    list_type TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'api',
    created_at {ts} NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_tool_unique
    ON mcp_tool_lists(list_type, tool_name, namespace_id);
CREATE INDEX IF NOT EXISTS idx_mcp_tool_lists_namespace ON mcp_tool_lists(namespace_id);
"""


def build_rule_analysis_schema(a: DatabaseAdapter) -> str:
    auto_id = a.auto_id_type()
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS rule_analysis (
    id {auto_id},
    namespace_id INTEGER NOT NULL DEFAULT 1 REFERENCES namespaces(id),
    timestamp {ts} NOT NULL,
    duration_s REAL NOT NULL DEFAULT 0,
    total_rules INTEGER NOT NULL DEFAULT 0,
    duplicates INTEGER NOT NULL DEFAULT 0,
    subsets INTEGER NOT NULL DEFAULT 0,
    overlap_count INTEGER NOT NULL DEFAULT 0,
    results_json TEXT NOT NULL DEFAULT '{{}}',
    dismissed_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_rule_analysis_namespace ON rule_analysis(namespace_id);
"""


def build_ws_connections_schema(_a: DatabaseAdapter) -> str:
    # ws_connections uses REAL for timestamps (Unix epoch), not TEXT/TIMESTAMPTZ
    return """\
CREATE TABLE IF NOT EXISTS ws_connections (
    id TEXT PRIMARY KEY,
    namespace_id INTEGER NOT NULL DEFAULT 1 REFERENCES namespaces(id),
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
CREATE INDEX IF NOT EXISTS idx_ws_conn_namespace ON ws_connections(namespace_id);
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
    namespace_id INTEGER NOT NULL DEFAULT 1 REFERENCES namespaces(id),
    tool_name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    input_schema TEXT NOT NULL DEFAULT '{{}}',
    first_seen {ts} NOT NULL,
    last_seen {ts} NOT NULL,
    call_count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (namespace_id, tool_name)
);
"""


def build_mcp_tool_calls_schema(a: DatabaseAdapter) -> str:
    auto_id = a.auto_id_type()
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS mcp_tool_calls (
    id {auto_id},
    namespace_id INTEGER NOT NULL DEFAULT 1 REFERENCES namespaces(id),
    tool_name TEXT NOT NULL,
    session_id TEXT NOT NULL DEFAULT '',
    timestamp {ts} NOT NULL,
    status TEXT NOT NULL DEFAULT 'allowed',
    finding_count INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL DEFAULT 'proxy'
);
CREATE INDEX IF NOT EXISTS idx_mcp_calls_session ON mcp_tool_calls(namespace_id, session_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_mcp_calls_ts ON mcp_tool_calls(timestamp);
"""


def build_mcp_tool_baselines_schema(a: DatabaseAdapter) -> str:
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS mcp_tool_baselines (
    namespace_id INTEGER NOT NULL DEFAULT 1 REFERENCES namespaces(id),
    tool_name TEXT NOT NULL,
    definition_hash TEXT NOT NULL,
    description TEXT,
    param_names TEXT,
    first_seen {ts} NOT NULL,
    last_seen {ts} NOT NULL,
    drift_count INTEGER DEFAULT 0,
    PRIMARY KEY (namespace_id, tool_name)
);
"""


def build_mcp_tool_policies_schema(a: DatabaseAdapter) -> str:
    auto_id = a.auto_id_type()
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS mcp_tool_policies (
    id {auto_id},
    namespace_id INTEGER NOT NULL DEFAULT 1 REFERENCES namespaces(id),
    name TEXT NOT NULL,
    match_json TEXT NOT NULL,
    action TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'medium',
    priority INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL DEFAULT 'dashboard',
    created_at {ts} NOT NULL,
    updated_at {ts} NOT NULL,
    hit_count INTEGER NOT NULL DEFAULT 0,
    UNIQUE(namespace_id, name)
);
"""


def build_mcp_approval_queue_schema(a: DatabaseAdapter) -> str:
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS mcp_approval_queue (
    id TEXT PRIMARY KEY,
    namespace_id INTEGER NOT NULL DEFAULT 1 REFERENCES namespaces(id),
    tool_name TEXT NOT NULL,
    arguments_hash TEXT NOT NULL,
    arguments_preview TEXT NOT NULL DEFAULT '',
    server_id TEXT NOT NULL DEFAULT '',
    session_id TEXT NOT NULL DEFAULT '',
    identity TEXT NOT NULL DEFAULT '',
    policy_name TEXT NOT NULL,
    risk_level TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    requested_at {ts} NOT NULL,
    decided_at {ts},
    decided_by TEXT,
    decision_reason TEXT NOT NULL DEFAULT '',
    expires_at {ts} NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approval_status ON mcp_approval_queue(status, requested_at);
"""


def build_mcp_tool_risk_schema(a: DatabaseAdapter) -> str:
    ts = a.timestamp_type()
    return f"""\
CREATE TABLE IF NOT EXISTS mcp_tool_risk (
    namespace_id INTEGER NOT NULL DEFAULT 1 REFERENCES namespaces(id),
    tool_name TEXT NOT NULL,
    server_id TEXT NOT NULL DEFAULT '',
    risk_level TEXT NOT NULL,
    auto_generated INTEGER NOT NULL DEFAULT 1,
    override_by TEXT,
    override_at {ts},
    scores_json TEXT NOT NULL DEFAULT '{{}}',
    PRIMARY KEY (namespace_id, tool_name, server_id)
);
"""


def build_all_schemas(adapter: DatabaseAdapter) -> str:
    """Build the complete community schema DDL for the given adapter.

    Order matters: namespaces must come first (other tables reference it).
    """
    return "\n".join(
        [
            build_namespaces_schema(adapter),
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
            build_enrollment_tokens_schema(adapter),
            build_mcp_tool_policies_schema(adapter),
            build_mcp_approval_queue_schema(adapter),
            build_mcp_tool_risk_schema(adapter),
        ]
    )
