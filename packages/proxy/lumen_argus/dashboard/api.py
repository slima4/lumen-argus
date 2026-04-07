"""Community dashboard API — dispatcher and small inline handlers.

Routes requests to domain-specific handler modules:
- api_findings: findings, sessions, stats
- api_rules: rules CRUD, analysis
- api_channels: notification channels
- api_config: config, pipeline, status, license, logs, clients
- api_allowlists: allowlist CRUD
- api_mcp: MCP tool lists

Shared helpers live in api_helpers.py.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore
    from lumen_argus.config import Config
    from lumen_argus.extensions import ExtensionRegistry

from lumen_argus.dashboard.api_helpers import (
    StoreUnavailable,
    json_response,
    parse_days,
    parse_pagination,
    parse_query,
    require_store,
)

log = logging.getLogger("argus.dashboard.api")

# Pro endpoint prefixes — return 402 when Pro is not installed
_PRO_ENDPOINTS: tuple[str, ...] = ()

# Start time for uptime calculation (used by api_config.handle_status)
_start_time = time.monotonic()

# Re-export helpers that external code (server.py, Pro) may import from api.py
# for backward compatibility. New code should import from api_helpers directly.
_json_response = json_response
_StoreUnavailable = StoreUnavailable
_COMMUNITY_ACTIONS = ("log", "alert", "block")


def _parse_query(path: str) -> tuple[str, dict[str, str]]:
    return parse_query(path)


def handle_community_api(
    path: str,
    method: str,
    body: bytes,
    store: AnalyticsStore | None,
    audit_reader: Any = None,
    config: Config | None = None,
    extensions: ExtensionRegistry | None = None,
    request_user: str = "",
) -> tuple[int, bytes]:
    """Handle a community API request.

    Returns (status_code, response_body_bytes).
    """
    try:
        return _dispatch_api(path, method, body, store, audit_reader, config, extensions, request_user)
    except StoreUnavailable:
        return json_response(500, {"error": "analytics store not available"})


def _dispatch_api(
    path: str,
    method: str,
    body: bytes,
    store: AnalyticsStore | None,
    audit_reader: Any = None,
    config: Config | None = None,
    extensions: ExtensionRegistry | None = None,
    request_user: str = "",
) -> tuple[int, bytes]:
    """Internal dispatcher — StoreUnavailable propagates to handle_community_api."""
    from lumen_argus.dashboard import api_allowlists, api_channels, api_config, api_findings, api_mcp, api_rules

    path, params = parse_query(path)

    # --- GET endpoints ---

    if method == "GET":
        if path == "/api/v1/status":
            return api_config.handle_status(store, extensions, _start_time)

        if path == "/api/v1/findings":
            return api_findings.handle_findings_list(params, store)

        if path == "/api/v1/findings/by-project":
            return api_findings.handle_findings_by_project(params, store)

        if path == "/api/v1/stats":
            return api_findings.handle_stats(params, store)

        if path == "/api/v1/stats/advanced":
            return api_findings.handle_stats_advanced(params, store, extensions)

        if path == "/api/v1/config":
            return api_config.handle_config(config, store)

        if path == "/api/v1/pipeline":
            return api_config.handle_pipeline_get(config, store)

        if path == "/api/v1/clients":
            return api_config.handle_clients_list(extensions)

        if path == "/api/v1/sessions":
            return api_findings.handle_sessions(params, store)

        if path == "/api/v1/sessions/dashboard":
            return api_findings.handle_dashboard_sessions(params, store)

        if path == "/api/v1/audit":
            return _handle_audit(params, audit_reader)

        if path == "/api/v1/logs/tail":
            return api_config.handle_logs_tail(config)

        if path.startswith("/api/v1/findings/"):
            finding_id_str = path.split("/")[-1]
            try:
                finding_id_int = int(finding_id_str)
            except (ValueError, TypeError):
                return json_response(400, {"error": "invalid finding ID"})
            return api_findings.handle_finding_detail(finding_id_int, store)

        # Rules GET
        if path == "/api/v1/rules":
            return api_rules.handle_rules_list(params, store)

        if path == "/api/v1/rules/stats":
            return api_rules.handle_rules_stats(store)

        if path == "/api/v1/rules/analysis":
            return api_rules.handle_rule_analysis_get(store)

        if path == "/api/v1/rules/analysis/status":
            return api_rules.handle_rule_analysis_status(params)

        if path.startswith("/api/v1/rules/"):
            rule_name = path[len("/api/v1/rules/") :]
            return api_rules.handle_rule_detail(rule_name, store)

        # Allowlists GET
        if path == "/api/v1/allowlists":
            return api_allowlists.handle_allowlists(store, config)

    # --- POST endpoints ---

    if method == "POST":
        if path == "/api/v1/license":
            return api_config.handle_license_activation(body)

    # --- Notification endpoints ---

    if path.startswith("/api/v1/notifications"):
        result = api_channels.handle_notifications(path, method, body, store, extensions, request_user)
        if result is not None:
            return result

    # --- WebSocket endpoints ---

    if method == "GET":
        if path == "/api/v1/ws/connections":
            return _handle_ws_connections(params, store)
        if path == "/api/v1/ws/stats":
            return _handle_ws_stats(params, store)

    # --- Allowlist mutation ---

    if path == "/api/v1/allowlists" and method == "POST":
        return api_allowlists.handle_allowlist_add(body, store)

    if path == "/api/v1/allowlists/test" and method == "POST":
        return api_allowlists.handle_allowlist_test(body, store)

    if path.startswith("/api/v1/allowlists/") and method == "DELETE":
        entry_id = path[len("/api/v1/allowlists/") :]
        return api_allowlists.handle_allowlist_delete(entry_id, store)

    # --- Rule analysis mutation ---

    if path == "/api/v1/rules/analysis" and method == "POST":
        return api_rules.handle_rule_analysis_trigger(body, store, extensions, config)

    if path == "/api/v1/rules/analysis/dismiss" and method == "POST":
        return api_rules.handle_rule_analysis_dismiss(body, store)

    # --- Rules mutation ---

    if path == "/api/v1/rules/bulk-update" and method == "POST":
        return api_rules.handle_rules_bulk_update(body, store, extensions)

    if path == "/api/v1/rules" and method == "POST":
        return api_rules.handle_rule_create(body, store, extensions)

    if path.startswith("/api/v1/rules/") and path.endswith("/clone") and method == "POST":
        rule_name = path[len("/api/v1/rules/") : -len("/clone")]
        return api_rules.handle_rule_clone(rule_name, body, store, extensions)

    if path.startswith("/api/v1/rules/") and method == "PUT":
        rule_name = path[len("/api/v1/rules/") :]
        return api_rules.handle_rule_update(rule_name, body, store, extensions)

    if path.startswith("/api/v1/rules/") and method == "DELETE":
        rule_name = path[len("/api/v1/rules/") :]
        return api_rules.handle_rule_delete(rule_name, store, extensions)

    # --- MCP tool lists ---

    if path == "/api/v1/mcp/tools":
        if method == "GET":
            return api_mcp.handle_mcp_tools_list(store, config)
        if method == "POST":
            return api_mcp.handle_mcp_tools_add(body, store)

    if path.startswith("/api/v1/mcp/tools/") and method == "DELETE":
        entry_id_str = path.split("/")[-1]
        try:
            entry_id_int = int(entry_id_str)
        except (ValueError, TypeError):
            return json_response(400, {"error": "invalid entry ID"})
        return api_mcp.handle_mcp_tools_delete(entry_id_int, store)

    if path == "/api/v1/mcp/detected-tools" and method == "GET":
        return api_mcp.handle_mcp_detected_tools(store)

    if path == "/api/v1/mcp/tool-calls" and method == "GET":
        return api_mcp.handle_mcp_tool_calls(params, store)

    if path == "/api/v1/mcp/baselines" and method == "GET":
        return api_mcp.handle_mcp_baselines(store)

    # --- Config mutation ---

    if path == "/api/v1/config" and method == "PUT":
        return api_config.handle_config_update(body, config, store, extensions)

    if path == "/api/v1/pipeline" and method == "PUT":
        return api_config.handle_pipeline_update(body, config, store, extensions)

    # --- Tier gating: known Pro paths return 402 ---

    if path.startswith("/api/v1/enrollment/"):
        return json_response(
            402,
            {
                "error": "pro_required",
                "message": "Enrollment requires a Pro license",
                "upgrade_url": "https://lumen-argus.com/pro",
            },
        )

    # MCP tool policies, approvals, and risk classification (Pro)
    if path.startswith(("/api/v1/mcp/policies", "/api/v1/mcp/approvals", "/api/v1/mcp/risk")):
        return json_response(
            402,
            {
                "error": "pro_required",
                "message": "MCP tool policies require a Pro license",
                "upgrade_url": "https://lumen-argus.com/pro",
            },
        )

    if method in ("POST", "PUT", "DELETE"):
        for prefix in _PRO_ENDPOINTS:
            if path.startswith(prefix):
                return json_response(
                    402,
                    {
                        "error": "pro_required",
                        "message": "This feature requires a Pro license",
                        "upgrade_url": "https://lumen-argus.com/pro",
                    },
                )

    return json_response(404, {"error": "not_found"})


# ---------------------------------------------------------------------------
# Small inline handlers (too small for their own module)
# ---------------------------------------------------------------------------


def _handle_audit(params: dict[str, str], audit_reader: Any) -> tuple[int, bytes]:
    if not audit_reader:
        return json_response(200, {"entries": [], "total": 0, "providers": []})

    result = parse_pagination(params)
    if isinstance(result[1], bytes):
        return result
    limit, offset = result
    action = params.get("action") or None
    provider = params.get("provider") or None
    search = params.get("search") or None

    entries, total = audit_reader.read_entries(
        limit=limit,
        offset=offset,
        action=action,
        provider=provider,
        search=search,
    )
    providers = audit_reader.get_providers()
    return json_response(200, {"entries": entries, "total": total, "providers": providers})


def _handle_ws_connections(params: dict[str, str], store: AnalyticsStore | None) -> tuple[int, bytes]:
    """Return recent WebSocket connections, newest first."""
    store = require_store(store, "GET /api/v1/ws/connections")

    result = parse_pagination(params, max_limit=200)
    if isinstance(result[1], bytes):
        return result
    limit, offset = result

    connections = store.get_ws_connections(limit=limit, offset=offset)
    log.debug("GET /api/v1/ws/connections: %d result(s) (limit=%d, offset=%d)", len(connections), limit, offset)
    return json_response(200, {"connections": connections, "count": len(connections)})


def _handle_ws_stats(params: dict[str, str], store: AnalyticsStore | None) -> tuple[int, bytes]:
    """Return aggregate WebSocket stats for the given period."""
    store = require_store(store, "GET /api/v1/ws/stats")

    days = min(max(parse_days(params, default=7), 1), 365)

    stats = store.get_ws_stats(days=days)
    log.debug("GET /api/v1/ws/stats: days=%d, %d connections", days, stats.get("total_connections", 0))
    return json_response(200, stats)
