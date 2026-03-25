"""Community dashboard API — read endpoints, config save, and license activation.

Community endpoints: GET (read), PUT /api/v1/config (save community settings),
POST /api/v1/license (activate). Known Pro endpoint paths return 402 instead
of 404 when no Pro handler is registered, giving API consumers a clear upgrade signal.
"""

import fnmatch
import json
import logging
import os
import re
import signal
import time
from urllib.parse import unquote_plus

from lumen_argus import __version__
from lumen_argus.log_utils import sanitize_user_input

log = logging.getLogger("argus.dashboard.api")

# Pro endpoint prefixes — return 402 when Pro is not installed
_PRO_ENDPOINTS = ()

_SENSITIVE_FIELDS = frozenset(
    {
        "webhook_url",
        "routing_key",
        "password",
        "url",
        "username",
        "api_key",
        "token",
        "api_token",
    }
)

# Start time for uptime calculation
_start_time = time.monotonic()


def _parse_query(path: str) -> tuple:
    """Split path and query string, return (path, params_dict)."""
    query = ""
    if "?" in path:
        path, query = path.split("?", 1)
    params = {}
    if query:
        for part in query.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                params[unquote_plus(k)] = unquote_plus(v)
    return path, params


def _json_response(status: int, data) -> tuple:
    """Return (status, body_bytes) JSON response."""
    body = json.dumps(data).encode("utf-8")
    return status, body


def handle_community_api(
    path: str, method: str, body: bytes, store, audit_reader=None, config=None, extensions=None, request_user: str = ""
) -> tuple:
    """Handle a community API request.

    Args:
        request_user: Authenticated user identity for audit trail.
            "dashboard:admin" when password auth is active,
            "dashboard" when no auth, or "dashboard:<user_id>" from auth providers.

    Returns (status_code, response_body_bytes).
    """
    path, params = _parse_query(path)

    # --- GET endpoints ---

    if method == "GET":
        if path == "/api/v1/status":
            return _handle_status(store, extensions)

        if path == "/api/v1/findings":
            return _handle_findings_list(params, store)

        if path == "/api/v1/stats":
            return _handle_stats(params, store)

        if path == "/api/v1/stats/advanced":
            return _handle_stats_advanced(params, store, extensions)

        if path == "/api/v1/config":
            return _handle_config(config, store)

        if path == "/api/v1/pipeline":
            return _handle_pipeline_get(config, store)

        if path == "/api/v1/sessions":
            return _handle_sessions(params, store)

        if path == "/api/v1/sessions/dashboard":
            return _handle_dashboard_sessions(params, store)

        if path == "/api/v1/audit":
            return _handle_audit(params, audit_reader)

        if path == "/api/v1/logs/tail":
            return _handle_logs_tail(config)

        # Finding by ID: /api/v1/findings/123
        if path.startswith("/api/v1/findings/"):
            finding_id = path.split("/")[-1]
            try:
                finding_id = int(finding_id)
            except (ValueError, TypeError):
                return _json_response(400, {"error": "invalid finding ID"})
            return _handle_finding_detail(finding_id, store)

        # --- Rules GET endpoints ---

        if path == "/api/v1/rules":
            return _handle_rules_list(params, store)

        if path == "/api/v1/rules/stats":
            return _handle_rules_stats(store)

        if path.startswith("/api/v1/rules/"):
            rule_name = path[len("/api/v1/rules/") :]
            return _handle_rule_detail(rule_name, store)

        # --- Allowlist GET endpoint ---

        if path == "/api/v1/allowlists":
            return _handle_allowlists(store, config)

    # --- POST endpoints ---

    if method == "POST":
        if path == "/api/v1/license":
            return _handle_license_activation(body)

    # --- Notification endpoints (community-handled) ---

    if path.startswith("/api/v1/notifications"):
        result = _handle_notifications(path, method, body, store, extensions, request_user)
        if result is not None:
            return result

    # --- WebSocket connection endpoints ---

    if method == "GET":
        if path == "/api/v1/ws/connections":
            return _handle_ws_connections(params, store)
        if path == "/api/v1/ws/stats":
            return _handle_ws_stats(params, store)

    # --- Allowlist mutation endpoints ---

    if path == "/api/v1/allowlists" and method == "POST":
        return _handle_allowlist_add(body, store)

    if path == "/api/v1/allowlists/test" and method == "POST":
        return _handle_allowlist_test(body, store)

    if path.startswith("/api/v1/allowlists/") and method == "DELETE":
        entry_id = path[len("/api/v1/allowlists/") :]
        return _handle_allowlist_delete(entry_id, store)

    # --- Rules mutation endpoints ---

    if path == "/api/v1/rules" and method == "POST":
        return _handle_rule_create(body, store)

    if path.startswith("/api/v1/rules/") and path.endswith("/clone") and method == "POST":
        rule_name = path[len("/api/v1/rules/") : -len("/clone")]
        return _handle_rule_clone(rule_name, body, store)

    if path.startswith("/api/v1/rules/") and method == "PUT":
        rule_name = path[len("/api/v1/rules/") :]
        return _handle_rule_update(rule_name, body, store)

    if path.startswith("/api/v1/rules/") and method == "DELETE":
        rule_name = path[len("/api/v1/rules/") :]
        return _handle_rule_delete(rule_name, store)

    # --- MCP tool list endpoints ---

    if path == "/api/v1/mcp/tools":
        if method == "GET":
            return _handle_mcp_tools_list(store, config)
        if method == "POST":
            return _handle_mcp_tools_add(body, store)

    if path.startswith("/api/v1/mcp/tools/") and method == "DELETE":
        entry_id = path.split("/")[-1]
        try:
            entry_id = int(entry_id)
        except (ValueError, TypeError):
            return _json_response(400, {"error": "invalid entry ID"})
        return _handle_mcp_tools_delete(entry_id, store)

    # --- PUT config (community settings) ---

    if path == "/api/v1/config" and method == "PUT":
        return _handle_config_update(body, config, store)

    if path == "/api/v1/pipeline" and method == "PUT":
        return _handle_pipeline_update(body, config, store)

    # --- Tier gating: known Pro paths return 402 ---

    if method in ("POST", "PUT", "DELETE"):
        for prefix in _PRO_ENDPOINTS:
            if path.startswith(prefix):
                return _json_response(
                    402,
                    {
                        "error": "pro_required",
                        "message": "This feature requires a Pro license",
                        "upgrade_url": "https://lumen-argus.com/pro",
                    },
                )

    return _json_response(404, {"error": "not_found"})


# --- Handler implementations ---


def _handle_config_update(body: bytes, config, store) -> tuple:
    """Handle PUT /api/v1/config — save community-editable settings to DB.

    Uses the same config_overrides SQLite table as Pro, so settings
    survive license transitions without data loss.
    """
    try:
        changes = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        log.debug("PUT /api/v1/config: invalid JSON body")
        return _json_response(400, {"error": "invalid JSON"})

    if not isinstance(changes, dict) or not changes:
        log.debug("PUT /api/v1/config: empty or non-object body")
        return _json_response(400, {"error": "expected a JSON object with settings to update"})

    # Sanitize all user input at the boundary — downstream code (logging,
    # validation, storage) works with clean data, no per-call escaping.
    changes = sanitize_user_input(changes)

    if not store:
        log.error("PUT /api/v1/config: analytics store not available")
        return _json_response(500, {"error": "analytics store not available"})

    log.debug("PUT /api/v1/config: %d change(s) requested: %s", len(changes), list(changes.keys()))
    errors = []
    applied = {}

    for key, value in changes.items():
        try:
            store.set_config_override(key, str(value))
            applied[key] = value
        except ValueError as e:
            log.warning("config override rejected: %s = %s (%s)", key, value, e)
            errors.append({"key": key, "error": str(e)})

    if applied:
        summary = ", ".join("%s=%s" % (k, v) for k, v in applied.items())
        log.info("config update [settings]: %s", summary)

    # Trigger SIGHUP so the running server picks up the changes.
    # Only send if SIGHUP handler is registered (not default/test).
    if applied and hasattr(signal, "SIGHUP"):
        current_handler = signal.getsignal(signal.SIGHUP)
        if current_handler not in (signal.SIG_DFL, signal.SIG_IGN, None):
            try:
                os.kill(os.getpid(), signal.SIGHUP)
                log.debug("SIGHUP sent for config reload")
            except OSError:
                log.warning("could not send SIGHUP for config reload")

    if errors and not applied:
        return _json_response(400, {"error": "; ".join(e["error"] for e in errors)})
    if errors:
        log.info("config update partial: %d applied, %d errors", len(applied), len(errors))
        return _json_response(207, {"applied": applied, "errors": errors})
    return _json_response(200, {"applied": applied})


def _handle_status(store, extensions=None) -> tuple:
    uptime = time.monotonic() - _start_time
    plugins = extensions.loaded_plugins() if extensions else []
    pro_active = any(name == "pro" for name, _ in plugins)
    pro_version = ""
    for name, ver in plugins:
        if name == "pro":
            pro_version = ver
    data = {
        "status": "operational",
        "version": __version__,
        "uptime_seconds": round(uptime, 1),
        "total_findings": store.get_total_count() if store else 0,
        "tier": "pro" if pro_active else "community",
        "pro_version": pro_version,
    }
    return _json_response(200, data)


def _handle_findings_list(params: dict, store) -> tuple:
    if not store:
        return _json_response(200, {"findings": [], "total": 0})

    try:
        limit = min(int(params.get("limit", 50)), 100)
        offset = max(int(params.get("offset", 0)), 0)
    except (ValueError, TypeError):
        return _json_response(400, {"error": "invalid pagination parameters"})
    severity = params.get("severity") or None
    detector = params.get("detector") or None
    provider = params.get("provider") or None
    session_id = params.get("session_id") or None
    account_id = params.get("account_id") or None
    action = params.get("action") or None
    finding_type = params.get("finding_type") or None
    client_name = params.get("client") or None
    days_str = params.get("days")
    days = None
    if days_str:
        try:
            days = int(days_str)
        except (ValueError, TypeError):
            pass

    findings, total = store.get_findings_page(
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
    return _json_response(200, {"findings": findings, "total": total})


def _handle_finding_detail(finding_id: int, store) -> tuple:
    if not store:
        return _json_response(404, {"error": "not_found"})

    finding = store.get_finding_by_id(finding_id)
    if not finding:
        return _json_response(404, {"error": "finding not found"})
    return _json_response(200, finding)


def _handle_sessions(params: dict, store) -> tuple:
    if not store:
        return _json_response(200, {"sessions": []})
    try:
        limit = min(int(params.get("limit", 50)), 100)
    except (ValueError, TypeError):
        return _json_response(400, {"error": "invalid limit"})
    sessions = store.get_sessions(limit=limit)
    return _json_response(200, {"sessions": sessions})


def _handle_dashboard_sessions(params: dict, store) -> tuple:
    """Return active sessions (last 24h) with severity breakdown for dashboard."""
    if not store:
        return _json_response(200, {"sessions": [], "total": 0})
    try:
        limit = min(int(params.get("limit", 5)), 10)
    except (ValueError, TypeError):
        return _json_response(400, {"error": "invalid limit"})
    result = store.get_dashboard_sessions(limit=limit)
    return _json_response(200, result)


def _handle_stats(params: dict, store) -> tuple:
    if not store:
        return _json_response(
            200,
            {
                "total_findings": 0,
                "today_count": 0,
                "last_finding_time": None,
                "by_severity": {},
                "by_detector": {},
                "top_finding_types": {},
                "by_action": {},
                "by_provider": {},
                "by_model": {},
                "by_client": {},
                "daily_trend": [],
            },
        )

    days_str = params.get("days", "30")
    try:
        days = int(days_str)
    except (ValueError, TypeError):
        days = 30
    stats = store.get_stats(days=days)
    return _json_response(200, stats)


def _handle_stats_advanced(params: dict, store, extensions) -> tuple:
    """Pro-gated advanced analytics for dashboard charts."""
    # Check if Pro is active via extensions
    if extensions:
        try:
            checker = extensions.get_license_checker()
            is_valid = checker and checker.is_valid()
        except Exception:
            is_valid = False
        if is_valid:
            days_str = params.get("days", "30")
            try:
                days = int(days_str)
            except (ValueError, TypeError):
                days = 30
            data = {
                "action_trend": store.get_action_trend(days=days) if store else [],
                "activity_matrix": store.get_activity_matrix(days=days) if store else [],
                "top_accounts": store.get_top_accounts(days=days) if store else [],
                "top_projects": store.get_top_projects(days=days) if store else [],
                "detection_coverage": store.get_rules_coverage() if store else {},
            }
            return _json_response(200, data)

    return _json_response(
        402,
        {
            "error": "pro_required",
            "message": "Advanced analytics requires a Pro license",
            "upgrade_url": "https://lumen-argus.com/pro",
        },
    )


def _handle_config(config, store=None) -> tuple:
    """Return sanitized config with DB overrides applied."""
    if not config:
        return _json_response(200, {"community": {}})

    # Start with YAML values
    timeout = config.proxy.timeout
    retries = config.proxy.retries
    default_action = config.default_action
    secrets_action = config.secrets.action or config.default_action
    pii_action = config.pii.action or config.default_action
    proprietary_action = config.proprietary.action or config.default_action

    # Apply DB overrides on top (same values the running server uses)
    if store:
        try:
            overrides = store.get_config_overrides()
            if "proxy.timeout" in overrides:
                timeout = int(overrides["proxy.timeout"])
            if "proxy.retries" in overrides:
                retries = int(overrides["proxy.retries"])
            if "default_action" in overrides:
                default_action = overrides["default_action"]
            if "detectors.secrets.action" in overrides:
                secrets_action = overrides["detectors.secrets.action"]
            if "detectors.pii.action" in overrides:
                pii_action = overrides["detectors.pii.action"]
            if "detectors.proprietary.action" in overrides:
                proprietary_action = overrides["detectors.proprietary.action"]
        except Exception as e:
            log.warning("GET /api/v1/config: could not load DB overrides: %s", e)

    data = {
        "community": {
            "proxy": {
                "port": config.proxy.port,
                "bind": config.proxy.bind,
                "timeout": timeout,
                "retries": retries,
            },
            "default_action": default_action,
            "detectors": {
                "secrets": {"enabled": config.secrets.enabled, "action": secrets_action},
                "pii": {"enabled": config.pii.enabled, "action": pii_action},
                "proprietary": {"enabled": config.proprietary.enabled, "action": proprietary_action},
            },
        },
    }
    return _json_response(200, data)


# --- Allowlist handlers ---


def _handle_allowlists(store, config) -> tuple:
    result = {"secrets": [], "pii": [], "paths": [], "api_entries": []}
    if config:
        try:
            result["secrets"] = [{"pattern": p, "source": "config"} for p in config.allowlist.secrets]
            result["pii"] = [{"pattern": p, "source": "config"} for p in config.allowlist.pii]
            result["paths"] = [{"pattern": p, "source": "config"} for p in config.allowlist.paths]
        except Exception as e:
            log.warning("GET /api/v1/allowlists: config read failed: %s", e)
    if store:
        try:
            api_entries = store.list_allowlist_entries()
            result["api_entries"] = api_entries
            for entry in api_entries:
                lt = entry["list_type"]
                if lt in result:
                    result[lt].append({"pattern": entry["pattern"], "source": "api", "id": entry["id"]})
        except Exception as e:
            log.warning("GET /api/v1/allowlists: DB read failed: %s", e)
    return _json_response(200, result)


def _handle_allowlist_add(body: bytes, store) -> tuple:
    if not store:
        log.error("POST /api/v1/allowlist: analytics store not available")
        return _json_response(500, {"error": "analytics store not available"})
    try:
        data = sanitize_user_input(json.loads(body))
    except (json.JSONDecodeError, UnicodeDecodeError):
        log.debug("POST /api/v1/allowlist: invalid JSON body")
        return _json_response(400, {"error": "invalid JSON"})
    list_type = data.get("type", "")
    pattern = data.get("pattern", "")
    if list_type not in ("secrets", "pii", "paths"):
        log.warning("POST /api/v1/allowlist: invalid type '%s'", list_type)
        return _json_response(400, {"error": "type must be secrets, pii, or paths"})
    if not pattern or not pattern.strip():
        return _json_response(400, {"error": "pattern is required"})
    description = data.get("description", "")
    try:
        entry = store.add_allowlist_entry(list_type, pattern, description=description, created_by="dashboard")
        log.info("allowlist entry added: %s '%s' (id=%d)", list_type, pattern.strip(), entry["id"])
        return _json_response(201, entry)
    except ValueError as e:
        return _json_response(400, {"error": str(e)})


def _handle_allowlist_test(body: bytes, store) -> tuple:
    try:
        data = sanitize_user_input(json.loads(body))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _json_response(400, {"error": "invalid JSON"})
    pattern = data.get("pattern", "")
    test_value = data.get("value", "")
    if not pattern:
        return _json_response(400, {"error": "pattern is required"})
    value_match = fnmatch.fnmatch(test_value, pattern) if test_value else False
    matching = []
    matching_count = 0
    if store:
        try:
            findings, _ = store.get_findings_page(limit=200)
            for f in findings:
                preview = f.get("value_preview", "")
                if preview and fnmatch.fnmatch(preview, pattern):
                    matching_count += 1
                    if len(matching) < 20:
                        matching.append(
                            {
                                "id": f.get("id"),
                                "finding_type": f.get("finding_type", ""),
                                "value_preview": preview,
                                "severity": f.get("severity", ""),
                            }
                        )
        except Exception as e:
            log.warning("POST /api/v1/allowlist/test: findings scan failed: %s", e)
    log.debug("POST /api/v1/allowlist/test: pattern='%s' matched=%d findings", pattern, matching_count)
    return _json_response(
        200, {"value_match": value_match, "matching_findings_count": matching_count, "matching_findings": matching}
    )


def _handle_allowlist_delete(entry_id: str, store) -> tuple:
    if not store:
        log.error("DELETE /api/v1/allowlist: analytics store not available")
        return _json_response(500, {"error": "analytics store not available"})
    try:
        entry_id_int = int(entry_id)
    except (ValueError, TypeError):
        return _json_response(400, {"error": "invalid id"})
    if store.delete_allowlist_entry(entry_id_int):
        log.info("allowlist entry deleted: id=%d", entry_id_int)
        return _json_response(200, {"deleted": entry_id_int})
    return _json_response(404, {"error": "entry not found"})


# --- Rules handlers ---


def _handle_rules_list(params: dict, store) -> tuple:
    if not store:
        return _json_response(200, {"rules": [], "total": 0})
    try:
        limit = min(int(params.get("limit", 50)), 200)
        offset = max(int(params.get("offset", 0)), 0)
    except (ValueError, TypeError):
        return _json_response(400, {"error": "invalid pagination parameters"})
    search = params.get("search", "") or params.get("q", "") or None
    detector = params.get("detector") or None
    tier = params.get("tier") or None
    severity = params.get("severity") or None
    tag = params.get("tag") or None
    enabled_str = params.get("enabled", "")
    enabled = None
    if enabled_str == "true":
        enabled = True
    elif enabled_str == "false":
        enabled = False
    rules, total = store.get_rules_page(
        limit=limit,
        offset=offset,
        search=search,
        detector=detector,
        tier=tier,
        enabled=enabled,
        severity=severity,
        tag=tag,
    )
    return _json_response(200, {"rules": rules, "total": total, "limit": limit, "offset": offset})


def _handle_rules_stats(store) -> tuple:
    if not store:
        return _json_response(200, {"total": 0, "enabled": 0, "disabled": 0, "by_tier": {}, "by_detector": {}})
    stats = store.get_rule_stats()
    try:
        stats["tags"] = store.get_rule_tag_stats()
    except Exception as e:
        log.warning("GET /api/v1/rules/stats: tag stats failed: %s", e)
        stats["tags"] = []
    return _json_response(200, stats)


def _handle_rule_detail(rule_name: str, store) -> tuple:
    rule_name = unquote_plus(rule_name)
    if not store:
        return _json_response(404, {"error": "rule not found"})
    rule = store.get_rule_by_name(rule_name)
    if rule is None:
        return _json_response(404, {"error": "rule not found"})
    return _json_response(200, rule)


def _handle_rule_create(body: bytes, store) -> tuple:
    if not store:
        log.error("POST /api/v1/rules: analytics store not available")
        return _json_response(500, {"error": "analytics store not available"})
    try:
        data = sanitize_user_input(json.loads(body))
    except (json.JSONDecodeError, UnicodeDecodeError):
        log.debug("POST /api/v1/rules: invalid JSON body")
        return _json_response(400, {"error": "invalid JSON"})
    if not isinstance(data, dict) or not data.get("name"):
        return _json_response(400, {"error": "name is required"})
    if not data.get("pattern"):
        return _json_response(400, {"error": "pattern is required"})
    try:
        re.compile(data["pattern"])
    except re.error as e:
        log.warning("POST /api/v1/rules: invalid regex for '%s': %s", data.get("name"), e)
        return _json_response(400, {"error": "invalid regex: %s" % e})
    action = data.get("action", "")
    if action and action not in ("log", "alert", "block"):
        log.warning("POST /api/v1/rules: invalid action '%s' for '%s'", action, data.get("name"))
        return _json_response(400, {"error": "invalid action: %s (allowed: log, alert, block)" % action})
    data["source"] = "dashboard"
    data["tier"] = "custom"
    data["created_by"] = "dashboard"
    try:
        rule = store.create_rule(data)
        log.info(
            "rule created [dashboard]: %s (detector=%s, severity=%s)",
            data["name"],
            data.get("detector", "custom"),
            data.get("severity", "high"),
        )
        return _json_response(201, rule)
    except ValueError as e:
        log.warning("POST /api/v1/rules: conflict for '%s': %s", data.get("name"), e)
        return _json_response(409, {"error": str(e)})


def _handle_rule_update(rule_name: str, body: bytes, store) -> tuple:
    rule_name = sanitize_user_input(unquote_plus(rule_name))
    if not store:
        log.error("PUT /api/v1/rules: analytics store not available")
        return _json_response(500, {"error": "analytics store not available"})
    try:
        data = sanitize_user_input(json.loads(body))
    except (json.JSONDecodeError, UnicodeDecodeError):
        log.debug("PUT /api/v1/rules/%s: invalid JSON body", rule_name)
        return _json_response(400, {"error": "invalid JSON"})
    if not isinstance(data, dict):
        return _json_response(400, {"error": "invalid JSON"})
    action = data.get("action")
    if action is not None and action != "" and action not in ("log", "alert", "block"):
        log.warning("PUT /api/v1/rules/%s: invalid action '%s'", rule_name, action)
        return _json_response(400, {"error": "invalid action: %s (allowed: log, alert, block)" % action})
    data["updated_by"] = "dashboard"
    result = store.update_rule(rule_name, data)
    if result is None:
        return _json_response(404, {"error": "rule not found"})
    changes = ", ".join("%s=%s" % (k, v) for k, v in data.items() if k != "updated_by")
    log.info("rule updated [dashboard]: %s (%s)", rule_name, changes)
    return _json_response(200, result)


def _handle_rule_delete(rule_name: str, store) -> tuple:
    rule_name = sanitize_user_input(unquote_plus(rule_name))
    if not store:
        log.error("DELETE /api/v1/rules: analytics store not available")
        return _json_response(500, {"error": "analytics store not available"})
    if store.delete_rule(rule_name):
        log.info("rule deleted [dashboard]: %s", rule_name)
        return _json_response(200, {"deleted": rule_name})
    return _json_response(404, {"error": "rule not found"})


def _handle_rule_clone(rule_name: str, body: bytes, store) -> tuple:
    rule_name = sanitize_user_input(unquote_plus(rule_name))
    if not store:
        log.error("POST /api/v1/rules/clone: analytics store not available")
        return _json_response(500, {"error": "analytics store not available"})
    try:
        data = sanitize_user_input(json.loads(body)) if body else {}
    except (json.JSONDecodeError, UnicodeDecodeError):
        data = {}
    new_name = data.get("new_name", rule_name + "_custom")
    try:
        rule = store.clone_rule(rule_name, new_name)
        log.info("rule cloned [dashboard]: %s -> %s", rule_name, new_name)
        return _json_response(201, rule)
    except ValueError as e:
        log.warning("POST /api/v1/rules/%s/clone: %s", rule_name, e)
        return _json_response(409, {"error": str(e)})


def _handle_audit(params: dict, audit_reader) -> tuple:
    if not audit_reader:
        return _json_response(200, {"entries": [], "total": 0, "providers": []})

    try:
        limit = min(int(params.get("limit", 50)), 100)
        offset = max(int(params.get("offset", 0)), 0)
    except (ValueError, TypeError):
        return _json_response(400, {"error": "invalid pagination parameters"})
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
    return _json_response(200, {"entries": entries, "total": total, "providers": providers})


def _handle_logs_tail(config) -> tuple:
    """Return last N lines from the application log."""
    if not config:
        return _json_response(200, {"lines": []})

    log_dir = os.path.expanduser(config.logging_config.log_dir)
    log_file = os.path.join(log_dir, "lumen-argus.log")

    if not os.path.exists(log_file):
        return _json_response(200, {"lines": []})

    lines = []
    try:
        with open(log_file, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
            lines = [line.rstrip("\n") for line in all_lines[-100:]]
    except OSError:
        pass

    return _json_response(200, {"lines": lines})


def _handle_license_activation(body: bytes) -> tuple:
    """POST /api/v1/license — save license key to disk."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return _json_response(400, {"error": "invalid JSON"})

    data = sanitize_user_input(data)
    key = data.get("key", "").strip()
    if not key:
        return _json_response(400, {"error": "license key is required"})
    if len(key) > 4096:
        return _json_response(400, {"error": "invalid license key format"})

    # Save to ~/.lumen-argus/license.key
    license_path = os.path.expanduser("~/.lumen-argus/license.key")
    try:
        os.makedirs(os.path.dirname(license_path), exist_ok=True)
        with open(license_path, "w", encoding="utf-8") as f:
            f.write(key)
        os.chmod(license_path, 0o600)
    except OSError as e:
        return _json_response(500, {"error": "failed to save license: %s" % e})

    return _json_response(
        200,
        {
            "status": "saved",
            "message": "License key saved. Restart the proxy to activate.",
            "path": license_path,
        },
    )


# --- Notification channel handlers ---


def _mask_channel(channel: dict) -> dict:
    """Mask sensitive fields in channel config for API responses."""
    ch = dict(channel)
    config = ch.get("config", {})
    if isinstance(config, str):
        config = json.loads(config)
    masked = dict(config)
    for key in _SENSITIVE_FIELDS:
        if key in masked and masked[key]:
            val = str(masked[key])
            masked[key] = val[:4] + "****" + val[-4:] if len(val) > 8 else "****"
    ch["config_masked"] = masked
    ch.pop("config", None)
    return ch


def _rebuild_dispatcher(extensions):
    """Rebuild the notification dispatcher after channel CRUD."""
    dispatcher = extensions.get_dispatcher() if extensions else None
    if dispatcher and hasattr(dispatcher, "rebuild"):
        try:
            dispatcher.rebuild()
        except Exception as e:
            log.warning("dispatcher rebuild failed: %s", e)


def _handle_notifications(path, method, body, store, extensions, request_user=""):
    """Community notification API — CRUD, types, test, batch."""

    # GET /api/v1/notifications/types
    if path == "/api/v1/notifications/types" and method == "GET":
        types = extensions.get_channel_types() if extensions else {}
        limit = extensions.get_channel_limit() if extensions else 1
        count = store.count_notification_channels() if store else 0
        return _json_response(
            200,
            {
                "types": types,
                "channel_limit": limit,
                "channel_count": count,
            },
        )

    # No channel types registered — Pro not loaded (source install)
    # Still return DB channels (from YAML reconciliation) so users can see them
    if not extensions or not extensions.get_channel_types():
        if method == "GET" and path == "/api/v1/notifications/channels":
            channels = []
            count = 0
            if store:
                channels = [_mask_channel(ch) for ch in store.list_notification_channels()]
                count = len(channels)
            return _json_response(
                200,
                {
                    "channels": channels,
                    "channel_limit": 1,
                    "channel_count": count,
                    "notifications_unavailable": True,
                    "message": "Notification dispatch requires the published package. "
                    "Install from PyPI: pip install lumen-argus",
                },
            )
        return None  # fall through for unknown paths

    if not store:
        return _json_response(503, {"error": "analytics store not available"})

    # GET /api/v1/notifications/channels
    if path == "/api/v1/notifications/channels" and method == "GET":
        channels = store.list_notification_channels()
        safe = [_mask_channel(ch) for ch in channels]
        # Enrich with last dispatch status from dispatcher (in-memory)
        dispatcher = extensions.get_dispatcher() if extensions else None
        if dispatcher and hasattr(dispatcher, "get_last_status"):
            try:
                statuses = dispatcher.get_last_status()
                for ch in safe:
                    st = statuses.get(ch.get("id"))
                    if st:
                        ch["last_status"] = st["status"]
                        ch["last_status_at"] = st["timestamp"]
                        ch["last_error"] = st["error"]
            except Exception:
                log.debug("failed to enrich channels with dispatch status", exc_info=True)
        limit = extensions.get_channel_limit()
        return _json_response(
            200,
            {
                "channels": safe,
                "channel_limit": limit,
                "channel_count": len(channels),
            },
        )

    # POST /api/v1/notifications/channels
    if path == "/api/v1/notifications/channels" and method == "POST":
        try:
            data = sanitize_user_input(json.loads(body))
        except (json.JSONDecodeError, ValueError):
            return _json_response(400, {"error": "invalid JSON"})
        if not isinstance(data, dict):
            return _json_response(400, {"error": "invalid JSON"})
        # Validate channel type
        allowed_types = extensions.get_channel_types()
        if data.get("type") not in allowed_types:
            return _json_response(400, {"error": "unknown channel type"})
        # Create with atomic limit check (count + insert under same lock)
        limit = extensions.get_channel_limit()
        data["created_by"] = request_user or "dashboard"
        try:
            channel = store.create_notification_channel(
                data,
                channel_limit=limit,
            )
        except ValueError as e:
            err = str(e)
            if err == "channel_limit_reached":
                count = store.count_notification_channels()
                return _json_response(
                    409,
                    {
                        "error": "channel_limit_reached",
                        "message": "Free tier allows %d channel(s). Upgrade to Pro for unlimited." % (limit or 0),
                        "limit": limit,
                        "count": count,
                    },
                )
            return _json_response(400, {"error": err})
        _rebuild_dispatcher(extensions)
        log.info("notification channel created: %s (type=%s)", channel.get("name"), channel.get("type"))
        return _json_response(201, _mask_channel(channel))

    # POST /api/v1/notifications/channels/batch
    if path == "/api/v1/notifications/channels/batch" and method == "POST":
        try:
            data = sanitize_user_input(json.loads(body))
        except (json.JSONDecodeError, ValueError):
            return _json_response(400, {"error": "invalid JSON"})
        action = data.get("action", "")
        raw_ids = data.get("ids", [])
        if not isinstance(raw_ids, list):
            return _json_response(400, {"error": "ids must be a list"})
        ids = []
        for i in raw_ids:
            if isinstance(i, int):
                ids.append(i)
        if action not in ("enable", "disable", "delete") or not ids or len(ids) > 100:
            return _json_response(400, {"error": "invalid batch action"})
        count = store.bulk_update_channels(ids, action)
        _rebuild_dispatcher(extensions)
        return _json_response(200, {"affected": count})

    # Routes with channel ID: /api/v1/notifications/channels/:id[/test]
    parts = path.rstrip("/").split("/")
    # /api/v1/notifications/channels/:id → 6 parts
    # /api/v1/notifications/channels/:id/test → 7 parts
    if len(parts) in (6, 7) and parts[4] == "channels" and parts[5].isdigit():
        channel_id = int(parts[5])
        sub = parts[6] if len(parts) == 7 else None

        # POST /api/v1/notifications/channels/:id/test
        if sub == "test" and method == "POST":
            return _handle_notification_test(channel_id, store, extensions)

        # GET /api/v1/notifications/channels/:id
        # Returns full unmasked config — needed for edit form pre-population.
        # Protected by dashboard auth (password/session when configured).
        if method == "GET" and sub is None:
            channel = store.get_notification_channel(channel_id)
            if not channel:
                return _json_response(404, {"error": "not found"})
            return _json_response(200, channel)

        # PUT /api/v1/notifications/channels/:id
        if method == "PUT" and sub is None:
            try:
                data = sanitize_user_input(json.loads(body))
            except (json.JSONDecodeError, ValueError):
                return _json_response(400, {"error": "invalid JSON"})
            if not isinstance(data, dict):
                return _json_response(400, {"error": "invalid JSON"})
            data["updated_by"] = request_user or "dashboard"
            try:
                result = store.update_notification_channel(channel_id, data)
            except ValueError as e:
                return _json_response(400, {"error": str(e)})
            if result is None:
                return _json_response(404, {"error": "not found"})
            _rebuild_dispatcher(extensions)
            log.info("notification channel updated: id=%d name=%s", channel_id, result.get("name"))
            return _json_response(200, _mask_channel(result))

        # DELETE /api/v1/notifications/channels/:id
        if method == "DELETE" and sub is None:
            # Get name before deleting for the log
            ch = store.get_notification_channel(channel_id)
            if store.delete_notification_channel(channel_id):
                _rebuild_dispatcher(extensions)
                log.info("notification channel deleted: id=%d name=%s", channel_id, ch["name"] if ch else "?")
                return _json_response(200, {"deleted": channel_id})
            return _json_response(404, {"error": "not found"})

    return None  # fall through to Pro handler for extended endpoints


def _handle_notification_test(channel_id, store, extensions):
    """POST /api/v1/notifications/channels/:id/test"""
    channel = store.get_notification_channel(channel_id)
    if not channel:
        return _json_response(404, {"error": "not found"})

    builder = extensions.get_notifier_builder() if extensions else None
    if not builder:
        return _json_response(
            400,
            {
                "error": "notifications_unavailable",
                "message": "Install from PyPI: pip install lumen-argus",
            },
        )

    notifier = builder(channel)
    if not notifier:
        return _json_response(400, {"error": "invalid channel configuration"})

    from lumen_argus.models import Finding

    test_finding = Finding(
        detector="test",
        type="test_notification",
        severity="critical",
        location="test",
        value_preview="****",
        matched_value="",
        action="block",
    )
    try:
        notifier.notify([test_finding], provider="lumen-argus", model="test")
        return _json_response(200, {"status": "sent", "channel_id": channel_id})
    except Exception as e:
        return _json_response(502, {"status": "failed", "error": str(e)})


# ---------------------------------------------------------------------------
# Pipeline configuration
# ---------------------------------------------------------------------------

# Stage metadata — label, description, group, default enabled, availability
_PIPELINE_STAGES = [
    {
        "name": "outbound_dlp",
        "label": "Outbound DLP",
        "description": "Secret, PII, and proprietary code detection on outbound requests",
        "group": "request",
        "default_enabled": True,
        "available": True,
        "has_sub_detectors": True,
    },
    {
        "name": "encoding_decode",
        "label": "Encoding Decode",
        "description": "Decode base64, hex, URL, and Unicode before scanning",
        "group": "request",
        "default_enabled": True,
        "available": True,
        "has_sub_detectors": False,
        "has_encoding_settings": True,
    },
    {
        "name": "response_secrets",
        "label": "Response Secrets",
        "description": "Detect secrets leaked in API responses (async, no latency impact)",
        "group": "response",
        "default_enabled": False,
        "available": True,
        "has_sub_detectors": False,
    },
    {
        "name": "response_injection",
        "label": "Response Injection",
        "description": "Detect prompt injection patterns in API responses (async, no latency impact)",
        "group": "response",
        "default_enabled": False,
        "available": True,
        "has_sub_detectors": False,
    },
    {
        "name": "mcp_arguments",
        "label": "MCP Arguments",
        "description": "Scan MCP tool call arguments for sensitive data",
        "group": "protocol",
        "default_enabled": True,
        "available": True,
        "has_sub_detectors": False,
    },
    {
        "name": "mcp_responses",
        "label": "MCP Responses",
        "description": "Scan MCP tool return values for sensitive data and injection",
        "group": "protocol",
        "default_enabled": True,
        "available": True,
        "has_sub_detectors": False,
    },
    {
        "name": "websocket_outbound",
        "label": "WebSocket Outbound",
        "description": "Scan outbound WebSocket frames for sensitive data",
        "group": "protocol",
        "default_enabled": False,
        "available": True,
        "has_sub_detectors": False,
    },
    {
        "name": "websocket_inbound",
        "label": "WebSocket Inbound",
        "description": "Scan inbound WebSocket frames for sensitive data",
        "group": "protocol",
        "default_enabled": False,
        "available": True,
        "has_sub_detectors": False,
    },
]


def _handle_pipeline_get(config, store=None) -> tuple:
    """Return pipeline stage configuration with stats."""
    log.debug("GET /api/v1/pipeline")
    if not config:
        log.warning("GET /api/v1/pipeline: no config available")
        return _json_response(200, {"default_action": "alert", "stages": []})

    # Get DB overrides
    overrides = {}
    if store:
        try:
            overrides = store.get_config_overrides()
        except Exception as e:
            log.warning("GET /api/v1/pipeline: could not load DB overrides: %s", e)

    # Get finding stats per detector (for sub-detector counts)
    stats = {}
    if store:
        try:
            raw_stats = store.get_stats()
            stats = raw_stats.get("by_detector", {})
        except Exception:
            pass

    default_action = overrides.get("default_action", config.default_action)

    stages = []
    for meta in _PIPELINE_STAGES:
        name = meta["name"]
        stage_cfg = getattr(config.pipeline, name, None)

        # Apply DB override for enabled
        override_key = "pipeline.stages.%s.enabled" % name
        if override_key in overrides:
            enabled = overrides[override_key].lower() == "true"
        elif stage_cfg:
            enabled = stage_cfg.enabled
        else:
            enabled = meta["default_enabled"]

        stage = {
            "name": name,
            "label": meta["label"],
            "description": meta["description"],
            "group": meta["group"],
            "enabled": enabled,
            "available": meta["available"],
        }

        # Sub-detectors for outbound_dlp
        if meta["has_sub_detectors"]:
            sub_detectors = []
            for det_name in ("secrets", "pii", "proprietary"):
                det_cfg = getattr(config, det_name, None)

                # Apply DB overrides
                det_enabled_key = "detectors.%s.enabled" % det_name
                det_action_key = "detectors.%s.action" % det_name
                det_enabled = (
                    overrides.get(det_enabled_key, str(det_cfg.enabled if det_cfg else True)).lower() == "true"
                )
                det_action = overrides.get(det_action_key, det_cfg.action if det_cfg else "") or "default"

                det_count = stats.get(det_name, 0)
                # RulesDetector uses pattern names, not detector category names —
                # sum all detector entries that aren't in the other categories
                if det_name == "secrets" and not det_count:
                    det_count = sum(v for k, v in stats.items() if k not in ("pii", "proprietary", "custom"))

                sub_detectors.append(
                    {
                        "name": det_name,
                        "enabled": det_enabled,
                        "action": det_action,
                        "finding_count": det_count,
                    }
                )
            stage["sub_detectors"] = sub_detectors
            stage["finding_count"] = sum(d["finding_count"] for d in sub_detectors)
        elif meta.get("has_encoding_settings"):
            # Encoding decode settings
            enc_cfg = getattr(config.pipeline, "encoding_decode", None)
            enc_settings = {}
            for enc_name in ("base64", "hex", "url", "unicode"):
                override_key = "pipeline.stages.encoding_decode.%s" % enc_name
                if override_key in overrides:
                    enc_settings[enc_name] = overrides[override_key].lower() == "true"
                elif enc_cfg:
                    enc_settings[enc_name] = getattr(enc_cfg, enc_name, True)
                else:
                    enc_settings[enc_name] = True
            for int_key in ("max_depth", "min_decoded_length", "max_decoded_length"):
                override_key = "pipeline.stages.encoding_decode.%s" % int_key
                if override_key in overrides:
                    enc_settings[int_key] = int(overrides[override_key])
                elif enc_cfg:
                    enc_settings[int_key] = getattr(enc_cfg, int_key)
                else:
                    enc_settings[int_key] = {"max_depth": 2, "min_decoded_length": 8, "max_decoded_length": 10000}[
                        int_key
                    ]
            stage["encoding_settings"] = enc_settings
            stage["finding_count"] = 0
        else:
            stage["finding_count"] = 0

        # MCP tool list counts for mcp_arguments stage
        # DB includes both source='config' (reconciled from YAML) and source='api'
        # (dashboard-managed). Don't double-count by also adding config object entries.
        if name == "mcp_arguments" and store:
            try:
                tool_lists = store.get_mcp_tool_lists()
                allowed_count = len(tool_lists.get("allowed", []))
                blocked_count = len(tool_lists.get("blocked", []))
                # If DB is empty (no reconciliation yet), fall back to config
                if allowed_count == 0 and blocked_count == 0:
                    mcp_cfg = getattr(config, "mcp", None)
                    if mcp_cfg:
                        allowed_count = len(mcp_cfg.allowed_tools)
                        blocked_count = len(mcp_cfg.blocked_tools)
                stage["mcp_tools"] = {
                    "allowed_count": allowed_count,
                    "blocked_count": blocked_count,
                }
            except Exception:
                stage["mcp_tools"] = {"allowed_count": 0, "blocked_count": 0}

        stages.append(stage)

    # Parallel batching toggle
    parallel_key = "pipeline.parallel_batching"
    if parallel_key in overrides:
        parallel_batching = overrides[parallel_key].lower() == "true"
    else:
        parallel_batching = config.pipeline.parallel_batching

    return _json_response(
        200,
        {
            "default_action": default_action,
            "parallel_batching": parallel_batching,
            "stages": stages,
        },
    )


def _handle_pipeline_update(body: bytes, config, store) -> tuple:
    """Save pipeline configuration changes."""
    if not store:
        log.error("PUT /api/v1/pipeline: analytics store not available")
        return _json_response(500, {"error": "analytics store not available"})

    try:
        changes = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        log.debug("PUT /api/v1/pipeline: invalid JSON body")
        return _json_response(400, {"error": "invalid JSON"})

    if not isinstance(changes, dict):
        log.debug("PUT /api/v1/pipeline: empty or non-object body")
        return _json_response(400, {"error": "expected JSON object"})

    # Sanitize all user input at the boundary
    changes = sanitize_user_input(changes)

    log.debug("PUT /api/v1/pipeline: %d section(s) requested: %s", len(changes), list(changes.keys()))

    errors = []
    applied = {}

    # Handle parallel_batching
    if "parallel_batching" in changes:
        try:
            store.set_config_override("pipeline.parallel_batching", str(changes["parallel_batching"]).lower())
            applied["parallel_batching"] = changes["parallel_batching"]
        except ValueError as e:
            log.warning("pipeline config rejected: parallel_batching = %s (%s)", changes["parallel_batching"], e)
            errors.append({"key": "parallel_batching", "error": str(e)})

    # Handle default_action
    if "default_action" in changes:
        try:
            store.set_config_override("default_action", str(changes["default_action"]))
            applied["default_action"] = changes["default_action"]
        except ValueError as e:
            log.warning("pipeline config rejected: default_action = %s (%s)", changes["default_action"], e)
            errors.append({"key": "default_action", "error": str(e)})

    # Handle stage toggles
    stages = changes.get("stages", {})
    if isinstance(stages, dict):
        for stage_name, stage_data in stages.items():
            if not isinstance(stage_data, dict):
                continue
            if "enabled" in stage_data:
                key = "pipeline.stages.%s.enabled" % stage_name
                try:
                    store.set_config_override(key, str(stage_data["enabled"]).lower())
                    applied[key] = stage_data["enabled"]
                except ValueError as e:
                    log.warning("pipeline config rejected: %s = %s (%s)", key, stage_data["enabled"], e)
                    errors.append({"key": key, "error": str(e)})

    # Handle encoding settings
    _ALLOWED_ENC_KEYS = {"base64", "hex", "url", "unicode", "max_depth", "min_decoded_length", "max_decoded_length"}
    enc = changes.get("encoding_settings", {})
    if isinstance(enc, dict):
        for enc_key, enc_val in enc.items():
            if enc_key not in _ALLOWED_ENC_KEYS:
                log.warning("pipeline config rejected: unknown encoding setting '%s'", enc_key)
                errors.append({"key": enc_key, "error": "unknown encoding setting"})
                continue
            key = "pipeline.stages.encoding_decode.%s" % enc_key
            try:
                store.set_config_override(key, str(enc_val))
                applied[key] = enc_val
            except ValueError as e:
                log.warning("pipeline config rejected: %s = %s (%s)", key, enc_val, e)
                errors.append({"key": key, "error": str(e)})

    # Handle detector toggles and action overrides
    detectors = changes.get("detectors", {})
    if isinstance(detectors, dict):
        for det_name, det_data in detectors.items():
            if not isinstance(det_data, dict):
                continue
            if "enabled" in det_data:
                key = "detectors.%s.enabled" % det_name
                try:
                    store.set_config_override(key, str(det_data["enabled"]).lower())
                    applied[key] = det_data["enabled"]
                except ValueError as e:
                    log.warning("pipeline config rejected: %s = %s (%s)", key, det_data["enabled"], e)
                    errors.append({"key": key, "error": str(e)})
            if "action" in det_data:
                key = "detectors.%s.action" % det_name
                action_val = str(det_data["action"])
                try:
                    if action_val == "default":
                        store.delete_config_override(key)
                        applied[key] = "default"
                    else:
                        store.set_config_override(key, action_val)
                        applied[key] = action_val
                except ValueError as e:
                    log.warning("pipeline config rejected: %s = %s (%s)", key, action_val, e)
                    errors.append({"key": key, "error": str(e)})

    # Trigger SIGHUP for hot reload
    if applied and hasattr(signal, "SIGHUP"):
        current_handler = signal.getsignal(signal.SIGHUP)
        if current_handler not in (signal.SIG_DFL, signal.SIG_IGN, None):
            try:
                os.kill(os.getpid(), signal.SIGHUP)
                log.debug("SIGHUP sent for pipeline config reload")
            except OSError:
                log.warning("could not send SIGHUP for pipeline config reload")

    if applied:
        summary = ", ".join("%s=%s" % (k, v) for k, v in applied.items())
        if errors:
            log.info("pipeline update [dashboard]: %d applied, %d errors: %s", len(applied), len(errors), summary)
        else:
            log.info("pipeline update [dashboard]: %s", summary)

    status = 200 if not errors else 207
    return _json_response(status, {"applied": applied, "errors": errors})


# ---------------------------------------------------------------------------
# MCP tool lists
# ---------------------------------------------------------------------------


def _handle_mcp_tools_list(store, config) -> tuple:
    """Return merged MCP tool lists (config + DB)."""
    log.debug("GET /api/v1/mcp/tools")
    if not store:
        return _json_response(200, {"allowed": [], "blocked": []})

    try:
        db_lists = store.get_mcp_tool_lists()
    except Exception as e:
        log.warning("GET /api/v1/mcp/tools: DB error: %s", e)
        db_lists = {"allowed": [], "blocked": []}

    # Merge config entries (read-only, source=config)
    config_allowed = []
    config_blocked = []
    if config:
        mcp_cfg = getattr(config, "mcp", None)
        if mcp_cfg:
            for t in mcp_cfg.allowed_tools:
                config_allowed.append({"tool_name": t, "source": "config"})
            for t in mcp_cfg.blocked_tools:
                config_blocked.append({"tool_name": t, "source": "config"})

    return _json_response(
        200,
        {
            "allowed": config_allowed + db_lists.get("allowed", []),
            "blocked": config_blocked + db_lists.get("blocked", []),
        },
    )


def _handle_mcp_tools_add(body: bytes, store) -> tuple:
    """Add a tool to the allowed or blocked list."""
    if not store:
        log.error("POST /api/v1/mcp/tools: analytics store not available")
        return _json_response(500, {"error": "analytics store not available"})

    try:
        data = sanitize_user_input(json.loads(body))
    except (json.JSONDecodeError, UnicodeDecodeError):
        log.debug("POST /api/v1/mcp/tools: invalid JSON body")
        return _json_response(400, {"error": "invalid JSON"})

    list_type = data.get("list_type", "")
    tool_name = data.get("tool_name", "")

    try:
        entry_id = store.add_mcp_tool_entry(list_type, tool_name)
    except ValueError as e:
        log.warning("POST /api/v1/mcp/tools: rejected '%s' %s (%s)", tool_name, list_type, e)
        return _json_response(400, {"error": str(e)})

    if not entry_id:
        log.debug("POST /api/v1/mcp/tools: '%s' already in %s list", tool_name, list_type)
        return _json_response(409, {"error": "tool already in list"})

    log.info("POST /api/v1/mcp/tools: added '%s' to %s list (id=%d)", tool_name, list_type, entry_id)
    return _json_response(201, {"id": entry_id, "list_type": list_type, "tool_name": tool_name})


def _handle_mcp_tools_delete(entry_id: int, store) -> tuple:
    """Remove an API-managed MCP tool list entry."""
    if not store:
        log.error("DELETE /api/v1/mcp/tools: analytics store not available")
        return _json_response(500, {"error": "analytics store not available"})

    deleted = store.delete_mcp_tool_entry(entry_id)
    if not deleted:
        log.debug("DELETE /api/v1/mcp/tools/%d: not found or config-managed", entry_id)
        return _json_response(404, {"error": "entry not found or config-managed (read-only)"})

    log.info("DELETE /api/v1/mcp/tools/%d: deleted", entry_id)
    return _json_response(200, {"deleted": True})


# --- WebSocket connection endpoints ---


def _handle_ws_connections(params: dict, store) -> tuple:
    """Return recent WebSocket connections, newest first."""
    if not store:
        return _json_response(500, {"error": "analytics store not available"})

    try:
        limit = min(int(params.get("limit", 50)), 200)
        offset = max(int(params.get("offset", 0)), 0)
    except (ValueError, TypeError):
        return _json_response(400, {"error": "invalid limit or offset"})

    connections = store.get_ws_connections(limit=limit, offset=offset)
    log.debug("GET /api/v1/ws/connections: %d result(s) (limit=%d, offset=%d)", len(connections), limit, offset)
    return _json_response(200, {"connections": connections, "count": len(connections)})


def _handle_ws_stats(params: dict, store) -> tuple:
    """Return aggregate WebSocket stats for the given period."""
    if not store:
        return _json_response(500, {"error": "analytics store not available"})

    try:
        days = min(max(int(params.get("days", 7)), 1), 365)
    except (ValueError, TypeError):
        return _json_response(400, {"error": "invalid days parameter"})

    stats = store.get_ws_stats(days=days)
    log.debug("GET /api/v1/ws/stats: days=%d, %d connections", days, stats.get("total_connections", 0))
    return _json_response(200, stats)
