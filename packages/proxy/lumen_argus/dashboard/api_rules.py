"""Rules API handlers — CRUD, bulk update, clone, analysis."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING
from urllib.parse import unquote_plus

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore
    from lumen_argus.config import Config
    from lumen_argus.extensions import ExtensionRegistry

from lumen_argus.dashboard.api_helpers import (
    broadcast_sse,
    json_response,
    parse_json_body,
    parse_pagination,
    require_store,
)
from lumen_argus.log_utils import sanitize_user_input
from lumen_argus.models import ACTIONS

log = logging.getLogger("argus.dashboard.api")


def handle_rules_list(params: dict[str, str], store: AnalyticsStore | None) -> tuple[int, bytes]:
    if not store:
        return json_response(200, {"rules": [], "total": 0})
    result = parse_pagination(params, max_limit=200)
    if isinstance(result[1], bytes):
        return result
    limit, offset = result
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
    return json_response(200, {"rules": rules, "total": total, "limit": limit, "offset": offset})


def handle_rules_stats(store: AnalyticsStore | None) -> tuple[int, bytes]:
    if not store:
        return json_response(200, {"total": 0, "enabled": 0, "disabled": 0, "by_tier": {}, "by_detector": {}})
    stats = store.get_rule_stats()
    try:
        stats["tags"] = store.get_rule_tag_stats()
    except Exception as e:
        log.warning("GET /api/v1/rules/stats: tag stats failed: %s", e)
        stats["tags"] = []
    return json_response(200, stats)


def handle_rule_detail(rule_name: str, store: AnalyticsStore | None) -> tuple[int, bytes]:
    rule_name = unquote_plus(rule_name)
    if not store:
        return json_response(404, {"error": "rule not found"})
    rule = store.get_rule_by_name(rule_name)
    if rule is None:
        return json_response(404, {"error": "rule not found"})
    return json_response(200, rule)


def handle_rule_create(
    body: bytes, store: AnalyticsStore | None, extensions: ExtensionRegistry | None = None
) -> tuple[int, bytes]:
    store = require_store(store, "POST /api/v1/rules")
    data = parse_json_body(body, "POST /api/v1/rules")
    if isinstance(data, tuple):
        return data
    if not data.get("name"):
        return json_response(400, {"error": "name is required"})
    if not data.get("pattern"):
        return json_response(400, {"error": "pattern is required"})
    try:
        re.compile(data["pattern"])
    except re.error as e:
        log.warning("POST /api/v1/rules: invalid regex for '%s': %s", data.get("name"), e)
        return json_response(400, {"error": "invalid regex: %s" % e})
    action = data.get("action", "")
    if action and action not in ACTIONS:
        log.warning("POST /api/v1/rules: invalid action '%s' for '%s'", action, data.get("name"))
        return json_response(400, {"error": "invalid action: %s (allowed: %s)" % (action, ", ".join(ACTIONS))})
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
        broadcast_sse(extensions, "rules")
        return json_response(201, rule)
    except ValueError as e:
        log.warning("POST /api/v1/rules: conflict for '%s': %s", data.get("name"), e)
        return json_response(409, {"error": str(e)})


def handle_rule_update(
    rule_name: str, body: bytes, store: AnalyticsStore | None, extensions: ExtensionRegistry | None = None
) -> tuple[int, bytes]:
    rule_name = sanitize_user_input(unquote_plus(rule_name))
    store = require_store(store, "PUT /api/v1/rules/%s" % rule_name)
    data = parse_json_body(body, "PUT /api/v1/rules/%s" % rule_name)
    if isinstance(data, tuple):
        return data
    action = data.get("action")
    if action is not None and action != "" and action not in ACTIONS:
        log.warning("PUT /api/v1/rules/%s: invalid action '%s'", rule_name, action)
        return json_response(400, {"error": "invalid action: %s (allowed: %s)" % (action, ", ".join(ACTIONS))})
    data["updated_by"] = "dashboard"
    result = store.update_rule(rule_name, data)
    if result is None:
        return json_response(404, {"error": "rule not found"})
    changes = ", ".join("%s=%s" % (k, v) for k, v in data.items() if k != "updated_by")
    log.info("rule updated [dashboard]: %s (%s)", rule_name, changes)
    broadcast_sse(extensions, "rules")
    return json_response(200, result)


def handle_rules_bulk_update(
    body: bytes, store: AnalyticsStore | None, extensions: ExtensionRegistry | None = None
) -> tuple[int, bytes]:
    log.debug("POST /api/v1/rules/bulk-update")
    store = require_store(store, "POST /api/v1/rules/bulk-update")
    data = parse_json_body(body, "POST /api/v1/rules/bulk-update")
    if isinstance(data, tuple):
        return data
    names = data.get("names")
    if not isinstance(names, list):
        log.warning("POST /api/v1/rules/bulk-update: names is not a list")
        return json_response(400, {"error": "names must be a list"})
    if len(names) > 500:
        log.warning("POST /api/v1/rules/bulk-update: %d names exceeds cap of 500", len(names))
        return json_response(400, {"error": "too many names (max 500)"})
    update = data.get("update")
    if not isinstance(update, dict) or not update:
        log.warning("POST /api/v1/rules/bulk-update: update is missing or empty")
        return json_response(400, {"error": "update must be a non-empty object"})
    action = update.get("action")
    if action is not None and action != "" and action not in ACTIONS:
        log.warning("POST /api/v1/rules/bulk-update: invalid action '%s'", action)
        return json_response(400, {"error": "invalid action: %s (allowed: %s)" % (action, ", ".join(ACTIONS))})
    update["updated_by"] = "dashboard"
    result = store.rules.bulk_update(names, update)
    log.info(
        "bulk update [dashboard]: %d updated, %d failed, update=%s",
        result["updated"],
        len(result["failed"]),
        update,
    )
    if result["updated"] > 0:
        broadcast_sse(extensions, "rules")
    return json_response(
        200,
        {
            "updated": result["updated"],
            "failed": result["failed"],
            "message": "Updated %d rules" % result["updated"],
        },
    )


def handle_rule_delete(
    rule_name: str, store: AnalyticsStore | None, extensions: ExtensionRegistry | None = None
) -> tuple[int, bytes]:
    rule_name = sanitize_user_input(unquote_plus(rule_name))
    store = require_store(store, "DELETE /api/v1/rules")
    if store.delete_rule(rule_name):
        log.info("rule deleted [dashboard]: %s", rule_name)
        broadcast_sse(extensions, "rules")
        return json_response(200, {"deleted": rule_name})
    return json_response(404, {"error": "rule not found"})


def handle_rule_clone(
    rule_name: str, body: bytes, store: AnalyticsStore | None, extensions: ExtensionRegistry | None = None
) -> tuple[int, bytes]:
    rule_name = sanitize_user_input(unquote_plus(rule_name))
    store = require_store(store, "POST /api/v1/rules/%s/clone" % rule_name)
    if body:
        data = parse_json_body(body, "POST /api/v1/rules/%s/clone" % rule_name)
        if isinstance(data, tuple):
            return data
    else:
        data = {}
    new_name = data.get("new_name", rule_name + "_custom")
    try:
        rule = store.clone_rule(rule_name, new_name)
        log.info("rule cloned [dashboard]: %s -> %s", rule_name, new_name)
        broadcast_sse(extensions, "rules")
        return json_response(201, rule)
    except ValueError as e:
        log.warning("POST /api/v1/rules/%s/clone: %s", rule_name, e)
        return json_response(409, {"error": str(e)})


# --- Rule analysis ---


def handle_rule_analysis_get(store: AnalyticsStore | None) -> tuple[int, bytes]:
    """GET /api/v1/rules/analysis — return cached results or unavailable status."""
    from lumen_argus.rule_analysis import HAS_CROSSFIRE

    log.debug("GET /api/v1/rules/analysis")

    if not HAS_CROSSFIRE:
        return json_response(
            200,
            {
                "available": False,
                "message": (
                    "Rule overlap analysis requires the crossfire-rules package. "
                    "Install with: pip install lumen-argus-proxy[rules-analysis]"
                ),
            },
        )

    store = require_store(store, "rule analysis")

    cached = store.rule_analysis.get_latest_analysis_filtered()
    if not cached:
        return json_response(
            200,
            {
                "available": True,
                "has_results": False,
                "message": "No analysis results yet. Click Analyze to detect rule overlaps.",
            },
        )

    cached["available"] = True
    cached["has_results"] = True
    return json_response(200, cached)


def handle_rule_analysis_trigger(
    _body: bytes, store: AnalyticsStore | None, extensions: ExtensionRegistry | None, config: Config | None = None
) -> tuple[int, bytes]:
    """POST /api/v1/rules/analysis — trigger new analysis."""
    from lumen_argus.rule_analysis import HAS_CROSSFIRE, is_analysis_running, run_analysis_in_background

    log.debug("POST /api/v1/rules/analysis")

    if not HAS_CROSSFIRE:
        return json_response(
            400,
            {
                "error": "crossfire_not_installed",
                "message": (
                    "Rule overlap analysis requires the crossfire-rules package. "
                    "Install with: pip install lumen-argus-proxy[rules-analysis]"
                ),
            },
        )

    store = require_store(store, "rule analysis")

    if is_analysis_running():
        return json_response(
            409,
            {
                "error": "analysis_already_running",
                "message": "Analysis is already in progress. Please wait for it to complete.",
            },
        )

    run_analysis_in_background(store, extensions, thread_name="rule-analysis-api", config=config)

    return json_response(
        202,
        {
            "status": "started",
            "message": "Rule analysis started. Results will be available shortly.",
        },
    )


def handle_rule_analysis_dismiss(body: bytes, store: AnalyticsStore | None) -> tuple[int, bytes]:
    """POST /api/v1/rules/analysis/dismiss — dismiss a finding pair."""
    log.debug("POST /api/v1/rules/analysis/dismiss")

    store = require_store(store, "rule analysis dismiss")

    data = parse_json_body(body, "rule analysis dismiss")
    if isinstance(data, tuple):
        return data

    rule_a = data.get("rule_a", "")
    rule_b = data.get("rule_b", "")
    if not rule_a or not rule_b:
        return json_response(400, {"error": "rule_a and rule_b are required"})

    added = store.rule_analysis.dismiss_finding(rule_a, rule_b)
    if added:
        return json_response(200, {"status": "dismissed", "rule_a": rule_a, "rule_b": rule_b})
    return json_response(200, {"status": "already_dismissed", "rule_a": rule_a, "rule_b": rule_b})


def handle_rule_analysis_status(params: dict[str, str]) -> tuple[int, bytes]:
    """GET /api/v1/rules/analysis/status — return current analysis progress."""
    from lumen_argus.rule_analysis import get_analysis_status

    since = 0
    try:
        since = int(params.get("since", 0))
    except (ValueError, TypeError) as exc:
        log.debug("invalid 'since' param, defaulting to 0: %s", exc)
    status = get_analysis_status(since=since)
    return json_response(200, status)
