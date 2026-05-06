"""Findings API handlers — list, detail, sessions, stats."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore

from lumen_argus.dashboard.api_helpers import (
    json_response,
    parse_days,
    parse_pagination,
)

log = logging.getLogger("argus.dashboard.api")

# Filter parameter names mapped to their query-string keys.
# Each entry is (store_kwarg, query_param).
_FINDING_FILTER_KEYS: list[tuple[str, str]] = [
    ("severity", "severity"),
    ("detector", "detector"),
    ("provider", "provider"),
    ("session_id", "session_id"),
    ("account_id", "account_id"),
    ("action", "action"),
    ("finding_type", "finding_type"),
    ("client_name", "client"),
    ("working_directory", "working_directory"),
    ("hostname", "hostname"),
    ("username", "username"),
    ("sdk_name", "sdk_name"),
    ("runtime", "runtime"),
    ("intercept_mode", "intercept_mode"),
    ("original_host", "original_host"),
    ("origin", "origin"),
]


def handle_findings_list(params: dict[str, str], store: AnalyticsStore | None) -> tuple[int, bytes]:
    if not store:
        return json_response(200, {"findings": [], "total": 0})

    result = parse_pagination(params)
    if isinstance(result[1], bytes):
        return result
    limit, offset = result

    findings, total = store.get_findings_page(
        limit=limit,
        offset=offset,
        **{kwarg: params.get(key) or None for kwarg, key in _FINDING_FILTER_KEYS},  # type: ignore[arg-type]
        days=parse_days(params, default=0) or None,
    )
    return json_response(200, {"findings": findings, "total": total})


def handle_finding_detail(finding_id: int, store: AnalyticsStore | None) -> tuple[int, bytes]:
    if not store:
        return json_response(404, {"error": "not_found"})

    finding = store.get_finding_by_id(finding_id)
    if not finding:
        return json_response(404, {"error": "finding not found"})
    return json_response(200, finding)


def handle_sessions(params: dict[str, str], store: AnalyticsStore | None) -> tuple[int, bytes]:
    if not store:
        return json_response(200, {"sessions": []})
    result = parse_pagination(params)
    if isinstance(result[1], bytes):
        return result
    limit, _ = result
    sessions = store.get_sessions(limit=limit)
    return json_response(200, {"sessions": sessions})


def handle_dashboard_sessions(params: dict[str, str], store: AnalyticsStore | None) -> tuple[int, bytes]:
    """Return active sessions (last 24h) with severity breakdown for dashboard."""
    if not store:
        return json_response(200, {"sessions": [], "total": 0})
    result = parse_pagination(params, default_limit=5, max_limit=10)
    if isinstance(result[1], bytes):
        return result
    limit, _ = result
    data = store.get_dashboard_sessions(limit=limit)
    return json_response(200, data)


def handle_findings_by_project(params: dict[str, str], store: AnalyticsStore | None) -> tuple[int, bytes]:
    """Return findings grouped by working_directory."""
    if not store:
        return json_response(200, {"projects": []})
    days = parse_days(params)
    projects = store.get_by_project(days=days)
    return json_response(200, {"projects": projects})


def handle_stats(params: dict[str, str], store: AnalyticsStore | None) -> tuple[int, bytes]:
    if not store:
        return json_response(
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

    stats = store.get_stats(days=parse_days(params))
    return json_response(200, stats)


def handle_stats_advanced(params: dict[str, str], store: AnalyticsStore | None) -> tuple[int, bytes]:
    """Advanced analytics for dashboard charts."""
    days = parse_days(params)
    data = {
        "action_trend": store.get_action_trend(days=days) if store else [],
        "activity_matrix": store.get_activity_matrix(days=days) if store else [],
        "top_accounts": store.get_top_accounts(days=days) if store else [],
        "top_projects": store.get_top_projects(days=days) if store else [],
        "detection_coverage": store.get_rules_coverage() if store else {},
    }
    return json_response(200, data)
