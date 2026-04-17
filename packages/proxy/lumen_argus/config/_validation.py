"""Configuration validation — checks raw YAML dicts against known keys, types, ranges.

Changes when: validation rules or constraints are added/modified.
"""

from __future__ import annotations

import os
import re
from typing import Any

from lumen_argus.config._schema import _ENCODING_NAMES, _PIPELINE_STAGE_NAMES
from lumen_argus.models import ACTION_SET, SEVERITY_SET

_VALID_ACTIONS = ACTION_SET

_KNOWN_TOP_KEYS = {
    # Community keys
    "version",
    "proxy",
    "default_action",
    "detectors",
    "allowlists",
    "audit",
    "logging",
    "custom_rules",
    "dashboard",
    "analytics",
    "pipeline",
    "mcp",
    "websocket",
    "enrollment",
    "relay",
    "engine",
    # Pro/Enterprise extension keys
    "license_key",
    "redaction",
    "notifications",
    "dedup",
    "rules",
    "rule_analysis",
    "enterprise",
    "custom_detectors",
}
_KNOWN_PROXY_KEYS = {
    "port",
    "bind",
    "upstream",
    "timeout",
    "connect_timeout",
    "retries",
    "max_body_size",
    "max_connections",
    "drain_timeout",
    "ca_bundle",
    "verify_ssl",
}
_KNOWN_DETECTOR_KEYS = {
    "enabled",
    "action",
    "entropy_threshold",
    "severity_threshold",
    "patterns",
    "types",
    "keywords",
    "file_patterns",
}
_KNOWN_AUDIT_KEYS = {"log_dir", "retention_days", "include_request_summary", "redact_findings_in_log"}
_KNOWN_LOGGING_KEYS = {"log_dir", "file_level", "max_size_mb", "backup_count", "format", "output"}
_KNOWN_CUSTOM_RULE_KEYS = {"name", "pattern", "severity", "action", "detector"}
_KNOWN_DASHBOARD_KEYS = {"enabled", "port", "bind", "password"}
_KNOWN_ANALYTICS_KEYS = {"enabled", "db_path", "retention_days", "hash_secrets"}
_KNOWN_DEDUP_KEYS = {
    "conversation_ttl_minutes",
    "finding_ttl_minutes",
    "max_conversations",
    "max_hashes_per_conversation",
}
_VALID_SEVERITIES = SEVERITY_SET


def _validate_config(data: dict[str, Any], source: str) -> list[str]:
    """Validate parsed config data. Returns list of warnings."""
    warnings: list[str] = []

    if not isinstance(data, dict):
        warnings.append("%s: config root must be a mapping" % source)
        return warnings

    # Check for unknown top-level keys
    warnings.extend("%s: unknown key '%s'" % (source, key) for key in data if key not in _KNOWN_TOP_KEYS)

    # Validate default_action
    if "default_action" in data:
        action = str(data["default_action"])
        if action not in _VALID_ACTIONS:
            warnings.append(
                "%s: default_action '%s' is not valid (expected: %s)"
                % (source, action, ", ".join(sorted(_VALID_ACTIONS)))
            )

    # Validate proxy section
    proxy = data.get("proxy", {})
    if isinstance(proxy, dict):
        warnings.extend("%s: unknown key 'proxy.%s'" % (source, key) for key in proxy if key not in _KNOWN_PROXY_KEYS)
        if "port" in proxy:
            try:
                port = int(proxy["port"])
                if port < 1 or port > 65535:
                    warnings.append("%s: proxy.port %d is out of range (1-65535)" % (source, port))
            except (ValueError, TypeError):
                warnings.append("%s: proxy.port must be an integer" % source)
        if "bind" in proxy:
            bind = str(proxy["bind"])
            if bind not in ("127.0.0.1", "localhost"):
                warnings.append(
                    "%s: proxy.bind '%s' exposes the proxy on the network (use --host for Docker)" % (source, bind)
                )
        if "timeout" in proxy:
            try:
                t = int(proxy["timeout"])
                if t < 1 or t > 300:
                    warnings.append("%s: proxy.timeout %d is out of range (1-300)" % (source, t))
            except (ValueError, TypeError):
                warnings.append("%s: proxy.timeout must be an integer" % source)
        if "connect_timeout" in proxy:
            try:
                ct = int(proxy["connect_timeout"])
                if ct < 1 or ct > 120:
                    warnings.append("%s: proxy.connect_timeout %d is out of range (1-120)" % (source, ct))
            except (ValueError, TypeError):
                warnings.append("%s: proxy.connect_timeout must be an integer" % source)
        if "retries" in proxy:
            try:
                r = int(proxy["retries"])
                if r < 0 or r > 5:
                    warnings.append("%s: proxy.retries %d is out of range (0-5)" % (source, r))
            except (ValueError, TypeError):
                warnings.append("%s: proxy.retries must be an integer" % source)
        if "max_connections" in proxy:
            try:
                mc = int(proxy["max_connections"])
                if mc < 1 or mc > 100:
                    warnings.append("%s: proxy.max_connections %d is out of range (1-100)" % (source, mc))
            except (ValueError, TypeError):
                warnings.append("%s: proxy.max_connections must be an integer" % source)
        if "drain_timeout" in proxy:
            try:
                dt = int(proxy["drain_timeout"])
                if dt < 0 or dt > 300:
                    warnings.append("%s: proxy.drain_timeout %d is out of range (0-300)" % (source, dt))
            except (ValueError, TypeError):
                warnings.append("%s: proxy.drain_timeout must be an integer" % source)
        if "ca_bundle" in proxy:
            ca = str(proxy["ca_bundle"])
            if ca and not os.path.exists(os.path.expanduser(ca)):
                warnings.append("%s: proxy.ca_bundle path '%s' does not exist" % (source, ca))
        if "verify_ssl" in proxy:
            val = proxy["verify_ssl"]
            if not isinstance(val, bool):
                warnings.append("%s: proxy.verify_ssl must be true or false" % source)
            elif not val:
                warnings.append("%s: proxy.verify_ssl is disabled — TLS certificates will not be verified" % source)

    # Validate detector sections
    detectors = data.get("detectors", {})
    if isinstance(detectors, dict):
        for det_name in ("secrets", "pii", "proprietary"):
            det = detectors.get(det_name, {})
            if isinstance(det, dict):
                warnings.extend(
                    "%s: unknown key 'detectors.%s.%s'" % (source, det_name, key)
                    for key in det
                    if key not in _KNOWN_DETECTOR_KEYS
                )
                if "action" in det:
                    action = str(det["action"])
                    if action not in _VALID_ACTIONS:
                        warnings.append(
                            "%s: detectors.%s.action '%s' is not valid (expected: %s)"
                            % (source, det_name, action, ", ".join(sorted(_VALID_ACTIONS)))
                        )
                if "entropy_threshold" in det:
                    try:
                        threshold = float(det["entropy_threshold"])
                        if threshold < 0 or threshold > 10:
                            warnings.append(
                                "%s: detectors.%s.entropy_threshold %.1f is out of range (0-10)"
                                % (source, det_name, threshold)
                            )
                    except (ValueError, TypeError):
                        warnings.append("%s: detectors.%s.entropy_threshold must be a number" % (source, det_name))

    # Validate audit section
    audit = data.get("audit", {})
    if isinstance(audit, dict):
        warnings.extend("%s: unknown key 'audit.%s'" % (source, key) for key in audit if key not in _KNOWN_AUDIT_KEYS)
        if "retention_days" in audit:
            try:
                days = int(audit["retention_days"])
                if days < 1:
                    warnings.append("%s: audit.retention_days must be positive" % source)
            except (ValueError, TypeError):
                warnings.append("%s: audit.retention_days must be an integer" % source)

    # Validate logging section
    logging_sec = data.get("logging", {})
    if isinstance(logging_sec, dict):
        warnings.extend(
            "%s: unknown key 'logging.%s'" % (source, key) for key in logging_sec if key not in _KNOWN_LOGGING_KEYS
        )
        if "file_level" in logging_sec:
            lvl = str(logging_sec["file_level"]).lower()
            if lvl not in ("debug", "info", "warning", "error"):
                warnings.append(
                    "%s: logging.file_level '%s' is not valid (expected: debug, info, warning, error)" % (source, lvl)
                )
        if "max_size_mb" in logging_sec:
            try:
                sz = int(logging_sec["max_size_mb"])
                if sz < 1:
                    warnings.append("%s: logging.max_size_mb must be positive" % source)
            except (ValueError, TypeError):
                warnings.append("%s: logging.max_size_mb must be an integer" % source)
        if "backup_count" in logging_sec:
            try:
                bc = int(logging_sec["backup_count"])
                if bc < 0:
                    warnings.append("%s: logging.backup_count must be non-negative" % source)
            except (ValueError, TypeError):
                warnings.append("%s: logging.backup_count must be an integer" % source)
        if "format" in logging_sec:
            fmt = str(logging_sec["format"]).lower()
            if fmt not in ("text", "json"):
                warnings.append("%s: logging.format '%s' is not valid (expected: text, json)" % (source, fmt))
        if "output" in logging_sec:
            output = str(logging_sec["output"]).lower()
            if output not in ("file", "stdout", "both"):
                warnings.append(
                    "%s: logging.output '%s' is not valid (expected: file, stdout, both)" % (source, output)
                )

    # Validate custom_rules section
    rules = data.get("custom_rules", [])
    if isinstance(rules, list):
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                warnings.append("%s: custom_rules[%d] must be a mapping" % (source, i))
                continue
            warnings.extend(
                "%s: unknown key 'custom_rules[%d].%s'" % (source, i, key)
                for key in rule
                if key not in _KNOWN_CUSTOM_RULE_KEYS
            )
            if "name" not in rule or not rule["name"]:
                warnings.append("%s: custom_rules[%d] missing required 'name'" % (source, i))
            if "pattern" not in rule or not rule["pattern"]:
                warnings.append("%s: custom_rules[%d] missing required 'pattern'" % (source, i))
            else:
                try:
                    re.compile(str(rule["pattern"]))
                except re.error as e:
                    warnings.append("%s: custom_rules[%d].pattern is invalid regex: %s" % (source, i, e))
            if "severity" in rule:
                sev = str(rule["severity"]).lower()
                if sev not in _VALID_SEVERITIES:
                    warnings.append(
                        "%s: custom_rules[%d].severity '%s' is not valid (expected: %s)"
                        % (source, i, sev, ", ".join(sorted(_VALID_SEVERITIES)))
                    )
            if "action" in rule:
                act = str(rule["action"])
                if act not in _VALID_ACTIONS:
                    warnings.append(
                        "%s: custom_rules[%d].action '%s' is not valid (expected: %s)"
                        % (source, i, act, ", ".join(sorted(_VALID_ACTIONS)))
                    )

    # Validate notifications section
    notifications = data.get("notifications", [])
    if isinstance(notifications, list):
        _known_notif_keys = {
            "name",
            "type",
            "url",
            "headers",
            "webhook_url",
            "smtp_host",
            "smtp_port",
            "from_addr",
            "to_addrs",
            "username",
            "password",
            "use_tls",
            "channel",
            "routing_key",
            "api_key",
            "team",
            "project_key",
            "api_token",
            "email",
            "issue_type",
            "events",
            "min_severity",
            "enabled",
        }
        for i, notif in enumerate(notifications):
            if not isinstance(notif, dict):
                warnings.append("%s: notifications[%d] must be a mapping" % (source, i))
                continue
            if "name" not in notif or not notif["name"]:
                warnings.append("%s: notifications[%d] missing required 'name'" % (source, i))
            if "type" not in notif or not notif["type"]:
                warnings.append("%s: notifications[%d] missing required 'type'" % (source, i))
            warnings.extend(
                "%s: unknown key 'notifications[%d].%s'" % (source, i, key)
                for key in notif
                if key not in _known_notif_keys
            )

    # Validate dashboard section
    dashboard = data.get("dashboard", {})
    if isinstance(dashboard, dict):
        warnings.extend(
            "%s: unknown key 'dashboard.%s'" % (source, key) for key in dashboard if key not in _KNOWN_DASHBOARD_KEYS
        )
        if "port" in dashboard:
            try:
                port = int(dashboard["port"])
                if port < 1 or port > 65535:
                    warnings.append("%s: dashboard.port %d is out of range (1-65535)" % (source, port))
            except (ValueError, TypeError):
                warnings.append("%s: dashboard.port must be an integer" % source)
        if "bind" in dashboard:
            bind = str(dashboard["bind"])
            if bind not in ("127.0.0.1", "localhost"):
                warnings.append(
                    "%s: dashboard.bind '%s' exposes the dashboard on the network (use --host for Docker)"
                    % (source, bind)
                )

    # Validate analytics section
    analytics = data.get("analytics", {})
    if isinstance(analytics, dict):
        warnings.extend(
            "%s: unknown key 'analytics.%s'" % (source, key) for key in analytics if key not in _KNOWN_ANALYTICS_KEYS
        )
        if "retention_days" in analytics:
            try:
                days = int(analytics["retention_days"])
                if days < 1:
                    warnings.append("%s: analytics.retention_days must be positive" % source)
            except (ValueError, TypeError):
                warnings.append("%s: analytics.retention_days must be an integer" % source)

    # Validate dedup section
    dedup = data.get("dedup", {})
    if isinstance(dedup, dict):
        warnings.extend("%s: unknown key 'dedup.%s'" % (source, key) for key in dedup if key not in _KNOWN_DEDUP_KEYS)
        for int_key in (
            "conversation_ttl_minutes",
            "finding_ttl_minutes",
            "max_conversations",
            "max_hashes_per_conversation",
        ):
            if int_key in dedup:
                try:
                    val = int(dedup[int_key])
                    if val < 1:
                        warnings.append("%s: dedup.%s must be positive" % (source, int_key))
                except (ValueError, TypeError):
                    warnings.append("%s: dedup.%s must be an integer" % (source, int_key))

    # Validate pipeline section
    pipeline = data.get("pipeline", {})
    if isinstance(pipeline, dict):
        warnings.extend("%s: unknown key 'pipeline.%s'" % (source, key) for key in pipeline if key not in ("stages",))
        stages = pipeline.get("stages", {})
        if isinstance(stages, dict):
            for stage_name, stage_data in stages.items():
                if stage_name not in _PIPELINE_STAGE_NAMES:
                    warnings.append(
                        "%s: unknown pipeline stage '%s' (expected: %s)"
                        % (source, stage_name, ", ".join(sorted(_PIPELINE_STAGE_NAMES)))
                    )
                elif isinstance(stage_data, dict):
                    _allowed_stage_keys = {"enabled", "action", "mode"}
                    if stage_name == "encoding_decode":
                        _allowed_stage_keys |= _ENCODING_NAMES | {
                            "max_depth",
                            "min_decoded_length",
                            "max_decoded_length",
                        }
                    warnings.extend(
                        "%s: unknown key 'pipeline.stages.%s.%s'" % (source, stage_name, key)
                        for key in stage_data
                        if key not in _allowed_stage_keys
                    )
                    if "action" in stage_data:
                        action = str(stage_data["action"])
                        if action not in _VALID_ACTIONS:
                            warnings.append(
                                "%s: pipeline.stages.%s.action '%s' is not valid (expected: %s)"
                                % (source, stage_name, action, ", ".join(sorted(_VALID_ACTIONS)))
                            )
                    if "mode" in stage_data:
                        mode = str(stage_data["mode"])
                        if mode not in ("async", "buffered"):
                            warnings.append(
                                "%s: pipeline.stages.%s.mode '%s' is not valid (expected: async, buffered)"
                                % (source, stage_name, mode)
                            )

    # Validate allowlists section
    al = data.get("allowlists", {})
    if isinstance(al, dict):
        warnings.extend(
            "%s: unknown key 'allowlists.%s'" % (source, key) for key in al if key not in ("secrets", "pii", "paths")
        )
        for list_key in ("secrets", "pii", "paths"):
            val = al.get(list_key)
            if val is not None and not isinstance(val, list):
                warnings.append("%s: allowlists.%s must be a list" % (source, list_key))

    # Validate MCP section
    mcp = data.get("mcp", {})
    if isinstance(mcp, dict):
        _known_mcp_keys = {
            "allowed_tools",
            "blocked_tools",
            "env_filter",
            "env_allowlist",
            "request_tracking",
            "unsolicited_response_action",
            "scan_tool_descriptions",
            "detect_drift",
            "drift_action",
            "session_binding",
            "unknown_tool_action",
            "tool_policies",
            "default_tool_action",
            "enable_risk_classification",
            "approval_mode",
            "adaptive_enforcement",
            "chain_signatures",
        }
        warnings.extend("%s: unknown key 'mcp.%s'" % (source, key) for key in mcp if key not in _known_mcp_keys)
        # Validate action fields — each has different valid values
        _mcp_action_values = {
            "unsolicited_response_action": {"warn", "block"},
            "drift_action": {"alert", "block"},
            "unknown_tool_action": {"warn", "block"},
            "default_tool_action": {"allow", "alert", "block", "approval"},
            "approval_mode": {"dashboard", "webhook", "cli"},
        }
        for action_key, valid_vals in _mcp_action_values.items():
            if action_key in mcp:
                val = str(mcp[action_key])
                if val not in valid_vals:
                    warnings.append(
                        "%s: mcp.%s '%s' is not valid (expected: %s)"
                        % (source, action_key, val, ", ".join(sorted(valid_vals)))
                    )
        ae = mcp.get("adaptive_enforcement", {})
        if isinstance(ae, dict):
            _known_ae_keys = {"enabled", "escalation_threshold", "decay_per_clean"}
            warnings.extend(
                "%s: unknown key 'mcp.adaptive_enforcement.%s'" % (source, key)
                for key in ae
                if key not in _known_ae_keys
            )

    # Validate WebSocket section
    ws = data.get("websocket", {})
    if isinstance(ws, dict):
        _known_ws_keys = {"max_frame_size", "allowed_origins"}
        warnings.extend("%s: unknown key 'websocket.%s'" % (source, key) for key in ws if key not in _known_ws_keys)

    # Validate rules section
    rules = data.get("rules", {})
    if isinstance(rules, dict):
        _known_rules_keys = {"auto_import", "rebuild_delay_seconds"}
        warnings.extend("%s: unknown key 'rules.%s'" % (source, key) for key in rules if key not in _known_rules_keys)

    return warnings
