"""YAML-to-dataclass mapping — applies parsed dict values to typed Config fields.

Changes when: how a YAML value maps to a typed field changes.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from lumen_argus.config._schema import _ENCODING_NAMES, _PIPELINE_STAGE_NAMES, Config, CustomRuleConfig

log = logging.getLogger("argus.config")


def _apply_config(config: Config, data: dict[str, Any]) -> None:
    """Apply parsed YAML data to config object."""
    if not isinstance(data, dict):
        return

    # Proxy settings
    proxy = data.get("proxy", {})
    if isinstance(proxy, dict):
        if "port" in proxy:
            config.proxy.port = int(proxy["port"])
        if "bind" in proxy:
            config.proxy.bind = str(proxy["bind"])
        if "timeout" in proxy:
            config.proxy.timeout = int(proxy["timeout"])
        if "retries" in proxy:
            config.proxy.retries = int(proxy["retries"])
        if "max_body_size" in proxy:
            config.proxy.max_body_size = int(proxy["max_body_size"])
        if "max_connections" in proxy:
            config.proxy.max_connections = int(proxy["max_connections"])
        if "drain_timeout" in proxy:
            config.proxy.drain_timeout = int(proxy["drain_timeout"])
        if "ca_bundle" in proxy:
            config.proxy.ca_bundle = str(proxy["ca_bundle"])
        if "verify_ssl" in proxy:
            config.proxy.verify_ssl = bool(proxy["verify_ssl"])
        if "standalone" in proxy:
            config.proxy.standalone = bool(proxy["standalone"])
        upstream = proxy.get("upstream", {})
        if isinstance(upstream, dict):
            config.upstreams.update(upstream)

    # Default action
    if "default_action" in data:
        config.default_action = str(data["default_action"])

    # Detector settings
    detectors = data.get("detectors", {})
    if isinstance(detectors, dict):
        for name, det_config in [("secrets", config.secrets), ("pii", config.pii), ("proprietary", config.proprietary)]:
            det_data = detectors.get(name, {})
            if isinstance(det_data, dict):
                if "enabled" in det_data:
                    det_config.enabled = bool(det_data["enabled"])
                if "action" in det_data:
                    det_config.action = str(det_data["action"])
                if "entropy_threshold" in det_data:
                    config.entropy_threshold = float(det_data["entropy_threshold"])

    # Allowlists
    al = data.get("allowlists", {})
    if isinstance(al, dict):
        if "secrets" in al and isinstance(al["secrets"], list):
            config.allowlist.secrets = [str(s) for s in al["secrets"]]
        if "pii" in al and isinstance(al["pii"], list):
            config.allowlist.pii = [str(s) for s in al["pii"]]
        if "paths" in al and isinstance(al["paths"], list):
            config.allowlist.paths = [str(s) for s in al["paths"]]

    # Audit
    audit = data.get("audit", {})
    if isinstance(audit, dict):
        if "log_dir" in audit:
            config.audit.log_dir = str(audit["log_dir"])
        if "retention_days" in audit:
            config.audit.retention_days = int(audit["retention_days"])
        if "include_request_summary" in audit:
            config.audit.include_request_summary = bool(audit["include_request_summary"])

    # Logging
    logging_sec = data.get("logging", {})
    if isinstance(logging_sec, dict):
        if "log_dir" in logging_sec:
            config.logging_config.log_dir = str(logging_sec["log_dir"])
        if "file_level" in logging_sec:
            config.logging_config.file_level = str(logging_sec["file_level"]).lower()
        if "max_size_mb" in logging_sec:
            config.logging_config.max_size_mb = int(logging_sec["max_size_mb"])
        if "backup_count" in logging_sec:
            config.logging_config.backup_count = int(logging_sec["backup_count"])

    # Dashboard
    dashboard = data.get("dashboard", {})
    if isinstance(dashboard, dict):
        if "enabled" in dashboard:
            config.dashboard.enabled = bool(dashboard["enabled"])
        if "port" in dashboard:
            config.dashboard.port = int(dashboard["port"])
        if "bind" in dashboard:
            config.dashboard.bind = str(dashboard["bind"])
        if "password" in dashboard:
            config.dashboard.password = str(dashboard["password"])

    # Analytics
    analytics = data.get("analytics", {})
    if isinstance(analytics, dict):
        if "enabled" in analytics:
            config.analytics.enabled = bool(analytics["enabled"])
        if "db_path" in analytics:
            config.analytics.db_path = str(analytics["db_path"])
        if "retention_days" in analytics:
            config.analytics.retention_days = int(analytics["retention_days"])
        if "hash_secrets" in analytics:
            config.analytics.hash_secrets = bool(analytics["hash_secrets"])

    # Rules
    rules_sec = data.get("rules", {})
    if isinstance(rules_sec, dict):
        if "auto_import" in rules_sec:
            config.rules.auto_import = bool(rules_sec["auto_import"])
        if "rebuild_delay_seconds" in rules_sec:
            config.rules.rebuild_delay_seconds = float(rules_sec["rebuild_delay_seconds"])

    # Rule analysis
    ra = data.get("rule_analysis", {})
    if isinstance(ra, dict):
        if "samples" in ra:
            config.rule_analysis.samples = max(10, int(ra["samples"]))
        if "threshold" in ra:
            config.rule_analysis.threshold = float(ra["threshold"])
        if "seed" in ra:
            config.rule_analysis.seed = int(ra["seed"])
        if "auto_on_import" in ra:
            config.rule_analysis.auto_on_import = bool(ra["auto_on_import"])
        if "watchdog_total_s" in ra:
            config.rule_analysis.watchdog_total_s = max(0.0, float(ra["watchdog_total_s"]))
        if "watchdog_phase_s" in ra:
            config.rule_analysis.watchdog_phase_s = max(0.0, float(ra["watchdog_phase_s"]))

    # Dedup
    dedup = data.get("dedup", {})
    if isinstance(dedup, dict):
        if "conversation_ttl_minutes" in dedup:
            config.dedup.conversation_ttl_minutes = int(dedup["conversation_ttl_minutes"])
        if "finding_ttl_minutes" in dedup:
            config.dedup.finding_ttl_minutes = int(dedup["finding_ttl_minutes"])
        if "max_conversations" in dedup:
            config.dedup.max_conversations = int(dedup["max_conversations"])
        if "max_hashes_per_conversation" in dedup:
            config.dedup.max_hashes_per_conversation = int(dedup["max_hashes_per_conversation"])

    # Custom rules
    rules = data.get("custom_rules", [])
    if isinstance(rules, list):
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            name = str(rule.get("name", ""))
            pattern = str(rule.get("pattern", ""))
            if not name or not pattern:
                continue
            try:
                compiled = re.compile(pattern)
            except re.error:
                continue  # validation already warned
            config.custom_rules.append(
                CustomRuleConfig(
                    name=name,
                    pattern=pattern,
                    compiled=compiled,
                    severity=str(rule.get("severity", "high")).lower(),
                    action=str(rule.get("action", "")),
                    detector=str(rule.get("detector", "custom")),
                )
            )

    # WebSocket config
    ws_data = data.get("websocket", {})
    if isinstance(ws_data, dict):
        if "max_frame_size" in ws_data:
            config.websocket.max_frame_size = int(ws_data["max_frame_size"])
        if "allowed_origins" in ws_data and isinstance(ws_data["allowed_origins"], list):
            config.websocket.allowed_origins = [str(o) for o in ws_data["allowed_origins"]]

    # MCP config
    mcp_data = data.get("mcp", {})
    if isinstance(mcp_data, dict):
        if "allowed_tools" in mcp_data and isinstance(mcp_data["allowed_tools"], list):
            config.mcp.allowed_tools = [str(t) for t in mcp_data["allowed_tools"]]
        if "blocked_tools" in mcp_data and isinstance(mcp_data["blocked_tools"], list):
            config.mcp.blocked_tools = [str(t) for t in mcp_data["blocked_tools"]]
        if "env_filter" in mcp_data:
            config.mcp.env_filter = bool(mcp_data["env_filter"])
        if "env_allowlist" in mcp_data and isinstance(mcp_data["env_allowlist"], list):
            config.mcp.env_allowlist = [str(v) for v in mcp_data["env_allowlist"]]
        if "request_tracking" in mcp_data:
            config.mcp.request_tracking = bool(mcp_data["request_tracking"])
        if "unsolicited_response_action" in mcp_data:
            config.mcp.unsolicited_response_action = str(mcp_data["unsolicited_response_action"])
        if "scan_tool_descriptions" in mcp_data:
            config.mcp.scan_tool_descriptions = bool(mcp_data["scan_tool_descriptions"])
        if "detect_drift" in mcp_data:
            config.mcp.detect_drift = bool(mcp_data["detect_drift"])
        if "drift_action" in mcp_data:
            config.mcp.drift_action = str(mcp_data["drift_action"])
        if "session_binding" in mcp_data:
            config.mcp.session_binding = bool(mcp_data["session_binding"])
        if "unknown_tool_action" in mcp_data:
            config.mcp.unknown_tool_action = str(mcp_data["unknown_tool_action"])
        if "tool_policies" in mcp_data:
            policies = mcp_data["tool_policies"]
            if isinstance(policies, list):
                config.mcp.tool_policies = [p for p in policies if isinstance(p, dict)]
        if "default_tool_action" in mcp_data:
            config.mcp.default_tool_action = str(mcp_data["default_tool_action"])
        if "enable_risk_classification" in mcp_data:
            config.mcp.enable_risk_classification = bool(mcp_data["enable_risk_classification"])
        if "approval_mode" in mcp_data:
            config.mcp.approval_mode = str(mcp_data["approval_mode"])
        if "adaptive_enforcement" in mcp_data:
            ae = mcp_data["adaptive_enforcement"]
            if isinstance(ae, dict):
                if "enabled" in ae:
                    config.mcp.adaptive_enforcement.enabled = bool(ae["enabled"])
                if "escalation_threshold" in ae:
                    config.mcp.adaptive_enforcement.escalation_threshold = float(ae["escalation_threshold"])
                if "decay_per_clean" in ae:
                    config.mcp.adaptive_enforcement.decay_per_clean = float(ae["decay_per_clean"])
        if "chain_signatures" in mcp_data:
            chains = mcp_data["chain_signatures"]
            if isinstance(chains, list):
                config.mcp.chain_signatures = [c for c in chains if isinstance(c, dict)]

    # Pipeline stages
    pipeline = data.get("pipeline", {})
    if isinstance(pipeline, dict):
        stages = pipeline.get("stages", {})
        if isinstance(stages, dict):
            for stage_name, stage_data in stages.items():
                if stage_name not in _PIPELINE_STAGE_NAMES:
                    log.debug("skipping unknown pipeline stage: %s", stage_name)
                    continue
                stage_cfg = getattr(config.pipeline, stage_name, None)
                if stage_cfg is None:
                    continue
                if isinstance(stage_data, dict):
                    if "enabled" in stage_data:
                        stage_cfg.enabled = bool(stage_data["enabled"])
                        log.debug("pipeline stage %s: enabled=%s", stage_name, stage_cfg.enabled)
                    if "action" in stage_data:
                        stage_cfg.action = str(stage_data["action"])
                        log.debug("pipeline stage %s: action=%s", stage_name, stage_cfg.action)
                    if "mode" in stage_data:
                        stage_cfg.mode = str(stage_data["mode"])
                        log.debug("pipeline stage %s: mode=%s", stage_name, stage_cfg.mode)
                    # EncodingDecodeConfig extra fields
                    if stage_name == "encoding_decode" and hasattr(stage_cfg, "base64"):
                        for enc in _ENCODING_NAMES:
                            if enc in stage_data:
                                setattr(stage_cfg, enc, bool(stage_data[enc]))
                        if "max_depth" in stage_data:
                            stage_cfg.max_depth = int(stage_data["max_depth"])
                        if "min_decoded_length" in stage_data:
                            stage_cfg.min_decoded_length = int(stage_data["min_decoded_length"])
                        if "max_decoded_length" in stage_data:
                            stage_cfg.max_decoded_length = int(stage_data["max_decoded_length"])

    # Relay config (fault-isolation mode)
    relay_data = data.get("relay", {})
    if isinstance(relay_data, dict):
        if "port" in relay_data:
            p = int(relay_data["port"])
            if not 1 <= p <= 65535:
                log.warning("relay.port %d out of range (1-65535), using default", p)
            else:
                config.relay.port = p
        if "fail_mode" in relay_data:
            fm = str(relay_data["fail_mode"])
            if fm not in ("open", "closed"):
                log.warning("relay.fail_mode '%s' invalid (must be 'open' or 'closed'), using default", fm)
            else:
                config.relay.fail_mode = fm
        if "engine_url" in relay_data:
            eu = str(relay_data["engine_url"])
            if not eu.startswith(("http://", "https://")):
                log.warning("relay.engine_url '%s' must start with http:// or https://, using default", eu)
            else:
                config.relay.engine_url = eu
        if "health_check_interval" in relay_data:
            config.relay.health_check_interval = max(1, int(relay_data["health_check_interval"]))
        if "health_check_timeout" in relay_data:
            config.relay.health_check_timeout = max(1, int(relay_data["health_check_timeout"]))
        if "queue_on_startup" in relay_data:
            config.relay.queue_on_startup = max(0, int(relay_data["queue_on_startup"]))
        if "timeout" in relay_data:
            config.relay.timeout = max(1, int(relay_data["timeout"]))

    # Engine config (fault-isolation mode)
    engine_data = data.get("engine", {})
    if isinstance(engine_data, dict) and "port" in engine_data:
        p = int(engine_data["port"])
        if not 1 <= p <= 65535:
            log.warning("engine.port %d out of range (1-65535), using default", p)
        else:
            config.engine.port = p

    # Enrollment config (enterprise agent deployment)
    enrollment_data = data.get("enrollment", {})
    if isinstance(enrollment_data, dict) and enrollment_data:
        log.info(
            "enrollment config loaded: organization=%s, proxy_url=%s",
            enrollment_data.get("organization", ""),
            enrollment_data.get("proxy_url", ""),
        )
        if "organization" in enrollment_data:
            config.enrollment.organization = str(enrollment_data["organization"])
        if "proxy_url" in enrollment_data:
            config.enrollment.proxy_url = str(enrollment_data["proxy_url"])
        if "dashboard_url" in enrollment_data:
            config.enrollment.dashboard_url = str(enrollment_data["dashboard_url"])
        if "ca_cert" in enrollment_data:
            config.enrollment.ca_cert = str(enrollment_data["ca_cert"])
        policy_data = enrollment_data.get("policy", {})
        if isinstance(policy_data, dict):
            if "fail_mode" in policy_data:
                fm = str(policy_data["fail_mode"])
                if fm in ("open", "closed"):
                    config.enrollment.policy.fail_mode = fm
                else:
                    log.warning("enrollment.policy.fail_mode '%s' invalid, using default", fm)
            if "auto_configure" in policy_data:
                config.enrollment.policy.auto_configure = bool(policy_data["auto_configure"])
            if "allow_disable_protection" in policy_data:
                config.enrollment.policy.allow_disable_protection = bool(policy_data["allow_disable_protection"])
            if "telemetry_interval_seconds" in policy_data:
                config.enrollment.policy.telemetry_interval_seconds = max(
                    60, int(policy_data["telemetry_interval_seconds"])
                )
            if "watch_interval_seconds" in policy_data:
                config.enrollment.policy.watch_interval_seconds = max(60, int(policy_data["watch_interval_seconds"]))

    # Notifications (optional — reconciled to DB on startup)
    notifications = data.get("notifications", [])
    if isinstance(notifications, list):
        config.notifications = [n for n in notifications if isinstance(n, dict)]


def _apply_project_config(config: Config, data: dict[str, Any]) -> None:
    """Apply project-level overrides. Can only be MORE restrictive."""
    if not isinstance(data, dict):
        return

    ACTION_PRIORITY = {"block": 4, "redact": 3, "alert": 2, "log": 1}

    detectors = data.get("detectors", {})
    if isinstance(detectors, dict):
        for name, det_config in [("secrets", config.secrets), ("pii", config.pii), ("proprietary", config.proprietary)]:
            det_data = detectors.get(name, {})
            if isinstance(det_data, dict):
                # Can only upgrade action severity, not downgrade
                if "action" in det_data:
                    new_action = str(det_data["action"])
                    old_priority = ACTION_PRIORITY.get(det_config.action, 0)
                    new_priority = ACTION_PRIORITY.get(new_action, 0)
                    if new_priority > old_priority:
                        det_config.action = new_action

    # Allowlists — project can add to allowlists
    al = data.get("allowlists", {})
    if isinstance(al, dict):
        if "secrets" in al and isinstance(al["secrets"], list):
            config.allowlist.secrets.extend(str(s) for s in al["secrets"])
        if "pii" in al and isinstance(al["pii"], list):
            config.allowlist.pii.extend(str(s) for s in al["pii"])
