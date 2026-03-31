"""Configuration loading using PyYAML."""

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger("argus.config")


# ---------------------------------------------------------------------------
# YAML parsing
# ---------------------------------------------------------------------------


def _parse_yaml(text: str) -> dict[str, Any]:
    """Parse YAML text into a dict using PyYAML safe_load."""
    result = yaml.safe_load(text)
    return result if isinstance(result, dict) else {}


# ---------------------------------------------------------------------------
# Config dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ProxyConfig:
    port: int = 8080
    bind: str = "127.0.0.1"
    timeout: int = 120
    retries: int = 1
    max_body_size: int = 50 * 1024 * 1024  # 50MB
    max_connections: int = 10  # max concurrent upstream connections
    drain_timeout: int = 30  # seconds to wait for in-flight requests on shutdown
    ca_bundle: str = ""  # path to custom CA cert file/directory
    verify_ssl: bool = True  # set False for dev/testing only


@dataclass
class DetectorConfig:
    enabled: bool = True
    action: str = ""  # empty = use default_action


@dataclass
class AllowlistConfig:
    secrets: list[str] = field(default_factory=list)
    pii: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)


@dataclass
class AuditConfig:
    log_dir: str = "~/.lumen-argus/audit"
    retention_days: int = 90
    include_request_summary: bool = True


@dataclass
class LoggingConfig:
    log_dir: str = "~/.lumen-argus/logs"
    file_level: str = "info"
    max_size_mb: int = 10
    backup_count: int = 5


@dataclass
class DashboardConfig:
    enabled: bool = True
    port: int = 8081
    bind: str = "127.0.0.1"
    password: str = ""


@dataclass
class AnalyticsConfig:
    enabled: bool = True  # active when dashboard is enabled
    db_path: str = "~/.lumen-argus/analytics.db"
    retention_days: int = 365
    hash_secrets: bool = True  # HMAC-SHA-256 hash of matched values in findings DB


@dataclass
class RuleAnalysisConfig:
    samples: int = 50  # corpus strings per rule (higher = more stable, slower)
    threshold: float = 0.8  # overlap fraction to classify as duplicate/subset
    seed: int = 42  # reproducible corpus generation
    auto_on_import: bool = True  # re-run analysis after rule import


@dataclass
class RulesConfig:
    auto_import: bool = True  # auto-import community rules on first serve
    rebuild_delay_seconds: float = 2.0  # debounce delay for async accelerator rebuild


@dataclass
class DedupConfig:
    conversation_ttl_minutes: int = 30
    finding_ttl_minutes: int = 30
    max_conversations: int = 10_000
    max_hashes_per_conversation: int = 5_000


@dataclass
class AdaptiveEnforcementConfig:
    enabled: bool = False
    escalation_threshold: float = 5.0
    decay_per_clean: float = 0.5


@dataclass
class MCPConfig:
    allowed_tools: list[str] = field(default_factory=list)  # empty = all allowed
    blocked_tools: list[str] = field(default_factory=list)  # deny-list
    env_filter: bool = True  # restrict subprocess environment
    env_allowlist: list[str] = field(default_factory=list)  # additional safe vars
    request_tracking: bool = True  # confused deputy protection
    unsolicited_response_action: str = "warn"  # warn|block
    scan_tool_descriptions: bool = True  # poisoning detection
    detect_drift: bool = True  # rug-pull detection
    drift_action: str = "alert"  # alert|block
    session_binding: bool = False  # tool inventory validation (opt-in)
    unknown_tool_action: str = "warn"  # warn|block
    # Pro: policy rules for tool call validation
    tool_policies: list[dict[str, Any]] = field(default_factory=list)
    # Pro: adaptive enforcement config
    adaptive_enforcement: AdaptiveEnforcementConfig = field(default_factory=AdaptiveEnforcementConfig)
    # Pro: custom chain detection patterns
    chain_signatures: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class WebSocketConfig:
    max_frame_size: int = 1_048_576  # 1MB per frame cap
    allowed_origins: list[str] = field(default_factory=list)  # empty = all allowed


@dataclass
class CustomRuleConfig:
    name: str = ""
    pattern: str = ""  # raw regex string
    compiled: object = None  # compiled re.Pattern (set during parsing)
    severity: str = "high"  # critical, high, warning, info
    action: str = ""  # empty = use default_action
    detector: str = "custom"  # detector name reported in findings


@dataclass
class PipelineStageConfig:
    enabled: bool = True
    action: str = ""  # stage-level action override (Pro only, empty = use default_action)
    mode: str = ""  # stage-specific mode (e.g., "async" | "buffered" for response stages)


@dataclass
class EncodingDecodeConfig(PipelineStageConfig):
    """Extended config for the encoding_decode pipeline stage."""

    base64: bool = True
    hex: bool = True
    url: bool = True
    unicode: bool = True
    max_depth: int = 2  # nested encoding layers (base64 inside URL-encoding)
    min_decoded_length: int = 8  # ignore short decoded strings
    max_decoded_length: int = 10_000  # cap decoded output size


# All encoding names for validation
_ENCODING_NAMES = {"base64", "hex", "url", "unicode"}


@dataclass
class PipelineConfig:
    outbound_dlp: PipelineStageConfig = field(default_factory=PipelineStageConfig)
    encoding_decode: EncodingDecodeConfig = field(default_factory=EncodingDecodeConfig)
    response_secrets: PipelineStageConfig = field(
        default_factory=lambda: PipelineStageConfig(enabled=False, mode="async")
    )
    response_injection: PipelineStageConfig = field(
        default_factory=lambda: PipelineStageConfig(enabled=False, mode="async")
    )
    response_max_size: int = 1_048_576  # 1MB cap for response scanning
    mcp_arguments: PipelineStageConfig = field(default_factory=PipelineStageConfig)
    mcp_responses: PipelineStageConfig = field(default_factory=PipelineStageConfig)
    websocket_outbound: PipelineStageConfig = field(default_factory=lambda: PipelineStageConfig(enabled=False))
    websocket_inbound: PipelineStageConfig = field(default_factory=lambda: PipelineStageConfig(enabled=False))
    parallel_batching: bool = False


# All pipeline stage names for validation
_PIPELINE_STAGE_NAMES = {
    "outbound_dlp",
    "encoding_decode",
    "response_secrets",
    "response_injection",
    "mcp_arguments",
    "mcp_responses",
    "websocket_outbound",
    "websocket_inbound",
}

# Stages that are implemented and available for toggling
PIPELINE_AVAILABLE_STAGES = _PIPELINE_STAGE_NAMES  # all stages are now implemented


@dataclass
class RelayConfig:
    """Configuration for the relay process (fault-isolation mode)."""

    port: int = 8080
    fail_mode: str = "open"  # "open" or "closed"
    engine_url: str = "http://localhost:8090"
    health_check_interval: int = 2  # seconds between engine health checks
    health_check_timeout: int = 1  # seconds before health check times out
    queue_on_startup: int = 2  # seconds to buffer requests while engine starts


@dataclass
class EngineConfig:
    """Configuration for the engine process (fault-isolation mode)."""

    port: int = 8090


@dataclass
class Config:
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    default_action: str = "alert"
    secrets: DetectorConfig = field(default_factory=DetectorConfig)
    pii: DetectorConfig = field(default_factory=DetectorConfig)
    proprietary: DetectorConfig = field(default_factory=DetectorConfig)
    entropy_threshold: float = 4.5
    allowlist: AllowlistConfig = field(default_factory=AllowlistConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    logging_config: LoggingConfig = field(default_factory=LoggingConfig)
    custom_rules: list["CustomRuleConfig"] = field(default_factory=list)
    upstreams: dict[str, str] = field(default_factory=dict)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    analytics: AnalyticsConfig = field(default_factory=AnalyticsConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
    rule_analysis: RuleAnalysisConfig = field(default_factory=RuleAnalysisConfig)
    dedup: DedupConfig = field(default_factory=DedupConfig)
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    mcp: MCPConfig = field(default_factory=MCPConfig)
    websocket: WebSocketConfig = field(default_factory=WebSocketConfig)
    relay: RelayConfig = field(default_factory=RelayConfig)
    engine: EngineConfig = field(default_factory=EngineConfig)
    notifications: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_VALID_ACTIONS = {"log", "alert", "redact", "block"}

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
_VALID_SEVERITIES = {"critical", "high", "warning", "info"}


def _warn(msg: str) -> None:
    """Log a config warning. Falls through to stderr via logging handlers."""
    log.warning("%s", msg)


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
            elif fmt == "json":
                warnings.append("%s: JSON log format requires Pro license" % source)
        if "output" in logging_sec:
            output = str(logging_sec["output"]).lower()
            if output not in ("file", "stdout", "both"):
                warnings.append(
                    "%s: logging.output '%s' is not valid (expected: file, stdout, both)" % (source, output)
                )
            elif output in ("stdout", "both"):
                warnings.append("%s: logging.output '%s' requires Pro license" % (source, output))

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
                        elif mode == "buffered" and stage_name in ("response_secrets", "response_injection"):
                            warnings.append(
                                "%s: pipeline.stages.%s.mode 'buffered' requires Pro license" % (source, stage_name)
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
            "adaptive_enforcement",
            "chain_signatures",
        }
        warnings.extend("%s: unknown key 'mcp.%s'" % (source, key) for key in mcp if key not in _known_mcp_keys)
        # Validate action fields — each has different valid values
        _mcp_action_values = {
            "unsolicited_response_action": {"warn", "block"},
            "drift_action": {"alert", "block"},
            "unknown_tool_action": {"warn", "block"},
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


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------


_DEFAULT_CONFIG = """\
# lumen-argus configuration
# Docs: https://github.com/lumen-argus/lumen-argus
version: "1"

proxy:
  port: 8080
  bind: "127.0.0.1"
  timeout: 120
  retries: 1

# Global default action: log | alert | block
default_action: alert

detectors:
  secrets:
    enabled: true
    action: alert
    entropy_threshold: 4.5

  pii:
    enabled: true
    action: alert

  proprietary:
    enabled: true
    action: alert

# Never flag these
allowlists:
  secrets:
    - "AKIAIOSFODNN7EXAMPLE"
    - "sk-ant-api03-example-key-not-real"
  pii:
    - "*@example.com"
    - "*@test.local"
  paths:
    - "test/**"
    - "tests/**"
    - "fixtures/**"

# Notification channels (reconciled to DB on startup/SIGHUP)
# Manage via dashboard or define here for IaC. Requires published package.
# notifications:
#   - name: production-alerts
#     type: webhook
#     url: "https://hooks.slack.com/services/T00/B00/xxx"
#     events: [block, alert]
#     min_severity: high

audit:
  log_dir: "~/.lumen-argus/audit"
  retention_days: 90

# Application logging (file rotation)
logging:
  log_dir: "~/.lumen-argus/logs"
  file_level: info
  max_size_mb: 10
  backup_count: 5
"""


def _create_default_config(path: Path) -> None:
    """Create a default config file on first run."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_DEFAULT_CONFIG, encoding="utf-8")
        _warn("created default config at %s" % path)
    except OSError:
        pass  # Non-fatal — will use in-memory defaults


def load_config(
    config_path: str | None = None,
    project_path: str | None = None,
) -> Config:
    """Load and merge configuration from global and project YAML files.

    Args:
        config_path: Path to global config. Defaults to ~/.lumen-argus/config.yaml.
        project_path: Path to project-level .lumen-argus.yaml.

    Returns:
        Merged Config object.
    """
    config = Config()

    # Load global config — create default on first run
    global_path = Path(os.path.expanduser(config_path or "~/.lumen-argus/config.yaml"))
    if not global_path.exists() and config_path is None:
        _create_default_config(global_path)
    if global_path.exists():
        try:
            text = global_path.read_text(encoding="utf-8")
            data = _parse_yaml(text)
            for w in _validate_config(data, str(global_path)):
                _warn(w)
            _apply_config(config, data)
            log.debug("loaded config from %s", global_path)
        except Exception as e:
            log.error("failed to parse %s: %s (using defaults)", global_path, e)

    # Load project config (can only be more restrictive)
    if project_path:
        proj = Path(project_path)
    else:
        proj = Path.cwd() / ".lumen-argus.yaml"

    if proj.exists():
        try:
            text = proj.read_text(encoding="utf-8")
            data = _parse_yaml(text)
            for w in _validate_config(data, str(proj)):
                _warn(w)
            _apply_project_config(config, data)
        except Exception as e:
            log.error("failed to parse %s: %s (using defaults)", proj, e)

    return config


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
            config.relay.port = int(relay_data["port"])
        if "fail_mode" in relay_data:
            config.relay.fail_mode = str(relay_data["fail_mode"])
        if "engine_url" in relay_data:
            config.relay.engine_url = str(relay_data["engine_url"])
        if "health_check_interval" in relay_data:
            config.relay.health_check_interval = int(relay_data["health_check_interval"])
        if "health_check_timeout" in relay_data:
            config.relay.health_check_timeout = int(relay_data["health_check_timeout"])
        if "queue_on_startup" in relay_data:
            config.relay.queue_on_startup = int(relay_data["queue_on_startup"])

    # Engine config (fault-isolation mode)
    engine_data = data.get("engine", {})
    if isinstance(engine_data, dict):
        if "port" in engine_data:
            config.engine.port = int(engine_data["port"])

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
        if "paths" in al and isinstance(al["paths"], list):
            config.allowlist.paths.extend(str(s) for s in al["paths"])
