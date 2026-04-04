"""Configuration dataclasses — the shape of the config object.

Changes when: a new config field or section is added.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


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
    standalone: bool = True  # False when managed by tray app (--no-standalone)


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
    timeout: int = 150  # relay timeout (> proxy.timeout to account for scanning overhead)


@dataclass
class EngineConfig:
    """Configuration for the engine process (fault-isolation mode)."""

    port: int = 8090


@dataclass
class EnrollmentPolicyConfig:
    """Policy settings pushed to enrolled agents."""

    fail_mode: str = "open"  # "open" or "closed"
    auto_configure: bool = True
    allow_disable_protection: bool = True
    telemetry_interval_seconds: int = 300
    watch_interval_seconds: int = 300


@dataclass
class EnrollmentConfig:
    """Enrollment configuration for enterprise agent deployment."""

    organization: str = ""
    proxy_url: str = ""  # empty = derived from proxy.bind:proxy.port
    dashboard_url: str = ""  # empty = derived from dashboard.bind:dashboard.port
    ca_cert: str = ""  # PEM content or path to CA cert file
    policy: EnrollmentPolicyConfig = field(default_factory=EnrollmentPolicyConfig)


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
    enrollment: EnrollmentConfig = field(default_factory=EnrollmentConfig)
    notifications: list[dict[str, Any]] = field(default_factory=list)
