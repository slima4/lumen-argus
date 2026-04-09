"""Core data structures used across all modules."""

from dataclasses import dataclass, field
from typing import Any

# Canonical severity levels, ordered from lowest to highest priority.
# Used by config validation, policy engine, notifiers, and dashboard.
SEVERITIES = ("info", "warning", "high", "critical")
SEVERITY_SET: frozenset[str] = frozenset(SEVERITIES)
SEVERITY_ORDER: dict[str, int] = {s: i for i, s in enumerate(SEVERITIES)}

# Canonical policy actions, ordered from lowest to highest priority.
# "redact" is Pro-only -- community downgrades to "alert".
ACTIONS = ("log", "alert", "redact", "block")
ACTION_SET: frozenset[str] = frozenset(ACTIONS)


@dataclass
class Finding:
    """A single detection result from a scanner."""

    detector: str  # "secrets" | "pii" | "proprietary"
    type: str  # e.g. "aws_access_key", "ssn", "confidential_keyword"
    severity: str
    location: str  # path into request body, e.g. "messages[4].content"
    value_preview: str  # masked preview, e.g. "AKIA****"
    matched_value: str  # full match — kept in memory only, never written to disk
    action: str = ""  # resolved action for this finding
    count: int = 1  # number of occurrences (after deduplication)


@dataclass
class SessionContext:
    """Session/conversation identity extracted from a request.

    Populated by the proxy from request headers and body metadata.
    Passed through the pipeline to audit log and analytics store.
    Each field is a separate DB column for direct filtering/grouping.
    """

    # Identity — WHO
    account_id: str = ""  # Anthropic account UUID, OpenAI user ID
    api_key_hash: str = ""  # SHA-256[:16] of API key

    # Session — WHICH CONVERSATION
    session_id: str = ""  # Provider session ID or derived fingerprint (fp:<hash>)
    device_id: str = ""  # Device/machine identifier (from provider metadata)

    # Network — WHERE
    source_ip: str = ""  # Client IP (X-Forwarded-For first, fallback client_address)

    # Context — WHAT PROJECT
    working_directory: str = ""  # Project path from system prompt
    git_branch: str = ""  # Current git branch from system prompt
    os_platform: str = ""  # OS from system prompt (darwin, linux, win32)

    # Agent relay — WHICH MACHINE / WHO
    hostname: str = ""  # Machine hostname (from agent relay X-Lumen-Argus-Hostname)
    username: str = ""  # OS username (from agent relay X-Lumen-Argus-Username)

    # Client — HOW
    client_name: str = ""  # Normalized client ID from registry (e.g., "aider")
    client_version: str = ""  # Client version from User-Agent (e.g., "0.50.1")
    client_type: str = ""  # Interface type: "cli", "app", "ide", "web" (from tool headers)

    # Request metadata — SDK stack
    raw_user_agent: str = ""  # Full User-Agent string, unmodified (max 512 chars)
    api_format: str = ""  # Wire format: "anthropic", "openai", "gemini", or ""
    sdk_name: str = ""  # Primary SDK identifier (e.g., "ai-sdk/anthropic", "claude-code")
    sdk_version: str = ""  # SDK version (e.g., "3.0.64")
    runtime: str = ""  # Runtime and version (e.g., "bun/1.3.11", "node/22.0.0")

    # Intercept mode — HOW CAPTURED
    intercept_mode: str = "reverse"  # "reverse" (base URL) or "forward" (HTTPS_PROXY + TLS)
    original_host: str = ""  # Forward proxy: original destination host (e.g., "api.individual.githubcopilot.com")


@dataclass
class ScanField:
    """An extracted text field from a request body to be scanned."""

    path: str  # location descriptor, e.g. "messages[3].content"
    text: str  # the extracted string to scan
    source_filename: str = ""  # filename if from a tool_result file read


@dataclass
class ScanResult:
    """Aggregated result of scanning a request."""

    findings: list[Finding] = field(default_factory=list)
    scan_duration_ms: float = 0.0
    action: str = "pass"  # "pass" | "log" | "alert" | "block" | "strip" (audit-only)
    stage_timings: dict[str, float] = field(default_factory=dict)  # {stage_name: elapsed_ms}
    # Deferred fingerprint commit token. Set by pipeline on block
    # so the proxy can commit hashes after successful history stripping.
    _pending_hashes: tuple[str, list[str]] | None = field(default=None, repr=False)


@dataclass(frozen=True)
class AgentIdentity:
    """Verified agent identity extracted from an authenticated request.

    Populated by the AgentAuthProvider after validating the agent's
    credentials (bearer token, mTLS cert, OIDC JWT, etc.).

    All scoped data access methods accept this to enforce tenant isolation.
    namespace_id is the universal isolation boundary — all tenant-scoped
    queries filter by it.
    """

    agent_id: str  # e.g. "agent_ff9cc0dd77af6867"
    namespace_id: int  # FK to namespaces.id — 1 = default (self-hosted)
    scopes: frozenset[str] = frozenset()  # e.g. {"stats:read", "findings:read"}
    device_id: str = ""  # correlation to findings.device_id
    machine_id: str = ""  # correlation to enrollment_agents.machine_id
    namespace_slug: str = ""  # e.g. "acme-corp" — for logging/display only


@dataclass
class AuditEntry:
    """A single audit log record."""

    timestamp: str  # ISO 8601 UTC
    request_id: int
    provider: str
    model: str
    endpoint: str
    action: str
    findings: list[Finding] = field(default_factory=list)
    scan_duration_ms: float = 0.0
    request_size_bytes: int = 0
    passed: bool = True
    # Session context fields (all optional, omit empty in JSONL)
    account_id: str = ""
    api_key_hash: str = ""
    session_id: str = ""
    device_id: str = ""
    source_ip: str = ""
    working_directory: str = ""
    git_branch: str = ""
    os_platform: str = ""
    hostname: str = ""
    username: str = ""
    client_name: str = ""
    client_version: str = ""
    client_type: str = ""
    raw_user_agent: str = ""
    api_format: str = ""
    sdk_name: str = ""
    sdk_version: str = ""
    runtime: str = ""
    intercept_mode: str = "reverse"
    original_host: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSONL output. Never includes matched_value."""
        d = {
            "timestamp": self.timestamp,
            "request_id": self.request_id,
            "provider": self.provider,
            "model": self.model,
            "endpoint": self.endpoint,
            "action": self.action,
            "findings": [
                {
                    "detector": f.detector,
                    "type": f.type,
                    "severity": f.severity,
                    "location": f.location,
                    "value_preview": f.value_preview,
                    "action_taken": f.action,
                    "count": f.count,
                }
                for f in self.findings
            ],
            "scan_duration_ms": round(self.scan_duration_ms, 2),
            "request_size_bytes": self.request_size_bytes,
            "passed": self.passed,
        }
        # Include session fields only when populated (keeps JSONL compact)
        # api_key_hash excluded — stored in analytics DB for grouping,
        # but not serialized to JSONL audit log to limit credential exposure.
        for key in (
            "account_id",
            "session_id",
            "device_id",
            "source_ip",
            "working_directory",
            "git_branch",
            "os_platform",
            "hostname",
            "username",
            "client_name",
            "client_version",
            "client_type",
            "raw_user_agent",
            "api_format",
            "sdk_name",
            "sdk_version",
            "runtime",
        ):
            val = getattr(self, key, "")
            if val:
                d[key] = val
        # intercept_mode + original_host: only include when non-default
        if self.intercept_mode and self.intercept_mode != "reverse":
            d["intercept_mode"] = self.intercept_mode
        if self.original_host:
            d["original_host"] = self.original_host
        return d
