"""Core data structures used across all modules."""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Finding:
    """A single detection result from a scanner."""

    detector: str  # "secrets" | "pii" | "proprietary"
    type: str  # e.g. "aws_access_key", "ssn", "confidential_keyword"
    severity: str  # "critical" | "high" | "warning" | "info"
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

    # Client — HOW
    client_name: str = ""  # Normalized client ID from registry (e.g., "aider")
    client_version: str = ""  # Client version from User-Agent (e.g., "0.50.1")


@dataclass
class ScanField:
    """An extracted text field from a request body to be scanned."""

    path: str  # location descriptor, e.g. "messages[3].content"
    text: str  # the extracted string to scan
    source_filename: str = ""  # filename if from a tool_result file read


@dataclass
class ScanResult:
    """Aggregated result of scanning a request."""

    findings: List[Finding] = field(default_factory=list)
    scan_duration_ms: float = 0.0
    action: str = "pass"  # "pass" | "log" | "alert" | "block" | "strip" (audit-only)
    stage_timings: Dict[str, float] = field(default_factory=dict)  # {stage_name: elapsed_ms}
    # Opaque token for deferred fingerprint commit. Set by pipeline on block
    # so the proxy can commit hashes after successful history stripping.
    _pending_hashes: object = field(default=None, repr=False)


@dataclass
class AuditEntry:
    """A single audit log record."""

    timestamp: str  # ISO 8601 UTC
    request_id: int
    provider: str
    model: str
    endpoint: str
    action: str
    findings: List[Finding] = field(default_factory=list)
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
    client_name: str = ""
    client_version: str = ""

    def to_dict(self) -> dict:
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
            "client_name",
            "client_version",
        ):
            val = getattr(self, key, "")
            if val:
                d[key] = val
        return d
