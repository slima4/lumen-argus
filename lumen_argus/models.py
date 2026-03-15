"""Core data structures used across all modules."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Finding:
    """A single detection result from a scanner."""
    detector: str       # "secrets" | "pii" | "proprietary"
    type: str           # e.g. "aws_access_key", "ssn", "confidential_keyword"
    severity: str       # "critical" | "high" | "warning" | "info"
    location: str       # path into request body, e.g. "messages[4].content"
    value_preview: str  # masked preview, e.g. "AKIA****"
    matched_value: str  # full match — kept in memory only, never written to disk
    action: str = ""    # resolved action for this finding


@dataclass
class ScanField:
    """An extracted text field from a request body to be scanned."""
    path: str               # location descriptor, e.g. "messages[3].content"
    text: str               # the extracted string to scan
    source_filename: str = ""  # filename if from a tool_result file read


@dataclass
class ScanResult:
    """Aggregated result of scanning a request."""
    findings: List[Finding] = field(default_factory=list)
    scan_duration_ms: float = 0.0
    action: str = "pass"  # highest-priority action: "pass" | "log" | "alert" | "block"


@dataclass
class AuditEntry:
    """A single audit log record."""
    timestamp: str          # ISO 8601 UTC
    request_id: int
    provider: str
    model: str
    endpoint: str
    action: str
    findings: List[Finding] = field(default_factory=list)
    scan_duration_ms: float = 0.0
    request_size_bytes: int = 0
    passed: bool = True

    def to_dict(self) -> dict:
        """Serialize for JSONL output. Never includes matched_value."""
        return {
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
                }
                for f in self.findings
            ],
            "scan_duration_ms": round(self.scan_duration_ms, 2),
            "request_size_bytes": self.request_size_bytes,
            "passed": self.passed,
        }
