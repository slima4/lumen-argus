"""Session statistics: thread-safe counters for requests, findings, and timing."""

import threading
from typing import Any

from lumen_argus.models import ScanResult


class SessionStats:
    """Thread-safe session statistics collector."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total_requests = 0
        self.total_bytes_scanned = 0
        self.actions: dict[str, int] = {"pass": 0, "log": 0, "alert": 0, "block": 0}
        self.providers: dict[str, int] = {}
        self.finding_types: dict[str, int] = {}
        self.scan_times_ms: list[float] = []

    def record(
        self,
        provider: str,
        body_size: int,
        result: ScanResult,
    ) -> None:
        """Record a completed request."""
        with self._lock:
            self.total_requests += 1
            self.total_bytes_scanned += body_size

            action = result.action
            if action in self.actions:
                self.actions[action] += 1
            else:
                self.actions[action] = 1

            self.providers[provider] = self.providers.get(provider, 0) + 1

            for f in result.findings:
                self.finding_types[f.type] = self.finding_types.get(f.type, 0) + 1

            if result.scan_duration_ms > 0:
                self.scan_times_ms.append(result.scan_duration_ms)

    def summary(self) -> dict[str, Any]:
        """Return a snapshot of current stats."""
        with self._lock:
            avg_scan = 0.0
            p95_scan = 0.0
            if self.scan_times_ms:
                avg_scan = sum(self.scan_times_ms) / len(self.scan_times_ms)
                sorted_times = sorted(self.scan_times_ms)
                p95_idx = int(len(sorted_times) * 0.95)
                p95_scan = sorted_times[min(p95_idx, len(sorted_times) - 1)]

            return {
                "total_requests": self.total_requests,
                "total_bytes_scanned": self.total_bytes_scanned,
                "actions": dict(self.actions),
                "providers": dict(self.providers),
                "finding_types": dict(self.finding_types),
                "avg_scan_ms": round(avg_scan, 1),
                "p95_scan_ms": round(p95_scan, 1),
            }

    @staticmethod
    def _escape_label(value: str) -> str:
        """Escape a Prometheus label value."""
        return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

    def prometheus_metrics(
        self,
        active_requests: int = 0,
        active_ws_connections: int = 0,
        fingerprint_stats: dict[str, int] | None = None,
    ) -> str:
        """Return stats in Prometheus exposition format (plain text)."""
        with self._lock:
            lines = []

            # Active requests gauge
            lines.append("# HELP lumen_argus_active_requests Current in-flight requests")
            lines.append("# TYPE lumen_argus_active_requests gauge")
            lines.append("lumen_argus_active_requests %d" % active_requests)

            # Active WebSocket connections gauge
            lines.append("# HELP lumen_argus_ws_active_connections Current active WebSocket connections")
            lines.append("# TYPE lumen_argus_ws_active_connections gauge")
            lines.append("lumen_argus_ws_active_connections %d" % active_ws_connections)

            if fingerprint_stats is not None:
                lines.append(
                    "# HELP lumen_argus_fingerprint_conversations Tracked conversations in content-fingerprint cache"
                )
                lines.append("# TYPE lumen_argus_fingerprint_conversations gauge")
                lines.append(
                    "lumen_argus_fingerprint_conversations %d" % int(fingerprint_stats.get("conversations", 0))
                )
                lines.append("# HELP lumen_argus_fingerprint_hashes Total content hashes in fingerprint cache")
                lines.append("# TYPE lumen_argus_fingerprint_hashes gauge")
                lines.append("lumen_argus_fingerprint_hashes %d" % int(fingerprint_stats.get("total_hashes", 0)))

            # Request counters by action
            lines.append("# HELP lumen_argus_requests_total Total proxied requests by action")
            lines.append("# TYPE lumen_argus_requests_total counter")
            for action, count in self.actions.items():
                lines.append('lumen_argus_requests_total{action="%s"} %d' % (self._escape_label(action), count))

            # Bytes scanned
            lines.append("# HELP lumen_argus_bytes_scanned_total Total bytes scanned")
            lines.append("# TYPE lumen_argus_bytes_scanned_total counter")
            lines.append("lumen_argus_bytes_scanned_total %d" % self.total_bytes_scanned)

            # Findings by type
            lines.append("# HELP lumen_argus_findings_total Total findings by type")
            lines.append("# TYPE lumen_argus_findings_total counter")
            for ftype, count in self.finding_types.items():
                lines.append('lumen_argus_findings_total{type="%s"} %d' % (self._escape_label(ftype), count))

            # Requests by provider
            lines.append("# HELP lumen_argus_provider_requests_total Requests by provider")
            lines.append("# TYPE lumen_argus_provider_requests_total counter")
            for provider, count in self.providers.items():
                lines.append(
                    'lumen_argus_provider_requests_total{provider="%s"} %d' % (self._escape_label(provider), count)
                )

            # Scan duration
            lines.append("# HELP lumen_argus_scan_duration_seconds Scan duration summary")
            lines.append("# TYPE lumen_argus_scan_duration_seconds summary")
            total_s = sum(self.scan_times_ms) / 1000.0 if self.scan_times_ms else 0.0
            lines.append("lumen_argus_scan_duration_seconds_sum %.6f" % total_s)
            lines.append("lumen_argus_scan_duration_seconds_count %d" % len(self.scan_times_ms))

            lines.append("")  # trailing newline
            return "\n".join(lines)
