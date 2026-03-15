"""Scanner pipeline: orchestrates extraction, detection, and policy evaluation."""

import time
from typing import List

from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.detectors import BaseDetector
from lumen_argus.detectors.pii import PIIDetector
from lumen_argus.detectors.proprietary import ProprietaryDetector
from lumen_argus.detectors.secrets import SecretsDetector
from lumen_argus.extensions import ExtensionRegistry
from lumen_argus.extractor import RequestExtractor
from lumen_argus.models import Finding, ScanResult
from lumen_argus.policy import PolicyEngine


# Maximum total text bytes to scan per request. Fields beyond this are
# skipped (with a warning finding). This keeps scan time bounded even on
# very large payloads. 200KB covers the most recent/largest fields in
# a typical session while keeping scan time well under 50ms.
MAX_SCAN_TEXT_BYTES = 200_000


class ScannerPipeline:
    """Runs the full scan pipeline: extract → detect → evaluate policy."""

    def __init__(
        self,
        default_action: str = "alert",
        action_overrides: dict = None,
        allowlist: AllowlistMatcher = None,
        entropy_threshold: float = 4.5,
        extensions: ExtensionRegistry = None,
        max_scan_bytes: int = MAX_SCAN_TEXT_BYTES,
    ):
        self._extractor = RequestExtractor()
        self._allowlist = allowlist or AllowlistMatcher()
        self._policy = PolicyEngine(
            default_action=default_action,
            action_overrides=action_overrides,
        )
        self._max_scan_bytes = max_scan_bytes

        # Build detector chain
        self._detectors = []  # type: List[BaseDetector]
        self._detectors.append(SecretsDetector(entropy_threshold=entropy_threshold))
        self._detectors.append(PIIDetector())
        self._detectors.append(ProprietaryDetector())

        # Add any pro/enterprise extension detectors
        if extensions:
            self._detectors.extend(extensions.extra_detectors())

    def scan(self, body: bytes, provider: str) -> ScanResult:
        """Run the full scan pipeline on a request body.

        Args:
            body: Raw request body bytes (JSON).
            provider: Provider name for extraction format.

        Returns:
            ScanResult with findings, timing, and resolved action.
        """
        t0 = time.monotonic()

        # Extract scannable fields
        fields = self._extractor.extract(body, provider)

        # Filter out allowlisted paths
        fields = [
            f for f in fields
            if not (f.source_filename and self._allowlist.is_allowed_path(f.source_filename))
        ]

        # Prioritize scanning: reverse order so newest messages (end of
        # conversation) are scanned first, then cap total text to keep
        # scan time bounded. In a typical AI session, older messages were
        # already scanned in previous requests.
        fields_to_scan = []
        total_text = 0
        for field in reversed(fields):
            if total_text + len(field.text) > self._max_scan_bytes:
                # Include truncated field up to the budget
                remaining = self._max_scan_bytes - total_text
                if remaining > 100:
                    from lumen_argus.models import ScanField
                    fields_to_scan.append(ScanField(
                        path=field.path,
                        text=field.text[:remaining],
                        source_filename=field.source_filename,
                    ))
                break
            fields_to_scan.append(field)
            total_text += len(field.text)

        # Run all detectors
        all_findings = []  # type: List[Finding]
        for detector in self._detectors:
            all_findings.extend(detector.scan(fields_to_scan, self._allowlist))

        # Evaluate policy
        decision = self._policy.evaluate(all_findings)

        elapsed_ms = (time.monotonic() - t0) * 1000

        return ScanResult(
            findings=decision.findings,
            scan_duration_ms=elapsed_ms,
            action=decision.action,
        )
