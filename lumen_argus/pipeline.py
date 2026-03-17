"""Scanner pipeline: orchestrates extraction, detection, and policy evaluation."""

import logging
import time
from typing import List

log = logging.getLogger("argus.pipeline")

from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.detectors import BaseDetector
from lumen_argus.detectors.pii import PIIDetector
from lumen_argus.detectors.proprietary import ProprietaryDetector
from lumen_argus.detectors.secrets import SecretsDetector
from lumen_argus.extensions import ExtensionRegistry
from lumen_argus.extractor import RequestExtractor
from lumen_argus.models import Finding, ScanField, ScanResult
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
        self._extensions = extensions

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
        log.debug("extracted %d fields from %s request (%d bytes)", len(fields), provider, len(body))

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
                    fields_to_scan.append(ScanField(
                        path=field.path,
                        text=field.text[:remaining],
                        source_filename=field.source_filename,
                    ))
                break
            fields_to_scan.append(field)
            total_text += len(field.text)

        log.debug(
            "scanning %d fields (%d chars, budget %d)",
            len(fields_to_scan), total_text, self._max_scan_bytes,
        )

        # Run all detectors
        all_findings = []  # type: List[Finding]
        for detector in self._detectors:
            det_findings = detector.scan(fields_to_scan, self._allowlist)
            if det_findings:
                log.debug(
                    "%s: %d findings", detector.__class__.__name__, len(det_findings),
                )
            all_findings.extend(det_findings)

        # Deduplicate findings — same (detector, type, matched_value) collapsed
        # into one finding with a count. Reduces noise from repeated secrets
        # in conversation history.
        all_findings = self._deduplicate(all_findings)

        # Evaluate policy — plugins can override via evaluate hook
        eval_hook = self._extensions.get_evaluate_hook() if self._extensions else None
        if eval_hook:
            try:
                decision = eval_hook(all_findings, self._policy)
            except Exception:
                log.warning("evaluate_hook raised, falling back to default policy")
                decision = self._policy.evaluate(all_findings)
        else:
            decision = self._policy.evaluate(all_findings)

        elapsed_ms = (time.monotonic() - t0) * 1000

        if elapsed_ms > 50:
            log.warning(
                "slow scan: %.1fms (%d fields, %dKB, budget %dKB)",
                elapsed_ms, len(fields_to_scan), total_text // 1024, self._max_scan_bytes // 1024,
            )

        result = ScanResult(
            findings=decision.findings,
            scan_duration_ms=elapsed_ms,
            action=decision.action,
        )

        # Fire post-scan hook for plugins (analytics, notifications, SSE)
        if self._extensions:
            hook = self._extensions.get_post_scan_hook()
            if hook:
                try:
                    hook(result, body, provider)
                except Exception:
                    pass  # Never let plugin errors break the proxy

        return result

    @staticmethod
    def _deduplicate(findings: List[Finding]) -> List[Finding]:
        """Collapse duplicate findings into one with a count.

        Same (detector, type, matched_value) → keep first occurrence, set count.
        Creates new Finding objects to avoid mutating detector output.
        """
        from dataclasses import replace
        seen = {}  # type: dict[tuple, int]
        first = {}  # type: dict[tuple, Finding]
        for f in findings:
            key = (f.detector, f.type, f.matched_value)
            if key in seen:
                seen[key] += 1
            else:
                seen[key] = 1
                first[key] = f
        return [replace(first[k], count=c) for k, c in seen.items()]
