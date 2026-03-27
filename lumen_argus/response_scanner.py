"""Response scanner — detect secrets and prompt injection in API responses.

Scans response text (model output, tool call arguments) for:
1. Secrets leaked from context (reuses existing detectors)
2. Prompt injection patterns (DB-backed rules, fallback to hardcoded)

Injection patterns are stored in the rules table with detector='injection'.
Community ships 10 patterns; Pro adds extended patterns via the pro bundle.
Users can enable/disable individual patterns from the Rules dashboard page.

Runs asynchronously (post-hoc) in community edition — no latency impact.
Pro adds buffered/blocking mode and custom injection patterns.
"""

import logging
import re
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore

from lumen_argus.models import Finding, ScanField
from lumen_argus.text_utils import sanitize_text

log = logging.getLogger("argus.response_scanner")

# ---------------------------------------------------------------------------
# Hardcoded fallback — used when DB has zero injection rules (fresh install
# before auto-import, or if rules table is empty)
# ---------------------------------------------------------------------------

_FALLBACK_INJECTION_PATTERNS = [
    ("ignore_instructions", re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I)),
    ("ignore_prior", re.compile(r"ignore\s+(all\s+)?prior\s+instructions", re.I)),
    ("disregard_previous", re.compile(r"disregard\s+(all\s+)?previous", re.I)),
    ("persona_override", re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.I)),
    ("system_injection", re.compile(r"system\s*:\s*you\s+are", re.I)),
    ("system_tag", re.compile(r"<\s*system\s*>", re.I)),
    ("inst_tag", re.compile(r"\[INST\]", re.I)),
    ("execute_command", re.compile(r"execute\s+the\s+following\s+(command|code|script)", re.I)),
    ("exfil_curl", re.compile(r"curl\s+[^|]*\|\s*bash", re.I)),
    ("exfil_webhook", re.compile(r"(fetch|XMLHttpRequest|sendBeacon)\s*\(", re.I)),
]


def _mask_value(value: str) -> str:
    """Create a masked preview for display. Shows first 4 + last 2 chars."""
    if len(value) <= 8:
        return value[:2] + "****"
    return value[:4] + "****" + value[-2:]


# ---------------------------------------------------------------------------
# ResponseScanner
# ---------------------------------------------------------------------------


class ResponseScanner:
    """Scan API response text for secrets and injection patterns.

    Reuses the same detector chain as request scanning for secret detection.
    Injection patterns are loaded from the rules DB (detector='injection').
    Falls back to hardcoded patterns if DB has no injection rules.
    """

    def __init__(
        self,
        detectors: list[Any] | None | None = None,
        allowlist: Any = None,
        store: AnalyticsStore | None = None,
        scan_secrets: bool = True,
        scan_injection: bool = True,
        max_response_size: int = 1_048_576,  # 1MB
    ):
        self._detectors = detectors or []
        self._allowlist = allowlist
        self._store = store
        self._scan_secrets = scan_secrets
        self._scan_injection = scan_injection
        self._max_response_size = max_response_size

        # Load injection rules from DB or fallback
        self._injection_rules: list[dict[str, Any]] = []
        self._load_injection_rules()

    def _load_injection_rules(self) -> None:
        """Load injection rules from DB. Fallback to hardcoded if DB is empty."""
        if not self._scan_injection:
            return

        db_rules = []
        if self._store and hasattr(self._store, "get_active_rules"):
            try:
                db_rules = self._store.get_active_rules(detector="injection")
            except Exception as e:
                log.warning("failed to load injection rules from DB: %s", e)

        if db_rules:
            # Compile DB rules
            compiled = []
            for rule in db_rules:
                try:
                    pattern = re.compile(rule["pattern"])
                    compiled.append(
                        {
                            "name": rule["name"],
                            "compiled": pattern,
                            "severity": rule.get("severity", "high"),
                            "action": rule.get("action", ""),
                        }
                    )
                except re.error as e:
                    log.warning("invalid injection rule '%s': %s", rule["name"], e)
            self._injection_rules = compiled
            log.debug("loaded %d injection rules from DB", len(compiled))
        else:
            # Fallback to hardcoded patterns
            self._injection_rules = [
                {"name": name, "compiled": pattern, "severity": "high", "action": ""}
                for name, pattern in _FALLBACK_INJECTION_PATTERNS
            ]
            log.debug("using %d hardcoded injection patterns (no DB rules)", len(self._injection_rules))

    def scan(self, text: str, provider: str = "", model: str = "") -> list[Finding]:
        """Scan response text and return findings.

        Args:
            text: Accumulated response text (model output).
            provider: Provider name for finding metadata.
            model: Model name for finding metadata.

        Returns:
            List of findings (secrets + injection patterns).
        """
        if not text:
            return []

        t0 = time.monotonic()

        # Cap response size
        if len(text) > self._max_response_size:
            log.debug(
                "response text truncated: %d -> %d chars",
                len(text),
                self._max_response_size,
            )
            text = text[: self._max_response_size]

        # Sanitize (same pre-processing as request scanning)
        text = sanitize_text(text)

        findings: list[Finding] = []

        # Secret detection — reuse existing detectors on response text
        if self._scan_secrets and self._detectors:
            fields = [ScanField(path="response.content", text=text)]
            for detector in self._detectors:
                try:
                    det_findings = detector.scan(fields, self._allowlist)
                    for f in det_findings:
                        # Mark as response-sourced
                        f.location = "response.%s" % f.location
                    findings.extend(det_findings)
                except Exception as e:
                    log.warning("response detector %s failed: %s", detector.__class__.__name__, e)

        # Injection pattern detection (DB rules or hardcoded fallback)
        if self._scan_injection:
            findings.extend(self._scan_injection_patterns(text))

        elapsed = (time.monotonic() - t0) * 1000
        if findings:
            log.info(
                "response scan: %d finding(s) in %.1fms (%d chars)",
                len(findings),
                elapsed,
                len(text),
            )
        else:
            log.debug("response scan: clean in %.1fms (%d chars)", elapsed, len(text))

        return findings

    def _scan_injection_patterns(self, text: str) -> list[Finding]:
        """Scan text for prompt injection patterns (DB rules or fallback)."""
        findings = []
        for rule in self._injection_rules:
            match = rule["compiled"].search(text)
            if match:
                matched = match.group()
                findings.append(
                    Finding(
                        detector="injection",
                        type=rule["name"],
                        severity=rule["severity"],
                        location="response.content",
                        value_preview=_mask_value(matched),
                        matched_value=matched,
                        action=rule["action"],
                    )
                )
        return findings
