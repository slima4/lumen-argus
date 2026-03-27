"""Proprietary code detector: file pattern blocklist + keyword detection."""

import fnmatch

from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.detectors import BaseDetector
from lumen_argus.models import Finding, ScanField

# Default file patterns to block — these indicate sensitive file types.
DEFAULT_FILE_PATTERNS_CRITICAL = (
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "id_rsa*",
    "*.env",
    "*.env.*",
    ".npmrc",
    ".pypirc",
    "credentials.json",
    "service-account*.json",
    "*secret*",
)

DEFAULT_FILE_PATTERNS_WARNING = (
    "*.sqlite",
    "*.db",
    "*.sql",
    "*dump*",
)

# Default keywords indicating proprietary content.
DEFAULT_KEYWORDS_CRITICAL = (
    "CONFIDENTIAL",
    "PROPRIETARY",
    "TRADE SECRET",
    "DO NOT DISTRIBUTE",
    "INTERNAL ONLY",
    "NDA REQUIRED",
)

DEFAULT_KEYWORDS_WARNING = (
    "DRAFT",
    "PRE-RELEASE",
    "UNRELEASED",
)


class ProprietaryDetector(BaseDetector):
    """Detects proprietary content via file patterns and keywords."""

    def __init__(
        self,
        file_patterns_critical: tuple[str, ...] = DEFAULT_FILE_PATTERNS_CRITICAL,
        file_patterns_warning: tuple[str, ...] = DEFAULT_FILE_PATTERNS_WARNING,
        keywords_critical: tuple[str, ...] = DEFAULT_KEYWORDS_CRITICAL,
        keywords_warning: tuple[str, ...] = DEFAULT_KEYWORDS_WARNING,
    ) -> None:
        self._file_patterns_critical = file_patterns_critical
        self._file_patterns_warning = file_patterns_warning
        self._keywords_critical = keywords_critical
        self._keywords_warning = keywords_warning

    def scan(
        self,
        fields: list[ScanField],
        allowlist: AllowlistMatcher,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for field in fields:
            findings.extend(self._scan_field(field, allowlist))
        return findings

    def _scan_field(self, field: ScanField, allowlist: AllowlistMatcher) -> list[Finding]:
        findings: list[Finding] = []

        # Check source filename against file pattern blocklist
        if field.source_filename:
            fname = field.source_filename.split("/")[-1]  # basename
            for pat in self._file_patterns_critical:
                if fnmatch.fnmatch(fname, pat) or fnmatch.fnmatch(field.source_filename, pat):
                    findings.append(
                        Finding(
                            detector="proprietary",
                            type="blocked_file_pattern",
                            severity="critical",
                            location=field.path,
                            value_preview=field.source_filename,
                            matched_value=field.source_filename,
                        )
                    )
                    break
            else:
                for pat in self._file_patterns_warning:
                    if fnmatch.fnmatch(fname, pat) or fnmatch.fnmatch(field.source_filename, pat):
                        findings.append(
                            Finding(
                                detector="proprietary",
                                type="sensitive_file_pattern",
                                severity="warning",
                                location=field.path,
                                value_preview=field.source_filename,
                                matched_value=field.source_filename,
                            )
                        )
                        break

        # Keyword scan (case-insensitive)
        text_upper = field.text.upper()
        findings.extend(
            Finding(
                detector="proprietary",
                type="confidential_keyword",
                severity="critical",
                location=field.path,
                value_preview=kw,
                matched_value=kw,
            )
            for kw in self._keywords_critical
            if kw in text_upper
        )
        findings.extend(
            Finding(
                detector="proprietary",
                type="sensitive_keyword",
                severity="warning",
                location=field.path,
                value_preview=kw,
                matched_value=kw,
            )
            for kw in self._keywords_warning
            if kw in text_upper
        )

        return findings
