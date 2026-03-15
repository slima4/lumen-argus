"""PII detector: regex-based with validation (email, SSN, CC, phone, IP, IBAN)."""

from typing import List, Tuple

from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.detectors import BaseDetector
from lumen_argus.models import Finding, ScanField
from lumen_argus.patterns.pii_patterns import PII_PATTERNS


def _mask_value(value: str) -> str:
    """Create a masked preview: first 4 chars + ****."""
    if len(value) <= 4:
        return "****"
    return value[:4] + "****"


# Separator used to join fields — must not match any PII pattern.
_FIELD_SEP = "\x00\x00\x00"


def _build_merged_text(fields: List[ScanField]) -> Tuple[str, List[Tuple[int, int, int]]]:
    """Concatenate fields into single string for batch scanning."""
    parts = []
    boundaries = []  # type: List[Tuple[int, int, int]]
    offset = 0
    for i, field in enumerate(fields):
        if i > 0:
            parts.append(_FIELD_SEP)
            offset += len(_FIELD_SEP)
        start = offset
        parts.append(field.text)
        offset += len(field.text)
        boundaries.append((start, offset, i))
    return "".join(parts), boundaries


def _find_field(pos: int, boundaries: List[Tuple[int, int, int]]) -> int:
    """Binary search for which field index contains position `pos`."""
    lo, hi = 0, len(boundaries) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        start, end, _ = boundaries[mid]
        if pos < start:
            hi = mid - 1
        elif pos >= end:
            lo = mid + 1
        else:
            return boundaries[mid][2]
    return 0


class PIIDetector(BaseDetector):
    """Detects PII using regex patterns with optional validation."""

    def scan(
        self,
        fields: List[ScanField],
        allowlist: AllowlistMatcher,
    ) -> List[Finding]:
        if not fields:
            return []

        # Merge all fields into one string for batch scanning.
        merged, boundaries = _build_merged_text(fields)
        if not merged:
            return []

        findings = []  # type: List[Finding]

        for pat in PII_PATTERNS:
            for match in pat.pattern.finditer(merged):
                value = match.group(0)

                if pat.validator is not None and not pat.validator(value):
                    continue

                if allowlist.is_allowed_pii(value):
                    continue

                field_idx = _find_field(match.start(), boundaries)
                findings.append(Finding(
                    detector="pii",
                    type=pat.name,
                    severity=pat.severity,
                    location=fields[field_idx].path,
                    value_preview=_mask_value(value),
                    matched_value=value,
                ))

        return findings
