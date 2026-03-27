"""Secrets detector: regex pattern matching + Shannon entropy analysis."""

import math
import re

from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.detectors import BaseDetector
from lumen_argus.models import Finding, ScanField
from lumen_argus.patterns.secrets_patterns import SECRET_PROXIMITY_KEYWORDS, SECRETS_PATTERNS


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string in bits per character."""
    if not s:
        return 0.0
    freq = {}  # type: dict[str, int]
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def _mask_value(value: str) -> str:
    """Create a masked preview: first 4 chars + ****."""
    if len(value) <= 4:
        return "****"
    return value[:4] + "****"


# Precompiled pattern for tokenizing strings into potential secret tokens.
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{16,80}")

# Separator used to join fields — must not match any pattern.
_FIELD_SEP = "\x00\x00\x00"


def _build_merged_text(fields: list[ScanField]) -> tuple[str, list[tuple[int, int, int]]]:
    """Concatenate fields into single string for batch scanning.

    Returns:
        (merged_text, boundaries) where boundaries is a list of
        (start_offset, end_offset, field_index) tuples.
    """
    parts = []
    boundaries: list[tuple[int, int, int]] = []
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


def _find_field(pos: int, boundaries: list[tuple[int, int, int]]) -> int:
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
    # pos is in separator — return nearest field
    idx = min(lo, len(boundaries) - 1)
    return boundaries[idx][2]


class SecretsDetector(BaseDetector):
    """Detects secrets via regex patterns and entropy analysis."""

    def __init__(self, entropy_threshold: float = 4.5):
        self._entropy_threshold = entropy_threshold

    def scan(
        self,
        fields: list[ScanField],
        allowlist: AllowlistMatcher,
    ) -> list[Finding]:
        if not fields:
            return []

        # Merge all fields into one string for batch scanning.
        merged, boundaries = _build_merged_text(fields)
        if not merged:
            return []

        findings: list[Finding] = []
        matched_spans = set()  # type: set[tuple[int, int]]

        # Pass 1: regex patterns — one finditer per pattern over merged text
        for pat in SECRETS_PATTERNS:
            for match in pat.pattern.finditer(merged):
                value = match.group(1) if match.lastindex else match.group(0)

                if allowlist and allowlist.is_allowed_secret(value):
                    continue

                if pat.needs_entropy and shannon_entropy(value) < self._entropy_threshold:
                    continue

                field_idx = _find_field(match.start(), boundaries)
                matched_spans.add(match.span())
                findings.append(
                    Finding(
                        detector="secrets",
                        type=pat.name,
                        severity=pat.severity,
                        location=fields[field_idx].path,
                        value_preview=_mask_value(value),
                        matched_value=value,
                    )
                )

        # Pass 2: entropy sweep for unstructured high-entropy strings
        merged_lower = merged.lower()
        for token_match in _TOKEN_RE.finditer(merged):
            span = token_match.span()
            if any(s[0] <= span[0] and span[1] <= s[1] for s in matched_spans):
                continue

            token = token_match.group(0)
            if shannon_entropy(token) < self._entropy_threshold:
                continue

            # Clip context to same field's boundaries to avoid cross-field bleed
            field_idx = _find_field(span[0], boundaries)
            field_start, field_end, _ = boundaries[field_idx]
            start = max(field_start, span[0] - 100)
            end = min(field_end, span[1] + 100)
            context = merged_lower[start:end]

            if any(kw in context for kw in SECRET_PROXIMITY_KEYWORDS):
                if allowlist and allowlist.is_allowed_secret(token):
                    continue
                findings.append(
                    Finding(
                        detector="secrets",
                        type="high_entropy_string",
                        severity="warning",
                        location=fields[field_idx].path,
                        value_preview=_mask_value(token),
                        matched_value=token,
                    )
                )

        return findings
