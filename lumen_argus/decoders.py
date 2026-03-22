"""Content decoders — decode base64, hex, URL, and Unicode before scanning.

Sits between field extraction and content fingerprinting in the pipeline.
Each field is expanded into the original text plus any decoded variants.
Detectors then run on all variants, catching encoded secrets.
"""

import base64
import logging
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple
from urllib.parse import unquote

log = logging.getLogger("argus.decoders")

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class DecodedContent:
    """A decoded variant of a text field."""

    text: str
    encoding: str  # "raw", "base64", "hex", "url", "unicode"
    # (start, end) in original text — set for segment decodings (base64, hex),
    # None for full-text decodings (url, unicode) where the entire field is transformed
    original_span: Optional[Tuple[int, int]] = None


# ---------------------------------------------------------------------------
# Regex patterns for encoded content detection
# ---------------------------------------------------------------------------

# Base64: 20+ chars of base64 alphabet, optionally padded with =
# Lookahead/lookbehind instead of \b — \b breaks on +/ which are non-word chars
_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,}={0,3}(?![A-Za-z0-9+/=])")

# Hex: 16+ hex chars (even count), must look intentional (not just a hash)
# Word-bounded, even length enforced in decode step
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{16,}\b")

# Unicode escapes: \uXXXX sequences
_UNICODE_ESCAPE_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){2,}")


# ---------------------------------------------------------------------------
# Content quality filter
# ---------------------------------------------------------------------------

# Minimum ratio of printable ASCII in decoded text to consider it meaningful
_MIN_PRINTABLE_RATIO = 0.7


def _is_meaningful(text: str, min_length: int = 8) -> bool:
    """Check if decoded text looks like meaningful content, not random binary."""
    if not text or len(text) < min_length:
        return False
    printable = sum(1 for c in text if 32 <= ord(c) < 127)
    return (printable / len(text)) >= _MIN_PRINTABLE_RATIO


# ---------------------------------------------------------------------------
# ContentDecoder
# ---------------------------------------------------------------------------


class ContentDecoder:
    """Decode encoded content before scanning.

    Configured with per-encoding toggles and depth/length limits from
    EncodingDecodeConfig (pipeline.stages.encoding_decode in YAML).
    """

    def __init__(
        self,
        enable_base64: bool = True,
        enable_hex: bool = True,
        enable_url: bool = True,
        enable_unicode: bool = True,
        max_depth: int = 2,
        min_decoded_length: int = 8,
        max_decoded_length: int = 10_000,
    ):
        self._enable_base64 = enable_base64
        self._enable_hex = enable_hex
        self._enable_url = enable_url
        self._enable_unicode = enable_unicode
        self._max_depth = max_depth
        self._min_decoded_length = min_decoded_length
        self._max_decoded_length = max_decoded_length

    def decode_field(self, text: str) -> List[DecodedContent]:
        """Return original text plus any decoded variants found.

        The original text is always first in the list (encoding="raw").
        Decoded variants follow, each annotated with the encoding type
        and the span in the original text that was decoded.
        """
        results = [DecodedContent(text=text, encoding="raw")]
        self._decode_recursive(text, results, depth=0)
        return results

    def _decode_recursive(self, text: str, results: List[DecodedContent], depth: int) -> None:
        """Decode at the current depth, recurse for nested encodings."""
        if depth >= self._max_depth:
            return

        new_decoded = []

        if self._enable_base64:
            new_decoded.extend(self._decode_base64(text))

        if self._enable_hex:
            new_decoded.extend(self._decode_hex(text))

        if self._enable_url:
            new_decoded.extend(self._decode_url(text))

        if self._enable_unicode:
            new_decoded.extend(self._decode_unicode(text))

        for d in new_decoded:
            results.append(d)
            # Recurse for nested encoding (e.g., base64 inside URL-encoding)
            if depth + 1 < self._max_depth:
                self._decode_recursive(d.text, results, depth + 1)

    def _decode_base64(self, text: str) -> List[DecodedContent]:
        """Find and decode base64-encoded segments."""
        results = []
        for match in _BASE64_RE.finditer(text):
            raw = match.group()
            # Base64 length must be multiple of 4 (with padding)
            # Add padding if needed
            padded = raw + "=" * (-len(raw) % 4)
            try:
                decoded_bytes = base64.b64decode(padded, validate=True)
                decoded = decoded_bytes.decode("utf-8", errors="ignore")
            except Exception:
                continue
            if not _is_meaningful(decoded, self._min_decoded_length):
                continue
            if len(decoded) > self._max_decoded_length:
                decoded = decoded[: self._max_decoded_length]
            log.debug(
                "base64 decoded: %d chars -> %d chars",
                len(raw),
                len(decoded),
            )
            results.append(
                DecodedContent(
                    text=decoded,
                    encoding="base64",
                    original_span=(match.start(), match.end()),
                )
            )
        return results

    def _decode_hex(self, text: str) -> List[DecodedContent]:
        """Find and decode hex-encoded segments."""
        results = []
        for match in _HEX_RE.finditer(text):
            raw = match.group()
            # Must be even length for valid hex pairs
            if len(raw) % 2 != 0:
                continue
            try:
                decoded = bytes.fromhex(raw).decode("utf-8", errors="ignore")
            except Exception:
                continue
            if not _is_meaningful(decoded, self._min_decoded_length):
                continue
            if len(decoded) > self._max_decoded_length:
                decoded = decoded[: self._max_decoded_length]
            log.debug(
                "hex decoded: %d chars -> %d chars",
                len(raw),
                len(decoded),
            )
            results.append(
                DecodedContent(
                    text=decoded,
                    encoding="hex",
                    original_span=(match.start(), match.end()),
                )
            )
        return results

    def _decode_url(self, text: str) -> List[DecodedContent]:
        """Decode URL-encoded content."""
        if "%" not in text:
            return []
        decoded = unquote(text)
        if decoded == text:
            return []
        if not _is_meaningful(decoded, self._min_decoded_length):
            return []
        if len(decoded) > self._max_decoded_length:
            decoded = decoded[: self._max_decoded_length]
        log.debug("url decoded: %d chars -> %d chars", len(text), len(decoded))
        return [DecodedContent(text=decoded, encoding="url")]

    def _decode_unicode(self, text: str) -> List[DecodedContent]:
        """Decode Unicode escape sequences (\\uXXXX)."""
        if "\\u" not in text:
            return []
        # Only decode if there are actual unicode escape patterns
        if not _UNICODE_ESCAPE_RE.search(text):
            return []
        # Replace only the \uXXXX sequences, leave the rest intact
        # (raw_unicode_escape/unicode_escape codec chain corrupts non-ASCII)
        try:
            decoded = _UNICODE_ESCAPE_RE.sub(
                lambda m: m.group(0).encode().decode("unicode_escape"),
                text,
            )
        except Exception:
            return []
        if decoded == text:
            return []
        if not _is_meaningful(decoded, self._min_decoded_length):
            return []
        if len(decoded) > self._max_decoded_length:
            decoded = decoded[: self._max_decoded_length]
        log.debug("unicode decoded: %d chars -> %d chars", len(text), len(decoded))
        return [DecodedContent(text=decoded, encoding="unicode")]
