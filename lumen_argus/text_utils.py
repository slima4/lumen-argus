"""Shared text utilities — sanitization, normalization."""

import re
import unicodedata

# Zero-width and invisible Unicode characters used to evade pattern matching.
# Inserting these between letters breaks regex: P\u200Da\u200Ds\u200Ds → "Pass"
# Range ends at U+202E (not U+202F which is NARROW NO-BREAK SPACE — visible width).
_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u2028-\u202e\u2060\ufeff]")


def sanitize_text(text: str) -> str:
    """Strip zero-width characters and normalize Unicode homoglyphs.

    Runs on every field before encoding decode and detection. Two steps:
    1. Strip invisible chars (zero-width spaces, joiners, BOM, etc.)
    2. NFKC normalization (collapses homoglyphs: fullwidth A → ASCII A)
    """
    text = _ZERO_WIDTH_RE.sub("", text)
    text = unicodedata.normalize("NFKC", text)
    return text
