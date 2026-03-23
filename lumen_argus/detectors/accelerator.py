"""Aho-Corasick pre-filter for multi-pattern rule scanning.

Builds an Aho-Corasick automaton from fixed literal substrings extracted
from rule regex patterns. A single O(n) pass over the text identifies
which rules could possibly match, reducing the candidate set from 1,700+
to ~15 rules — a >95% reduction.

Rules without extractable literals ("fallback rules") are always evaluated.

Graceful fallback: if pyahocorasick is not installed, all rules are
returned as candidates (equivalent to no pre-filter).
"""

import logging
import time
from typing import List, Set

from lumen_argus.detectors.literal_extractor import extract_literals

log = logging.getLogger("argus.detectors.accelerator")

try:
    import ahocorasick

    _HAS_AHOCORASICK = True
except ImportError:
    _HAS_AHOCORASICK = False
    log.warning(
        "pyahocorasick not installed — rule pre-filter disabled, "
        "scanning will be slower with many rules. Install: pip install pyahocorasick"
    )


class AhoCorasickAccelerator:
    """Pre-filter that narrows candidate rules via Aho-Corasick multi-pattern matching.

    Build once at startup/reload, query per scan field.
    """

    def __init__(self):
        self._automaton = None  # type: Optional[ahocorasick.Automaton]
        self._fallback_indices = set()  # type: Set[int]
        self._rule_count = 0
        self._literal_count = 0
        self._available = _HAS_AHOCORASICK

    @property
    def available(self) -> bool:
        """True if Aho-Corasick is available and automaton is built."""
        return self._available and self._automaton is not None

    @property
    def stats(self) -> dict:
        """Return build stats for logging/diagnostics."""
        return {
            "total_rules": self._rule_count,
            "rules_with_literals": self._rule_count - len(self._fallback_indices),
            "fallback_rules": len(self._fallback_indices),
            "literal_count": self._literal_count,
            "available": self.available,
        }

    def build(self, compiled_rules: List[dict]) -> None:
        """Build automaton from compiled rules.

        Args:
            compiled_rules: List of rule dicts with 'name', 'compiled' (regex), etc.
                           Index in list is used as the rule identifier.
        """
        self._rule_count = len(compiled_rules)
        self._fallback_indices = set()
        self._automaton = None
        self._literal_count = 0

        if not _HAS_AHOCORASICK:
            # All rules are fallback when no Aho-Corasick
            self._fallback_indices = set(range(len(compiled_rules)))
            return

        if not compiled_rules:
            return

        t0 = time.monotonic()

        # Extract literals from each rule's regex pattern
        # Map: literal -> set of rule indices
        literal_to_rules = {}  # type: Dict[str, Set[int]]

        for idx, rule in enumerate(compiled_rules):
            pattern_str = rule["compiled"].pattern
            flags = rule["compiled"].flags
            literals = extract_literals(pattern_str, flags)

            if not literals:
                self._fallback_indices.add(idx)
                continue

            for literal, _case_insensitive in literals:
                # Always store lowercase — search runs against lowered text.
                # Case-sensitive rules may get extra false-positive candidates,
                # but the full regex pass rejects them. Zero false negatives.
                key = literal.lower()
                if key not in literal_to_rules:
                    literal_to_rules[key] = set()
                literal_to_rules[key].add(idx)

        # Build Aho-Corasick automaton
        A = ahocorasick.Automaton()
        for literal, rule_indices in literal_to_rules.items():
            # Store the set of rule indices as the value
            existing = A.get(literal, set())
            existing.update(rule_indices)
            A.add_word(literal, existing)

        if len(A) > 0:
            A.make_automaton()
            self._automaton = A

        self._literal_count = len(literal_to_rules)
        elapsed_ms = (time.monotonic() - t0) * 1000

        log.info(
            "accelerator built: %d rules, %d with literals, %d fallback, %d unique literals (%.1fms)",
            self._rule_count,
            self._rule_count - len(self._fallback_indices),
            len(self._fallback_indices),
            self._literal_count,
            elapsed_ms,
        )

    def filter(self, text: str) -> Set[int]:
        """Return set of candidate rule indices that could match the text.

        Performs a single O(n) Aho-Corasick scan plus adds all fallback rules.
        If Aho-Corasick is not available, returns all rule indices.

        Args:
            text: The text to scan for literal matches.

        Returns:
            Set of rule indices to evaluate with full regex.
        """
        if not self._available or self._automaton is None:
            # No pre-filter — return all rules
            return set(range(self._rule_count))

        candidates = set(self._fallback_indices)

        # Single-pass Aho-Corasick search
        # Search lowercase text to match case-insensitive literals
        text_lower = text.lower()
        for _end_index, rule_indices in self._automaton.iter(text_lower):
            candidates.update(rule_indices)

        return candidates

    def filter_ratio(self, candidates: Set[int]) -> float:
        """Calculate the filter ratio (percentage of rules eliminated)."""
        if self._rule_count == 0:
            return 0.0
        return 1.0 - (len(candidates) / self._rule_count)
