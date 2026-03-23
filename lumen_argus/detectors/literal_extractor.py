"""Extract fixed literal substrings from regex patterns for Aho-Corasick pre-filtering.

Parses regex patterns using Python's sre_parse module to find the longest
contiguous fixed-string sequences. These literals become Aho-Corasick
automaton keys — if none of a rule's literals appear in the text, the
full regex cannot match and can be skipped.

Handles:
- Simple literals: sk_live_ -> "sk_live_"
- Escaped metacharacters: https\\:// -> "https://"
- Case-insensitive (?i): AKIA -> "akia" (lowercased)
- Alternation: (?:password|secret) -> ["password", "secret"]
- Character classes / quantifiers: [A-Z]{16} -> no literal (empty)
"""

import logging
import sre_parse
from typing import List, Tuple

log = logging.getLogger("argus.detectors.literal_extractor")

# Minimum literal length to be useful as a pre-filter key.
# Shorter literals cause too many false-positive candidates.
MIN_LITERAL_LENGTH = 3


def extract_literals(pattern: str, flags: int = 0) -> List[Tuple[str, bool]]:
    """Extract fixed literal substrings from a regex pattern.

    Args:
        pattern: The regex pattern string.
        flags: Compiled regex flags (re.IGNORECASE, etc.).

    Returns:
        List of (literal, case_insensitive) tuples. Empty if no useful
        literal can be extracted (rule becomes a "fallback" rule).
    """
    try:
        parsed = sre_parse.parse(pattern, flags)
    except Exception:
        log.debug("literal_extractor: failed to parse pattern: %.60s", pattern)
        return []

    # Detect case-insensitive from explicit flags OR inline (?i) in pattern.
    # sre_parse absorbs (?i) into parsed.state.flags.
    effective_flags = flags | getattr(getattr(parsed, "state", None), "flags", 0)
    case_insensitive = bool(effective_flags & sre_parse.SRE_FLAG_IGNORECASE)

    literals = _extract_from_items(list(parsed), case_insensitive)

    # Filter by minimum length
    result = [(lit, ci) for lit, ci in literals if len(lit) >= MIN_LITERAL_LENGTH]

    if not result:
        log.debug("literal_extractor: no usable literals in: %.60s", pattern)

    return result


def _extract_from_items(items, case_insensitive: bool) -> List[Tuple[str, bool]]:
    """Extract literals from a sequence of sre_parse nodes.

    Walks the sequence collecting contiguous LITERAL runs. When a BRANCH
    node is encountered (alternation), each branch is processed independently
    and all alternatives are returned. The best non-branch literal found
    before/after the alternation is also included.
    """
    all_literals = []
    best_literal = ""
    current = ""

    for item_type, item_value in items:
        if item_type == sre_parse.LITERAL:
            current += chr(item_value)

        elif item_type == sre_parse.BRANCH:
            # Flush current run
            if len(current) > len(best_literal):
                best_literal = current
            current = ""
            # Extract from each branch alternative
            # item_value is (None, [branch1_items, branch2_items, ...])
            branches = item_value[1] if isinstance(item_value, tuple) else item_value
            for branch in branches:
                branch_lits = _collect_longest_literal(list(branch), case_insensitive)
                all_literals.extend(branch_lits)

        elif item_type == sre_parse.SUBPATTERN:
            # Recurse into group
            sub_pattern = item_value[3] if len(item_value) >= 4 else item_value[-1]
            sub_flags = item_value[1] if len(item_value) >= 4 else 0
            sub_ci = case_insensitive or bool(sub_flags & sre_parse.SRE_FLAG_IGNORECASE)

            sub_items = list(sub_pattern)

            # Check for alternation inside subpattern
            has_branch = any(t == sre_parse.BRANCH for t, _ in sub_items)
            if has_branch:
                if len(current) > len(best_literal):
                    best_literal = current
                current = ""
                sub_lits = _extract_from_items(sub_items, sub_ci)
                all_literals.extend(sub_lits)
            else:
                # Non-branching subpattern: try to extend the literal run
                sub_lits = _collect_longest_literal(sub_items, sub_ci)
                if sub_lits and len(sub_lits) == 1 and sub_ci == case_insensitive:
                    current += sub_lits[0][0] if not case_insensitive else sub_lits[0][0].lower()
                else:
                    if len(current) > len(best_literal):
                        best_literal = current
                    current = ""

        elif item_type == sre_parse.AT:
            # Anchors (^, $, \b) — don't break literal
            continue

        else:
            # Anything else breaks the literal run
            if len(current) > len(best_literal):
                best_literal = current
            current = ""

    # Final check
    if len(current) > len(best_literal):
        best_literal = current

    # Add the best non-branch literal if it exists
    if best_literal:
        lit = best_literal.lower() if case_insensitive else best_literal
        all_literals.append((lit, case_insensitive))

    return all_literals


def _collect_longest_literal(items, case_insensitive: bool) -> List[Tuple[str, bool]]:
    """Walk a flat sequence of sre_parse nodes, return the single longest literal run."""
    best = ""
    current = ""

    for item_type, item_value in items:
        if item_type == sre_parse.LITERAL:
            current += chr(item_value)
        elif item_type == sre_parse.SUBPATTERN:
            sub_pattern = item_value[3] if len(item_value) >= 4 else item_value[-1]
            sub_flags = item_value[1] if len(item_value) >= 4 else 0
            sub_ci = case_insensitive or bool(sub_flags & sre_parse.SRE_FLAG_IGNORECASE)
            sub_lits = _collect_longest_literal(list(sub_pattern), sub_ci)
            if sub_lits and len(sub_lits) == 1 and sub_ci == case_insensitive:
                current += sub_lits[0][0] if not case_insensitive else sub_lits[0][0].lower()
            else:
                if len(current) > len(best):
                    best = current
                current = ""
        elif item_type == sre_parse.AT:
            continue
        else:
            if len(current) > len(best):
                best = current
            current = ""

    if len(current) > len(best):
        best = current

    if not best:
        return []

    if case_insensitive:
        best = best.lower()

    return [(best, case_insensitive)]
