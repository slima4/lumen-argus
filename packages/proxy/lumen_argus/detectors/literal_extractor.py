"""Extract fixed literal substrings from regex patterns for Aho-Corasick pre-filtering.

Walks the pattern string with a small purpose-built scanner — no dependency on
CPython's internal regex parser (`re._parser` / the deprecated `sre_parse`).

Conservative by design: any construct the scanner cannot interpret terminates
the current literal run rather than risking a false-negative pre-filter (which
would silently skip rules that should have fired). Worst case: a rule lands in
the unfiltered fallback set and is matched against every input. Correctness is
never traded for speed.

Handles:
- Simple literals: ``sk_live_`` -> ``sk_live_``
- Escaped metacharacters: ``https\\:\\/\\/`` -> ``https://``
- Case-insensitive flag (``re.I`` or inline ``(?i)``): lowercases extracted literals
- Alternation: ``(?:password|secret)`` -> ``["password", "secret"]``
- Character classes / quantifiers: terminate the run
- Anchors (``^``, ``$``, ``\\b``, ``\\B``, ``\\A``, ``\\Z``): zero-width, do not break the run
- Non-branching groups: contribute their literal contents to the parent run only
  when the entire sub-group is a single continuous literal (otherwise the
  sub-group's longest internal run is added as its own sublit so that a regex
  like ``xyz(abc[0-9]def)ghi`` cannot extract the spurious ``xyzdefghi``).
- ``+`` on a literal or fully-literal group: BEFORE side is recorded as a
  sublit (the chars before the ``+`` plus one element copy are guaranteed
  contiguous in every match); the AFTER side restarts so that following chars
  combine with the last iteration's element.
"""

import logging
import re

log = logging.getLogger("argus.detectors.literal_extractor")

# Minimum literal length to be useful as a pre-filter key.
# Shorter literals cause too many false-positive candidates.
MIN_LITERAL_LENGTH = 3

# Backslash escapes that match a character but not a fixed one (terminate run).
# Note: '\n' is intentionally NOT here — it's a fixed literal newline, handled
# by `_CONTROL_ESCAPES` below. '\N{name}' (named-character escape) is also
# intentionally absent so it falls through to the unknown-escape branch and
# the pattern bails conservatively rather than mis-parsing the {name} suffix.
_NON_LITERAL_ESCAPES = frozenset("dDwWsS")
# Backslash escapes that are zero-width assertions (do not break the run).
_ZERO_WIDTH_ESCAPES = frozenset("bBAZ")
# Control-char escapes whose value is the corresponding ASCII char.
_CONTROL_ESCAPES = {"a": "\a", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}
# Punctuation that may legally appear after a backslash and yields the punct as a literal.
_ESCAPABLE_PUNCT = frozenset(r".\\^$*+?{}[]|()/-=:;,!@#%&~\"'<>` ")
# Valid inline flag characters in (?aiLmsux) / (?aiLmsux-imsx) groups.
_INLINE_FLAG_CHARS = frozenset("aiLmsux")


class _ParseError(Exception):
    """Pattern can't be safely parsed; caller returns an empty literal list."""


def extract_literals(pattern: str, flags: int = 0) -> list[tuple[str, bool]]:
    """Extract fixed literal substrings from a regex pattern.

    Args:
        pattern: The regex pattern string.
        flags: Compiled regex flags (re.IGNORECASE, etc.).

    Returns:
        List of (literal, case_insensitive) tuples. Empty if no useful
        literal can be extracted (rule becomes a "fallback" rule).
    """
    case_insensitive = bool(flags & re.IGNORECASE)
    try:
        raw = _extract(pattern, 0, len(pattern), case_insensitive)
    except _ParseError as exc:
        log.debug("literal_extractor: parse failed for %.60s: %s", pattern, exc)
        return []

    out: list[tuple[str, bool]] = []
    seen: set[tuple[str, bool]] = set()
    for lit, ci in raw:
        if len(lit) < MIN_LITERAL_LENGTH:
            continue
        key = (lit, ci)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)

    if not out:
        log.debug("literal_extractor: no usable literals in: %.60s", pattern)
    return out


def _extract(pattern: str, start: int, end: int, ci: bool) -> list[tuple[str, bool]]:
    """Extract literals from ``pattern[start:end]``.

    Splits on top-level ``|`` and scans each branch independently. Returns
    every literal found across all branches: each branch contributes its
    longest continuous run plus any sublits it accumulated (from inner
    alternations, non-continuous sub-groups, or ``+``-quantified atoms).
    """
    pipes = _find_top_level_pipes(pattern, start, end)
    splits = [start, *pipes, end]
    out: list[tuple[str, bool]] = []
    for k in range(len(splits) - 1):
        b_start = splits[k] + (1 if k > 0 else 0)
        b_end = splits[k + 1]
        best_run, best_ci, sublits, _ = _scan_branch(pattern, b_start, b_end, ci)
        out.extend(sublits)
        if best_run:
            out.append((best_run, best_ci))
    return out


def _scan_branch(pattern: str, start: int, end: int, ci: bool) -> tuple[str, bool, list[tuple[str, bool]], bool]:
    """Scan a single alternative (no top-level ``|``).

    Returns ``(best_run, best_ci, sublits, is_fully_literal)``:
    - ``best_run``: the single longest continuous literal run in this branch.
    - ``best_ci``: the case-insensitivity flag in effect when ``best_run`` was
      captured (may differ from the entry ``ci`` if a mid-branch ``(?i)``
      flipped it).
    - ``sublits``: literals from nested alternations, non-continuous sub-groups,
      flag flips, or BEFORE-sides of ``+`` quantifiers. Each is independently
      guaranteed to appear contiguously in every string the branch matches and
      carries its own ci flag.
    - ``is_fully_literal``: True iff the entire branch is one continuous literal
      with no breaks. A parent group may then safely concatenate ``best_run``
      onto its own current run.
    """
    sublits: list[tuple[str, bool]] = []
    best_run = ""
    best_ci = ci
    current_run = ""
    is_fully_literal = True
    i = start

    def consider() -> None:
        """Promote current_run to best_run if strictly longer (with the current ci)."""
        nonlocal best_run, best_ci
        if len(current_run) > len(best_run):
            best_run = current_run
            best_ci = ci

    def hard_break() -> None:
        """Terminate the current run and mark the branch as not fully literal."""
        nonlocal current_run, is_fully_literal
        consider()
        current_run = ""
        is_fully_literal = False

    while i < end:
        c = pattern[i]

        if c == "\\":
            if i + 1 >= end:
                raise _ParseError("trailing backslash")
            nxt = pattern[i + 1]

            if nxt in _ZERO_WIDTH_ESCAPES:
                # \b \B \A \Z — zero-width, no break.
                i += 2
                continue
            if nxt in _NON_LITERAL_ESCAPES:
                # \d \D \w \W \s \S — char-class shorthand.
                hard_break()
                i = _skip_quantifier(pattern, i + 2, end)
                continue
            if nxt.isdigit():
                # Backreference (\1..\99) or octal escape (\012) — consume all
                # consecutive digits so the trailing digit isn't misread as a
                # plain literal char.
                j = i + 2
                while j < end and pattern[j].isdigit():
                    j += 1
                hard_break()
                i = j
                continue
            if nxt == "x" and i + 4 <= end:
                ch, advance = _decode_hex_escape(pattern, i, 2)
                i += advance
            elif nxt == "u" and i + 6 <= end:
                ch, advance = _decode_hex_escape(pattern, i, 4)
                i += advance
            elif nxt in _CONTROL_ESCAPES:
                ch = _CONTROL_ESCAPES[nxt]
                i += 2
            elif nxt in _ESCAPABLE_PUNCT:
                ch = nxt
                i += 2
            else:
                raise _ParseError(f"unknown escape \\{nxt}")

            qkind = _peek_quantifier(pattern, i, end)
            atom = ch.lower() if ci else ch
            current_run, before_side, after_side = _apply_atom(current_run, atom, qkind)
            if qkind is not None:
                is_fully_literal = False
                if before_side:
                    sublits.append((before_side, ci))
                if after_side is not None:
                    current_run = after_side
                i = _skip_quantifier(pattern, i, end)
            continue

        if c == "[":
            j = _skip_charclass(pattern, i, end)
            hard_break()
            i = _skip_quantifier(pattern, j, end)
            continue

        if c == "(":
            close = _find_matching_paren(pattern, i, end)
            inner_start, inner_end, inner_ci, kind = _classify_group(pattern, i, close, ci)
            after_close = close + 1

            if kind == "comment":
                i = after_close
                continue
            if kind == "set_flag_only":
                # (?i) flips case-insensitivity for chars *after* the flag in
                # this branch. Chars before the flag keep their original ci, so
                # we flush the current run as a sublit (with the OLD ci) and
                # reset, rather than retroactively lowercasing them.
                if inner_ci != ci:
                    consider()
                    # After consider(), best_run is the longest run with the
                    # old ci; current_run may equal best_run (if just promoted)
                    # or be a different, shorter, still-guaranteed run. Push
                    # both as sublits, but skip the duplicate when they coincide
                    # so callers never see redundant entries.
                    if best_run:
                        sublits.append((best_run, best_ci))
                    if current_run and current_run != best_run:
                        sublits.append((current_run, ci))
                    current_run = ""
                    best_run = ""
                    best_ci = inner_ci
                    is_fully_literal = False
                ci = inner_ci
                i = after_close
                continue
            if kind in ("lookaround", "opaque"):
                hard_break()
                i = after_close
                continue

            inner_pipes = _find_top_level_pipes(pattern, inner_start, inner_end)
            qkind = _peek_quantifier(pattern, after_close, end)

            if inner_pipes:
                hard_break()
                if qkind in (None, "plus"):
                    sublits.extend(_extract(pattern, inner_start, inner_end, inner_ci))
                # qkind in ("optional", "complex"): branches not guaranteed; drop.
                i = _skip_quantifier(pattern, after_close, end)
                continue

            sub_best, sub_best_ci, sub_sublits, sub_continuous = _scan_branch(pattern, inner_start, inner_end, inner_ci)

            if sub_continuous and inner_ci == ci and qkind is None:
                # Safe to extend parent's run with the entire sub literal.
                current_run += sub_best
                sublits.extend(sub_sublits)
                i = after_close
                continue

            if sub_continuous and inner_ci == ci and qkind == "plus":
                # BEFORE side: prior + first iteration. AFTER side: last iteration only.
                current_run += sub_best
                if current_run:
                    sublits.append((current_run, ci))
                current_run = sub_best
                is_fully_literal = False
                sublits.extend(sub_sublits)
                i = _skip_quantifier(pattern, after_close, end)
                continue

            # Non-continuous sub, or quantifier ?/*/{}, or mixed CI.
            hard_break()
            if qkind in (None, "plus"):
                sublits.extend(sub_sublits)
                if sub_best:
                    sublits.append((sub_best, sub_best_ci))
            i = _skip_quantifier(pattern, after_close, end)
            continue

        if c == "|":
            raise _ParseError("unexpected | inside scan_branch")

        if c in "^$":
            i += 1
            continue

        if c == ".":
            hard_break()
            i = _skip_quantifier(pattern, i + 1, end)
            continue

        if c in "*+?":
            raise _ParseError(f"stray quantifier '{c}'")

        if c == "{":
            # Stray { — Python re sometimes treats as literal but we bail conservatively.
            hard_break()
            i += 1
            continue

        # Plain literal char.
        ch = c.lower() if ci else c
        i += 1
        qkind = _peek_quantifier(pattern, i, end)
        current_run, before_side, after_side = _apply_atom(current_run, ch, qkind)
        if qkind is not None:
            is_fully_literal = False
            if before_side:
                sublits.append((before_side, ci))
            if after_side is not None:
                current_run = after_side
            i = _skip_quantifier(pattern, i, end)

    consider()
    return best_run, best_ci, sublits, is_fully_literal


def _apply_atom(current_run: str, atom: str, qkind: str | None) -> tuple[str, str, str | None]:
    """Apply a single literal atom to ``current_run`` given the next quantifier.

    Returns ``(new_current_run, before_side_to_emit, after_side_seed)``:
    - ``new_current_run`` is the run state after handling the atom (without
      reset).
    - ``before_side_to_emit``: a sublit string to emit, or ``""`` if none.
    - ``after_side_seed``: when not ``None``, the caller should reset
      ``current_run`` to this value (used by ``+`` to seed the AFTER side).
    """
    if qkind is None:
        return current_run + atom, "", None
    if qkind == "plus":
        before = current_run + atom
        return before, before, atom
    # "optional" or "complex" — atom not guaranteed; flush current as a sublit.
    return current_run, current_run, ""


def _peek_quantifier(pattern: str, i: int, end: int) -> str | None:
    """Return ``'optional'``, ``'plus'``, ``'complex'``, or ``None``."""
    if i >= end:
        return None
    c = pattern[i]
    if c in "?*":
        return "optional"
    if c == "+":
        return "plus"
    if c == "{":
        return "complex"
    return None


def _skip_quantifier(pattern: str, i: int, end: int) -> int:
    """If a quantifier starts at ``pattern[i]``, return position after it; else ``i``."""
    if i >= end:
        return i
    c = pattern[i]
    if c in "?*+":
        i += 1
    elif c == "{":
        j = pattern.find("}", i)
        if j == -1:
            raise _ParseError("unclosed {")
        i = j + 1
    else:
        return i
    # Lazy / possessive suffix.
    if i < end and pattern[i] in "?+":
        i += 1
    return i


def _decode_hex_escape(pattern: str, i: int, digits: int) -> tuple[str, int]:
    """Decode ``\\xNN`` (digits=2) or ``\\uNNNN`` (digits=4); return ``(char, length)``."""
    try:
        ch = chr(int(pattern[i + 2 : i + 2 + digits], 16))
    except ValueError as exc:
        raise _ParseError(f"bad hex escape: {exc}") from exc
    return ch, 2 + digits


def _skip_charclass(pattern: str, start: int, end: int) -> int:
    """Skip a character class starting at ``pattern[start] == '['``; return index past ``]``."""
    i = start + 1
    if i < end and pattern[i] == "^":
        i += 1
    # First ']' is treated as a literal in a char class.
    if i < end and pattern[i] == "]":
        i += 1
    while i < end and pattern[i] != "]":
        if pattern[i] == "\\" and i + 1 < end:
            i += 2
        else:
            i += 1
    if i >= end:
        raise _ParseError("unclosed [")
    return i + 1


def _find_matching_paren(pattern: str, start: int, end: int) -> int:
    """Find the ``)`` matching ``(`` at ``pattern[start]``; return its index."""
    depth = 1
    i = start + 1
    while i < end:
        c = pattern[i]
        if c == "\\" and i + 1 < end:
            i += 2
            continue
        if c == "[":
            i = _skip_charclass(pattern, i, end)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise _ParseError("unclosed (")


def _find_top_level_pipes(pattern: str, start: int, end: int) -> list[int]:
    """Return positions of ``|`` that are not inside groups or character classes."""
    pipes: list[int] = []
    i = start
    while i < end:
        c = pattern[i]
        if c == "\\" and i + 1 < end:
            i += 2
        elif c == "[":
            i = _skip_charclass(pattern, i, end)
        elif c == "(":
            i = _find_matching_paren(pattern, i, end) + 1
        elif c == "|":
            pipes.append(i)
            i += 1
        else:
            i += 1
    return pipes


def _classify_group(pattern: str, open_pos: int, close_pos: int, current_ci: bool) -> tuple[int, int, bool, str]:
    """Classify the group at ``pattern[open_pos:close_pos+1]``.

    Returns ``(inner_start, inner_end, inner_ci, kind)`` where ``kind`` is one
    of ``"regular"``, ``"lookaround"``, ``"comment"``, ``"set_flag_only"``,
    or ``"opaque"``.
    """
    j = open_pos + 1
    if j >= close_pos or pattern[j] != "?":
        # Plain capturing group, or empty ().
        return j, close_pos, current_ci, "regular"

    j += 1
    if j >= close_pos:
        raise _ParseError("incomplete (?")
    c = pattern[j]

    if c == ":":
        return j + 1, close_pos, current_ci, "regular"
    if c == "P":
        if j + 1 >= close_pos:
            raise _ParseError("incomplete (?P")
        if pattern[j + 1] == "<":
            close_name = pattern.find(">", j + 2)
            if close_name == -1 or close_name >= close_pos:
                raise _ParseError("unclosed (?P<")
            return close_name + 1, close_pos, current_ci, "regular"
        if pattern[j + 1] == "=":
            return j, close_pos, current_ci, "opaque"
        raise _ParseError("bad (?P")
    if c in "=!":
        return j + 1, close_pos, current_ci, "lookaround"
    if c == "<":
        if j + 1 < close_pos and pattern[j + 1] in "=!":
            return j + 2, close_pos, current_ci, "lookaround"
        raise _ParseError("bad (?<")
    if c == "#":
        return j, close_pos, current_ci, "comment"
    if c in _INLINE_FLAG_CHARS or c == "-":
        # Inline flag group: (?aiLmsux) or (?aiLmsux-imsx) or (?aiLmsux:...).
        # Loop exits at pattern[close_pos]=')' (set_flag_only) or at an inner ':' (scoped).
        k = j
        while k < close_pos and pattern[k] not in ":)":
            if pattern[k] != "-" and pattern[k] not in _INLINE_FLAG_CHARS:
                raise _ParseError(f"bad inline flag char {pattern[k]!r}")
            k += 1
        flag_str = pattern[j:k]
        parts = flag_str.split("-", 1)
        set_flags, unset_flags = parts[0], parts[1] if len(parts) > 1 else ""
        new_ci = current_ci
        if "i" in set_flags:
            new_ci = True
        if "i" in unset_flags:
            new_ci = False
        if k < close_pos and pattern[k] == ":":
            return k + 1, close_pos, new_ci, "regular"
        return k, k, new_ci, "set_flag_only"
    raise _ParseError(f"unknown group prefix (?{c}")
