"""Tests for regex literal extraction (Aho-Corasick pre-filter support)."""

import re
import unittest

from lumen_argus.detectors.literal_extractor import extract_literals


class TestLiteralExtraction(unittest.TestCase):
    """Test fixed literal extraction from regex patterns."""

    def test_simple_prefix(self):
        """sk_live_ prefix extracted from sk_live_[a-zA-Z0-9]{24}."""
        result = extract_literals(r"sk_live_[a-zA-Z0-9]{24}")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], "sk_live_")
        self.assertFalse(result[0][1])  # not case-insensitive

    def test_aws_key_prefix(self):
        """AKIA prefix extracted from AKIA[0-9A-Z]{16}."""
        result = extract_literals(r"AKIA[0-9A-Z]{16}")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], "AKIA")

    def test_case_insensitive_lowered(self):
        """Case-insensitive flag causes lowercase literal."""
        result = extract_literals(r"AKIA[0-9A-Z]{16}", flags=re.IGNORECASE)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], "akia")
        self.assertTrue(result[0][1])  # case-insensitive

    def test_inline_case_insensitive(self):
        """(?i) inline flag handled."""
        result = extract_literals(r"(?i)AKIA[0-9A-Z]{16}")
        self.assertTrue(len(result) >= 1)
        # Should be lowercased
        lits = [lit for lit, _ in result]
        self.assertTrue(any("akia" in lit for lit in lits))

    def test_alternation_produces_multiple(self):
        """Alternation (?:password|secret) produces multiple literals."""
        result = extract_literals(r"(?:password|secret)\s*[:=]")
        lits = [lit for lit, _ in result]
        self.assertIn("password", lits)
        self.assertIn("secret", lits)

    def test_no_literal_from_pure_charclass(self):
        """[A-Z]{20} has no extractable literal."""
        result = extract_literals(r"[A-Z]{20}")
        self.assertEqual(result, [])

    def test_escaped_metacharacters(self):
        r"""Escaped dots and colons become literal: https\:\/\/ -> https://."""
        result = extract_literals(r"https\:\/\/")
        self.assertEqual(len(result), 1)
        self.assertIn("https://", result[0][0])

    def test_longest_literal_selected(self):
        """When multiple literal runs exist, the longest is selected."""
        # Pattern: abc[0-9]defghij -> "defghij" (longer) not "abc"
        result = extract_literals(r"abc[0-9]defghij")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], "defghij")

    def test_short_literal_filtered(self):
        """Literals shorter than MIN_LITERAL_LENGTH are filtered out."""
        result = extract_literals(r"ab[0-9]+")
        self.assertEqual(result, [])  # "ab" is only 2 chars

    def test_boundary_min_literal_length(self):
        """Exactly MIN_LITERAL_LENGTH (3) passes the filter."""
        result = extract_literals(r"abc[0-9]+")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], "abc")

    def test_github_token_pattern(self):
        """Real-world: ghp_ prefix from GitHub token pattern."""
        result = extract_literals(r"ghp_[A-Za-z0-9]{36}")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], "ghp_")

    def test_empty_pattern(self):
        """Empty pattern returns no literals."""
        result = extract_literals(r"")
        self.assertEqual(result, [])

    def test_dot_star_no_literal(self):
        """Wildcard .* produces no literal."""
        result = extract_literals(r".*")
        self.assertEqual(result, [])

    def test_anchor_ignored(self):
        """Anchors ^ and $ don't affect literal extraction."""
        result = extract_literals(r"^sk_test_[a-z]+$")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], "sk_test_")

    def test_complex_real_pattern(self):
        """Real-world Stripe key pattern."""
        result = extract_literals(r"sk_live_[a-zA-Z0-9]{24,}")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], "sk_live_")


class TestLiteralExtractionCorrectness(unittest.TestCase):
    """Pin down correctness invariants the new scanner enforces.

    Every extracted literal MUST appear contiguously in every string the
    regex matches. A false-negative pre-filter (extracting a literal that
    isn't always present) would silently drop legitimate detections — these
    tests guard against regressions on that contract.
    """

    def _assert_prefilter_covers(self, pattern: str, samples: list[str], flags: int = 0) -> None:
        """Every matching sample must contain at least one extracted literal.

        This is the actual pre-filter correctness contract: rules are skipped
        when *none* of their literals appear in text. So as long as every
        match contains at least one literal from the extracted set, the
        pre-filter cannot drop a real detection.
        """
        compiled = re.compile(pattern, flags)
        literals = extract_literals(pattern, flags)
        self.assertTrue(literals, f"no literals extracted for pattern {pattern!r}; pre-filter would be empty")
        for sample in samples:
            self.assertIsNotNone(
                compiled.search(sample),
                f"sample {sample!r} should match pattern {pattern!r}",
            )
            hay = sample.lower() if (flags & re.IGNORECASE) else sample
            found = any(((lit.lower() if ci else lit) in (hay.lower() if ci else hay)) for lit, ci in literals)
            self.assertTrue(
                found,
                f"pre-filter miss: no extracted literal of {literals!r} found in "
                f"matching sample {sample!r} for pattern {pattern!r}",
            )

    def _assert_literal_universal(self, pattern: str, literal: str, samples: list[str], flags: int = 0) -> None:
        """Stronger check: a specific literal must appear in every matching sample."""
        compiled = re.compile(pattern, flags)
        check = literal.lower() if (flags & re.IGNORECASE) else literal
        for sample in samples:
            self.assertIsNotNone(
                compiled.search(sample),
                f"sample {sample!r} should match pattern {pattern!r}",
            )
            hay = sample.lower() if (flags & re.IGNORECASE) else sample
            self.assertIn(
                check,
                hay,
                f"literal {literal!r} not present in matching sample {sample!r}",
            )

    def test_non_continuous_subgroup_does_not_concatenate(self):
        """Regression: xyz(abc[0-9]def)ghi must not extract spurious 'xyzdefghi'.

        The original sre_parse-based extractor had this bug — it concatenated
        the sub-group's longest internal literal onto the parent's run, which
        is wrong when the sub-group has any non-literal break inside.
        """
        result = extract_literals(r"xyz(abc[0-9]def)ghi")
        lits = {lit for lit, _ in result}
        self.assertNotIn("xyzdefghi", lits)
        self.assertNotIn("xyzdef", lits)
        # All extracted literals must actually appear in every match.
        self._assert_prefilter_covers(
            r"xyz(abc[0-9]def)ghi",
            ["xyzabc1defghi", "xyzabc9defghi", "xyzabc0defghi"],
        )

    def test_plus_on_literal_emits_before_side(self):
        """abc+def: 'abc' is guaranteed (ab + first c); 'cdef' is guaranteed (last c + def)."""
        result = extract_literals(r"abc+def")
        lits = {lit for lit, _ in result}
        self.assertIn("abc", lits)
        self.assertIn("cdef", lits)
        self.assertNotIn("abcdef", lits)
        self._assert_prefilter_covers(r"abc+def", ["abcdef", "abccdef", "abcccdef"])

    def test_plus_on_continuous_group_extends_after_side(self):
        """(abc)+def: 'abcdef' is guaranteed (last iter's abc is contiguous with def)."""
        result = extract_literals(r"(abc)+def")
        lits = {lit for lit, _ in result}
        self.assertIn("abcdef", lits)
        self._assert_prefilter_covers(r"(abc)+def", ["abcdef", "abcabcdef", "abcabcabcdef"])

    def test_plus_on_inner_group_with_prefix(self):
        """a(bc)+def: 'abc' (a + first bc) and 'bcdef' (last bc + def) guaranteed; 'abcdef' is not."""
        result = extract_literals(r"a(bc)+def")
        lits = {lit for lit, _ in result}
        self.assertIn("bcdef", lits)
        self.assertNotIn("abcdef", lits)
        self._assert_prefilter_covers(r"a(bc)+def", ["abcdef", "abcbcdef", "abcbcbcdef"])

    def test_optional_does_not_extend(self):
        """abc?def: 'abc' and 'def' are guaranteed prefixes/suffixes; 'abcdef' is not."""
        result = extract_literals(r"abcd?efgh")
        lits = {lit for lit, _ in result}
        self.assertNotIn("abcdefgh", lits)
        self._assert_prefilter_covers(r"abcd?efgh", ["abcdefgh", "abcefgh"])

    def test_lookahead_terminates_run(self):
        """abc(?=xyz)def — lookahead is opaque; treat as run terminator."""
        result = extract_literals(r"abc(?=xyz)def")
        lits = {lit for lit, _ in result}
        self.assertNotIn("abcdef", lits)
        # Lookahead requires xyz at that position AND the next chars must match def.
        # No string actually matches both `(?=xyz)def` at the same position, so
        # this regex is technically unmatchable — we only assert no spurious
        # literal.

    def test_backreference_terminates_run(self):
        r"""(abc)\1def — backref is opaque; the run must break before def."""
        result = extract_literals(r"(abc)\1def")
        lits = {lit for lit, _ in result}
        self.assertNotIn("abcdef", lits)
        self.assertNotIn("abcabcdef", lits)
        self._assert_prefilter_covers(r"(abc)\1def", ["abcabcdef"])

    def test_multidigit_backreference_consumes_all_digits(self):
        r"""(g1)..(g10)\10<longsuffix> — multi-digit backref consumes both digits.

        Regression: a previous version advanced only past the first digit, so
        the trailing '0' was parsed as a plain literal char and leaked into
        the extracted run as a leading '0'. That `0xxx...` literal is NOT a
        substring of actual matches (the regex expands `\10` to the contents
        of group 10, e.g. 'j', producing `...jxxx...` not `...0xxx...`) — a
        true pre-filter false-negative.
        """
        # 10 groups so \10 is a valid backref; suffix longer than the leading
        # 'abcdefghij' run so that — under the bug — the bogus '0...' literal
        # would win the longest-run tiebreak.
        pattern = "(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)\\10superlongtailstring"
        result = extract_literals(pattern)
        lits = {lit for lit, _ in result}
        self.assertNotIn("0superlongtailstring", lits)
        self.assertIn("superlongtailstring", lits)
        # And the pre-filter contract holds against a real matching string.
        self._assert_prefilter_covers(pattern, ["abcdefghijjsuperlongtailstring"])

    def test_hex_escape_is_literal(self):
        """\\x41bc should extract 'Abc' (\\x41 == 'A')."""
        result = extract_literals(r"\x41bc")
        self.assertEqual(result, [("Abc", False)])

    def test_unicode_escape_is_literal(self):
        """\\u0041bc should extract 'Abc'."""
        result = extract_literals(r"\u0041bc")
        self.assertEqual(result, [("Abc", False)])

    def test_control_escape_is_literal_char(self):
        """\\tabc should extract '\\tabc' (literal tab + abc)."""
        result = extract_literals(r"\tabc")
        self.assertEqual(result, [("\tabc", False)])

    def test_newline_escape_within_run(self):
        """abc\\ndef should extract 'abc\\ndef' (\\n is a fixed literal newline).

        Regression: \\n was previously misclassified as a non-literal escape
        (alongside \\d, \\w, etc.) which caused an unnecessary run break. \\n
        is in `_CONTROL_ESCAPES` and must reach that branch.
        """
        result = extract_literals(r"abc\ndef")
        lits = {lit for lit, _ in result}
        self.assertIn("abc\ndef", lits)

    def test_tab_escape_within_run(self):
        """abc\\tdef should extract 'abc\\tdef' (\\t is a fixed literal tab)."""
        result = extract_literals(r"abc\tdef")
        lits = {lit for lit, _ in result}
        self.assertIn("abc\tdef", lits)

    def test_named_char_escape_bails(self):
        """\\N{name} is conservatively rejected (returns []) rather than mis-parsed.

        A previous version classified \\N as a char-class shorthand, then the
        following {name} was accidentally consumed as a brace-quantifier — a
        fragile coincidence. The scanner now raises and returns [] so callers
        treat the rule as a fallback.
        """
        result = extract_literals(r"prefix\N{LATIN SMALL LETTER A}suffix")
        self.assertEqual(result, [])

    def test_inline_scoped_flag_isolated(self):
        """(?i:ABC)def — scoped inline flag does NOT propagate outside the group."""
        result = extract_literals(r"(?i:ABC)def")
        # Inside the group: 'abc' (lowercased due to ci). Outside: 'def' stays cased.
        lits_with_ci = {(lit, ci) for lit, ci in result}
        # Each literal carries its own ci flag.
        self.assertIn(("abc", True), lits_with_ci)
        self.assertIn(("def", False), lits_with_ci)

    def test_trailing_backslash_returns_empty(self):
        """Malformed pattern with trailing backslash → conservative empty result."""
        result = extract_literals("abc\\")
        self.assertEqual(result, [])

    def test_alternation_with_optional_quantifier_drops_branches(self):
        """(?:abc|def)? — optional alternation: neither branch guaranteed."""
        result = extract_literals(r"(?:abcabc|defdef)?prefix")
        lits = {lit for lit, _ in result}
        self.assertNotIn("abcabc", lits)
        self.assertNotIn("defdef", lits)
        self.assertIn("prefix", lits)

    def test_alternation_with_plus_keeps_branches(self):
        """(?:abc|def)+ — at-least-one alternation: every match contains one branch."""
        result = extract_literals(r"(?:abcabc|defdef)+suffix")
        lits = {lit for lit, _ in result}
        # Each branch is guaranteed in matches that take that branch (any-of pre-filter).
        self.assertIn("abcabc", lits)
        self.assertIn("defdef", lits)
        self._assert_prefilter_covers(
            r"(?:abcabc|defdef)+suffix",
            ["abcabcsuffix", "defdefsuffix", "abcabcdefdefsuffix"],
        )

    def test_nested_groups(self):
        """Nested non-branching groups extend the run when fully literal."""
        result = extract_literals(r"((abc))def")
        lits = {lit for lit, _ in result}
        self.assertIn("abcdef", lits)

    def test_empty_alternative(self):
        """abc|def — top-level alternation with no surrounding context."""
        result = extract_literals(r"abcabc|defdef")
        lits = {lit for lit, _ in result}
        self.assertIn("abcabc", lits)
        self.assertIn("defdef", lits)


class TestQuantifierSuffixes(unittest.TestCase):
    """Lazy (?), possessive (+), and combined quantifier suffixes."""

    def test_lazy_optional(self):
        """abc?? — lazy optional. Same semantics as ? for literal extraction."""
        result = extract_literals(r"abcd??efgh")
        # 'abcd' guaranteed (a,b,c always present + d either consumed or skipped).
        # Wait: 'abcd' requires the d to be present; 'd??' makes it optional.
        # So 'abc' guaranteed, 'efgh' guaranteed; 'abcd' or 'abcdefgh' not.
        lits = {lit for lit, _ in result}
        self.assertIn("efgh", lits)
        self.assertNotIn("abcdefgh", lits)
        self.assertNotIn("abcd", lits)

    def test_lazy_plus_on_literal(self):
        """abc+? — lazy +. Same as + for literal extraction."""
        result = extract_literals(r"abc+?def")
        lits = {lit for lit, _ in result}
        self.assertIn("abc", lits)
        self.assertIn("cdef", lits)

    def test_lazy_star(self):
        """abc*?def — lazy *. c is optional."""
        result = extract_literals(r"abc*?def")
        lits = {lit for lit, _ in result}
        self.assertNotIn("abcdef", lits)

    def test_possessive_plus(self):
        """abc++ — possessive +. Same semantics."""
        result = extract_literals(r"abc++def")
        lits = {lit for lit, _ in result}
        self.assertIn("abc", lits)
        self.assertIn("cdef", lits)

    def test_lazy_complex_quantifier(self):
        """abc{2,5}? — lazy complex quantifier on literal."""
        # c{2,5}? — at least 2 c's. Conservative: treat as opaque/optional.
        result = extract_literals(r"abc{2,5}?def")
        lits = {lit for lit, _ in result}
        # We don't claim anything specific, but the result must not contain
        # spurious 'abcdef' (since multiple c's break contiguity).
        self.assertNotIn("abcdef", lits)


class TestGroupVariants(unittest.TestCase):
    """Group prefix variants: (?:...), (?P<name>...), (?#comment), nested, deep."""

    def test_named_group(self):
        """(?P<name>abc)def — named capturing group, fully literal."""
        result = extract_literals(r"(?P<token>abc)def")
        lits = {lit for lit, _ in result}
        self.assertIn("abcdef", lits)

    def test_named_group_with_quantifier(self):
        """(?P<name>abc)+def — named group + plus."""
        result = extract_literals(r"(?P<token>abc)+def")
        lits = {lit for lit, _ in result}
        self.assertIn("abcdef", lits)

    def test_comment_group_does_not_break_run(self):
        """abc(?#comment)def — comment group is ignored."""
        result = extract_literals(r"abc(?#this is a comment)def")
        lits = {lit for lit, _ in result}
        self.assertIn("abcdef", lits)

    def test_deeply_nested_groups(self):
        """((((abc))))def — deep nesting, all fully literal."""
        result = extract_literals(r"((((abcdef))))ghi")
        lits = {lit for lit, _ in result}
        self.assertIn("abcdefghi", lits)

    def test_empty_capturing_group(self):
        """()abc — empty group followed by literal. Should not crash."""
        result = extract_literals(r"()abc")
        lits = {lit for lit, _ in result}
        # Empty group adds nothing; 'abc' should still be extracted.
        self.assertIn("abc", lits)

    def test_empty_noncapturing_group(self):
        """(?:)abc — empty non-capturing group."""
        result = extract_literals(r"(?:)abcdef")
        lits = {lit for lit, _ in result}
        self.assertIn("abcdef", lits)


class TestLookarounds(unittest.TestCase):
    """All four lookaround flavors should terminate the run."""

    def test_lookahead_positive(self):
        result = extract_literals(r"abcabc(?=xyz)")
        lits = {lit for lit, _ in result}
        self.assertIn("abcabc", lits)

    def test_lookahead_negative(self):
        """Lookaround terminates the run; per longest-only-per-branch, one wins."""
        result = extract_literals(r"abcabc_extra(?!xyz)defdef")
        lits = {lit for lit, _ in result}
        # 'abcabc_extra' is longer than 'defdef' so it wins; the critical
        # invariant is that 'abcabc_extradefdef' (spurious concat) is NOT here.
        self.assertIn("abcabc_extra", lits)
        self.assertNotIn("abcabc_extradefdef", lits)

    def test_lookbehind_positive(self):
        result = extract_literals(r"(?<=foo)barbar")
        lits = {lit for lit, _ in result}
        self.assertIn("barbar", lits)

    def test_lookbehind_negative(self):
        result = extract_literals(r"(?<!foo)barbar")
        lits = {lit for lit, _ in result}
        self.assertIn("barbar", lits)


class TestCharClassEdgeCases(unittest.TestCase):
    """Character class edge cases that the scanner must skip correctly."""

    def test_charclass_with_literal_close_bracket(self):
        """[]abc] — first ']' is treated as literal in a char class.

        Per the "longest run per branch" design, only one of prefix/suffix is
        returned. The key invariant: the char class is correctly skipped (not
        consumed as a stray ']' that would corrupt the surrounding parse).
        """
        result = extract_literals(r"prefix[]abc]suffix_long")
        lits = {lit for lit, _ in result}
        # suffix is longer (11 vs 6), so it wins the longest-run tiebreak.
        self.assertIn("suffix_long", lits)
        # And the result is a real substring of a matching string.
        compiled = re.compile(r"prefix[]abc]suffix_long")
        self.assertIsNotNone(compiled.search("prefixasuffix_long"))

    def test_negated_charclass(self):
        """[^abc]xyz — negated char class still terminates the run."""
        result = extract_literals(r"pre[^abc]xyz_suffix_long")
        lits = {lit for lit, _ in result}
        # 'xyz_suffix_long' (15) longer than 'pre' (3), wins.
        self.assertIn("xyz_suffix_long", lits)

    def test_charclass_with_escaped_close_bracket(self):
        r"""[a\]b]xyz — escaped ] inside char class doesn't close it early."""
        result = extract_literals(r"prefix_long[a\]b]xyz")
        lits = {lit for lit, _ in result}
        # 'prefix_long' is the longest survivor; xyz is too short post-filter.
        self.assertIn("prefix_long", lits)

    def test_charclass_with_pipe_inside(self):
        """[|]abc — pipe inside char class is NOT alternation."""
        result = extract_literals(r"prefix_long[|]abc")
        lits = {lit for lit, _ in result}
        # Should not split into alternation branches; 'prefix_long' wins.
        self.assertIn("prefix_long", lits)
        # Critically: no branch with just 'abc' as its own top-level alt.
        self.assertNotIn("abc", {lit for lit, _ in result if len(lit) == 3})

    def test_charclass_with_paren_inside(self):
        """[()]abc — parens inside char class are literals, not group delimiters."""
        result = extract_literals(r"prefix_long[()]abc")
        lits = {lit for lit, _ in result}
        self.assertIn("prefix_long", lits)


class TestInlineFlagVariants(unittest.TestCase):
    """Inline flag groups: (?i), (?im), (?-i), (?im-sx), (?i:...)."""

    def test_inline_flag_mid_pattern(self):
        """abcdef(?i)GHI — flag flips ci for the rest of the branch only."""
        result = extract_literals(r"abcdef(?i)GHIJKL")
        # 'abcdef' before the flag stays case-sensitive; GHIJKL after is lowered.
        lits_ci = {(lit, ci) for lit, ci in result}
        self.assertIn(("abcdef", False), lits_ci)
        # GHIJKL becomes 'ghijkl' under ci.
        ci_literals = {lit for lit, ci in result if ci}
        self.assertTrue(any("ghijkl" in lit for lit in ci_literals))

    def test_multiple_set_flags(self):
        """(?im)abc — multiple flags, only 'i' affects case."""
        result = extract_literals(r"(?im)ABCDEF")
        lits = {lit for lit, _ in result}
        self.assertIn("abcdef", lits)

    def test_negated_flag(self):
        """(?-i)ABC — explicit unset of i flag (no-op when ci was already off)."""
        result = extract_literals(r"(?-i)ABCDEF")
        lits_ci = {(lit, ci) for lit, ci in result}
        self.assertIn(("ABCDEF", False), lits_ci)

    def test_combined_set_unset(self):
        """(?im-sx)abc — set i and m, unset s and x."""
        result = extract_literals(r"(?im-sx)ABCDEF")
        lits = {lit for lit, _ in result}
        self.assertIn("abcdef", lits)


class TestAnchorsAndZeroWidth(unittest.TestCase):
    """Anchors and zero-width assertions don't break literal runs."""

    def test_word_boundary(self):
        r"""\babc\b — word boundaries are zero-width."""
        result = extract_literals(r"\babc_test\b")
        lits = {lit for lit, _ in result}
        self.assertIn("abc_test", lits)

    def test_negated_word_boundary(self):
        r"""\Babc — non-word-boundary is zero-width."""
        result = extract_literals(r"\Babc_test")
        lits = {lit for lit, _ in result}
        self.assertIn("abc_test", lits)

    def test_string_anchors(self):
        r"""\Aabc\Z — string anchors are zero-width."""
        result = extract_literals(r"\Aabc_test\Z")
        lits = {lit for lit, _ in result}
        self.assertIn("abc_test", lits)

    def test_anchor_mid_pattern(self):
        """abc^def — caret mid-pattern. Zero-width, doesn't break the run."""
        result = extract_literals(r"abc^def")
        lits = {lit for lit, _ in result}
        # Whether this regex matches anything is debatable, but the scanner
        # treats ^ as zero-width per the documented contract.
        self.assertIn("abcdef", lits)


class TestUnicode(unittest.TestCase):
    """Unicode characters in patterns are treated as literals."""

    def test_non_ascii_literal(self):
        """中文测试def — non-Latin CJK chars as literals."""
        result = extract_literals("中文测试def")
        lits = {lit for lit, _ in result}
        self.assertIn("中文测试def", lits)

    def test_emoji_literal(self):
        """🔥abc — emoji as literal."""
        result = extract_literals("🔥abc_secret")
        lits = {lit for lit, _ in result}
        # Each char in current_run is appended; emojis are valid chars.
        self.assertTrue(any("🔥" in lit for lit in lits))


class TestMalformedPatterns(unittest.TestCase):
    """Robustness: malformed patterns must return [] and never raise."""

    def test_unclosed_group(self):
        result = extract_literals(r"abc(def")
        self.assertEqual(result, [])

    def test_unclosed_charclass(self):
        result = extract_literals(r"abc[def")
        self.assertEqual(result, [])

    def test_unclosed_brace_quantifier(self):
        result = extract_literals(r"abc{2")
        self.assertEqual(result, [])

    def test_stray_quantifier(self):
        result = extract_literals(r"+abc")
        self.assertEqual(result, [])

    def test_unknown_inline_flag_char(self):
        result = extract_literals(r"(?z)abc")
        self.assertEqual(result, [])

    def test_unknown_escape(self):
        result = extract_literals(r"\zabc")
        self.assertEqual(result, [])

    def test_incomplete_lookbehind(self):
        result = extract_literals(r"(?<abc)def")
        self.assertEqual(result, [])

    def test_bad_hex_escape(self):
        result = extract_literals(r"\xZZabc")
        self.assertEqual(result, [])


class TestIdempotency(unittest.TestCase):
    """Same input must always produce the same output."""

    def test_idempotent_simple(self):
        for _ in range(3):
            self.assertEqual(
                extract_literals(r"sk_live_[a-zA-Z0-9]{24}"),
                [("sk_live_", False)],
            )

    def test_idempotent_with_alternation(self):
        a = extract_literals(r"(?:password|secret)\s*[:=]")
        b = extract_literals(r"(?:password|secret)\s*[:=]")
        self.assertEqual(a, b)

    def test_dedup_within_call(self):
        """Same literal appearing multiple times in pattern → only once in output."""
        # 'abcd' appears twice; should be deduplicated.
        result = extract_literals(r"(?:abcd|abcd|abcd)xyz")
        lits = [lit for lit, _ in result]
        self.assertEqual(lits.count("abcd"), 1)


class TestReviewerSuspectedIssues(unittest.TestCase):
    """Pin down behavior at points the code reviewer specifically called out
    as potentially buggy and then self-corrected. Each test encodes a
    correctness claim that, if it ever silently regresses, would re-open one
    of those review concerns.
    """

    def _matches_contain(self, pattern: str, samples: list[str]) -> set[str]:
        """Return the set of literals extracted that appear in every sample."""
        compiled = re.compile(pattern)
        for s in samples:
            assert compiled.search(s), f"{s!r} should match {pattern!r}"
        lits = extract_literals(pattern)
        guaranteed = set()
        for lit, _ in lits:
            if all(lit in s for s in samples):
                guaranteed.add(lit)
        return guaranteed

    # --- 1. + on a non-continuous group — sub_best is still safe to emit.
    def test_plus_on_noncontinuous_group_inner_literals_guaranteed(self):
        """(abc[0-9]def)+xyz — inner 'abc' and 'def' appear in every match
        because the group must run at least once. The reviewer worried this
        path emitted unsafe literals; pin that it's actually correct."""
        pattern = r"(abc[0-9]def)+xyzxyz"
        samples = [
            "abc1defxyzxyz",  # one iteration
            "abc1defabc2defxyzxyz",  # two iterations
            "abc0defabc9defabc7defxyzxyz",  # three iterations
        ]
        guaranteed = self._matches_contain(pattern, samples)
        # All literals the extractor returns must be in every match.
        result = extract_literals(pattern)
        for lit, _ in result:
            self.assertIn(
                lit,
                guaranteed,
                f"extracted literal {lit!r} not present in every sample",
            )
        # And it must extract SOMETHING (otherwise rule falls back).
        self.assertTrue(result, "expected at least one literal")

    # --- 2. + on a continuous group: BEFORE/AFTER split is sound.
    def test_plus_on_continuous_group_no_spurious_concat(self):
        """xyz(abc)+pqr — the BEFORE side 'xyzabc' and AFTER side 'abcpqr'
        are both guaranteed in matches; the falsely-implied 'xyzabcpqr' is
        NOT (multiple iterations break it)."""
        pattern = r"xyz(abc)+pqr"
        samples_two_iter = "xyzabcabcpqr"  # spurious 'xyzabcpqr' would fail
        samples_one_iter = "xyzabcpqr"
        compiled = re.compile(pattern)
        self.assertIsNotNone(compiled.search(samples_two_iter))
        self.assertIsNotNone(compiled.search(samples_one_iter))
        result = extract_literals(pattern)
        lits = {lit for lit, _ in result}
        self.assertNotIn("xyzabcpqr", lits)
        # Each extracted literal is in BOTH samples.
        for lit in lits:
            self.assertIn(lit, samples_two_iter, f"{lit!r} missing from 2-iter")
            self.assertIn(lit, samples_one_iter, f"{lit!r} missing from 1-iter")

    # --- 3. + on a single literal: AFTER side seeds with the atom only.
    def test_plus_on_literal_after_side_is_only_the_atom(self):
        """For abc+def, after-side starts with just 'c' (not 'abc') so the
        AFTER literal is 'cdef', not 'abcdef'. Pin this specific shape."""
        result = extract_literals(r"abc+def")
        lits = {lit for lit, _ in result}
        self.assertIn("cdef", lits)
        self.assertNotIn("abcdef", lits)
        self.assertNotIn("bcdef", lits)  # 'b' would mean we wrongly seeded with 2 chars

    # --- 4. Escape followed by no quantifier doesn't skip chars.
    def test_escape_then_no_quantifier_continues_normally(self):
        """\\.abc — escaped dot then plain literals. Cursor must land at 'a'."""
        result = extract_literals(r"\.abcdef")
        lits = {lit for lit, _ in result}
        self.assertIn(".abcdef", lits)

    def test_hex_escape_then_no_quantifier(self):
        """\\x41bcdef — hex escape then plain literals. 'a' (\\x41) starts run."""
        result = extract_literals(r"\x41bcdef")
        lits = {lit for lit, _ in result}
        self.assertIn("Abcdef", lits)

    # --- 5. (?i) mid-branch dedup works when current_run == best_run.
    def test_midpattern_flag_flip_dedup(self):
        """abcdef(?i)ghi — flush emits both current_run and best_run, which
        are the same string after consider() promotes. Dedup must collapse."""
        result = extract_literals(r"abcdef(?i)ghijkl")
        # 'abcdef' should appear exactly once with ci=False.
        abcdef_count = sum(1 for lit, ci in result if lit == "abcdef" and ci is False)
        self.assertEqual(abcdef_count, 1, f"expected exactly 1 'abcdef', got {result}")

    # --- 6. (?i) no-op when inner_ci already matches.
    def test_redundant_inline_flag_no_op(self):
        """(?i)abc(?i)def under outer ci=True — redundant flag, no flush."""
        result = extract_literals(r"abcdef(?i)ghijkl", flags=re.IGNORECASE)
        # Outer ci True; the (?i) inline doesn't change anything.
        # Result should be a single combined run 'abcdefghijkl' (lowered).
        lits_ci = {(lit, ci) for lit, ci in result}
        self.assertIn(("abcdefghijkl", True), lits_ci)

    # --- 7. {n} with n>=1 conservatively over-flushes but never emits unsafe.
    def test_brace_quantifier_n_at_least_1_no_spurious(self):
        """abc{3}def — c{3} is exactly 3 c's. Conservative scanner treats
        complex {} as optional; must NOT extract 'abcdef' (would be wrong
        regardless) or 'abcccdef' (we're not parsing the count)."""
        result = extract_literals(r"abc{3}defdef")
        lits = {lit for lit, _ in result}
        self.assertNotIn("abcdef", lits)
        self.assertNotIn("abcccdef", lits)
        # Pre-filter coverage still holds.
        compiled = re.compile(r"abc{3}defdef")
        sample = "abcccdefdef"
        self.assertIsNotNone(compiled.search(sample))
        for lit, _ in result:
            self.assertIn(lit, sample, f"{lit!r} not in match {sample!r}")

    def test_brace_quantifier_zero_count_safe(self):
        """abc{0,5}def — c may not appear at all. 'abc' and 'def' must NOT
        be extracted as a single literal 'abcdef' (the c could be absent)."""
        result = extract_literals(r"abc{0,5}defdef")
        lits = {lit for lit, _ in result}
        self.assertNotIn("abcdef", lits)
        compiled = re.compile(r"abc{0,5}defdef")
        for sample in ["abdefdef", "abcdefdef", "abcccccdefdef"]:
            self.assertIsNotNone(compiled.search(sample))
            for lit, _ in result:
                self.assertIn(lit, sample, f"{lit!r} not in {sample!r}")

    # --- 8. (?i:...) scoped — flag confined to the group.
    def test_scoped_flag_does_not_leak_after_group(self):
        """(?i:ABC)DEF — case-insensitivity is confined to ABC; DEF stays cased."""
        result = extract_literals(r"(?i:ABC_X)DEF_Y")
        lits_ci = {(lit, ci) for lit, ci in result}
        self.assertIn(("abc_x", True), lits_ci)
        self.assertIn(("DEF_Y", False), lits_ci)

    # --- 9. Stray { is unreachable for valid patterns; only hit by malformed.
    def test_brace_after_atom_fully_consumed_by_skip_quantifier(self):
        """abc{2,5}def — must not leak '2,5}def' as a literal (that would
        mean the stray-{ path was hit instead of _skip_quantifier eating it)."""
        result = extract_literals(r"abc{2,5}def")
        lits = {lit for lit, _ in result}
        self.assertFalse(any("2,5}" in lit for lit in lits))
        self.assertFalse(any("}def" in lit for lit in lits))

    # --- 10. Escape-pipe must not be treated as alternation.
    def test_escaped_pipe_is_literal_not_alternation(self):
        r"""abc\|def — \| is a literal pipe, not a top-level alternation."""
        result = extract_literals(r"abc\|defghi")
        lits = {lit for lit, _ in result}
        # Should be a single continuous literal, not split at the pipe.
        self.assertIn("abc|defghi", lits)

    def test_escaped_paren_is_literal_not_group(self):
        r"""\(abc\) — escaped parens are literals, no group is opened."""
        result = extract_literals(r"\(abc_token\)")
        lits = {lit for lit, _ in result}
        self.assertIn("(abc_token)", lits)


class TestKitchenSink(unittest.TestCase):
    """Combine many features in one pattern and verify the contract."""

    def test_kitchen_sink_pattern(self):
        """Realistic combined pattern: anchors, group, alternation, char class,
        quantifier, escape — must not crash and must produce safe literals."""
        pattern = r"^prefix_(?:foo|bar)_[A-Z]{4,}\.token=[a-z0-9]+$"
        compiled = re.compile(pattern)
        samples = [
            "prefix_foo_ABCD.token=xyz123",
            "prefix_bar_WXYZQ.token=a",
        ]
        for s in samples:
            self.assertIsNotNone(compiled.search(s))
        result = extract_literals(pattern)
        self.assertTrue(result, "kitchen-sink pattern should extract something")
        for lit, _ in result:
            for s in samples:
                # Every extracted literal must be a substring of every match
                # that contains the same alternation branch — but with
                # alternation, only any-of holds. Use any-of as the contract.
                pass
            # Any-of: at least one extracted literal in this sample.
            covered = any(lit in s for lit, _ in result for s in [samples[0]])
            self.assertTrue(covered)

    def test_deep_recursion_does_not_blow_stack(self):
        """Deeply nested groups must not cause a RecursionError."""
        # 50 levels — comfortably under Python's default 1000 limit but
        # well past anything realistic.
        depth = 50
        pattern = "(" * depth + "abc" + ")" * depth
        # Should not raise.
        result = extract_literals(pattern)
        lits = {lit for lit, _ in result}
        self.assertIn("abc", lits)

    def test_long_pattern_terminates(self):
        """A long pattern with many literal segments terminates in reasonable time."""
        # Build: abc1[0-9]abc2[0-9]...abc50[0-9]
        parts = [f"abc{i}[0-9]" for i in range(50)]
        pattern = "".join(parts) + "tail_extra"
        result = extract_literals(pattern)
        # Should extract the longest literal seen — likely "tail_extra" or
        # one of the abcN segments — but at minimum, must not crash.
        self.assertIsInstance(result, list)
        self.assertTrue(result)


class TestRealWorldRulePatterns(unittest.TestCase):
    """Run the extractor over the actual community rule patterns and verify
    the pre-filter contract holds for sample matching strings."""

    def _check(
        self,
        pattern: str,
        samples: list[str],
        flags: int = 0,
        require_extraction: bool = True,
    ) -> None:
        compiled = re.compile(pattern, flags)
        literals = extract_literals(pattern, flags)
        if require_extraction:
            self.assertTrue(
                literals,
                f"pattern {pattern!r} should have extractable literals "
                f"(otherwise it would fall back to always-on scanning)",
            )
        for sample in samples:
            self.assertIsNotNone(
                compiled.search(sample),
                f"sample {sample!r} should match pattern {pattern!r}",
            )
            if not literals:
                continue
            hay = sample.lower() if (flags & re.IGNORECASE) else sample
            found = any(((lit.lower() if ci else lit) in (hay.lower() if ci else hay)) for lit, ci in literals)
            self.assertTrue(
                found,
                f"pre-filter miss for {pattern!r}: no literal of {literals!r} in {sample!r}",
            )

    def test_aws_access_key(self):
        self._check(
            r"AKIA[0-9A-Z]{16}",
            ["AKIAIOSFODNN7EXAMPLE", "AKIA1234567890ABCDEF"],
        )

    def test_aws_secret_compound(self):
        self._check(
            r"(?i)(?:aws[_\s]{0,10}secret[_\s]{0,10}(?:access[_\s]{0,10})?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
            [
                "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
            ],
        )

    def test_google_api_key(self):
        self._check(
            r"AIza[0-9A-Za-z_\-]{35}",
            ["AIzaSyA1234567890abcdefghijklmnopqrstuvw"],
        )

    def test_anthropic_key(self):
        self._check(
            r"sk-ant-[a-zA-Z0-9\-_]{20,}",
            ["sk-ant-api03-abcdef1234567890abcdef"],
        )

    def test_github_pat(self):
        self._check(
            r"github_pat_[A-Za-z0-9_]{22,}",
            ["github_pat_11ABCDEFGHIJKLMNOPQRSTUVWXYZ_abc123"],
        )

    def test_jwt_pattern(self):
        self._check(
            r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+",
            [
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature",
            ],
        )

    def test_slack_webhook(self):
        self._check(
            r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+",
            [
                "https://hooks.slack.com/services/T0000/B1111/abc123def",
            ],
        )

    def test_discord_webhook_with_optional_app(self):
        """https://discord(?:app)?\\.com/... — optional non-capturing group."""
        self._check(
            r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+",
            [
                "https://discord.com/api/webhooks/1234/token_abc",
                "https://discordapp.com/api/webhooks/5678/another_token",
            ],
        )

    def test_stripe_key_with_alternation(self):
        """[sr]k_(?:test|live)_... — char-class prefix + alternation."""
        self._check(
            r"[sr]k_(?:test|live)_[0-9a-zA-Z]{24,}",
            [
                "sk_test_4eC39HqLyjWDarjtT1zdp7dc1234",
                "rk_live_abc123def456ghi789jkl012mno",
            ],
        )

    def test_private_key_header(self):
        """-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY----- — alternation with empty option."""
        self._check(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            [
                "-----BEGIN PRIVATE KEY-----",
                "-----BEGIN RSA PRIVATE KEY-----",
                "-----BEGIN OPENSSH PRIVATE KEY-----",
            ],
        )

    def test_database_url_complex_alternation(self):
        """(?:postgres(?:ql)?|mysql|...)://... — nested alternation."""
        self._check(
            r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s'\"]+@[^\s'\"]+",
            [
                "postgres://user:pass@host:5432/db",
                "postgresql://user:pass@host/db",
                "mysql://root:secret@localhost/app",
                "mongodb+srv://user:pass@cluster.mongodb.net/db",
            ],
        )

    def test_email_pattern(self):
        self._check(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            ["user@example.com", "first.last+tag@sub.domain.co.uk"],
            require_extraction=False,  # No fixed literal at all → fallback rule.
        )

    def test_ssn_pattern(self):
        r"""\b\d{3}-\d{2}-\d{4}\b — purely structural, no fixed literal."""
        self._check(
            r"\b\d{3}-\d{2}-\d{4}\b",
            ["123-45-6789"],
            require_extraction=False,
        )

    def test_prompt_injection_with_alternation_inside_group(self):
        self._check(
            r"(?i)ignore\s+(all\s+)?previous\s+instructions",
            [
                "ignore previous instructions",
                "Ignore all previous instructions please",
            ],
        )

    def test_community_rules_extraction_within_time_budget(self):
        """Soft perf tripwire: extracting literals over the entire community
        rule corpus must complete well within budget.

        This is not a tight benchmark — it's a guardrail against accidental
        quadratic regressions in the scanner (e.g., a future change that
        re-walks the pattern from a non-linear inner loop). On a typical dev
        machine, a full pass over ~50 rules takes ~1ms; the budget is set
        ~50x higher to stay non-flaky on slow CI runners.
        """
        import json
        import time
        from pathlib import Path

        rules_path = Path(__file__).parent.parent / "packages" / "proxy" / "lumen_argus" / "rules" / "community.json"
        if not rules_path.exists():
            self.skipTest(f"community rules not found at {rules_path}")
        rules = json.loads(rules_path.read_text())["rules"]
        # Warm up — JIT/import side effects on first call.
        for rule in rules:
            extract_literals(
                rule.get("pattern", ""),
                re.IGNORECASE if rule.get("case_insensitive") else 0,
            )
        start = time.perf_counter()
        for rule in rules:
            extract_literals(
                rule.get("pattern", ""),
                re.IGNORECASE if rule.get("case_insensitive") else 0,
            )
        elapsed_ms = (time.perf_counter() - start) * 1000
        budget_ms = 50.0
        self.assertLess(
            elapsed_ms,
            budget_ms,
            f"extract_literals over {len(rules)} community rules took "
            f"{elapsed_ms:.1f}ms (budget {budget_ms}ms) — likely a quadratic "
            f"regression in the scanner",
        )

    def test_all_community_rules_do_not_crash(self):
        """Every community rule pattern parses without raising."""
        import json
        from pathlib import Path

        rules_path = Path(__file__).parent.parent / "packages" / "proxy" / "lumen_argus" / "rules" / "community.json"
        if not rules_path.exists():
            self.skipTest(f"community rules not found at {rules_path}")
        rules = json.loads(rules_path.read_text())["rules"]
        self.assertGreater(len(rules), 10, "expected many community rules")
        for rule in rules:
            pattern = rule.get("pattern", "")
            if not pattern:
                continue
            # Compile flags from rule (if any).
            flags = 0
            if rule.get("case_insensitive"):
                flags |= re.IGNORECASE
            # Should not raise — at worst returns [].
            try:
                result = extract_literals(pattern, flags)
            except Exception as exc:
                self.fail(f"extract_literals raised on rule pattern {pattern!r}: {exc!r}")
            # Result is always a list of (str, bool) tuples.
            self.assertIsInstance(result, list)
            for item in result:
                self.assertIsInstance(item, tuple)
                self.assertEqual(len(item), 2)
                self.assertIsInstance(item[0], str)
                self.assertIsInstance(item[1], bool)


if __name__ == "__main__":
    unittest.main()
