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


if __name__ == "__main__":
    unittest.main()
