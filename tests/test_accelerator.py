"""Tests for the Aho-Corasick pre-filter accelerator."""

import re
import unittest

from lumen_argus.detectors.accelerator import AhoCorasickAccelerator, _HAS_AHOCORASICK


def _make_rule(name, pattern, detector="secrets", severity="high", action="alert"):
    """Create a compiled rule dict matching RulesDetector format."""
    return {
        "name": name,
        "compiled": re.compile(pattern),
        "detector": detector,
        "severity": severity,
        "action": action,
        "validator": None,
        "hit_count": 0,
    }


@unittest.skipUnless(_HAS_AHOCORASICK, "pyahocorasick not installed")
class TestAhoCorasickAccelerator(unittest.TestCase):
    """Test pre-filter correctness."""

    def test_filter_narrows_candidates(self):
        """Only rules whose literals appear in text are candidates."""
        rules = [
            _make_rule("aws_key", r"AKIA[0-9A-Z]{16}"),
            _make_rule("stripe_key", r"sk_live_[a-zA-Z0-9]{24}"),
            _make_rule("github_token", r"ghp_[A-Za-z0-9]{36}"),
        ]
        acc = AhoCorasickAccelerator()
        acc.build(rules)

        candidates = acc.filter("my key is AKIA1234567890ABCDEF and nothing else")
        self.assertIn(0, candidates)  # aws_key
        self.assertNotIn(1, candidates)  # stripe_key
        self.assertNotIn(2, candidates)  # github_token

    def test_fallback_rules_always_included(self):
        """Rules without extractable literals are always candidates."""
        rules = [
            _make_rule("aws_key", r"AKIA[0-9A-Z]{16}"),
            _make_rule("generic", r"[A-Z]{30}"),  # no literal
        ]
        acc = AhoCorasickAccelerator()
        acc.build(rules)

        # Even though text has no AKIA, the fallback rule is still a candidate
        candidates = acc.filter("hello world")
        self.assertNotIn(0, candidates)  # aws_key not a candidate
        self.assertIn(1, candidates)  # generic is always a candidate

    def test_case_insensitive_matching(self):
        """Case-insensitive rules match regardless of text case."""
        rules = [
            _make_rule("ci_rule", r"(?i)password\s*[:=]"),
        ]
        acc = AhoCorasickAccelerator()
        acc.build(rules)

        candidates = acc.filter("my PASSWORD = secret123")
        self.assertIn(0, candidates)

    def test_empty_rules(self):
        """Empty rule list produces empty candidates."""
        acc = AhoCorasickAccelerator()
        acc.build([])
        candidates = acc.filter("any text")
        self.assertEqual(len(candidates), 0)

    def test_multiple_rules_same_literal(self):
        """Multiple rules sharing a literal prefix are all candidates."""
        rules = [
            _make_rule("sk_live", r"sk_live_[a-zA-Z0-9]{24}"),
            _make_rule("sk_test", r"sk_test_[a-zA-Z0-9]{24}"),
        ]
        acc = AhoCorasickAccelerator()
        acc.build(rules)

        candidates = acc.filter("found sk_live_abc123 and sk_test_xyz456")
        self.assertIn(0, candidates)
        self.assertIn(1, candidates)

    def test_filter_ratio(self):
        """Filter ratio correctly reports elimination percentage."""
        rules = [_make_rule("r%d" % i, r"unique_prefix_%d_[A-Z]+" % i) for i in range(100)]
        acc = AhoCorasickAccelerator()
        acc.build(rules)

        candidates = acc.filter("text with unique_prefix_5_MATCH")
        ratio = acc.filter_ratio(candidates)
        self.assertGreater(ratio, 0.9)  # >90% filtered

    def test_stats(self):
        """Stats report correct counts."""
        rules = [
            _make_rule("with_lit", r"sk_live_[a-z]+"),
            _make_rule("no_lit", r"[A-Z]{20}"),
        ]
        acc = AhoCorasickAccelerator()
        acc.build(rules)

        stats = acc.stats
        self.assertEqual(stats["total_rules"], 2)
        self.assertEqual(stats["rules_with_literals"], 1)
        self.assertEqual(stats["fallback_rules"], 1)
        self.assertTrue(stats["available"])

    def test_no_false_negatives(self):
        """Pre-filter must never exclude a rule that would actually match.

        This is the critical correctness property — lossless filtering.
        """
        rules = [
            _make_rule("aws_key", r"AKIA[0-9A-Z]{16}"),
            _make_rule("stripe_key", r"sk_live_[a-zA-Z0-9]{24}"),
            _make_rule("email", r"[a-z]+@example\.com"),
        ]
        acc = AhoCorasickAccelerator()
        acc.build(rules)

        # Text that matches aws_key — must be in candidates
        text_aws = "key=AKIAIOSFODNN7EXAMPLE"
        candidates = acc.filter(text_aws)
        self.assertIn(0, candidates)

        # Text that matches stripe — must be in candidates
        text_stripe = "sk_live_xxxtestvaluehere"
        candidates = acc.filter(text_stripe)
        self.assertIn(1, candidates)


class TestAcceleratorFallback(unittest.TestCase):
    """Test behavior when pyahocorasick is not available."""

    def test_returns_all_rules_when_disabled(self):
        """When accelerator is unavailable, all rules are candidates."""
        acc = AhoCorasickAccelerator()
        acc._available = False
        acc._rule_count = 5
        acc._fallback_indices = set(range(5))

        candidates = acc.filter("any text")
        self.assertEqual(candidates, {0, 1, 2, 3, 4})


if __name__ == "__main__":
    unittest.main()
