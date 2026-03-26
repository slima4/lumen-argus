"""Tests for rule overlap analysis (crossfire integration)."""

import json
import unittest
from unittest.mock import MagicMock, patch

from tests.helpers import StoreTestCase

_EMPTY_RESULTS = json.dumps({"duplicates": [], "subsets": [], "overlaps": [], "clusters": [], "quality": {}})


class TestHasCrossfireFlag(unittest.TestCase):
    """Test optional dependency detection."""

    def test_flag_is_boolean(self):
        from lumen_argus.rule_analysis import HAS_CROSSFIRE

        self.assertIsInstance(HAS_CROSSFIRE, bool)

    def test_run_analysis_returns_none_without_crossfire(self):
        """When crossfire is missing, run_analysis returns None."""
        with patch("lumen_argus.rule_analysis.HAS_CROSSFIRE", False):
            from lumen_argus.rule_analysis import run_analysis

            result = run_analysis(MagicMock())
            self.assertIsNone(result)


class TestRuleAnalysisRepository(StoreTestCase):
    """Test DB repository for analysis results."""

    def test_get_latest_empty(self):
        result = self.store.rule_analysis.get_latest_analysis()
        self.assertIsNone(result)

    def test_save_and_get(self):
        results_json = json.dumps(
            {
                "duplicates": [{"rule_a": "r1", "rule_b": "r2"}],
                "subsets": [],
                "overlaps": [],
                "clusters": [],
                "quality": {},
            }
        )
        self.store.rule_analysis.save_analysis(
            timestamp="2026-03-26T10:00:00Z",
            duration_s=1.5,
            total_rules=50,
            duplicates=1,
            subsets=0,
            overlaps=0,
            results_json=results_json,
        )
        cached = self.store.rule_analysis.get_latest_analysis()
        self.assertIsNotNone(cached)
        self.assertEqual(cached["timestamp"], "2026-03-26T10:00:00Z")
        self.assertAlmostEqual(cached["duration_s"], 1.5)
        self.assertEqual(cached["total_rules"], 50)
        self.assertEqual(cached["summary"]["duplicates"], 1)
        self.assertEqual(len(cached["duplicates"]), 1)
        self.assertEqual(cached["duplicates"][0]["rule_a"], "r1")

    def test_save_replaces_previous(self):
        """Only the latest analysis is kept."""
        self.store.rule_analysis.save_analysis("2026-01-01T00:00:00Z", 1.0, 10, 1, 0, 0, _EMPTY_RESULTS)
        self.store.rule_analysis.save_analysis("2026-02-01T00:00:00Z", 2.0, 20, 2, 1, 0, _EMPTY_RESULTS)
        cached = self.store.rule_analysis.get_latest_analysis()
        self.assertEqual(cached["timestamp"], "2026-02-01T00:00:00Z")
        self.assertEqual(cached["summary"]["duplicates"], 2)

    def test_dismiss_finding(self):
        self.store.rule_analysis.save_analysis("2026-01-01T00:00:00Z", 1.0, 10, 1, 0, 0, _EMPTY_RESULTS)
        added = self.store.rule_analysis.dismiss_finding("rule_a", "rule_b")
        self.assertTrue(added)

        dismissed = self.store.rule_analysis.get_dismissed_findings()
        self.assertEqual(len(dismissed), 1)
        self.assertEqual(dismissed[0], ["rule_a", "rule_b"])

    def test_dismiss_duplicate_ignored(self):
        self.store.rule_analysis.save_analysis("2026-01-01T00:00:00Z", 1.0, 10, 1, 0, 0, _EMPTY_RESULTS)
        self.store.rule_analysis.dismiss_finding("a", "b")
        added = self.store.rule_analysis.dismiss_finding("a", "b")
        self.assertFalse(added)
        self.assertEqual(len(self.store.rule_analysis.get_dismissed_findings()), 1)

    def test_dismiss_reverse_pair_ignored(self):
        self.store.rule_analysis.save_analysis("2026-01-01T00:00:00Z", 1.0, 10, 1, 0, 0, _EMPTY_RESULTS)
        self.store.rule_analysis.dismiss_finding("a", "b")
        added = self.store.rule_analysis.dismiss_finding("b", "a")
        self.assertFalse(added)

    def test_dismiss_no_analysis_returns_false(self):
        added = self.store.rule_analysis.dismiss_finding("a", "b")
        self.assertFalse(added)

    def test_dismissed_preserved_across_save(self):
        """Dismissed pairs survive re-analysis."""
        self.store.rule_analysis.save_analysis("2026-01-01T00:00:00Z", 1.0, 10, 1, 0, 0, _EMPTY_RESULTS)
        self.store.rule_analysis.dismiss_finding("a", "b")

        # Re-save (simulating re-analysis)
        self.store.rule_analysis.save_analysis("2026-02-01T00:00:00Z", 2.0, 20, 2, 1, 0, _EMPTY_RESULTS)
        dismissed = self.store.rule_analysis.get_dismissed_findings()
        self.assertEqual(len(dismissed), 1)
        self.assertEqual(dismissed[0], ["a", "b"])

    def test_clear_analysis(self):
        self.store.rule_analysis.save_analysis("2026-01-01T00:00:00Z", 1.0, 10, 1, 0, 0, _EMPTY_RESULTS)
        self.store.rule_analysis.clear_analysis()
        self.assertIsNone(self.store.rule_analysis.get_latest_analysis())

    def test_get_dismissed_empty(self):
        self.assertEqual(self.store.rule_analysis.get_dismissed_findings(), [])


class TestFilterDismissed(unittest.TestCase):
    """Test dismissed finding filtering."""

    def test_filters_matching_pairs(self):
        from lumen_argus.rule_analysis import filter_dismissed

        result = {
            "duplicates": [
                {"rule_a": "a", "rule_b": "b"},
                {"rule_a": "c", "rule_b": "d"},
            ],
            "subsets": [{"rule_a": "e", "rule_b": "f"}],
            "overlaps": [],
        }
        dismissed = [["a", "b"]]
        filtered = filter_dismissed(result, dismissed)
        self.assertEqual(len(filtered["duplicates"]), 1)
        self.assertEqual(filtered["duplicates"][0]["rule_a"], "c")
        self.assertEqual(len(filtered["subsets"]), 1)

    def test_filters_reverse_pair(self):
        from lumen_argus.rule_analysis import filter_dismissed

        result = {
            "duplicates": [{"rule_a": "a", "rule_b": "b"}],
            "subsets": [],
            "overlaps": [],
        }
        dismissed = [["b", "a"]]  # reverse order
        filtered = filter_dismissed(result, dismissed)
        self.assertEqual(len(filtered["duplicates"]), 0)

    def test_no_dismissed_passes_through(self):
        from lumen_argus.rule_analysis import filter_dismissed

        result = {
            "duplicates": [{"rule_a": "a", "rule_b": "b"}],
            "subsets": [],
            "overlaps": [],
        }
        filtered = filter_dismissed(result, [])
        self.assertEqual(len(filtered["duplicates"]), 1)


class TestTierPriority(unittest.TestCase):
    def test_community_highest(self):
        from lumen_argus.rule_analysis import _tier_priority

        self.assertGreater(_tier_priority("community"), _tier_priority("pro"))

    def test_custom_between(self):
        from lumen_argus.rule_analysis import _tier_priority

        self.assertGreater(_tier_priority("custom"), _tier_priority("pro"))
        self.assertLess(_tier_priority("custom"), _tier_priority("community"))

    def test_unknown_tier(self):
        from lumen_argus.rule_analysis import _tier_priority

        self.assertEqual(_tier_priority("unknown"), 50)


class TestRulesToCrossfire(unittest.TestCase):
    """Test conversion of DB rules to Crossfire format."""

    @unittest.skipUnless(
        __import__("importlib").util.find_spec("crossfire"),
        "crossfire not installed",
    )
    def test_converts_valid_rules(self):
        from lumen_argus.rule_analysis import _rules_to_crossfire

        db_rules = [
            {
                "name": "aws_key",
                "pattern": "AKIA[0-9A-Z]{16}",
                "tier": "community",
                "detector": "secrets",
                "severity": "critical",
            },
            {
                "name": "email",
                "pattern": r"[\w.+-]+@[\w-]+\.[\w.]+",
                "tier": "community",
                "detector": "pii",
                "severity": "medium",
            },
        ]
        cf_rules, lookup = _rules_to_crossfire(db_rules)
        self.assertEqual(len(cf_rules), 2)
        self.assertEqual(cf_rules[0].name, "aws_key")
        self.assertIn("aws_key", lookup)

    @unittest.skipUnless(
        __import__("importlib").util.find_spec("crossfire"),
        "crossfire not installed",
    )
    def test_skips_invalid_pattern(self):
        from lumen_argus.rule_analysis import _rules_to_crossfire

        db_rules = [
            {"name": "bad", "pattern": "[invalid(", "tier": "community"},
            {"name": "good", "pattern": "abc", "tier": "community", "detector": "secrets"},
        ]
        cf_rules, lookup = _rules_to_crossfire(db_rules)
        self.assertEqual(len(cf_rules), 1)
        self.assertEqual(cf_rules[0].name, "good")

    @unittest.skipUnless(
        __import__("importlib").util.find_spec("crossfire"),
        "crossfire not installed",
    )
    def test_skips_empty_name_or_pattern(self):
        from lumen_argus.rule_analysis import _rules_to_crossfire

        db_rules = [
            {"name": "", "pattern": "abc"},
            {"name": "good", "pattern": ""},
        ]
        cf_rules, _ = _rules_to_crossfire(db_rules)
        self.assertEqual(len(cf_rules), 0)


class TestAPIEndpoints(StoreTestCase):
    """Test rule analysis API handlers."""

    def test_get_without_crossfire(self):
        from lumen_argus.dashboard.api import _handle_rule_analysis_get

        with patch("lumen_argus.rule_analysis.HAS_CROSSFIRE", False):
            status, body = _handle_rule_analysis_get(self.store)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertFalse(data["available"])
        self.assertIn("crossfire", data["message"])

    def test_get_no_results(self):
        from lumen_argus.dashboard.api import _handle_rule_analysis_get

        with patch("lumen_argus.rule_analysis.HAS_CROSSFIRE", True):
            status, body = _handle_rule_analysis_get(self.store)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["available"])
        self.assertFalse(data["has_results"])

    def test_get_with_results(self):
        from lumen_argus.dashboard.api import _handle_rule_analysis_get

        self.store.rule_analysis.save_analysis(
            "2026-03-26T10:00:00Z",
            1.5,
            50,
            1,
            2,
            3,
            json.dumps(
                {
                    "duplicates": [{"rule_a": "a", "rule_b": "b"}],
                    "subsets": [],
                    "overlaps": [],
                    "clusters": [],
                    "quality": {},
                }
            ),
        )
        with patch("lumen_argus.rule_analysis.HAS_CROSSFIRE", True):
            status, body = _handle_rule_analysis_get(self.store)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["available"])
        self.assertTrue(data["has_results"])
        self.assertEqual(data["summary"]["duplicates"], 1)

    def test_trigger_without_crossfire(self):
        from lumen_argus.dashboard.api import _handle_rule_analysis_trigger

        with patch("lumen_argus.rule_analysis.HAS_CROSSFIRE", False):
            status, body = _handle_rule_analysis_trigger(b"{}", self.store, None)
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertEqual(data["error"], "crossfire_not_installed")

    def test_trigger_starts_background(self):
        from lumen_argus.dashboard.api import _handle_rule_analysis_trigger

        with (
            patch("lumen_argus.rule_analysis.HAS_CROSSFIRE", True),
            patch("lumen_argus.rule_analysis.run_analysis_in_background") as mock_run,
        ):
            status, body = _handle_rule_analysis_trigger(b"{}", self.store, None)
        self.assertEqual(status, 202)
        data = json.loads(body)
        self.assertEqual(data["status"], "started")
        mock_run.assert_called_once()

    def test_dismiss_missing_fields(self):
        from lumen_argus.dashboard.api import _handle_rule_analysis_dismiss

        status, body = _handle_rule_analysis_dismiss(json.dumps({"rule_a": "a"}).encode(), self.store)
        self.assertEqual(status, 400)

    def test_dismiss_success(self):
        from lumen_argus.dashboard.api import _handle_rule_analysis_dismiss

        self.store.rule_analysis.save_analysis("2026-01-01T00:00:00Z", 1.0, 10, 1, 0, 0, _EMPTY_RESULTS)
        status, body = _handle_rule_analysis_dismiss(json.dumps({"rule_a": "a", "rule_b": "b"}).encode(), self.store)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["status"], "dismissed")

    def test_get_no_store(self):
        from lumen_argus.dashboard.api import _handle_rule_analysis_get

        with patch("lumen_argus.rule_analysis.HAS_CROSSFIRE", True):
            status, body = _handle_rule_analysis_get(None)
        self.assertEqual(status, 500)


class TestRunAnalysisEmptyRules(StoreTestCase):
    """Test analysis with no rules."""

    @unittest.skipUnless(
        __import__("importlib").util.find_spec("crossfire"),
        "crossfire not installed",
    )
    def test_empty_rules_returns_clean(self):
        from lumen_argus.rule_analysis import run_analysis

        result = run_analysis(self.store)
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["total_rules"], 0)
        self.assertEqual(result["summary"]["duplicates"], 0)


class TestQualityDataRoundTrip(StoreTestCase):
    """Test that quality data is saved and loaded through DB."""

    def test_quality_round_trips_through_db(self):
        quality = {
            "broad_patterns": [{"name": "generic_secret", "overlap_count": 12, "source": "community"}],
            "low_specificity": [],
            "fully_redundant": [{"name": "old_rule", "unique_coverage": 0, "source": "custom"}],
            "summary": {"total_rules": 50, "broad_patterns": 1, "low_specificity": 0, "fully_redundant": 1},
        }
        results_json = json.dumps(
            {
                "duplicates": [],
                "subsets": [],
                "overlaps": [],
                "clusters": [],
                "quality": quality,
            }
        )
        self.store.rule_analysis.save_analysis("2026-03-26T10:00:00Z", 1.5, 50, 0, 0, 0, results_json)
        cached = self.store.rule_analysis.get_latest_analysis()
        self.assertEqual(cached["quality"], quality)
        self.assertEqual(cached["quality"]["broad_patterns"][0]["name"], "generic_secret")
        self.assertEqual(cached["quality"]["summary"]["fully_redundant"], 1)

    def test_quality_in_filtered_results(self):
        quality = {"broad_patterns": [], "summary": {"total_rules": 5}}
        results_json = json.dumps(
            {
                "duplicates": [{"rule_a": "a", "rule_b": "b"}],
                "subsets": [],
                "overlaps": [],
                "clusters": [],
                "quality": quality,
            }
        )
        self.store.rule_analysis.save_analysis("2026-03-26T10:00:00Z", 1.0, 5, 1, 0, 0, results_json)
        self.store.rule_analysis.dismiss_finding("a", "b")
        filtered = self.store.rule_analysis.get_latest_analysis_filtered()
        self.assertEqual(filtered["quality"], quality)
        self.assertEqual(len(filtered["duplicates"]), 0)


class TestQualityToDict(unittest.TestCase):
    """Test quality report serialization."""

    @unittest.skipUnless(
        __import__("importlib").util.find_spec("crossfire"),
        "crossfire not installed",
    )
    def test_converts_quality_report(self):
        from crossfire.quality import QualityReport, RuleQuality
        from lumen_argus.rule_analysis import _quality_to_dict

        rq = RuleQuality(
            name="test_rule",
            source="community",
            specificity=0.95,
            false_positive_potential=3,
            pattern_complexity=12,
            unique_coverage=45,
            is_broad=True,
            overlap_count=7,
            flags=["Broad pattern"],
        )
        report = QualityReport(
            rules=[rq],
            broad_patterns=[rq],
            low_specificity=[],
            fully_redundant=[],
            summary={"total_rules": 1, "broad_patterns": 1},
        )
        result = _quality_to_dict(report)
        self.assertEqual(len(result["broad_patterns"]), 1)
        self.assertEqual(result["broad_patterns"][0]["name"], "test_rule")
        self.assertEqual(result["broad_patterns"][0]["specificity"], 0.95)
        self.assertEqual(result["summary"]["broad_patterns"], 1)
        self.assertEqual(result["low_specificity"], [])
        self.assertEqual(result["fully_redundant"], [])


if __name__ == "__main__":
    unittest.main()
