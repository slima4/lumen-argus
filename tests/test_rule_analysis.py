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
        cf_rules, _lookup = _rules_to_crossfire(db_rules)
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
        from lumen_argus.dashboard.api_rules import handle_rule_analysis_get

        with patch("lumen_argus.rule_analysis.HAS_CROSSFIRE", False):
            status, body = handle_rule_analysis_get(self.store)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertFalse(data["available"])
        self.assertIn("crossfire", data["message"])

    def test_get_no_results(self):
        from lumen_argus.dashboard.api_rules import handle_rule_analysis_get

        with patch("lumen_argus.rule_analysis.HAS_CROSSFIRE", True):
            status, body = handle_rule_analysis_get(self.store)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["available"])
        self.assertFalse(data["has_results"])

    def test_get_with_results(self):
        from lumen_argus.dashboard.api_rules import handle_rule_analysis_get

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
            status, body = handle_rule_analysis_get(self.store)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["available"])
        self.assertTrue(data["has_results"])
        self.assertEqual(data["summary"]["duplicates"], 1)

    def test_trigger_without_crossfire(self):
        from lumen_argus.dashboard.api_rules import handle_rule_analysis_trigger

        with patch("lumen_argus.rule_analysis.HAS_CROSSFIRE", False):
            status, body = handle_rule_analysis_trigger(b"{}", self.store, None)
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertEqual(data["error"], "crossfire_not_installed")

    def test_trigger_starts_background(self):
        from lumen_argus.dashboard.api_rules import handle_rule_analysis_trigger

        with (
            patch("lumen_argus.rule_analysis.HAS_CROSSFIRE", True),
            patch("lumen_argus.rule_analysis.run_analysis_in_background") as mock_run,
        ):
            status, body = handle_rule_analysis_trigger(b"{}", self.store, None)
        self.assertEqual(status, 202)
        data = json.loads(body)
        self.assertEqual(data["status"], "started")
        mock_run.assert_called_once()

    def test_dismiss_missing_fields(self):
        from lumen_argus.dashboard.api_rules import handle_rule_analysis_dismiss

        status, _body = handle_rule_analysis_dismiss(json.dumps({"rule_a": "a"}).encode(), self.store)
        self.assertEqual(status, 400)

    def test_dismiss_success(self):
        from lumen_argus.dashboard.api_rules import handle_rule_analysis_dismiss

        self.store.rule_analysis.save_analysis("2026-01-01T00:00:00Z", 1.0, 10, 1, 0, 0, _EMPTY_RESULTS)
        status, body = handle_rule_analysis_dismiss(json.dumps({"rule_a": "a", "rule_b": "b"}).encode(), self.store)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["status"], "dismissed")

    def test_get_no_store(self):
        from lumen_argus.dashboard.api import handle_community_api

        with patch("lumen_argus.rule_analysis.HAS_CROSSFIRE", True):
            status, _body = handle_community_api("/api/v1/rules/analysis", "GET", b"", None)
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


class _RuleAnalysisStateTest(unittest.TestCase):
    """Base class that resets the module-level analysis state between tests.

    The rule_analysis module uses module globals (_analysis_status, _analysis_log_lines)
    so two tests touching them without cleanup would race against each other in the
    same process. We snapshot+restore in setUp/tearDown.
    """

    def setUp(self):
        from lumen_argus import rule_analysis as ra

        self._ra = ra
        with ra._analysis_lock:
            self._saved_status = dict(ra._analysis_status)
            self._saved_log = list(ra._analysis_log_lines)
            ra._analysis_status.update(
                running=False,
                phase="",
                progress="",
                started_at="",
                last_phase_change_at=0.0,
                error=None,
            )
            ra._analysis_log_lines.clear()

    def tearDown(self):
        with self._ra._analysis_lock:
            self._ra._analysis_status.clear()
            self._ra._analysis_status.update(self._saved_status)
            self._ra._analysis_log_lines.clear()
            self._ra._analysis_log_lines.extend(self._saved_log)


class TestPhaseContext(_RuleAnalysisStateTest):
    """The _Phase context manager handles success and failure paths."""

    def test_phase_success_updates_status_and_clears(self):
        from lumen_argus.rule_analysis import (
            PHASE_GENERATING,
            _Phase,
            get_analysis_status,
        )

        with _Phase(PHASE_GENERATING, "test progress") as phase:
            mid = get_analysis_status()
            self.assertTrue(mid["running"])
            self.assertEqual(mid["phase"], PHASE_GENERATING)
            self.assertEqual(mid["progress"], "test progress")
            self.assertGreater(phase.start_monotonic, 0.0)

        # After exit, status still reflects the phase but no error.
        post = get_analysis_status()
        self.assertIsNone(post["error"])

    def test_phase_failure_records_structured_error(self):
        from lumen_argus.rule_analysis import (
            PHASE_EVALUATING,
            _Phase,
            get_analysis_status,
        )

        with self.assertRaises(ValueError):
            with _Phase(PHASE_EVALUATING, "evaluating..."):
                raise ValueError("simulated boom")

        status = get_analysis_status()
        self.assertFalse(status["running"])
        self.assertIsNotNone(status["error"])
        self.assertEqual(status["error"]["type"], "ValueError")
        self.assertEqual(status["error"]["message"], "simulated boom")
        self.assertEqual(status["error"]["phase"], PHASE_EVALUATING)

    def test_phase_does_not_swallow_keyboard_interrupt(self):
        from lumen_argus.rule_analysis import PHASE_CLASSIFYING, _Phase, get_analysis_status

        with self.assertRaises(KeyboardInterrupt):
            with _Phase(PHASE_CLASSIFYING):
                raise KeyboardInterrupt()

        status = get_analysis_status()
        # KeyboardInterrupt is not captured into the error field.
        self.assertIsNone(status["error"])

    def test_phase_emits_grepable_log_markers(self):
        import logging

        from lumen_argus.rule_analysis import PHASE_GENERATING, _Phase

        captured: list[str] = []

        class _Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                captured.append(record.getMessage())

        handler = _Capture()
        handler.setLevel(logging.DEBUG)
        logger = logging.getLogger("argus.rule_analysis")
        prior_level = logger.level
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        try:
            with _Phase(PHASE_GENERATING):
                pass
        finally:
            logger.removeHandler(handler)
            logger.setLevel(prior_level)

        markers = [m for m in captured if m.startswith("phase=")]
        self.assertTrue(
            any(m == "phase=generating start" for m in markers),
            f"missing start marker; captured={captured}",
        )
        self.assertTrue(
            any(m.startswith("phase=generating end duration=") for m in markers),
            f"missing end marker; captured={captured}",
        )


class TestStatusErrorReporting(_RuleAnalysisStateTest):
    """Structured error field on the status dict."""

    def test_set_error_clears_running_and_populates_error(self):
        from lumen_argus.rule_analysis import _set_error, get_analysis_status

        _set_error("RuntimeError", "kapow", "evaluating")
        status = get_analysis_status()
        self.assertFalse(status["running"])
        self.assertEqual(status["phase"], "failed")
        self.assertEqual(status["error"]["type"], "RuntimeError")
        self.assertEqual(status["error"]["message"], "kapow")
        self.assertEqual(status["error"]["phase"], "evaluating")

    def test_status_dict_does_not_leak_internal_heartbeat(self):
        from lumen_argus.rule_analysis import _set_status, get_analysis_status

        _set_status(True, "generating", "go")
        status = get_analysis_status()
        # last_phase_change_at is internal — never serialized to clients.
        self.assertNotIn("last_phase_change_at", status)


class TestWatchdog(_RuleAnalysisStateTest):
    """The watchdog thread enforces total and per-phase deadlines."""

    def test_watchdog_total_deadline_fires(self):
        import threading

        from lumen_argus.rule_analysis import (
            PHASE_GENERATING,
            _set_status,
            _watchdog,
            get_analysis_status,
        )

        # Make the worker look like it's in 'generating' phase.
        _set_status(True, PHASE_GENERATING, "stuck")

        worker_done = threading.Event()
        # Total deadline very short, phase deadline disabled. Note: the
        # watchdog's poll_interval is floored at 1.0s, so the first deadline
        # check fires ~1s after start regardless of how small total_s is —
        # the sub-second value just guarantees the check trips on its first
        # pass. Don't expect a sub-second fire.
        watchdog = threading.Thread(
            target=_watchdog,
            args=(threading.current_thread(), worker_done, 0.3, 0.0),
            daemon=True,
        )
        watchdog.start()
        watchdog.join(timeout=5.0)
        self.assertFalse(watchdog.is_alive(), "watchdog thread should have exited")

        status = get_analysis_status()
        self.assertFalse(status["running"])
        self.assertEqual(status["phase"], "failed")
        self.assertIsNotNone(status["error"])
        self.assertEqual(status["error"]["type"], "WatchdogTotalTimeout")
        self.assertIn("total deadline", status["error"]["message"])

    def test_watchdog_phase_deadline_fires(self):
        import threading
        import time as _time

        from lumen_argus import rule_analysis as ra

        # Manually advance the heartbeat backwards so per-phase elapsed
        # exceeds the threshold immediately.
        ra._set_status(True, ra.PHASE_EVALUATING, "stuck in eval")
        with ra._analysis_lock:
            ra._analysis_status["last_phase_change_at"] = _time.monotonic() - 100.0

        worker_done = threading.Event()
        # Same poll-interval-floor caveat as test_watchdog_total_deadline_fires:
        # the first check fires ~1s after start regardless of phase_s=0.5.
        watchdog = threading.Thread(
            target=ra._watchdog,
            args=(threading.current_thread(), worker_done, 0.0, 0.5),
            daemon=True,
        )
        watchdog.start()
        watchdog.join(timeout=5.0)
        self.assertFalse(watchdog.is_alive())

        status = ra.get_analysis_status()
        self.assertEqual(status["error"]["type"], "WatchdogPhaseTimeout")
        self.assertEqual(status["error"]["phase"], ra.PHASE_EVALUATING)
        self.assertIn("evaluating", status["error"]["message"])

    def test_watchdog_exits_cleanly_when_worker_finishes(self):
        import threading

        from lumen_argus.rule_analysis import _watchdog, get_analysis_status

        worker_done = threading.Event()
        worker_done.set()  # already finished
        watchdog = threading.Thread(
            target=_watchdog,
            args=(threading.current_thread(), worker_done, 60.0, 60.0),
            daemon=True,
        )
        watchdog.start()
        watchdog.join(timeout=2.0)
        self.assertFalse(watchdog.is_alive())

        status = get_analysis_status()
        # Watchdog must not falsely report an error when the worker finished.
        self.assertIsNone(status["error"])

    def test_watchdog_with_both_deadlines_disabled_never_fires(self):
        """Both total_s=0 and phase_s=0 → watchdog polls but never flags an error."""
        import threading

        from lumen_argus.rule_analysis import (
            PHASE_GENERATING,
            _set_status,
            _watchdog,
            get_analysis_status,
        )

        # Put the worker in a phase that would normally trip a phase deadline
        # (heartbeat pushed 100s into the past). With phase_s=0 the check is
        # suppressed and the watchdog must exit cleanly once worker_done fires.
        _set_status(True, PHASE_GENERATING, "stuck but not timed")
        with self._ra._analysis_lock:
            import time as _time

            self._ra._analysis_status["last_phase_change_at"] = _time.monotonic() - 100.0

        worker_done = threading.Event()
        watchdog = threading.Thread(
            target=_watchdog,
            args=(threading.current_thread(), worker_done, 0.0, 0.0),
            daemon=True,
        )
        watchdog.start()
        # Give the watchdog a couple of poll cycles to prove it doesn't fire
        # anything, then signal the worker finished.
        import time as _time

        _time.sleep(2.2)
        self.assertTrue(watchdog.is_alive(), "watchdog should still be polling")
        worker_done.set()
        watchdog.join(timeout=3.0)
        self.assertFalse(watchdog.is_alive())

        status = get_analysis_status()
        self.assertIsNone(status["error"], "no error should be recorded when both deadlines are disabled")

    def test_run_analysis_does_not_spawn_watchdog_when_both_disabled(self):
        """The call-site guard skips the watchdog thread entirely for total=phase=0."""
        import threading
        from dataclasses import dataclass

        from lumen_argus.rule_analysis import run_analysis_in_background

        @dataclass
        class _RA:
            samples: int = 5
            threshold: float = 0.8
            seed: int = 1
            watchdog_total_s: float = 0.0
            watchdog_phase_s: float = 0.0

        @dataclass
        class _Config:
            rule_analysis: _RA

        class _NoopRules:
            @staticmethod
            def get_active():
                return []

        class _NoopRuleAnalysis:
            @staticmethod
            def save_analysis(**kwargs):
                pass

            @staticmethod
            def get_dismissed_findings():
                return []

        class _NoopStore:
            rules = _NoopRules()
            rule_analysis = _NoopRuleAnalysis()

        config = _Config(rule_analysis=_RA())
        before = {t.name for t in threading.enumerate()}
        started = run_analysis_in_background(
            _NoopStore(),
            config=config,
            thread_name="rule-analysis-test-guard",
        )
        # Without crossfire installed, run_analysis_in_background short-circuits
        # to False — skip the thread assertion in that case.
        if not started:
            self.skipTest("crossfire not installed — background analysis disabled")

        # Wait for the worker to settle (it has no rules, so it exits fast),
        # then snapshot the new threads. The -watchdog companion must not be
        # in there.
        import time as _time

        for _ in range(20):
            _time.sleep(0.05)
            new = {t.name for t in threading.enumerate()} - before
            if "rule-analysis-test-guard" not in new:
                break
        new = {t.name for t in threading.enumerate()} - before
        self.assertNotIn(
            "rule-analysis-test-guard-watchdog",
            new,
            "watchdog thread should not be spawned when both deadlines are 0",
        )


class TestDoAnalysisSequential(StoreTestCase):
    """End-to-end sanity check that _do_analysis runs in sequential mode.

    Pins the regression: no subprocesses are spawned even when crossfire-rules
    is installed and there are >= 8 rules. This is the call-site fix for the
    fork-from-thread hang in crossfire 0.2.0.
    """

    @unittest.skipUnless(
        __import__("importlib").util.find_spec("crossfire"),
        "crossfire not installed",
    )
    def test_no_subprocesses_spawned_during_analysis(self):
        """Guard rail against re-introducing multiprocessing at any phase.

        The previous version of this test compared
        `multiprocessing.active_children()` before and after `_do_analysis`,
        which is racy: workers that spawn and finish before the "after"
        snapshot are invisible. That's exactly how we shipped a bug where
        `Evaluator(workers=0)` was spawning ProcessPoolExecutor children on
        dev machines (tests passed) but crashing the PyInstaller tray-app
        bundle with BrokenProcessPool (no freeze_support at the entry point).

        This version monkey-patches `ProcessPoolExecutor.__init__` and the
        `multiprocessing.Process` constructor to fail loudly the moment
        anything tries to instantiate them, so even transient spawns fail
        the test.
        """
        import concurrent.futures
        import multiprocessing
        from unittest.mock import patch

        from lumen_argus.rule_analysis import _do_analysis

        # Seed enough rules to trip any heuristic that auto-parallelizes
        # above a threshold (crossfire uses >= 2 rules and >= 50 corpus
        # strings as its gate).
        for i in range(12):
            self.store.rules.create(
                {
                    "name": f"test_rule_{i}",
                    "pattern": rf"[a-z]{{{i + 3}}}",
                    "detector": "secrets",
                    "severity": "high",
                    "action": "alert",
                    "enabled": True,
                    "tier": "custom",
                    "description": "",
                    "tags": [],
                }
            )

        spawn_attempts: list[str] = []
        real_ppe_init = concurrent.futures.ProcessPoolExecutor.__init__
        real_process_init = multiprocessing.Process.__init__

        def _blocked_ppe(self, *args, **kwargs):
            spawn_attempts.append("ProcessPoolExecutor")
            raise AssertionError(
                "rule analysis tried to instantiate a ProcessPoolExecutor — "
                "must stay single-threaded (PyInstaller tray-app compatibility)"
            )

        def _blocked_process(self, *args, **kwargs):
            spawn_attempts.append("multiprocessing.Process")
            raise AssertionError(
                "rule analysis tried to start a multiprocessing.Process — "
                "must stay single-threaded (PyInstaller tray-app compatibility)"
            )

        with (
            patch.object(concurrent.futures.ProcessPoolExecutor, "__init__", _blocked_ppe),
            patch.object(multiprocessing.Process, "__init__", _blocked_process),
        ):
            try:
                result = _do_analysis(self.store, samples=20, threshold=0.8, seed=42)
            finally:
                concurrent.futures.ProcessPoolExecutor.__init__ = real_ppe_init
                multiprocessing.Process.__init__ = real_process_init

        self.assertEqual(
            spawn_attempts,
            [],
            f"rule analysis spawned workers: {spawn_attempts}",
        )
        self.assertIsNotNone(result, "analysis should have produced a result")


if __name__ == "__main__":
    unittest.main()
