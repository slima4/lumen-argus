"""Tests for the agent relay's upstream-health rolling-window tracker."""

import unittest

from lumen_argus_agent.upstream_health import UpstreamHealth


class TestUpstreamHealth(unittest.TestCase):
    """Rolling-window state machine for the /health ``upstream`` field."""

    def test_empty_window_is_healthy(self):
        h = UpstreamHealth()
        self.assertEqual(h.state(), "healthy")

    def test_all_success_is_healthy(self):
        h = UpstreamHealth(window=5)
        for _ in range(5):
            h.record(True)
        self.assertEqual(h.state(), "healthy")

    def test_all_failure_is_unhealthy(self):
        h = UpstreamHealth(window=5)
        for _ in range(5):
            h.record(False)
        self.assertEqual(h.state(), "unhealthy")

    def test_mixed_is_degraded(self):
        h = UpstreamHealth(window=5)
        h.record(True)
        h.record(False)
        h.record(True)
        self.assertEqual(h.state(), "degraded")

    def test_window_evicts_old_outcomes(self):
        h = UpstreamHealth(window=3)
        h.record(False)
        h.record(False)
        h.record(False)
        self.assertEqual(h.state(), "unhealthy")
        h.record(True)
        h.record(True)
        h.record(True)
        self.assertEqual(h.state(), "healthy")

    def test_single_failure_after_successes_is_degraded(self):
        h = UpstreamHealth(window=10)
        for _ in range(9):
            h.record(True)
        h.record(False)
        self.assertEqual(h.state(), "degraded")


if __name__ == "__main__":
    unittest.main()
