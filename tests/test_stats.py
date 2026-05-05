"""Tests for session statistics."""

import unittest

from lumen_argus.models import Finding, ScanResult
from lumen_argus.stats import SessionStats


class TestSessionStats(unittest.TestCase):
    def test_empty_summary(self):
        stats = SessionStats()
        s = stats.summary()
        self.assertEqual(s["total_requests"], 0)
        self.assertEqual(s["avg_scan_ms"], 0)

    def test_record_pass(self):
        stats = SessionStats()
        stats.record("anthropic", 1000, ScanResult(action="pass", scan_duration_ms=5.0))
        s = stats.summary()
        self.assertEqual(s["total_requests"], 1)
        self.assertEqual(s["actions"]["pass"], 1)
        self.assertEqual(s["providers"]["anthropic"], 1)
        self.assertEqual(s["total_bytes_scanned"], 1000)

    def test_record_with_findings(self):
        stats = SessionStats()
        result = ScanResult(
            action="alert",
            scan_duration_ms=10.0,
            findings=[
                Finding(
                    detector="secrets",
                    type="aws_access_key",
                    severity="critical",
                    location="msg[0]",
                    value_preview="AKIA****",
                    matched_value="x",
                ),
                Finding(
                    detector="pii",
                    type="email",
                    severity="warning",
                    location="msg[1]",
                    value_preview="john****",
                    matched_value="x",
                ),
            ],
        )
        stats.record("anthropic", 5000, result)
        s = stats.summary()
        self.assertEqual(s["actions"]["alert"], 1)
        self.assertEqual(s["finding_types"]["aws_access_key"], 1)
        self.assertEqual(s["finding_types"]["email"], 1)

    def test_multiple_requests(self):
        stats = SessionStats()
        stats.record("anthropic", 1000, ScanResult(action="pass", scan_duration_ms=5.0))
        stats.record("openai", 2000, ScanResult(action="alert", scan_duration_ms=15.0))
        stats.record("anthropic", 3000, ScanResult(action="block", scan_duration_ms=8.0))

        s = stats.summary()
        self.assertEqual(s["total_requests"], 3)
        self.assertEqual(s["total_bytes_scanned"], 6000)
        self.assertEqual(s["providers"]["anthropic"], 2)
        self.assertEqual(s["providers"]["openai"], 1)
        self.assertEqual(s["actions"]["pass"], 1)
        self.assertEqual(s["actions"]["alert"], 1)
        self.assertEqual(s["actions"]["block"], 1)
        self.assertGreater(s["avg_scan_ms"], 0)
        self.assertGreater(s["p95_scan_ms"], 0)

    def test_scan_timing_stats(self):
        stats = SessionStats()
        for ms in [5.0, 10.0, 15.0, 20.0, 25.0]:
            stats.record("anthropic", 100, ScanResult(action="pass", scan_duration_ms=ms))

        s = stats.summary()
        self.assertAlmostEqual(s["avg_scan_ms"], 15.0)
        self.assertGreaterEqual(s["p95_scan_ms"], 20.0)


class TestPrometheusMetrics(unittest.TestCase):
    def test_empty_metrics(self):
        stats = SessionStats()
        output = stats.prometheus_metrics()
        self.assertIn("lumen_argus_requests_total", output)
        self.assertIn("lumen_argus_bytes_scanned_total 0", output)
        # Duration sum/count must always be present (Prometheus spec)
        self.assertIn("lumen_argus_scan_duration_seconds_sum", output)
        self.assertIn("lumen_argus_scan_duration_seconds_count 0", output)

    def test_metrics_after_requests(self):
        stats = SessionStats()
        stats.record("anthropic", 1000, ScanResult(action="pass", scan_duration_ms=5.0))
        stats.record(
            "anthropic",
            2000,
            ScanResult(
                action="block",
                scan_duration_ms=10.0,
                findings=[
                    Finding(
                        detector="secrets",
                        type="aws_access_key",
                        severity="critical",
                        location="msg",
                        value_preview="****",
                        matched_value="x",
                    )
                ],
            ),
        )
        output = stats.prometheus_metrics()
        self.assertIn('lumen_argus_requests_total{action="pass"} 1', output)
        self.assertIn('lumen_argus_requests_total{action="block"} 1', output)
        self.assertIn("lumen_argus_bytes_scanned_total 3000", output)
        self.assertIn('lumen_argus_findings_total{type="aws_access_key"} 1', output)
        self.assertIn('lumen_argus_provider_requests_total{provider="anthropic"} 2', output)
        self.assertIn("lumen_argus_scan_duration_seconds_count 2", output)

    def test_metrics_content_type_header(self):
        """Prometheus exposition format uses text/plain with version."""
        output = SessionStats().prometheus_metrics()
        # Should be valid text, no binary
        self.assertIsInstance(output, str)

    def test_fingerprint_gauge_emitted_when_stats_provided(self):
        output = SessionStats().prometheus_metrics(fingerprint_stats={"conversations": 42, "total_hashes": 137})
        self.assertIn("lumen_argus_fingerprint_conversations 42", output)
        self.assertIn("lumen_argus_fingerprint_hashes 137", output)
        self.assertIn("# TYPE lumen_argus_fingerprint_conversations gauge", output)

    def test_fingerprint_gauge_omitted_when_stats_missing(self):
        output = SessionStats().prometheus_metrics()
        self.assertNotIn("lumen_argus_fingerprint_conversations", output)
        self.assertNotIn("lumen_argus_fingerprint_hashes", output)

    def test_matched_value_not_in_metrics(self):
        """Prometheus output must never contain matched_value."""
        stats = SessionStats()
        stats.record(
            "anthropic",
            100,
            ScanResult(
                action="alert",
                scan_duration_ms=1.0,
                findings=[
                    Finding(
                        detector="secrets",
                        type="test_key",
                        severity="high",
                        location="msg",
                        value_preview="****",
                        matched_value="SUPER_SECRET_VALUE_12345",
                    )
                ],
            ),
        )
        output = stats.prometheus_metrics()
        self.assertNotIn("SUPER_SECRET_VALUE_12345", output)


if __name__ == "__main__":
    unittest.main()
