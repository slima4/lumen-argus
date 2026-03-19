"""Tests for lumen_argus.analytics.store.AnalyticsStore."""

import os
import shutil
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone

from lumen_argus.analytics.store import AnalyticsStore
from lumen_argus.models import Finding


def _make_finding(
    detector="secrets",
    type_="aws_access_key",
    severity="critical",
    location="messages[0].content",
    value_preview="AKIA****",
    matched_value="AKIAIOSFODNN7EXAMPLE",
    action="block",
):
    return Finding(
        detector=detector,
        type=type_,
        severity=severity,
        location=location,
        value_preview=value_preview,
        matched_value=matched_value,
        action=action,
    )


class TestAnalyticsStore(unittest.TestCase):
    """Tests for AnalyticsStore."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_analytics.db")
        self.store = AnalyticsStore(db_path=self.db_path)

    def tearDown(self):
        # Close thread-local connections
        conn = getattr(self.store._local, "conn", None)
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        # Remove the entire temp directory tree
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # ── WAL mode ──────────────────────────────────────────────────

    def test_wal_mode_enabled(self):
        """Database should use WAL journal mode."""
        conn = self.store._connect()
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(mode, "wal")

    # ── record_findings ───────────────────────────────────────────

    def test_record_findings_inserts_rows(self):
        """record_findings should insert one row per finding."""
        findings = [_make_finding(), _make_finding(detector="pii", type_="ssn", severity="high")]
        self.store.record_findings(findings, provider="anthropic", model="claude-3")

        conn = self.store._connect()
        count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        self.assertEqual(count, 2)

    def test_record_findings_empty_list_noop(self):
        """Passing an empty list should not insert anything."""
        self.store.record_findings([])
        conn = self.store._connect()
        count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        self.assertEqual(count, 0)

    def test_record_findings_matched_value_not_stored(self):
        """matched_value must never appear in the database."""
        secret = "AKIAIOSFODNN7EXAMPLE"
        finding = _make_finding(matched_value=secret)
        self.store.record_findings([finding])

        conn = self.store._connect()
        # Dump every column for every row and ensure the secret is absent
        rows = conn.execute("SELECT * FROM findings").fetchall()
        for row in rows:
            for key in row.keys():
                self.assertNotEqual(str(row[key]), secret,
                                    f"matched_value found in column '{key}'")

    def test_record_findings_stores_provider_and_model(self):
        """Provider and model should be persisted."""
        self.store.record_findings([_make_finding()], provider="openai", model="gpt-4")

        conn = self.store._connect()
        row = conn.execute("SELECT provider, model FROM findings").fetchone()
        self.assertEqual(row["provider"], "openai")
        self.assertEqual(row["model"], "gpt-4")

    def test_record_findings_stores_all_fields(self):
        """All finding fields should be stored correctly."""
        f = _make_finding(
            detector="pii",
            type_="email",
            severity="warning",
            location="messages[2].content",
            value_preview="j***@example.com",
            action="alert",
        )
        self.store.record_findings([f], provider="gemini", model="gemini-pro")

        row = self.store.get_finding_by_id(1)
        self.assertIsNotNone(row)
        self.assertEqual(row["detector"], "pii")
        self.assertEqual(row["finding_type"], "email")
        self.assertEqual(row["severity"], "warning")
        self.assertEqual(row["location"], "messages[2].content")
        self.assertEqual(row["value_preview"], "j***@example.com")
        self.assertEqual(row["action_taken"], "alert")
        self.assertEqual(row["provider"], "gemini")
        self.assertEqual(row["model"], "gemini-pro")

    def test_record_findings_defaults_provider_model_empty(self):
        """Provider and model default to empty string."""
        self.store.record_findings([_make_finding()])
        row = self.store.get_finding_by_id(1)
        self.assertEqual(row["provider"], "")
        self.assertEqual(row["model"], "")

    # ── get_findings_page ─────────────────────────────────────────

    def _seed_findings(self):
        """Insert a variety of findings for pagination/filter tests."""
        findings = [
            _make_finding(detector="secrets", type_="aws_access_key", severity="critical"),
            _make_finding(detector="secrets", type_="github_token", severity="high"),
            _make_finding(detector="pii", type_="ssn", severity="high"),
            _make_finding(detector="pii", type_="email", severity="warning"),
            _make_finding(detector="proprietary", type_="confidential_keyword", severity="info"),
        ]
        # Record in two batches with different providers
        self.store.record_findings(findings[:3], provider="anthropic", model="claude-3")
        self.store.record_findings(findings[3:], provider="openai", model="gpt-4")

    def test_get_findings_page_returns_all(self):
        """Without filters, should return all findings."""
        self._seed_findings()
        rows, total = self.store.get_findings_page(limit=50, offset=0)
        self.assertEqual(total, 5)
        self.assertEqual(len(rows), 5)

    def test_get_findings_page_pagination(self):
        """Limit and offset should paginate correctly."""
        self._seed_findings()
        page1, total = self.store.get_findings_page(limit=2, offset=0)
        self.assertEqual(total, 5)
        self.assertEqual(len(page1), 2)

        page2, total = self.store.get_findings_page(limit=2, offset=2)
        self.assertEqual(total, 5)
        self.assertEqual(len(page2), 2)

        page3, total = self.store.get_findings_page(limit=2, offset=4)
        self.assertEqual(total, 5)
        self.assertEqual(len(page3), 1)

        # IDs should not overlap
        ids = [r["id"] for r in page1 + page2 + page3]
        self.assertEqual(len(ids), len(set(ids)))

    def test_get_findings_page_ordered_desc(self):
        """Results should be ordered by id descending (newest first)."""
        self._seed_findings()
        rows, _ = self.store.get_findings_page(limit=50, offset=0)
        ids = [r["id"] for r in rows]
        self.assertEqual(ids, sorted(ids, reverse=True))

    def test_get_findings_page_filter_by_severity(self):
        """Filtering by severity should return matching rows only."""
        self._seed_findings()
        rows, total = self.store.get_findings_page(severity="high")
        self.assertEqual(total, 2)
        self.assertEqual(len(rows), 2)
        for r in rows:
            self.assertEqual(r["severity"], "high")

    def test_get_findings_page_filter_by_detector(self):
        """Filtering by detector should return matching rows only."""
        self._seed_findings()
        rows, total = self.store.get_findings_page(detector="pii")
        self.assertEqual(total, 2)
        for r in rows:
            self.assertEqual(r["detector"], "pii")

    def test_get_findings_page_filter_by_provider(self):
        """Filtering by provider should return matching rows only."""
        self._seed_findings()
        rows, total = self.store.get_findings_page(provider="openai")
        self.assertEqual(total, 2)
        for r in rows:
            self.assertEqual(r["provider"], "openai")

    def test_get_findings_page_combined_filters(self):
        """Multiple filters should be ANDed."""
        self._seed_findings()
        rows, total = self.store.get_findings_page(severity="high", detector="secrets")
        self.assertEqual(total, 1)
        self.assertEqual(rows[0]["detector"], "secrets")
        self.assertEqual(rows[0]["severity"], "high")

    def test_get_findings_page_no_match(self):
        """Filters that match nothing should return empty list with total 0."""
        self._seed_findings()
        rows, total = self.store.get_findings_page(severity="nonexistent")
        self.assertEqual(total, 0)
        self.assertEqual(rows, [])

    def test_get_findings_page_returns_dicts(self):
        """Each item should be a plain dict, not a sqlite3.Row."""
        self._seed_findings()
        rows, _ = self.store.get_findings_page(limit=1)
        self.assertIsInstance(rows[0], dict)

    # ── get_stats ─────────────────────────────────────────────────

    def test_get_stats_empty_db(self):
        """Stats on an empty database should return zero totals."""
        stats = self.store.get_stats()
        self.assertEqual(stats["total_findings"], 0)
        self.assertEqual(stats["by_severity"], {})
        self.assertEqual(stats["by_detector"], {})
        self.assertEqual(stats["top_finding_types"], {})
        self.assertEqual(stats["by_action"], {})
        self.assertEqual(stats["daily_trend"], [])

    def test_get_stats_totals(self):
        """total_findings should reflect the count of rows."""
        self._seed_findings()
        stats = self.store.get_stats()
        self.assertEqual(stats["total_findings"], 5)

    def test_get_stats_by_severity(self):
        """by_severity should count correctly per severity level."""
        self._seed_findings()
        stats = self.store.get_stats()
        self.assertEqual(stats["by_severity"]["critical"], 1)
        self.assertEqual(stats["by_severity"]["high"], 2)
        self.assertEqual(stats["by_severity"]["warning"], 1)
        self.assertEqual(stats["by_severity"]["info"], 1)

    def test_get_stats_by_detector(self):
        """by_detector should count correctly per detector."""
        self._seed_findings()
        stats = self.store.get_stats()
        self.assertEqual(stats["by_detector"]["secrets"], 2)
        self.assertEqual(stats["by_detector"]["pii"], 2)
        self.assertEqual(stats["by_detector"]["proprietary"], 1)

    def test_get_stats_by_provider(self):
        """by_provider should count correctly per provider."""
        self._seed_findings()
        stats = self.store.get_stats()
        self.assertEqual(stats["by_provider"]["anthropic"], 3)
        self.assertEqual(stats["by_provider"]["openai"], 2)

    def test_get_stats_by_model(self):
        """by_model should count correctly per model."""
        self._seed_findings()
        stats = self.store.get_stats()
        self.assertEqual(stats["by_model"]["claude-3"], 3)
        self.assertEqual(stats["by_model"]["gpt-4"], 2)

    def test_get_stats_by_action(self):
        """by_action should count correctly per action."""
        self._seed_findings()
        stats = self.store.get_stats()
        # All seeded findings have action="block"
        self.assertEqual(stats["by_action"]["block"], 5)

    def test_get_stats_top_finding_types(self):
        """top_finding_types should list types with counts."""
        self._seed_findings()
        stats = self.store.get_stats()
        self.assertIn("aws_access_key", stats["top_finding_types"])
        self.assertIn("ssn", stats["top_finding_types"])

    def test_get_stats_daily_trend(self):
        """daily_trend should include today's date if findings exist."""
        self._seed_findings()
        stats = self.store.get_stats()
        self.assertGreaterEqual(len(stats["daily_trend"]), 1)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        dates = [d["date"] for d in stats["daily_trend"]]
        self.assertIn(today, dates)
        for entry in stats["daily_trend"]:
            if entry["date"] == today:
                self.assertEqual(entry["count"], 5)

    # ── get_total_count ───────────────────────────────────────────

    def test_get_total_count_no_filter(self):
        """Without filters, returns total row count."""
        self._seed_findings()
        self.assertEqual(self.store.get_total_count(), 5)

    def test_get_total_count_empty(self):
        """Empty DB should return 0."""
        self.assertEqual(self.store.get_total_count(), 0)

    def test_get_total_count_filter_severity(self):
        self._seed_findings()
        self.assertEqual(self.store.get_total_count(severity="critical"), 1)

    def test_get_total_count_filter_detector(self):
        self._seed_findings()
        self.assertEqual(self.store.get_total_count(detector="pii"), 2)

    def test_get_total_count_filter_provider(self):
        self._seed_findings()
        self.assertEqual(self.store.get_total_count(provider="anthropic"), 3)

    def test_get_total_count_combined_filters(self):
        self._seed_findings()
        self.assertEqual(
            self.store.get_total_count(severity="high", detector="secrets"), 1
        )

    def test_get_total_count_no_match(self):
        self._seed_findings()
        self.assertEqual(self.store.get_total_count(severity="nonexistent"), 0)

    # ── get_finding_by_id ─────────────────────────────────────────

    def test_get_finding_by_id_found(self):
        """Should return a dict for an existing ID."""
        self.store.record_findings([_make_finding()])
        result = self.store.get_finding_by_id(1)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["id"], 1)
        self.assertEqual(result["detector"], "secrets")

    def test_get_finding_by_id_not_found(self):
        """Should return None for a non-existent ID."""
        result = self.store.get_finding_by_id(999)
        self.assertIsNone(result)

    # ── cleanup ───────────────────────────────────────────────────

    def test_cleanup_deletes_old_records(self):
        """Cleanup should delete findings older than retention_days."""
        self.store.record_findings([_make_finding()])

        # Manually backdate the row to 400 days ago
        conn = self.store._connect()
        with self.store._lock:
            with conn:
                conn.execute(
                    "UPDATE findings SET timestamp = DATE('now', '-400 days') WHERE id = 1"
                )

        deleted = self.store.cleanup(retention_days=365)
        self.assertEqual(deleted, 1)
        self.assertEqual(self.store.get_total_count(), 0)

    def test_cleanup_keeps_recent_records(self):
        """Cleanup should not delete findings within retention window."""
        self.store.record_findings([_make_finding()])
        deleted = self.store.cleanup(retention_days=365)
        self.assertEqual(deleted, 0)
        self.assertEqual(self.store.get_total_count(), 1)

    def test_cleanup_returns_count(self):
        """Cleanup should return the number of deleted rows."""
        findings = [_make_finding() for _ in range(3)]
        self.store.record_findings(findings)

        conn = self.store._connect()
        with self.store._lock:
            with conn:
                conn.execute(
                    "UPDATE findings SET timestamp = DATE('now', '-500 days')"
                )

        deleted = self.store.cleanup(retention_days=365)
        self.assertEqual(deleted, 3)

    def test_cleanup_mixed_old_and_new(self):
        """Cleanup should delete only old records, keeping recent ones."""
        self.store.record_findings([_make_finding(), _make_finding()])

        # Backdate only the first record
        conn = self.store._connect()
        with self.store._lock:
            with conn:
                conn.execute(
                    "UPDATE findings SET timestamp = DATE('now', '-400 days') WHERE id = 1"
                )

        deleted = self.store.cleanup(retention_days=365)
        self.assertEqual(deleted, 1)
        self.assertEqual(self.store.get_total_count(), 1)

    # ── start_cleanup_scheduler ───────────────────────────────────

    def test_start_cleanup_scheduler_starts_daemon_thread(self):
        """Scheduler should start a daemon thread named 'analytics-cleanup'."""
        before = {t.name for t in threading.enumerate()}
        self.store.start_cleanup_scheduler(retention_days=365)
        # Give the thread a moment to start
        time.sleep(0.05)
        after = {t.name for t in threading.enumerate()}
        new_threads = after - before
        self.assertIn("analytics-cleanup", new_threads)

        # Verify it is a daemon thread
        for t in threading.enumerate():
            if t.name == "analytics-cleanup":
                self.assertTrue(t.daemon)
                break

    # ── Thread safety ─────────────────────────────────────────────

    def test_concurrent_writes(self):
        """Multiple threads writing concurrently should not corrupt the DB."""
        errors = []
        num_threads = 8
        writes_per_thread = 20

        def writer(thread_id):
            try:
                for i in range(writes_per_thread):
                    f = _make_finding(
                        type_=f"type_t{thread_id}_i{i}",
                        location=f"thread{thread_id}[{i}]",
                    )
                    self.store.record_findings([f], provider=f"provider_{thread_id}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(errors, [], f"Concurrent write errors: {errors}")
        self.assertEqual(
            self.store.get_total_count(), num_threads * writes_per_thread
        )

    def test_concurrent_read_write(self):
        """Reads and writes happening concurrently should not raise."""
        self._seed_findings()
        errors = []

        def reader():
            try:
                for _ in range(20):
                    self.store.get_findings_page(limit=10)
                    self.store.get_stats()
                    self.store.get_total_count()
            except Exception as e:
                errors.append(e)

        def writer():
            try:
                for _ in range(20):
                    self.store.record_findings(
                        [_make_finding()], provider="test"
                    )
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=reader),
            threading.Thread(target=reader),
            threading.Thread(target=writer),
            threading.Thread(target=writer),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(errors, [], f"Concurrent read/write errors: {errors}")

    # ── DB path expansion ─────────────────────────────────────────

    def test_db_path_tilde_expansion(self):
        """Tilde in db_path should be expanded."""
        store = AnalyticsStore(db_path=self.db_path)
        self.assertNotIn("~", store._db_path)

    def test_creates_parent_directories(self):
        """Store should create parent directories for the DB file."""
        nested = os.path.join(self.tmpdir, "a", "b", "c", "analytics.db")
        _store = AnalyticsStore(db_path=nested)  # side effect: creates dirs
        self.assertTrue(os.path.exists(nested))


if __name__ == "__main__":
    unittest.main()
