"""Phase 3 integration tests — community edition lifecycle.

Tests the community dashboard, analytics store, and extension registry
work correctly in isolation. Pro integration tests live in the Pro repo.
"""

import os
import sqlite3
import tempfile
import unittest

from lumen_argus.analytics.store import AnalyticsStore
from lumen_argus.extensions import ExtensionRegistry
from lumen_argus.models import Finding


def _make_findings(count=3):
    """Create test findings."""
    findings = []
    for i in range(count):
        findings.append(Finding(
            detector="secrets",
            type="aws_access_key",
            severity="critical",
            location="messages[%d].content" % i,
            value_preview="AKIA****EXAMPLE",
            matched_value="AKIAIOSFODNN7EXAMPLE",
            action="alert",
        ))
    return findings


class TestCommunityOnly(unittest.TestCase):
    """Community-only install — dashboard works, findings recorded."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "analytics.db")

    def test_community_store_creates_tables(self):
        _store = AnalyticsStore(db_path=self.db_path)  # side effect: creates tables
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        tables = {r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        conn.close()
        self.assertIn("findings", tables)
        self.assertIn("notification_channels", tables)

    def test_community_store_records_and_retrieves(self):
        store = AnalyticsStore(db_path=self.db_path)
        findings = _make_findings(5)
        store.record_findings(findings, provider="anthropic", model="opus")

        page, total = store.get_findings_page(limit=10, offset=0)
        self.assertEqual(total, 5)
        self.assertEqual(len(page), 5)
        self.assertEqual(page[0]["provider"], "anthropic")

    def test_community_stats_work(self):
        store = AnalyticsStore(db_path=self.db_path)
        store.record_findings(_make_findings(3), provider="anthropic")
        stats = store.get_stats()
        self.assertEqual(stats["total_findings"], 3)
        self.assertIn("critical", stats["by_severity"])
        self.assertIn("secrets", stats["by_detector"])

    def test_community_store_file_permissions(self):
        _store = AnalyticsStore(db_path=self.db_path)  # side effect: creates DB file
        mode = os.stat(self.db_path).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_extension_registry_community_only(self):
        """Registry works without any plugins registered."""
        reg = ExtensionRegistry()
        self.assertIsNone(reg.get_analytics_store())
        self.assertIsNone(reg.get_dashboard_api_handler())
        self.assertIsNone(reg.get_sse_broadcaster())
        self.assertEqual(reg.get_dashboard_pages(), [])
        self.assertEqual(reg.get_dashboard_css(), [])
        self.assertEqual(reg.get_auth_providers(), [])

    def test_findings_survive_store_reinit(self):
        """Findings persist across AnalyticsStore re-initialization."""
        store1 = AnalyticsStore(db_path=self.db_path)
        store1.record_findings(_make_findings(5), provider="anthropic")

        store2 = AnalyticsStore(db_path=self.db_path)
        page, total = store2.get_findings_page(limit=100)
        self.assertEqual(total, 5)

    def test_pro_tables_on_disk_are_harmless(self):
        """Community store ignores unknown tables (e.g. leftover Pro tables)."""
        _store = AnalyticsStore(db_path=self.db_path)  # side effect: creates tables
        # Simulate Pro tables left on disk after downgrade
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE IF NOT EXISTS custom_rules (name TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE IF NOT EXISTS notification_channels (id INTEGER PRIMARY KEY)")
        conn.commit()
        conn.close()

        # Community store still works fine
        store2 = AnalyticsStore(db_path=self.db_path)
        store2.record_findings(_make_findings(3), provider="anthropic")
        page, total = store2.get_findings_page()
        self.assertEqual(total, 3)


if __name__ == "__main__":
    unittest.main()
