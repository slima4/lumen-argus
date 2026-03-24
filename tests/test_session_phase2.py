"""Tests for session tracking Phase 2: analytics queries and API endpoints."""

import json
import os
import tempfile
import unittest

from lumen_argus.analytics.store import AnalyticsStore
from lumen_argus.dashboard.api import handle_community_api
from lumen_argus.models import Finding, SessionContext


_finding_counter = 0


def _make_finding():
    global _finding_counter
    _finding_counter += 1
    return Finding(
        detector="secrets",
        type="aws_access_key_%d" % _finding_counter,
        severity="critical",
        location="messages[0].content",
        value_preview="AKIA****%d" % _finding_counter,
        matched_value="AKIAIOSFODNN7EXAMPLE",
        action="block",
    )


class TestGetSessions(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = AnalyticsStore(db_path=os.path.join(self.tmpdir, "test.db"))

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_groups_by_session_id(self):
        s1 = SessionContext(session_id="fp:aaa111", account_id="acct-1")
        s2 = SessionContext(session_id="fp:ccc333", account_id="acct-2")
        self.store.record_findings([_make_finding()], provider="anthropic", session=s1)
        self.store.record_findings([_make_finding()], provider="anthropic", session=s1)
        self.store.record_findings([_make_finding()], provider="openai", session=s2)
        sessions = self.store.get_sessions()
        self.assertEqual(len(sessions), 2)
        by_id = {s["session_id"]: s for s in sessions}
        self.assertEqual(by_id["fp:aaa111"]["finding_count"], 2)
        self.assertEqual(by_id["fp:ccc333"]["finding_count"], 1)

    def test_excludes_empty_session(self):
        self.store.record_findings([_make_finding()], session=SessionContext())
        self.store.record_findings([_make_finding()], session=SessionContext(session_id="fp:has"))
        self.assertEqual(len(self.store.get_sessions()), 1)

    def test_includes_new_fields(self):
        s = SessionContext(
            session_id="fp:abc",
            account_id="acct",
            device_id="dev",
            working_directory="/repo",
            git_branch="main",
        )
        self.store.record_findings([_make_finding()], provider="anthropic", model="opus", session=s)
        sessions = self.store.get_sessions()
        self.assertEqual(sessions[0]["account_id"], "acct")
        self.assertEqual(sessions[0]["device_id"], "dev")
        self.assertEqual(sessions[0]["git_branch"], "main")

    def test_limit(self):
        for i in range(5):
            self.store.record_findings([_make_finding()], session=SessionContext(session_id="s%d" % i))
        self.assertEqual(len(self.store.get_sessions(limit=3)), 3)

    def test_empty_store(self):
        self.assertEqual(self.store.get_sessions(), [])


class TestFindingsFilters(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = AnalyticsStore(db_path=os.path.join(self.tmpdir, "test.db"))
        sa = SessionContext(session_id="sa", account_id="acct-a")
        sb = SessionContext(session_id="sb", account_id="acct-b")
        self.store.record_findings([_make_finding()], session=sa)
        self.store.record_findings([_make_finding()], session=sa)
        self.store.record_findings([_make_finding()], session=sb)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_filter_by_session_id(self):
        _, total = self.store.get_findings_page(session_id="sa")
        self.assertEqual(total, 2)

    def test_filter_by_account_id(self):
        _, total = self.store.get_findings_page(account_id="acct-b")
        self.assertEqual(total, 1)

    def test_no_filter_returns_all(self):
        _, total = self.store.get_findings_page()
        self.assertEqual(total, 3)


class TestSessionsAPI(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = AnalyticsStore(db_path=os.path.join(self.tmpdir, "test.db"))
        s = SessionContext(session_id="fp:abc", account_id="acct-1", working_directory="/repo", git_branch="main")
        self.store.record_findings([_make_finding()], provider="anthropic", model="opus", session=s)
        self.store.record_findings([_make_finding()], provider="anthropic", model="opus", session=s)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _api(self, path):
        return handle_community_api(path, "GET", b"", self.store)

    def test_sessions_endpoint(self):
        status, body = self._api("/api/v1/sessions")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(len(data["sessions"]), 1)
        s = data["sessions"][0]
        self.assertEqual(s["session_id"], "fp:abc")
        self.assertEqual(s["account_id"], "acct-1")
        self.assertEqual(s["finding_count"], 2)

    def test_sessions_no_store(self):
        status, body = handle_community_api("/api/v1/sessions", "GET", b"", None)
        self.assertEqual(json.loads(body)["sessions"], [])

    def test_findings_filtered_by_session(self):
        status, body = self._api("/api/v1/findings?session_id=fp%3Aabc")
        data = json.loads(body)
        self.assertEqual(data["total"], 2)

    def test_findings_filtered_by_account(self):
        status, body = self._api("/api/v1/findings?account_id=acct-1")
        data = json.loads(body)
        self.assertEqual(data["total"], 2)

    def test_findings_include_all_session_columns(self):
        status, body = self._api("/api/v1/findings")
        data = json.loads(body)
        f = data["findings"][0]
        for col in (
            "account_id",
            "session_id",
            "device_id",
            "source_ip",
            "working_directory",
            "git_branch",
            "os_platform",
            "client_name",
            "api_key_hash",
        ):
            self.assertIn(col, f)

    def test_dashboard_sessions_endpoint(self):
        status, body = self._api("/api/v1/sessions/dashboard")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["total"], 1)
        self.assertEqual(len(data["sessions"]), 1)
        s = data["sessions"][0]
        self.assertEqual(s["session_id"], "fp:abc")
        self.assertEqual(s["finding_count"], 2)
        self.assertIn("critical_count", s)
        self.assertIn("high_count", s)
        self.assertIn("warning_count", s)
        self.assertIn("info_count", s)

    def test_dashboard_sessions_no_store(self):
        status, body = handle_community_api("/api/v1/sessions/dashboard", "GET", b"", None)
        data = json.loads(body)
        self.assertEqual(data["sessions"], [])
        self.assertEqual(data["total"], 0)

    def test_stats_includes_today_and_last_finding(self):
        status, body = self._api("/api/v1/stats")
        data = json.loads(body)
        self.assertIn("today_count", data)
        self.assertIn("last_finding_time", data)
        self.assertEqual(data["today_count"], 2)
        self.assertIsNotNone(data["last_finding_time"])


if __name__ == "__main__":
    unittest.main()
