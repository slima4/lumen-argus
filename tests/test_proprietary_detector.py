"""Tests for the proprietary code detector."""

import unittest

from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.detectors.proprietary import ProprietaryDetector
from lumen_argus.models import ScanField


class TestProprietaryDetector(unittest.TestCase):
    def setUp(self):
        self.detector = ProprietaryDetector()
        self.allowlist = AllowlistMatcher()

    def _scan(self, text, path="test", source_filename=""):
        fields = [ScanField(path=path, text=text, source_filename=source_filename)]
        return self.detector.scan(fields, self.allowlist)

    # --- File pattern blocklist ---
    def test_pem_file_blocked(self):
        findings = self._scan("key data", source_filename="server.pem")
        types = [f.type for f in findings]
        self.assertIn("blocked_file_pattern", types)

    def test_env_file_blocked(self):
        findings = self._scan("SECRET=value", source_filename=".env")
        types = [f.type for f in findings]
        self.assertIn("blocked_file_pattern", types)

    def test_env_local_blocked(self):
        findings = self._scan("data", source_filename=".env.local")
        types = [f.type for f in findings]
        self.assertIn("blocked_file_pattern", types)

    def test_credentials_json_blocked(self):
        findings = self._scan("{}", source_filename="credentials.json")
        types = [f.type for f in findings]
        self.assertIn("blocked_file_pattern", types)

    def test_sql_file_warning(self):
        findings = self._scan("SELECT *", source_filename="data.sql")
        types = [f.type for f in findings]
        self.assertIn("sensitive_file_pattern", types)

    def test_normal_file_not_flagged(self):
        findings = self._scan("code", source_filename="app.py")
        file_findings = [f for f in findings if "file_pattern" in f.type]
        self.assertEqual(len(file_findings), 0)

    # --- Keyword detection ---
    def test_confidential_keyword(self):
        findings = self._scan("This document is CONFIDENTIAL")
        types = [f.type for f in findings]
        self.assertIn("confidential_keyword", types)

    def test_trade_secret_keyword(self):
        findings = self._scan("TRADE SECRET: Algorithm details")
        types = [f.type for f in findings]
        self.assertIn("confidential_keyword", types)

    def test_case_insensitive_keyword(self):
        findings = self._scan("This is confidential information")
        types = [f.type for f in findings]
        self.assertIn("confidential_keyword", types)

    def test_unreleased_keyword_warning(self):
        findings = self._scan("UNRELEASED: v2 API design")
        types = [f.type for f in findings]
        self.assertIn("sensitive_keyword", types)

    def test_draft_keyword_no_longer_fires(self):
        # DRAFT is too ambiguous in LLM-code contexts (GitHub PR status,
        # email subjects) — dropped from DEFAULT_KEYWORDS_WARNING.
        findings = self._scan("DRAFT: v2 API design")
        types = [f.type for f in findings]
        self.assertNotIn("sensitive_keyword", types)

    def test_normal_text_no_findings(self):
        findings = self._scan("def calculate_sum(a, b):\n    return a + b")
        self.assertEqual(len(findings), 0)

    # --- Combined ---
    def test_env_file_with_confidential(self):
        findings = self._scan(
            "CONFIDENTIAL settings",
            source_filename=".env",
        )
        types = [f.type for f in findings]
        self.assertIn("blocked_file_pattern", types)
        self.assertIn("confidential_keyword", types)


if __name__ == "__main__":
    unittest.main()
