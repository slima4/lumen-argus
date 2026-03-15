"""Tests for the allowlist matcher."""

import unittest

from lumen_argus.allowlist import AllowlistMatcher


class TestAllowlistMatcher(unittest.TestCase):
    def test_exact_secret_match(self):
        al = AllowlistMatcher(secrets=["AKIAIOSFODNN7EXAMPLE"])
        self.assertTrue(al.is_allowed_secret("AKIAIOSFODNN7EXAMPLE"))
        self.assertFalse(al.is_allowed_secret("AKIAIOSFODNN7OTHER"))

    def test_glob_secret_match(self):
        al = AllowlistMatcher(secrets=["sk-ant-api03-example*"])
        self.assertTrue(al.is_allowed_secret("sk-ant-api03-example-key"))
        self.assertFalse(al.is_allowed_secret("sk-ant-api03-real-key"))

    def test_pii_domain_glob(self):
        al = AllowlistMatcher(pii=["*@example.com"])
        self.assertTrue(al.is_allowed_pii("test@example.com"))
        self.assertTrue(al.is_allowed_pii("admin@example.com"))
        self.assertFalse(al.is_allowed_pii("user@company.com"))

    def test_path_glob(self):
        al = AllowlistMatcher(paths=["test/**", "fixtures/**"])
        self.assertTrue(al.is_allowed_path("test/data/secrets.txt"))
        self.assertTrue(al.is_allowed_path("fixtures/sample.json"))
        self.assertFalse(al.is_allowed_path("src/main.py"))

    def test_empty_allowlist(self):
        al = AllowlistMatcher()
        self.assertFalse(al.is_allowed_secret("anything"))
        self.assertFalse(al.is_allowed_pii("anything"))
        self.assertFalse(al.is_allowed_path("anything"))


if __name__ == "__main__":
    unittest.main()
