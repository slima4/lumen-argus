"""Tests for the secrets detector."""

import unittest

from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.detectors.secrets import SecretsDetector, shannon_entropy
from lumen_argus.models import ScanField


class TestShannonEntropy(unittest.TestCase):
    def test_empty_string(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_single_char_repeated(self):
        self.assertAlmostEqual(shannon_entropy("aaaa"), 0.0)

    def test_high_entropy(self):
        # Random-looking string should have high entropy
        val = "aB3$xZ9!mK7@pQ2&"
        self.assertGreater(shannon_entropy(val), 3.5)

    def test_low_entropy(self):
        # Repetitive string should have low entropy
        self.assertLess(shannon_entropy("abcabcabcabc"), 2.0)


class TestSecretsDetector(unittest.TestCase):
    def setUp(self):
        self.detector = SecretsDetector()
        self.allowlist = AllowlistMatcher()

    def _scan(self, text, path="test"):
        fields = [ScanField(path=path, text=text)]
        return self.detector.scan(fields, self.allowlist)

    # --- AWS ---
    def test_aws_access_key(self):
        findings = self._scan("key = AKIAIOSFODNN7EXAMPLE")
        types = [f.type for f in findings]
        self.assertIn("aws_access_key", types)

    def test_aws_secret_key(self):
        findings = self._scan(
            'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        )
        types = [f.type for f in findings]
        self.assertIn("aws_secret_key", types)

    # --- GitHub ---
    def test_github_pat(self):
        findings = self._scan("token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl")
        types = [f.type for f in findings]
        self.assertIn("github_token", types)

    def test_github_fine_grained_pat(self):
        findings = self._scan("github_pat_ABCDEFGHIJ1234567890ab")
        types = [f.type for f in findings]
        self.assertIn("github_fine_grained_pat", types)

    # --- AI Provider Keys ---
    def test_anthropic_key(self):
        key = "sk-ant-" + "a" * 80
        findings = self._scan("key: " + key)
        types = [f.type for f in findings]
        self.assertIn("anthropic_api_key", types)

    def test_openai_key(self):
        findings = self._scan("sk-proj1234567890abcdefghij")
        types = [f.type for f in findings]
        self.assertIn("openai_api_key", types)

    def test_google_api_key(self):
        key = "AIza" + "a" * 35
        findings = self._scan(key)
        types = [f.type for f in findings]
        self.assertIn("google_api_key", types)

    # --- Cryptographic Material ---
    def test_private_key_pem(self):
        findings = self._scan("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
        types = [f.type for f in findings]
        self.assertIn("private_key_pem", types)

    def test_openssh_private_key(self):
        findings = self._scan("-----BEGIN OPENSSH PRIVATE KEY-----")
        types = [f.type for f in findings]
        # Should match either private_key_pem or ssh_private_key
        self.assertTrue(
            "private_key_pem" in types or "ssh_private_key" in types,
            "Expected private key detection, got: %s" % types,
        )

    # --- Tokens ---
    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        findings = self._scan(jwt)
        types = [f.type for f in findings]
        self.assertIn("jwt_token", types)

    def test_slack_token(self):
        # Build token dynamically to avoid GitHub push protection
        token = "xoxb-" + "1" * 12 + "-" + "2" * 13 + "-" + "a" * 16
        findings = self._scan(token)
        types = [f.type for f in findings]
        self.assertIn("slack_token", types)

    # --- Payment ---
    def test_stripe_secret_key(self):
        # Build key dynamically to avoid GitHub push protection
        key = "sk_" + "live" + "_" + "a" * 24 + "EXAMPLE"
        findings = self._scan(key)
        types = [f.type for f in findings]
        self.assertIn("stripe_secret_key", types)

    def test_stripe_test_key(self):
        key = "sk_" + "test" + "_" + "a" * 24 + "EXAMPLE"
        findings = self._scan(key)
        types = [f.type for f in findings]
        self.assertIn("stripe_secret_key", types)

    # --- Database ---
    def test_postgres_url(self):
        findings = self._scan("postgres://user:password@localhost:5432/mydb")
        types = [f.type for f in findings]
        self.assertIn("database_url", types)

    def test_mongodb_url(self):
        findings = self._scan("mongodb+srv://admin:secret@cluster0.abc.mongodb.net/db")
        types = [f.type for f in findings]
        self.assertIn("database_url", types)

    # --- Generic patterns ---
    def test_generic_password(self):
        # High entropy password should be detected
        findings = self._scan('password = "Xk9mPq2vLr7nQs4zRt8jWu3bYv6"')
        types = [f.type for f in findings]
        self.assertIn("generic_password", types)

    def test_basic_auth_url(self):
        findings = self._scan("https://admin:secretpass@api.example.com/v1")
        types = [f.type for f in findings]
        self.assertIn("basic_auth_url", types)

    # --- Allowlist ---
    def test_allowlisted_secret_skipped(self):
        allowlist = AllowlistMatcher(secrets=["AKIAIOSFODNN7EXAMPLE"])
        detector = SecretsDetector()
        fields = [ScanField(path="test", text="AKIAIOSFODNN7EXAMPLE")]
        findings = detector.scan(fields, allowlist)
        aws_findings = [f for f in findings if f.type == "aws_access_key"]
        self.assertEqual(len(aws_findings), 0)

    # --- Value masking ---
    def test_value_preview_masked(self):
        findings = self._scan("key = AKIAIOSFODNN7EXAMPLE")
        aws = [f for f in findings if f.type == "aws_access_key"][0]
        self.assertTrue(aws.value_preview.startswith("AKIA"))
        self.assertIn("****", aws.value_preview)
        # Full value should be in matched_value
        self.assertEqual(aws.matched_value, "AKIAIOSFODNN7EXAMPLE")

    # --- False positive prevention (#8) ---
    def test_openai_low_entropy_not_flagged(self):
        """#8: Low-entropy sk- strings should not be flagged (needs_entropy=True)."""
        findings = self._scan("sk-aaaaaaaaaaaaaaaaaaaaaaa")
        openai = [f for f in findings if f.type == "openai_api_key"]
        self.assertEqual(len(openai), 0)

    def test_openai_high_entropy_flagged(self):
        """#8: High-entropy sk- strings should still be detected."""
        findings = self._scan("sk-proj1234567890abcdefghij")
        types = [f.type for f in findings]
        self.assertIn("openai_api_key", types)

    # --- No false positives ---
    def test_normal_code_no_findings(self):
        findings = self._scan("def hello():\n    return 'world'")
        self.assertEqual(len(findings), 0)


class TestEntropySwept(unittest.TestCase):
    def test_high_entropy_near_keyword(self):
        detector = SecretsDetector(entropy_threshold=4.0)
        allowlist = AllowlistMatcher()
        # High entropy token near "secret" keyword
        text = 'secret_key = aB3xZ9mK7pQ2nW8jF5hL1'
        fields = [ScanField(path="test", text=text)]
        findings = detector.scan(fields, allowlist)
        # Should find something (either generic pattern or entropy sweep)
        self.assertTrue(len(findings) > 0)


if __name__ == "__main__":
    unittest.main()
