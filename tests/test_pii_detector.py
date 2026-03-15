"""Tests for the PII detector."""

import unittest

from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.detectors.pii import PIIDetector
from lumen_argus.models import ScanField
from lumen_argus.patterns.pii_patterns import _luhn_check, _validate_ssn, _exclude_private_ips


class TestLuhnCheck(unittest.TestCase):
    def test_valid_visa(self):
        self.assertTrue(_luhn_check("4111111111111111"))

    def test_valid_with_spaces(self):
        self.assertTrue(_luhn_check("4111 1111 1111 1111"))

    def test_valid_with_dashes(self):
        self.assertTrue(_luhn_check("4111-1111-1111-1111"))

    def test_invalid_number(self):
        self.assertFalse(_luhn_check("4111111111111112"))

    def test_too_short(self):
        self.assertFalse(_luhn_check("411111111"))


class TestSSNValidation(unittest.TestCase):
    def test_valid_ssn(self):
        self.assertTrue(_validate_ssn("123-45-6789"))

    def test_invalid_area_000(self):
        self.assertFalse(_validate_ssn("000-45-6789"))

    def test_invalid_area_666(self):
        self.assertFalse(_validate_ssn("666-45-6789"))

    def test_invalid_area_900_plus(self):
        self.assertFalse(_validate_ssn("900-45-6789"))
        self.assertFalse(_validate_ssn("999-45-6789"))

    def test_invalid_group_00(self):
        self.assertFalse(_validate_ssn("123-00-6789"))

    def test_invalid_serial_0000(self):
        self.assertFalse(_validate_ssn("123-45-0000"))


class TestIPValidation(unittest.TestCase):
    def test_public_ip(self):
        self.assertTrue(_exclude_private_ips("8.8.8.8"))

    def test_private_10(self):
        self.assertFalse(_exclude_private_ips("10.0.0.1"))

    def test_private_172(self):
        self.assertFalse(_exclude_private_ips("172.16.0.1"))

    def test_private_192(self):
        self.assertFalse(_exclude_private_ips("192.168.1.1"))

    def test_loopback(self):
        self.assertFalse(_exclude_private_ips("127.0.0.1"))

    def test_link_local(self):
        self.assertFalse(_exclude_private_ips("169.254.1.1"))


class TestPIIDetector(unittest.TestCase):
    def setUp(self):
        self.detector = PIIDetector()
        self.allowlist = AllowlistMatcher()

    def _scan(self, text, path="test"):
        fields = [ScanField(path=path, text=text)]
        return self.detector.scan(fields, self.allowlist)

    def test_email(self):
        findings = self._scan("Contact: john.smith@company.com")
        types = [f.type for f in findings]
        self.assertIn("email", types)

    def test_ssn(self):
        findings = self._scan("SSN: 123-45-6789")
        types = [f.type for f in findings]
        self.assertIn("ssn", types)

    def test_invalid_ssn_not_detected(self):
        findings = self._scan("Number: 000-45-6789")
        ssn_findings = [f for f in findings if f.type == "ssn"]
        self.assertEqual(len(ssn_findings), 0)

    def test_credit_card_valid(self):
        findings = self._scan("Card: 4111111111111111")
        cc_findings = [f for f in findings if f.type == "credit_card"]
        self.assertEqual(len(cc_findings), 1)

    def test_credit_card_invalid_luhn(self):
        findings = self._scan("Card: 4111111111111112")
        cc_findings = [f for f in findings if f.type == "credit_card"]
        self.assertEqual(len(cc_findings), 0)

    def test_phone_us(self):
        findings = self._scan("Call: (555) 123-4567")
        types = [f.type for f in findings]
        self.assertIn("phone_us", types)

    def test_public_ip(self):
        findings = self._scan("Server: 52.14.200.1")
        ip_findings = [f for f in findings if f.type == "ip_address"]
        self.assertEqual(len(ip_findings), 1)

    def test_private_ip_excluded(self):
        findings = self._scan("Server: 192.168.1.1")
        ip_findings = [f for f in findings if f.type == "ip_address"]
        self.assertEqual(len(ip_findings), 0)

    def test_allowlisted_email_skipped(self):
        allowlist = AllowlistMatcher(pii=["*@example.com"])
        detector = PIIDetector()
        fields = [ScanField(path="test", text="test@example.com")]
        findings = detector.scan(fields, allowlist)
        email_findings = [f for f in findings if f.type == "email"]
        self.assertEqual(len(email_findings), 0)

    def test_value_preview_masked(self):
        findings = self._scan("SSN: 123-45-6789")
        ssn = [f for f in findings if f.type == "ssn"][0]
        self.assertIn("****", ssn.value_preview)
        self.assertEqual(ssn.matched_value, "123-45-6789")

    def test_no_false_positives_normal_text(self):
        findings = self._scan("Hello world, this is normal text without PII.")
        # Filter out low-confidence matches
        significant = [f for f in findings if f.severity in ("critical", "high")]
        self.assertEqual(len(significant), 0)


if __name__ == "__main__":
    unittest.main()
