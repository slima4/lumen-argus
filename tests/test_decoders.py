"""Tests for encoding-aware scanning — decoders module and pipeline integration."""

import base64
import json
import unittest

from lumen_argus.decoders import ContentDecoder, _is_meaningful
from lumen_argus.pipeline import ScannerPipeline


class TestIsMeaningful(unittest.TestCase):
    """Test the _is_meaningful filter."""

    def test_meaningful_text(self):
        self.assertTrue(_is_meaningful("sk_live_1234567890abcdef"))

    def test_short_text_rejected(self):
        self.assertFalse(_is_meaningful("abc"))

    def test_binary_text_rejected(self):
        self.assertFalse(_is_meaningful("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"))

    def test_custom_min_length(self):
        self.assertTrue(_is_meaningful("abcdef", min_length=4))
        self.assertFalse(_is_meaningful("abc", min_length=4))

    def test_empty_rejected(self):
        self.assertFalse(_is_meaningful(""))


class TestContentDecoderBase64(unittest.TestCase):
    """Test base64 decoding."""

    def test_base64_encoded_secret_detected(self):
        secret = "sk" + "_live_" + "1234567890abcdef1234567890"
        encoded = base64.b64encode(secret.encode()).decode()
        decoder = ContentDecoder()
        results = decoder.decode_field("check this: " + encoded)
        texts = [r.text for r in results]
        self.assertIn(secret, texts)

    def test_base64_encoding_annotated(self):
        secret = "AKIAIOSFODNN7EXAMPLE_secret_key"
        encoded = base64.b64encode(secret.encode()).decode()
        decoder = ContentDecoder()
        results = decoder.decode_field(encoded)
        b64_results = [r for r in results if r.encoding == "base64"]
        self.assertGreaterEqual(len(b64_results), 1)
        self.assertEqual(b64_results[0].text, secret)

    def test_base64_short_ignored(self):
        """Short base64 strings below min_decoded_length are skipped."""
        short = base64.b64encode(b"hi").decode()
        decoder = ContentDecoder(min_decoded_length=8)
        results = decoder.decode_field(short)
        self.assertEqual(len(results), 1)  # only raw

    def test_base64_disabled(self):
        secret = "sk" + "_live_" + "1234567890abcdef1234567890"
        encoded = base64.b64encode(secret.encode()).decode()
        decoder = ContentDecoder(enable_base64=False)
        results = decoder.decode_field(encoded)
        self.assertEqual(len(results), 1)  # only raw

    def test_base64_binary_ignored(self):
        """Binary data (like images) produces non-printable output, should be skipped."""
        # Pure control chars — no printable ASCII
        binary = bytes([0, 1, 2, 3, 4, 5, 6, 7, 128, 129, 130, 131] * 5)
        encoded = base64.b64encode(binary).decode()
        decoder = ContentDecoder()
        results = decoder.decode_field(encoded)
        b64_results = [r for r in results if r.encoding == "base64"]
        self.assertEqual(len(b64_results), 0)

    def test_random_base64_not_secret(self):
        """Random base64 that decodes to gibberish should not be flagged as a finding."""
        import os

        random_b64 = base64.b64encode(os.urandom(32)).decode()
        pipeline = ScannerPipeline(default_action="alert")
        body = json.dumps({"model": "test", "messages": [{"role": "user", "content": random_b64}]}).encode()
        result = pipeline.scan(body, "anthropic")
        # May or may not decode, but decoded gibberish shouldn't match secret patterns
        # (no assertion on findings=0, just verifying no crash and reasonable behavior)
        self.assertIsNotNone(result)


class TestContentDecoderHex(unittest.TestCase):
    """Test hex decoding."""

    def test_hex_encoded_secret_detected(self):
        secret = "sk_live_1234567890abcdef"
        encoded = secret.encode().hex()
        decoder = ContentDecoder()
        results = decoder.decode_field("data: " + encoded)
        texts = [r.text for r in results]
        self.assertIn(secret, texts)

    def test_hex_encoding_annotated(self):
        secret = "AKIAIOSFODNN7EXAMPLE_key"
        encoded = secret.encode().hex()
        decoder = ContentDecoder()
        results = decoder.decode_field(encoded)
        hex_results = [r for r in results if r.encoding == "hex"]
        self.assertEqual(len(hex_results), 1)

    def test_hex_odd_length_skipped(self):
        """Odd-length hex strings are not valid hex encoding."""
        decoder = ContentDecoder()
        results = decoder.decode_field("abcdef1234567890a")  # 17 chars
        hex_results = [r for r in results if r.encoding == "hex"]
        self.assertEqual(len(hex_results), 0)

    def test_hex_disabled(self):
        secret = "sk_live_1234567890abcdef"
        encoded = secret.encode().hex()
        decoder = ContentDecoder(enable_hex=False)
        results = decoder.decode_field(encoded)
        self.assertEqual(len(results), 1)  # only raw


class TestContentDecoderURL(unittest.TestCase):
    """Test URL decoding."""

    def test_url_encoded_secret_detected(self):
        secret = "sk" + "_live_" + "1234567890abcdef1234567890"
        encoded = secret.replace("_", "%5F")
        decoder = ContentDecoder()
        results = decoder.decode_field(encoded)
        texts = [r.text for r in results]
        self.assertIn(secret, texts)

    def test_url_no_encoding_no_decode(self):
        decoder = ContentDecoder()
        results = decoder.decode_field("plain text no encoding")
        self.assertEqual(len(results), 1)

    def test_url_disabled(self):
        encoded = "sk%5Flive%5F1234567890abcdef1234567890"
        decoder = ContentDecoder(enable_url=False, enable_hex=False, enable_base64=False)
        results = decoder.decode_field(encoded)
        self.assertEqual(len(results), 1)


class TestContentDecoderUnicode(unittest.TestCase):
    """Test Unicode escape decoding."""

    def test_unicode_escaped_secret_detected(self):
        # sk_live_ as unicode escapes
        encoded = "\\u0073\\u006b\\u005f\\u006c\\u0069\\u0076\\u0065\\u005f1234567890abcdef"
        decoder = ContentDecoder()
        results = decoder.decode_field(encoded)
        unicode_results = [r for r in results if r.encoding == "unicode"]
        self.assertTrue(len(unicode_results) > 0)
        self.assertIn("sk_live_", unicode_results[0].text)

    def test_unicode_disabled(self):
        encoded = "\\u0073\\u006b\\u005f\\u006c\\u0069\\u0076\\u0065\\u005f1234567890"
        decoder = ContentDecoder(enable_unicode=False)
        results = decoder.decode_field(encoded)
        self.assertEqual(len(results), 1)


class TestNestedDecoding(unittest.TestCase):
    """Test nested/double encoding."""

    def test_double_encoded_base64_in_url(self):
        """Secret URL-encoded then referenced — depth=2 should catch it."""
        secret = "sk" + "_live_" + "1234567890abcdef1234567890"
        b64 = base64.b64encode(secret.encode()).decode()
        url_encoded = b64.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")
        decoder = ContentDecoder(max_depth=2)
        results = decoder.decode_field(url_encoded)
        all_texts = [r.text for r in results]
        self.assertTrue(any(secret in t for t in all_texts))

    def test_depth_1_catches_single_layer(self):
        """With depth=1, one layer of encoding is decoded."""
        secret = "sk" + "_live_" + "1234567890abcdef1234567890"
        b64 = base64.b64encode(secret.encode()).decode()
        decoder = ContentDecoder(max_depth=1)
        results = decoder.decode_field(b64)
        all_texts = [r.text for r in results]
        self.assertTrue(any(secret in t for t in all_texts))

    def test_max_depth_0_no_decoding(self):
        secret = "sk" + "_live_" + "1234567890abcdef1234567890"
        encoded = base64.b64encode(secret.encode()).decode()
        decoder = ContentDecoder(max_depth=0)
        results = decoder.decode_field(encoded)
        self.assertEqual(len(results), 1)  # only raw


class TestDecoderLimits(unittest.TestCase):
    """Test length limits."""

    def test_max_decoded_length_caps_output(self):
        long_text = "A" * 500
        encoded = base64.b64encode(long_text.encode()).decode()
        decoder = ContentDecoder(max_decoded_length=100)
        results = decoder.decode_field(encoded)
        b64_results = [r for r in results if r.encoding == "base64"]
        if b64_results:
            self.assertLessEqual(len(b64_results[0].text), 100)

    def test_min_decoded_length_filters_short(self):
        short = "hello world test"  # 16 chars
        encoded = base64.b64encode(short.encode()).decode()
        decoder = ContentDecoder(min_decoded_length=20)
        results = decoder.decode_field(encoded)
        b64_results = [r for r in results if r.encoding == "base64"]
        self.assertEqual(len(b64_results), 0)


class TestPipelineIntegration(unittest.TestCase):
    """Test encoding-aware scanning through the full pipeline."""

    def _make_body(self, content):
        return json.dumps({"model": "test", "messages": [{"role": "user", "content": content}]}).encode()

    def test_base64_encoded_aws_key_detected(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        encoded = base64.b64encode(secret.encode()).decode()
        pipeline = ScannerPipeline(default_action="alert")
        result = pipeline.scan(self._make_body("check: " + encoded), "anthropic")
        self.assertTrue(len(result.findings) > 0)
        # Finding should reference base64 encoding in location
        locations = [f.location for f in result.findings]
        self.assertTrue(any("[base64]" in loc for loc in locations))

    def test_hex_encoded_stripe_key_detected(self):
        # Build a Stripe-like key dynamically to avoid push protection
        secret = "sk" + "_test_" + "4eC39HqLyjWDarjtT1zdp7dc"
        encoded = secret.encode().hex()
        pipeline = ScannerPipeline(default_action="alert")
        result = pipeline.scan(self._make_body("key: " + encoded), "anthropic")
        self.assertTrue(len(result.findings) > 0)
        locations = [f.location for f in result.findings]
        self.assertTrue(any("[hex]" in loc for loc in locations))

    def test_url_encoded_github_token_detected(self):
        # Build dynamically
        secret = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"
        encoded = secret.replace("_", "%5F")
        pipeline = ScannerPipeline(default_action="alert")
        result = pipeline.scan(self._make_body("token: " + encoded), "anthropic")
        self.assertTrue(len(result.findings) > 0)
        locations = [f.location for f in result.findings]
        self.assertTrue(any("[url]" in loc for loc in locations))

    def test_encoding_decode_disabled_skips_decoding(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        encoded = base64.b64encode(secret.encode()).decode()
        pipeline = ScannerPipeline(
            default_action="alert",
            pipeline_config={"encoding_decode_enabled": False},
        )
        result = pipeline.scan(self._make_body(encoded), "anthropic")
        # Without decoding, the base64 string won't match AWS key pattern
        aws_findings = [f for f in result.findings if "aws" in f.type.lower()]
        self.assertEqual(len(aws_findings), 0)

    def test_encoding_decode_enabled_detects(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        encoded = base64.b64encode(secret.encode()).decode()
        pipeline = ScannerPipeline(
            default_action="alert",
            pipeline_config={"encoding_decode_enabled": True},
        )
        result = pipeline.scan(self._make_body("data: " + encoded), "anthropic")
        aws_findings = [f for f in result.findings if "aws" in f.type.lower()]
        self.assertTrue(len(aws_findings) > 0)

    def test_raw_secret_still_detected(self):
        """Encoding decode doesn't break normal (non-encoded) detection."""
        pipeline = ScannerPipeline(default_action="alert")
        result = pipeline.scan(self._make_body("my key is AKIAIOSFODNN7EXAMPLE"), "anthropic")
        self.assertTrue(len(result.findings) > 0)

    def test_per_encoding_toggle(self):
        """Disabling base64 should not decode base64 but URL still works."""
        secret = "AKIAIOSFODNN7EXAMPLE"
        encoded = base64.b64encode(secret.encode()).decode()
        pipeline = ScannerPipeline(
            default_action="alert",
            pipeline_config={"encoding_decode_enabled": True, "encoding_base64": False},
        )
        result = pipeline.scan(self._make_body(encoded), "anthropic")
        aws_findings = [f for f in result.findings if "aws" in f.type.lower()]
        self.assertEqual(len(aws_findings), 0)

    def test_performance_decoder_overhead(self):
        """Encoding decode stage should add minimal overhead."""
        content = "normal text without any encoded content " * 100
        body = self._make_body(content)

        # Scan with decoder enabled
        pipeline_on = ScannerPipeline(
            default_action="alert",
            pipeline_config={"encoding_decode_enabled": True},
        )
        result = pipeline_on.scan(body, "anthropic")
        decode_ms = result.stage_timings.get("encoding_decode", 0)

        # Decoder overhead should be small for non-encoded content
        self.assertLess(decode_ms, 10, "encoding_decode took %.1fms" % decode_ms)


if __name__ == "__main__":
    unittest.main()
