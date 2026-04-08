"""Tests for ProviderRouter — auto-detect and named upstream routing."""

import unittest

from lumen_argus.provider import ProviderRouter


class TestProviderAutoDetect(unittest.TestCase):
    """Verify path + header heuristic provider detection."""

    def setUp(self):
        self.router = ProviderRouter()

    def test_anthropic_by_path_and_header(self):
        _, _, _, prov = self.router.route("/v1/messages", {"x-api-key": "sk-ant-xxx"})
        self.assertEqual(prov, "anthropic")

    def test_openai_by_path(self):
        _, _, _, prov = self.router.route("/v1/chat/completions", {})
        self.assertEqual(prov, "openai")

    def test_gemini_by_path(self):
        _, _, _, prov = self.router.route("/v1beta/models/gemini:generateContent", {})
        self.assertEqual(prov, "gemini")

    def test_default_is_anthropic(self):
        _, _, _, prov = self.router.route("/unknown", {})
        self.assertEqual(prov, "anthropic")

    def test_bearer_sk_ant_detects_anthropic(self):
        _, _, _, prov = self.router.route("/some/path", {"authorization": "Bearer sk-ant-abc"})
        self.assertEqual(prov, "anthropic")

    def test_bearer_sk_detects_openai(self):
        _, _, _, prov = self.router.route("/some/path", {"authorization": "Bearer sk-abc"})
        self.assertEqual(prov, "openai")


class TestCustomUpstreams(unittest.TestCase):
    """Verify custom upstream URL override via config."""

    def test_override_openai_upstream(self):
        router = ProviderRouter(upstreams={"openai": "https://custom-openai.example.com"})
        host, port, use_ssl, prov = router.route("/v1/chat/completions", {})
        self.assertEqual(prov, "openai")
        self.assertEqual(host, "custom-openai.example.com")
        self.assertEqual(port, 443)
        self.assertTrue(use_ssl)

    def test_http_upstream(self):
        router = ProviderRouter(upstreams={"openai": "http://internal:9090"})
        host, port, use_ssl, _ = router.route("/v1/chat/completions", {})
        self.assertEqual(host, "internal")
        self.assertEqual(port, 9090)
        self.assertFalse(use_ssl)


class TestNamedUpstreamRouting(unittest.TestCase):
    """Verify /_upstream/<name>/... path prefix routing."""

    def setUp(self):
        self.router = ProviderRouter(
            upstreams={
                "opencode_zen": "https://opencode.ai/zen/v1",
                "groq": "https://api.groq.com/openai/v1",
            }
        )

    def test_named_upstream_resolves(self):
        result = self.router.resolve_named_upstream("/_upstream/opencode_zen/chat/completions")
        self.assertIsNotNone(result)
        host, port, use_ssl, provider, path = result
        self.assertEqual(host, "opencode.ai")
        self.assertEqual(port, 443)
        self.assertTrue(use_ssl)
        self.assertEqual(provider, "opencode_zen")
        self.assertEqual(path, "/zen/v1/chat/completions")

    def test_named_upstream_preserves_query_string(self):
        result = self.router.resolve_named_upstream("/_upstream/groq/chat/completions?stream=true")
        self.assertIsNotNone(result)
        _, _, _, _, path = result
        self.assertEqual(path, "/openai/v1/chat/completions?stream=true")

    def test_unknown_name_returns_none(self):
        result = self.router.resolve_named_upstream("/_upstream/nonexistent/chat/completions")
        self.assertIsNone(result)

    def test_no_prefix_returns_none(self):
        result = self.router.resolve_named_upstream("/v1/chat/completions")
        self.assertIsNone(result)

    def test_query_string_on_name_without_path(self):
        """Query string at name level must not poison the upstream name lookup."""
        result = self.router.resolve_named_upstream("/_upstream/opencode_zen?stream=true")
        self.assertIsNotNone(result)
        _, _, _, _, path = result
        self.assertEqual(path, "/zen/v1?stream=true")

    def test_name_only_no_trailing_path(self):
        result = self.router.resolve_named_upstream("/_upstream/opencode_zen")
        self.assertIsNotNone(result)
        _, _, _, _, path = result
        self.assertEqual(path, "/zen/v1")

    def test_has_named_upstreams(self):
        self.assertTrue(self.router.has_named_upstreams())

    def test_default_router_has_gateway_defaults(self):
        """Default router includes well-known gateway providers from core."""
        router = ProviderRouter()
        self.assertTrue(router.has_named_upstreams())
        # Verify a known gateway provider is routable
        result = router.resolve_named_upstream("/_upstream/opencode/chat/completions")
        self.assertIsNotNone(result)
        host, _, _, _, _path = result
        self.assertEqual(host, "opencode.ai")


class TestParseUpstream(unittest.TestCase):
    """Verify URL parsing edge cases."""

    def test_https_default_port(self):
        router = ProviderRouter()
        host, port, use_ssl, _ = router.route("/v1/messages", {"x-api-key": "k"})
        self.assertEqual(host, "api.anthropic.com")
        self.assertEqual(port, 443)
        self.assertTrue(use_ssl)

    def test_upstream_with_path(self):
        """Upstream URL with base path (e.g. opencode.ai/zen/v1)."""
        router = ProviderRouter(upstreams={"opencode_zen": "https://opencode.ai/zen/v1"})
        result = router.resolve_named_upstream("/_upstream/opencode_zen/chat/completions")
        self.assertIsNotNone(result)
        host, _port, _, _, path = result
        self.assertEqual(host, "opencode.ai")
        self.assertEqual(path, "/zen/v1/chat/completions")


class TestDetectApiProvider(unittest.TestCase):
    """Verify detect_api_provider for named upstream session extraction."""

    def setUp(self):
        self.router = ProviderRouter()

    def test_chat_completions_is_openai(self):
        self.assertEqual(self.router.detect_api_provider("/zen/v1/chat/completions"), "openai")

    def test_messages_is_anthropic(self):
        self.assertEqual(self.router.detect_api_provider("/v1/messages"), "anthropic")

    def test_generate_content_is_gemini(self):
        self.assertEqual(self.router.detect_api_provider("/v1beta/models/gemini:generateContent"), "gemini")

    def test_unknown_defaults_to_openai(self):
        self.assertEqual(self.router.detect_api_provider("/some/unknown/path"), "openai")


if __name__ == "__main__":
    unittest.main()
