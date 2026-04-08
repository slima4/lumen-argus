"""Tests for OpenCode provider registry and config writing."""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from lumen_argus_core.opencode_providers import (
    GATEWAY_PROVIDERS,
    OPTIONAL_GATEWAY_PROVIDERS,
    STANDARD_PROVIDERS,
    build_provider_overrides,
    get_all_upstream_defaults,
)


class TestProviderRegistry(unittest.TestCase):
    """Test the built-in provider registries."""

    def test_standard_providers_have_known_entries(self):
        self.assertIn("anthropic", STANDARD_PROVIDERS)
        self.assertIn("openai", STANDARD_PROVIDERS)
        self.assertIn("google", STANDARD_PROVIDERS)

    def test_gateway_providers_have_known_entries(self):
        self.assertIn("opencode", GATEWAY_PROVIDERS)

    def test_optional_gateway_providers_have_known_entries(self):
        self.assertIn("groq", OPTIONAL_GATEWAY_PROVIDERS)
        self.assertIn("mistral", OPTIONAL_GATEWAY_PROVIDERS)
        self.assertIn("deepseek", OPTIONAL_GATEWAY_PROVIDERS)

    def test_no_overlap(self):
        all_ids = set(STANDARD_PROVIDERS) | set(GATEWAY_PROVIDERS) | set(OPTIONAL_GATEWAY_PROVIDERS)
        self.assertEqual(
            len(all_ids),
            len(STANDARD_PROVIDERS) + len(GATEWAY_PROVIDERS) + len(OPTIONAL_GATEWAY_PROVIDERS),
            "provider IDs must not overlap",
        )

    def test_all_urls_start_with_https(self):
        all_urls = {**STANDARD_PROVIDERS, **GATEWAY_PROVIDERS}
        for pid, (url, _) in OPTIONAL_GATEWAY_PROVIDERS.items():
            all_urls[pid] = url
        for name, url in all_urls.items():
            self.assertTrue(url.startswith("https://"), "%s has non-HTTPS URL: %s" % (name, url))


class TestBuildProviderOverrides(unittest.TestCase):
    """Test build_provider_overrides() output."""

    def test_standard_provider_gets_direct_url(self):
        overrides = build_provider_overrides("http://localhost:8070")
        self.assertEqual(
            overrides["anthropic"]["options"]["baseURL"],
            "http://localhost:8070",
        )

    def test_optional_gateway_included_when_key_set(self):
        with patch.dict(os.environ, {"GROQ_API_KEY": "test-key"}):
            overrides = build_provider_overrides("http://localhost:8070")
        self.assertEqual(
            overrides["groq"]["options"]["baseURL"],
            "http://localhost:8070/_upstream/groq",
        )

    def test_optional_gateway_excluded_without_key(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GROQ_API_KEY", None)
            overrides = build_provider_overrides("http://localhost:8070")
        self.assertNotIn("groq", overrides)

    def test_opencode_zen_gets_upstream_prefix(self):
        overrides = build_provider_overrides("http://localhost:8070")
        self.assertEqual(
            overrides["opencode"]["options"]["baseURL"],
            "http://localhost:8070/_upstream/opencode",
        )

    def test_trailing_slash_stripped(self):
        overrides = build_provider_overrides("http://localhost:8070/")
        self.assertEqual(
            overrides["openai"]["options"]["baseURL"],
            "http://localhost:8070",
        )

    def test_default_providers_covered(self):
        """Without any API keys set, only standard + default gateway are included."""
        # Clear all optional gateway env vars to avoid environment sensitivity
        optional_keys = [env for _, env in OPTIONAL_GATEWAY_PROVIDERS.values()]
        with patch.dict(os.environ, {}, clear=False):
            for k in optional_keys:
                os.environ.pop(k, None)
            overrides = build_provider_overrides("http://proxy:8080")
        expected = set(STANDARD_PROVIDERS) | set(GATEWAY_PROVIDERS)
        self.assertEqual(set(overrides.keys()), expected)


class TestGetAllUpstreamDefaults(unittest.TestCase):
    """Test get_all_upstream_defaults() for proxy router."""

    def test_returns_gateway_providers(self):
        defaults = get_all_upstream_defaults()
        self.assertIn("opencode", defaults)
        self.assertIn("groq", defaults)
        self.assertEqual(defaults["opencode"], "https://opencode.ai/zen/v1")

    def test_does_not_include_standard(self):
        defaults = get_all_upstream_defaults()
        self.assertNotIn("anthropic", defaults)
        self.assertNotIn("openai", defaults)


class TestConfigureOpenCode(unittest.TestCase):
    """Test configure_opencode() and unconfigure_opencode()."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.tmpdir, "opencode.json")
        self.tracking_path = os.path.join(self.tmpdir, "opencode_providers.json")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _patches(self):
        """Context manager patching both config path and tracking file."""
        from contextlib import ExitStack

        stack = ExitStack()
        stack.enter_context(
            patch(
                "lumen_argus_core.opencode_providers.OPENCODE_CONFIG_PATH",
                self.config_path,
            )
        )
        stack.enter_context(
            patch(
                "lumen_argus_core.setup_wizard._OPENCODE_TRACKING_FILE",
                self.tracking_path,
            )
        )
        return stack

    def test_creates_config_from_scratch(self):
        from lumen_argus_core.setup_wizard import configure_opencode

        with self._patches():
            change = configure_opencode("http://localhost:8070")

        self.assertIsNotNone(change)
        with open(self.config_path) as f:
            data = json.load(f)
        # Check that providers were written
        self.assertIn("provider", data)
        self.assertIn("anthropic", data["provider"])
        self.assertEqual(
            data["provider"]["anthropic"]["options"]["baseURL"],
            "http://localhost:8070",
        )
        # No marker key in the config (would break OpenCode schema validation)
        self.assertNotIn("_lumen_argus", data["provider"]["anthropic"])
        # Tracking file created
        self.assertTrue(os.path.exists(self.tracking_path))

    def test_preserves_existing_config(self):
        from lumen_argus_core.setup_wizard import configure_opencode

        # Write existing config with user settings
        existing = {
            "$schema": "https://opencode.ai/config.json",
            "plugin": ["opencode-agent-skills"],
            "model": "anthropic/claude-sonnet-4-5",
        }
        with open(self.config_path, "w") as f:
            json.dump(existing, f)

        with self._patches():
            configure_opencode("http://localhost:8070")

        with open(self.config_path) as f:
            data = json.load(f)
        # User settings preserved
        self.assertEqual(data["$schema"], "https://opencode.ai/config.json")
        self.assertEqual(data["plugin"], ["opencode-agent-skills"])
        self.assertEqual(data["model"], "anthropic/claude-sonnet-4-5")
        # Provider overrides added
        self.assertIn("provider", data)

    def test_preserves_user_provider_settings(self):
        from lumen_argus_core.setup_wizard import configure_opencode

        # User has custom headers for a provider
        existing = {
            "provider": {
                "anthropic": {
                    "options": {
                        "headers": {"X-Custom": "value"},
                    }
                }
            }
        }
        with open(self.config_path, "w") as f:
            json.dump(existing, f)

        with self._patches():
            configure_opencode("http://localhost:8070")

        with open(self.config_path) as f:
            data = json.load(f)
        # Custom headers preserved
        self.assertEqual(
            data["provider"]["anthropic"]["options"]["headers"],
            {"X-Custom": "value"},
        )
        # baseURL added
        self.assertEqual(
            data["provider"]["anthropic"]["options"]["baseURL"],
            "http://localhost:8070",
        )

    def test_idempotent(self):
        from lumen_argus_core.setup_wizard import configure_opencode

        with self._patches():
            change1 = configure_opencode("http://localhost:8070")
            change2 = configure_opencode("http://localhost:8070")

        self.assertIsNotNone(change1)
        self.assertIsNone(change2)  # already configured

    def test_dry_run_does_not_write(self):
        from lumen_argus_core.setup_wizard import configure_opencode

        with self._patches():
            change = configure_opencode("http://localhost:8070", dry_run=True)

        self.assertIsNotNone(change)
        self.assertFalse(os.path.exists(self.config_path))

    def test_unconfigure_removes_overrides(self):
        from lumen_argus_core.setup_wizard import configure_opencode, unconfigure_opencode

        with self._patches():
            configure_opencode("http://localhost:8070")
            cleaned = unconfigure_opencode()

        self.assertGreater(cleaned, 0)
        with open(self.config_path) as f:
            data = json.load(f)
        # Provider section should be empty or removed
        providers = data.get("provider", {})
        self.assertEqual(len(providers), 0)
        # Tracking file removed
        self.assertFalse(os.path.exists(self.tracking_path))

    def test_unconfigure_preserves_user_providers(self):
        from lumen_argus_core.setup_wizard import configure_opencode, unconfigure_opencode

        # Start with user's custom provider
        existing = {
            "provider": {
                "my_custom": {
                    "npm": "@ai-sdk/openai-compatible",
                    "options": {"baseURL": "https://custom.example.com"},
                }
            }
        }
        with open(self.config_path, "w") as f:
            json.dump(existing, f)

        with self._patches():
            configure_opencode("http://localhost:8070")
            unconfigure_opencode()

        with open(self.config_path) as f:
            data = json.load(f)
        # User's custom provider preserved
        self.assertIn("my_custom", data["provider"])
        self.assertEqual(
            data["provider"]["my_custom"]["options"]["baseURL"],
            "https://custom.example.com",
        )

    def test_unconfigure_no_config_returns_zero(self):
        from lumen_argus_core.setup_wizard import unconfigure_opencode

        with self._patches():
            cleaned = unconfigure_opencode()

        self.assertEqual(cleaned, 0)


if __name__ == "__main__":
    unittest.main()
