"""Tests for the client registry."""

import unittest

from lumen_argus.clients import (
    CLIENT_REGISTRY,
    ClientDef,
    get_all_clients,
    get_client_by_id,
    identify_client,
)


class TestRegistryIntegrity(unittest.TestCase):
    """Verify the built-in registry is well-formed."""

    def test_has_15_clients(self):
        self.assertEqual(len(CLIENT_REGISTRY), 15)

    def test_no_duplicate_ids(self):
        ids = [c.id for c in CLIENT_REGISTRY]
        self.assertEqual(len(ids), len(set(ids)))

    def test_no_duplicate_prefixes(self):
        all_prefixes = []
        for c in CLIENT_REGISTRY:
            all_prefixes.extend(c.ua_prefixes)
        self.assertEqual(len(all_prefixes), len(set(all_prefixes)))

    def test_all_fields_populated(self):
        for c in CLIENT_REGISTRY:
            self.assertTrue(c.id, "missing id")
            self.assertTrue(c.display_name, "missing display_name for %s" % c.id)
            self.assertIn(c.category, ("cli", "ide"), "bad category for %s" % c.id)
            self.assertIn(c.provider, ("anthropic", "openai", "gemini", "multi"), "bad provider for %s" % c.id)
            self.assertTrue(c.ua_prefixes, "missing ua_prefixes for %s" % c.id)
            self.assertTrue(c.env_var, "missing env_var for %s" % c.id)
            self.assertTrue(c.setup_cmd, "missing setup_cmd for %s" % c.id)
            self.assertTrue(c.website, "missing website for %s" % c.id)

    def test_prefixes_are_lowercase(self):
        for c in CLIENT_REGISTRY:
            for p in c.ua_prefixes:
                self.assertEqual(p, p.lower(), "prefix %r for %s not lowercase" % (p, c.id))


class TestIdentifyClient(unittest.TestCase):
    """Test client identification from User-Agent strings."""

    def test_claude_code(self):
        cid, name, ver, raw = identify_client("claude-code/1.2.3 python/3.12")
        self.assertEqual(cid, "claude_code")
        self.assertEqual(name, "Claude Code")
        self.assertEqual(ver, "1.2.3")
        self.assertEqual(raw, "claude-code/1.2.3")

    def test_cursor(self):
        cid, name, ver, _ = identify_client("Cursor/0.45.1")
        self.assertEqual(cid, "cursor")
        self.assertEqual(name, "Cursor")
        self.assertEqual(ver, "0.45.1")

    def test_aider(self):
        cid, name, ver, _ = identify_client("aider/0.50.1 python-httpx/0.27")
        self.assertEqual(cid, "aider")
        self.assertEqual(name, "Aider")
        self.assertEqual(ver, "0.50.1")

    def test_copilot(self):
        cid, _, ver, _ = identify_client("github-copilot/1.0")
        self.assertEqual(cid, "copilot")
        self.assertEqual(ver, "1.0")

    def test_continue(self):
        cid, _, ver, _ = identify_client("continue/0.8.1")
        self.assertEqual(cid, "continue")
        self.assertEqual(ver, "0.8.1")

    def test_cody(self):
        cid, _, _, _ = identify_client("cody/5.0.0")
        self.assertEqual(cid, "cody")

    def test_cody_sourcegraph(self):
        cid, _, _, _ = identify_client("sourcegraph-cody/1.2")
        self.assertEqual(cid, "cody")

    def test_windsurf(self):
        cid, _, _, _ = identify_client("windsurf/1.0.0")
        self.assertEqual(cid, "windsurf")

    def test_codeium_maps_to_windsurf(self):
        cid, _, _, _ = identify_client("codeium/2.0")
        self.assertEqual(cid, "windsurf")

    def test_cline(self):
        cid, _, _, _ = identify_client("cline/3.0.0")
        self.assertEqual(cid, "cline")

    def test_roo_code(self):
        cid, _, _, _ = identify_client("roo-code/1.0")
        self.assertEqual(cid, "roo_code")

    def test_codex_cli(self):
        cid, _, _, _ = identify_client("codex/0.1.0")
        self.assertEqual(cid, "codex_cli")

    def test_aide(self):
        cid, _, _, _ = identify_client("aide/1.0.0")
        self.assertEqual(cid, "aide")

    def test_case_insensitive(self):
        cid, _, _, _ = identify_client("CLAUDE-CODE/1.2.3")
        self.assertEqual(cid, "claude_code")

    def test_case_insensitive_mixed(self):
        cid, _, _, _ = identify_client("Aider/0.50.1")
        self.assertEqual(cid, "aider")

    def test_unknown_ua_passthrough(self):
        cid, name, ver, raw = identify_client("my-custom-tool/1.0")
        self.assertEqual(cid, "my-custom-tool/1.0")
        self.assertEqual(name, "my-custom-tool/1.0")
        self.assertEqual(ver, "1.0")
        self.assertEqual(raw, "my-custom-tool/1.0")

    def test_empty_ua(self):
        cid, name, ver, raw = identify_client("")
        self.assertEqual(cid, "")
        self.assertEqual(ver, "")

    def test_none_ua(self):
        cid, name, ver, raw = identify_client(None)
        self.assertEqual(cid, "")
        self.assertEqual(ver, "")

    def test_mozilla_filtered(self):
        cid, _, ver, _ = identify_client("Mozilla/5.0 (Macintosh; Intel Mac OS X)")
        self.assertEqual(cid, "")
        self.assertEqual(ver, "")

    def test_truncation(self):
        long_ua = "x" * 200
        _, _, _, raw = identify_client(long_ua)
        self.assertEqual(len(raw), 128)

    def test_python_requests_passthrough(self):
        """Generic python-requests UA doesn't match any client."""
        cid, _, ver, _ = identify_client("python-requests/2.31.0")
        self.assertEqual(cid, "python-requests/2.31.0")
        self.assertEqual(ver, "2.31.0")

    def test_no_version(self):
        """UA without a slash has no version."""
        cid, _, ver, _ = identify_client("custom-tool")
        self.assertEqual(cid, "custom-tool")
        self.assertEqual(ver, "")


class TestGetClientById(unittest.TestCase):
    def test_valid_id(self):
        c = get_client_by_id("claude_code")
        self.assertIsNotNone(c)
        self.assertEqual(c.display_name, "Claude Code")

    def test_invalid_id(self):
        self.assertIsNone(get_client_by_id("nonexistent"))


class TestGetAllClients(unittest.TestCase):
    def test_returns_15_clients(self):
        clients = get_all_clients()
        self.assertEqual(len(clients), 15)
        self.assertIsInstance(clients[0], dict)
        self.assertIn("id", clients[0])

    def test_with_extra_clients(self):
        extra = ClientDef(
            id="enterprise_tool",
            display_name="Enterprise Tool",
            category="ide",
            provider="openai",
            ua_prefixes=("enterprise-tool/",),
            env_var="OPENAI_BASE_URL",
            setup_cmd="OPENAI_BASE_URL=http://localhost:8080",
            website="https://example.com",
        )
        clients = get_all_clients(extra_clients=[extra])
        self.assertEqual(len(clients), 16)
        self.assertEqual(clients[-1]["id"], "enterprise_tool")

    def test_with_extra_dict(self):
        extra = {"id": "custom", "display_name": "Custom Tool"}
        clients = get_all_clients(extra_clients=[extra])
        self.assertEqual(len(clients), 16)
        self.assertEqual(clients[-1]["id"], "custom")


if __name__ == "__main__":
    unittest.main()
