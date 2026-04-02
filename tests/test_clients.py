"""Tests for the client registry."""

import unittest

from lumen_argus_core.clients import (
    CLIENT_REGISTRY,
    PROXY_ENV_VARS,
    ClientDef,
    ProxyConfig,
    ProxyConfigType,
    get_all_clients,
    get_client_by_id,
    identify_client,
)


class TestRegistryIntegrity(unittest.TestCase):
    """Verify the built-in registry is well-formed."""

    def test_has_27_clients(self):
        self.assertEqual(len(CLIENT_REGISTRY), 27)

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
            self.assertIsNotNone(c.proxy_config, "missing proxy_config for %s" % c.id)
            self.assertIsInstance(c.proxy_config.config_type, ProxyConfigType)
            self.assertTrue(c.proxy_config.setup_instructions, "missing setup_instructions for %s" % c.id)
            self.assertTrue(c.website, "missing website for %s" % c.id)

    def test_env_var_clients_have_env_var(self):
        """ENV_VAR type clients must have env_var and setup_cmd."""
        for c in CLIENT_REGISTRY:
            if c.proxy_config.config_type == ProxyConfigType.ENV_VAR:
                self.assertTrue(c.proxy_config.env_var, "ENV_VAR type but no env_var for %s" % c.id)
                self.assertTrue(c.proxy_config.setup_cmd, "ENV_VAR type but no setup_cmd for %s" % c.id)

    def test_unsupported_have_no_env_var(self):
        """UNSUPPORTED clients must not have env_var set."""
        for c in CLIENT_REGISTRY:
            if c.proxy_config.config_type == ProxyConfigType.UNSUPPORTED:
                self.assertEqual(c.proxy_config.env_var, "", "UNSUPPORTED client %s should not have env_var" % c.id)

    def test_proxy_config_type_distribution(self):
        """Verify expected count of each proxy config type."""
        counts: dict[ProxyConfigType, int] = {}
        for c in CLIENT_REGISTRY:
            counts[c.proxy_config.config_type] = counts.get(c.proxy_config.config_type, 0) + 1
        self.assertEqual(counts[ProxyConfigType.ENV_VAR], 6)
        self.assertEqual(counts[ProxyConfigType.IDE_SETTINGS], 2)
        self.assertEqual(counts[ProxyConfigType.CONFIG_FILE], 1)
        self.assertEqual(counts[ProxyConfigType.MANUAL], 7)
        self.assertEqual(counts[ProxyConfigType.UNSUPPORTED], 11)

    def test_proxy_env_vars_derived(self):
        """PROXY_ENV_VARS should be derived from registry, not hardcoded."""
        self.assertIn("ANTHROPIC_BASE_URL", PROXY_ENV_VARS)
        self.assertIn("OPENAI_BASE_URL", PROXY_ENV_VARS)
        self.assertIn("COPILOT_PROVIDER_BASE_URL", PROXY_ENV_VARS)
        self.assertIn("GEMINI_BASE_URL", PROXY_ENV_VARS)

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

    def test_copilot_cli(self):
        cid, name, ver, _ = identify_client("copilot/1.0.12")
        self.assertEqual(cid, "copilot_cli")
        self.assertEqual(name, "GitHub Copilot CLI")
        self.assertEqual(ver, "1.0.12")

    def test_copilot_prefix_disambiguation(self):
        """copilot/ matches CLI, copilot- matches IDE extension."""
        cid_cli, _, _, _ = identify_client("copilot/2.0")
        cid_ide, _, _, _ = identify_client("copilot-chat/1.0")
        self.assertEqual(cid_cli, "copilot_cli")
        self.assertEqual(cid_ide, "copilot")

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

    def test_opencode(self):
        cid, name, ver, _ = identify_client("opencode/0.5.0")
        self.assertEqual(cid, "opencode")
        self.assertEqual(name, "OpenCode")
        self.assertEqual(ver, "0.5.0")

    def test_gemini_cli(self):
        cid, name, ver, _ = identify_client("GeminiCLI/0.35.3")
        self.assertEqual(cid, "gemini_cli")
        self.assertEqual(name, "Gemini CLI")
        self.assertEqual(ver, "0.35.3")

    def test_gemini_cli_full_ua(self):
        """Gemini CLI sends GeminiCLI/{ver}/{model} ({platform}; {arch})."""
        cid, _, ver, raw = identify_client("GeminiCLI/0.34.0/gemini-pro (linux; x64; terminal)")
        self.assertEqual(cid, "gemini_cli")
        self.assertEqual(ver, "0.34.0")
        self.assertEqual(raw, "GeminiCLI/0.34.0/gemini-pro")

    def test_droid(self):
        cid, _, _, _ = identify_client("droid/1.0.0")
        self.assertEqual(cid, "droid")

    def test_factory_maps_to_droid(self):
        cid, _, _, _ = identify_client("factory/2.0")
        self.assertEqual(cid, "droid")

    def test_codebuddy(self):
        cid, _, _, _ = identify_client("codebuddy/1.0.0")
        self.assertEqual(cid, "codebuddy")

    def test_kilo_code(self):
        cid, _, _, _ = identify_client("kilo-code/1.5.0")
        self.assertEqual(cid, "kilo_code")

    def test_kilo_prefix(self):
        cid, _, _, _ = identify_client("kilo/2.0")
        self.assertEqual(cid, "kilo_code")

    def test_antigravity(self):
        cid, _, _, _ = identify_client("antigravity/1.0")
        self.assertEqual(cid, "antigravity")

    def test_kiro(self):
        cid, name, _, _ = identify_client("kiro/1.0.0")
        self.assertEqual(cid, "kiro")
        self.assertEqual(name, "Kiro")

    def test_kiro_cli(self):
        cid, name, _, _ = identify_client("kiro-cli/0.5.0")
        self.assertEqual(cid, "kiro_cli")
        self.assertEqual(name, "Kiro CLI")

    def test_trae(self):
        cid, _, _, _ = identify_client("trae/1.0.0")
        self.assertEqual(cid, "trae")

    def test_qoder(self):
        cid, _, _, _ = identify_client("qoder/1.0.0")
        self.assertEqual(cid, "qoder")

    def test_warp(self):
        cid, _, _, _ = identify_client("warp/1.0.0")
        self.assertEqual(cid, "warp")

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
        cid, _name, ver, _raw = identify_client("")
        self.assertEqual(cid, "")
        self.assertEqual(ver, "")

    def test_none_ua(self):
        cid, _name, ver, _raw = identify_client(None)
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
    def test_returns_27_clients(self):
        clients = get_all_clients()
        self.assertEqual(len(clients), 27)
        self.assertIsInstance(clients[0], dict)
        self.assertIn("id", clients[0])

    def test_with_extra_clients(self):
        extra = ClientDef(
            id="enterprise_tool",
            display_name="Enterprise Tool",
            category="ide",
            provider="openai",
            ua_prefixes=("enterprise-tool/",),
            proxy_config=ProxyConfig(
                config_type=ProxyConfigType.ENV_VAR,
                env_var="OPENAI_BASE_URL",
                setup_cmd="OPENAI_BASE_URL=http://localhost:8080",
                setup_instructions="Set OPENAI_BASE_URL.",
            ),
            website="https://example.com",
        )
        clients = get_all_clients(extra_clients=[extra])
        self.assertEqual(len(clients), 28)
        self.assertEqual(clients[-1]["id"], "enterprise_tool")

    def test_with_extra_dict(self):
        extra = {"id": "custom", "display_name": "Custom Tool"}
        clients = get_all_clients(extra_clients=[extra])
        self.assertEqual(len(clients), 28)
        self.assertEqual(clients[-1]["id"], "custom")


class TestCLICommandExtension(unittest.TestCase):
    """Test CLI command extension hooks in ExtensionRegistry."""

    def test_register_and_retrieve(self):
        from lumen_argus.extensions import CliCommandDef, ExtensionRegistry

        reg = ExtensionRegistry()
        self.assertEqual(reg.get_extra_cli_commands(), [])

        commands = [
            CliCommandDef(
                name="enroll",
                help="Enroll this machine",
                arguments=[
                    {"args": ["--server"], "kwargs": {"default": "", "help": "Proxy URL"}},
                ],
                handler=lambda args: None,
            ),
            CliCommandDef(
                name="enrollment",
                help="Manage enrollments",
                handler=lambda args: None,
            ),
        ]
        reg.register_cli_commands(commands)
        result = reg.get_extra_cli_commands()
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].name, "enroll")
        self.assertEqual(result[1].name, "enrollment")

    def test_returns_copy(self):
        from lumen_argus.extensions import CliCommandDef, ExtensionRegistry

        reg = ExtensionRegistry()
        reg.register_cli_commands([CliCommandDef(name="test", handler=lambda a: None)])
        first = reg.get_extra_cli_commands()
        first.clear()
        self.assertEqual(len(reg.get_extra_cli_commands()), 1)

    def test_multiple_registrations_accumulate(self):
        from lumen_argus.extensions import CliCommandDef, ExtensionRegistry

        reg = ExtensionRegistry()
        reg.register_cli_commands([CliCommandDef(name="cmd1", handler=lambda a: None)])
        reg.register_cli_commands([CliCommandDef(name="cmd2", handler=lambda a: None)])
        self.assertEqual(len(reg.get_extra_cli_commands()), 2)

    def test_rejects_dict(self):
        from lumen_argus.extensions import ExtensionRegistry

        reg = ExtensionRegistry()
        with self.assertRaises(TypeError):
            reg.register_cli_commands([{"name": "bad", "handler": lambda a: None}])

    def test_rejects_empty_name(self):
        from lumen_argus.extensions import CliCommandDef, ExtensionRegistry

        reg = ExtensionRegistry()
        with self.assertRaises(ValueError):
            reg.register_cli_commands([CliCommandDef(name="", handler=lambda a: None)])

    def test_rejects_non_callable_handler(self):
        from lumen_argus.extensions import CliCommandDef, ExtensionRegistry

        reg = ExtensionRegistry()
        with self.assertRaises(ValueError):
            reg.register_cli_commands([CliCommandDef(name="broken", handler="not_callable")])


if __name__ == "__main__":
    unittest.main()
