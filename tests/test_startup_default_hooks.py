"""Tests for community default-hook registration in startup."""

import unittest

from lumen_argus.extensions import ExtensionRegistry
from lumen_argus.notifiers import WEBHOOK_CHANNEL_TYPE, build_notifier
from lumen_argus.redaction import redact_request_body
from lumen_argus.startup import register_default_hooks


class TestRegisterDefaultHooks(unittest.TestCase):
    def test_redact_default_registered(self):
        ext = ExtensionRegistry()
        self.assertIsNone(ext.get_redact_hook())
        register_default_hooks(ext)
        self.assertIs(ext.get_redact_hook(), redact_request_body)

    def test_plugin_redact_hook_not_clobbered(self):
        ext = ExtensionRegistry()

        def plugin_hook(body: bytes, findings: list) -> bytes:
            return body

        ext.set_redact_hook(plugin_hook)
        register_default_hooks(ext)
        self.assertIs(ext.get_redact_hook(), plugin_hook)

    def test_notifier_builder_default_registered(self):
        ext = ExtensionRegistry()
        self.assertIsNone(ext.get_notifier_builder())
        register_default_hooks(ext)
        self.assertIs(ext.get_notifier_builder(), build_notifier)

    def test_plugin_notifier_builder_not_clobbered(self):
        ext = ExtensionRegistry()

        def plugin_builder(channel: dict) -> object:
            return None

        ext.set_notifier_builder(plugin_builder)
        register_default_hooks(ext)
        self.assertIs(ext.get_notifier_builder(), plugin_builder)

    def test_channel_types_default_registered(self):
        ext = ExtensionRegistry()
        self.assertEqual(ext.get_channel_types(), {})
        register_default_hooks(ext)
        for name in WEBHOOK_CHANNEL_TYPE:
            self.assertIn(name, ext.get_channel_types())

    def test_plugin_channel_types_not_clobbered(self):
        ext = ExtensionRegistry()
        ext.register_channel_types({"slack": object()})
        register_default_hooks(ext)
        # Plugin's prior registration survives; community webhook default skipped.
        self.assertIn("slack", ext.get_channel_types())
        self.assertNotIn("webhook", ext.get_channel_types())

    def test_idempotent(self):
        ext = ExtensionRegistry()
        register_default_hooks(ext)
        first_redact = ext.get_redact_hook()
        first_builder = ext.get_notifier_builder()
        first_types = ext.get_channel_types()
        register_default_hooks(ext)
        self.assertIs(ext.get_redact_hook(), first_redact)
        self.assertIs(ext.get_notifier_builder(), first_builder)
        self.assertEqual(ext.get_channel_types(), first_types)


if __name__ == "__main__":
    unittest.main()
