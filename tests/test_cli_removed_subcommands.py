"""Tests for proxy-CLI subcommands that have been migrated to the agent.

``setup``, ``protection``, and ``watch`` are workstation concerns. The proxy
is a server binary and should not expose them. Invoking any of these names
on the proxy must exit non-zero with a pointer to the agent binary, and
the argparse surface itself must not know about them (so ``--help`` stays
uncluttered and argparse's own "invalid choice" message never runs).
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr
from unittest import mock

from lumen_argus.cli._dispatch import _REMOVED_SUBCOMMANDS, _reject_removed_subcommand
from lumen_argus.cli._parser import build_parser


class TestRejectRemovedSubcommand(unittest.TestCase):
    def test_each_removed_subcommand_exits_with_agent_pointer(self) -> None:
        for cmd, replacement in _REMOVED_SUBCOMMANDS.items():
            buf = io.StringIO()
            with self.subTest(cmd=cmd), redirect_stderr(buf), self.assertRaises(SystemExit) as ctx:
                _reject_removed_subcommand([cmd])
            self.assertEqual(ctx.exception.code, 2, "removed subcommand should exit 2, got %r" % ctx.exception.code)
            err = buf.getvalue()
            self.assertIn(cmd, err, "stderr must name the rejected subcommand")
            self.assertIn(replacement, err, "stderr must point at the agent replacement")

    def test_unrelated_subcommand_does_not_exit(self) -> None:
        # serve/detect/relay/scan/logs/rules/clients/mcp all survive on the
        # proxy — calling the helper with them must be a no-op.
        for cmd in ("serve", "detect", "relay", "scan", "logs", "rules", "clients", "mcp", "engine"):
            with self.subTest(cmd=cmd):
                _reject_removed_subcommand([cmd])  # would SystemExit on mismatch

    def test_empty_argv_is_noop(self) -> None:
        _reject_removed_subcommand([])  # argparse will produce its own "required" error

    def test_none_argv_reads_sys_argv(self) -> None:
        with mock.patch("sys.argv", ["lumen-argus", "setup"]):
            buf = io.StringIO()
            with redirect_stderr(buf), self.assertRaises(SystemExit) as ctx:
                _reject_removed_subcommand(None)
            self.assertEqual(ctx.exception.code, 2)
            self.assertIn("lumen-argus-agent setup", buf.getvalue())

    def test_logs_warning_on_rejection(self) -> None:
        with (
            self.assertLogs("argus.cli", level="WARNING") as captured,
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            _reject_removed_subcommand(["protection"])
        joined = "\n".join(captured.output)
        self.assertIn("protection", joined)
        self.assertIn("lumen-argus-agent protection", joined)


class TestParserDoesNotExposeRemovedSubcommands(unittest.TestCase):
    def test_build_parser_omits_removed_subcommands(self) -> None:
        _, subparsers = build_parser()
        exposed = set(subparsers.choices.keys())
        for cmd in _REMOVED_SUBCOMMANDS:
            self.assertNotIn(cmd, exposed, "proxy parser must not re-expose %r — it lives in lumen-argus-agent" % cmd)

    def test_build_parser_keeps_server_subcommands(self) -> None:
        _, subparsers = build_parser()
        exposed = set(subparsers.choices.keys())
        for cmd in ("serve", "engine", "relay", "scan", "logs", "rules", "clients", "detect", "mcp"):
            self.assertIn(cmd, exposed, "proxy parser dropped %r by mistake" % cmd)


if __name__ == "__main__":
    unittest.main()
