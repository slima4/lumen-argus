"""Tests for the lumen-argus-agent CLI."""

import argparse
import io
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from lumen_argus_agent.cli import _run_uninstall
from lumen_argus_agent.uninstall import UninstallResult


class TestAgentCLI(unittest.TestCase):
    """Verify agent CLI commands work end-to-end."""

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "lumen_argus_agent", *args],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_version(self):
        result = self._run("--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn("lumen-argus-agent", result.stdout)

    def test_help(self):
        result = self._run("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("detect", result.stdout)
        self.assertIn("setup", result.stdout)
        self.assertIn("watch", result.stdout)
        self.assertIn("protection", result.stdout)
        self.assertIn("clients", result.stdout)
        self.assertIn("uninstall", result.stdout)

    def test_uninstall_help_documents_flags(self):
        result = self._run("uninstall", "--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--keep-data", result.stdout)
        self.assertIn("--non-interactive", result.stdout)

    def test_no_command_shows_help(self):
        result = self._run()
        self.assertNotEqual(result.returncode, 0)

    def test_clients_json(self):
        result = self._run("clients", "--json")
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertIn("clients", data)
        self.assertGreaterEqual(len(data["clients"]), 27)

    def test_clients_text(self):
        result = self._run("clients")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Claude Code", result.stdout)
        self.assertIn("Gemini CLI", result.stdout)

    def test_detect_json(self):
        result = self._run("detect", "--json")
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertIn("platform", data)
        self.assertIn("clients", data)
        self.assertIn("total_detected", data)

    def test_detect_audit(self):
        result = self._run("detect", "--audit")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Audit", result.stdout)

    def test_protection_status(self):
        result = self._run("protection", "status")
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertIn("enabled", data)

    def test_watch_status(self):
        result = self._run("watch", "--status")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Platform", result.stdout)


class TestRunUninstallHandler(unittest.TestCase):
    """Unit tests for the ``_run_uninstall`` dispatch wrapper.

    The end-to-end CLI is already covered via subprocess in
    ``TestAgentCLI`` above.  These tests pin the contract of the thin
    wrapper itself: JSON on stdout, exit-code mapping from
    ``UninstallResult.ok``, and correct propagation of ``--keep-data``
    into the call.  Running them in-process keeps the round-trip fast
    and lets us assert on the exact orchestrator call, which a
    subprocess test cannot observe.
    """

    @staticmethod
    def _args(*, keep_data: bool = False) -> argparse.Namespace:
        return argparse.Namespace(keep_data=keep_data, non_interactive=False)

    def test_prints_json_and_exits_zero_when_result_is_ok(self):
        ok_result = UninstallResult(steps={"protection_disable": "ok"})
        buf = io.StringIO()
        with (
            patch("lumen_argus_agent.cli.sys.stdout", buf),
            patch("lumen_argus_agent.uninstall.uninstall_agent", return_value=ok_result) as fake,
        ):
            _run_uninstall(self._args())  # does not raise SystemExit

        fake.assert_called_once_with(keep_data=False)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["steps"], {"protection_disable": "ok"})
        self.assertEqual(payload["errors"], [])

    def test_exits_nonzero_when_result_has_errors(self):
        failed = UninstallResult(
            steps={"protection_disable": "failed"},
            errors=["protection_disable: boom"],
        )
        buf = io.StringIO()
        with (
            patch("lumen_argus_agent.cli.sys.stdout", buf),
            patch("lumen_argus_agent.uninstall.uninstall_agent", return_value=failed),
            self.assertRaises(SystemExit) as cm,
        ):
            _run_uninstall(self._args())
        self.assertEqual(cm.exception.code, 1)
        # The JSON still has to be on stdout before the exit — callers
        # (tray app) parse it even on the failure path.
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["errors"], ["protection_disable: boom"])

    def test_keep_data_flag_is_forwarded(self):
        ok = UninstallResult(steps={"protection_disable": "ok"})
        with (
            patch("lumen_argus_agent.cli.sys.stdout", io.StringIO()),
            patch("lumen_argus_agent.uninstall.uninstall_agent", return_value=ok) as fake,
        ):
            _run_uninstall(self._args(keep_data=True))
        fake.assert_called_once_with(keep_data=True)


if __name__ == "__main__":
    unittest.main()
