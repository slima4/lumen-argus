"""Tests for the lumen-argus-agent CLI."""

import json
import subprocess
import sys
import unittest


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


if __name__ == "__main__":
    unittest.main()
