"""Tests for ``lumen_argus_agent.uninstall`` — workstation uninstall orchestrator.

The orchestrator composes three primitives (``disable_protection``,
``undo_mcp_setup``, ``undo_setup``) and adds agent-owned data file
removal on top.  Tests patch the primitives so the orchestrator's
own contract — step ordering, best-effort error handling, keep-data
branching, structured result — is exercised in isolation from the
full setup wizard.

End-to-end coverage of the underlying primitives lives in
``packages/core/tests/test_setup_wizard.py`` and
``packages/core/tests/test_mcp_setup.py``; re-testing them here would
only couple this suite to unrelated refactors.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from lumen_argus_agent.uninstall import UninstallResult, uninstall_agent


def _ok_disable() -> dict[str, object]:
    return {
        "enabled": False,
        "env_file": "/ignored",
        "env_vars_set": 0,
        "managed_by": None,
        "launchctl_vars_cleared": ["ANTHROPIC_BASE_URL", "OPENAI_BASE_URL"],
    }


class TestUninstallHappyPath(unittest.TestCase):
    """All steps succeed on a cleanly-set-up machine."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        # Seed plausible agent-owned state files so the removal step has
        # something to delete.  The orchestrator uses module-level path
        # constants; we patch those to point into tmpdir.
        self.env = os.path.join(self.tmpdir, "env")
        self.env_lock = os.path.join(self.tmpdir, ".env.lock")
        self.enrollment = os.path.join(self.tmpdir, "enrollment.json")
        self.relay = os.path.join(self.tmpdir, "relay.json")
        for path in (self.env, self.env_lock, self.enrollment, self.relay):
            with open(path, "w") as f:
                f.write("{}\n")
        self._patches = [
            patch(
                "lumen_argus_agent.uninstall._AGENT_DATA_FILES",
                (self.env, self.env_lock, self.enrollment, self.relay),
            ),
            patch("lumen_argus_agent.uninstall.disable_protection", return_value=_ok_disable()),
            patch("lumen_argus_agent.uninstall.undo_mcp_setup", return_value=3),
            patch("lumen_argus_agent.uninstall.undo_setup", return_value=7),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_runs_all_steps_in_order(self):
        result = uninstall_agent()
        self.assertEqual(
            result.steps,
            {
                "protection_disable": "ok",
                "mcp_undo": "ok",
                "setup_undo": "ok",
                "data_files_removed": "ok",
            },
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.errors, [])

    def test_surfaces_launchctl_cleared_from_disable_status(self):
        result = uninstall_agent()
        self.assertEqual(
            result.launchctl_vars_cleared,
            ["ANTHROPIC_BASE_URL", "OPENAI_BASE_URL"],
        )

    def test_removes_every_agent_data_file(self):
        result = uninstall_agent()
        self.assertEqual(
            set(result.data_files_removed),
            {self.env, self.env_lock, self.enrollment, self.relay},
        )
        for path in (self.env, self.env_lock, self.enrollment, self.relay):
            self.assertFalse(os.path.exists(path), "%s must be removed" % path)

    def test_keep_data_skips_file_removal(self):
        result = uninstall_agent(keep_data=True)
        self.assertEqual(result.steps["data_files_removed"], "skipped")
        self.assertEqual(result.data_files_removed, [])
        # And the files are still there.
        for path in (self.env, self.env_lock, self.enrollment, self.relay):
            self.assertTrue(os.path.exists(path), "%s must NOT be removed" % path)

    def test_result_is_json_serialisable(self):
        import json

        result = uninstall_agent()
        payload = json.dumps(result.to_dict())
        self.assertIn('"protection_disable"', payload)
        self.assertIn('"launchctl_vars_cleared"', payload)


class TestUninstallBestEffort(unittest.TestCase):
    """Orchestrator continues past failures, records them, returns non-ok."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.env = os.path.join(self.tmpdir, "env")
        with open(self.env, "w") as f:
            f.write("")
        self._patches = [
            patch(
                "lumen_argus_agent.uninstall._AGENT_DATA_FILES",
                (self.env,),
            ),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_failure_in_one_step_does_not_abort_others(self):
        with (
            patch(
                "lumen_argus_agent.uninstall.disable_protection",
                side_effect=RuntimeError("proxy not reachable"),
            ),
            patch("lumen_argus_agent.uninstall.undo_mcp_setup", return_value=0),
            patch("lumen_argus_agent.uninstall.undo_setup", return_value=0),
        ):
            result = uninstall_agent()

        self.assertEqual(result.steps["protection_disable"], "failed")
        self.assertEqual(result.steps["mcp_undo"], "ok")
        self.assertEqual(result.steps["setup_undo"], "ok")
        self.assertEqual(result.steps["data_files_removed"], "ok")
        self.assertFalse(result.ok)
        self.assertEqual(len(result.errors), 1)
        self.assertIn("proxy not reachable", result.errors[0])
        self.assertIn("protection_disable", result.errors[0])
        # The env file still got removed — subsequent steps ran.
        self.assertFalse(os.path.exists(self.env))

    def test_two_failures_record_two_errors(self):
        with (
            patch("lumen_argus_agent.uninstall.disable_protection", side_effect=RuntimeError("a")),
            patch("lumen_argus_agent.uninstall.undo_mcp_setup", side_effect=RuntimeError("b")),
            patch("lumen_argus_agent.uninstall.undo_setup", return_value=0),
        ):
            result = uninstall_agent()
        self.assertEqual(result.steps["protection_disable"], "failed")
        self.assertEqual(result.steps["mcp_undo"], "failed")
        self.assertEqual(len(result.errors), 2)


class TestUninstallIdempotent(unittest.TestCase):
    """Running uninstall on a clean machine is a no-op (data files absent)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._patches = [
            # Point at paths that do not exist
            patch(
                "lumen_argus_agent.uninstall._AGENT_DATA_FILES",
                (os.path.join(self.tmpdir, "nope"),),
            ),
            patch("lumen_argus_agent.uninstall.disable_protection", return_value=_ok_disable()),
            patch("lumen_argus_agent.uninstall.undo_mcp_setup", return_value=0),
            patch("lumen_argus_agent.uninstall.undo_setup", return_value=0),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_no_data_files_still_reports_ok(self):
        result = uninstall_agent()
        self.assertTrue(result.ok)
        self.assertEqual(result.data_files_removed, [])
        self.assertEqual(result.steps["data_files_removed"], "ok")


class TestStandaloneMain(unittest.TestCase):
    """Tests for the ``lumen-argus-uninstall`` console_scripts entry.

    ``main()`` parses its own argv (so ``pip uninstall lumen-argus-agent``
    victims can still run cleanup by binary name) and reuses
    ``emit_and_exit`` with ``uninstall_agent``.  These pin that the
    standalone entry matches the sub-command entry's contract:
    same JSON shape, same exit-code mapping, same keep-data semantics.
    """

    def test_exit_zero_on_clean_run(self):
        from lumen_argus_agent.uninstall import UninstallResult, main

        ok = UninstallResult(steps={"protection_disable": "ok"})
        with (
            patch("sys.argv", ["lumen-argus-uninstall"]),
            patch("lumen_argus_agent.uninstall.uninstall_agent", return_value=ok) as fake,
        ):
            main()  # no SystemExit
        fake.assert_called_once_with(keep_data=False)

    def test_exit_one_on_errors(self):
        import io

        from lumen_argus_agent.uninstall import UninstallResult, main

        failed = UninstallResult(
            steps={"protection_disable": "failed"},
            errors=["protection_disable: boom"],
        )
        buf = io.StringIO()
        with (
            patch("sys.argv", ["lumen-argus-uninstall"]),
            patch("sys.stdout", buf),
            patch("lumen_argus_agent.uninstall.uninstall_agent", return_value=failed),
            self.assertRaises(SystemExit) as cm,
        ):
            main()
        self.assertEqual(cm.exception.code, 1)
        # Machine-readable output still lands on stdout on failure.
        import json

        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["errors"], ["protection_disable: boom"])

    def test_keep_data_flag_is_forwarded(self):
        from lumen_argus_agent.uninstall import UninstallResult, main

        ok = UninstallResult(steps={"protection_disable": "ok"})
        with (
            patch("sys.argv", ["lumen-argus-uninstall", "--keep-data"]),
            patch("lumen_argus_agent.uninstall.uninstall_agent", return_value=ok) as fake,
        ):
            main()
        fake.assert_called_once_with(keep_data=True)

    def test_non_interactive_flag_parses_and_is_ignored(self):
        """Flag is a no-op (uninstall has no prompts) but must parse
        so scripts passing it blindly do not crash.
        """
        from lumen_argus_agent.uninstall import UninstallResult, main

        ok = UninstallResult(steps={"protection_disable": "ok"})
        with (
            patch("sys.argv", ["lumen-argus-uninstall", "--non-interactive"]),
            patch("lumen_argus_agent.uninstall.uninstall_agent", return_value=ok),
        ):
            main()  # does not raise SystemExit from argparse


class TestUninstallResult(unittest.TestCase):
    """Sanity: the dataclass has the shape the CLI writes out."""

    def test_default_result_serialises_cleanly(self):
        r = UninstallResult()
        d = r.to_dict()
        self.assertEqual(d["steps"], {})
        self.assertEqual(d["launchctl_vars_cleared"], [])
        self.assertEqual(d["data_files_removed"], [])
        self.assertEqual(d["errors"], [])

    def test_ok_true_when_no_errors(self):
        r = UninstallResult()
        r.steps["x"] = "ok"
        self.assertTrue(r.ok)

    def test_ok_false_when_errors_present(self):
        r = UninstallResult()
        r.errors.append("something broke")
        self.assertFalse(r.ok)


if __name__ == "__main__":
    unittest.main()
