"""Tests for ``lumen_argus_core.platform_env`` — launchctl env cleanup.

The module is macOS-only in behaviour but must be importable and
no-op on every platform, so the test matrix exercises both branches:

* the Darwin path calls ``launchctl unsetenv`` once per var name and
  tolerates per-name failures,
* the non-Darwin path returns an empty list without spawning anything.

We patch ``platform.system`` and ``subprocess.run`` rather than using
a real ``launchctl`` so the suite runs identically on Linux CI.
"""

from __future__ import annotations

import subprocess
import unittest
from unittest.mock import MagicMock, patch

from lumen_argus_core.platform_env import clear_launchctl_env_vars


class TestClearLaunchctlEnvVars(unittest.TestCase):
    def test_empty_input_returns_empty_without_spawning(self):
        with patch("lumen_argus_core.platform_env.subprocess.run") as run:
            result = clear_launchctl_env_vars([])
        self.assertEqual(result, [])
        run.assert_not_called()

    def test_non_darwin_returns_empty(self):
        with (
            patch("lumen_argus_core.platform_env.platform.system", return_value="Linux"),
            patch("lumen_argus_core.platform_env.subprocess.run") as run,
        ):
            result = clear_launchctl_env_vars(["ANTHROPIC_BASE_URL"])
        self.assertEqual(result, [])
        run.assert_not_called()

    def test_darwin_calls_launchctl_once_per_name(self):
        run = MagicMock(return_value=MagicMock(returncode=0, stderr=""))
        with (
            patch("lumen_argus_core.platform_env.platform.system", return_value="Darwin"),
            patch("lumen_argus_core.platform_env.shutil.which", return_value="/bin/launchctl"),
            patch("lumen_argus_core.platform_env.subprocess.run", run),
        ):
            result = clear_launchctl_env_vars(["ANTHROPIC_BASE_URL", "OPENAI_BASE_URL"])
        self.assertEqual(result, ["ANTHROPIC_BASE_URL", "OPENAI_BASE_URL"])
        self.assertEqual(run.call_count, 2)
        for call, expected_name in zip(run.call_args_list, ["ANTHROPIC_BASE_URL", "OPENAI_BASE_URL"]):
            args = call.args[0]
            self.assertEqual(args[0], "/bin/launchctl")
            self.assertEqual(args[1], "unsetenv")
            self.assertEqual(args[2], expected_name)

    def test_nonzero_exit_is_excluded_from_result(self):
        def side_effect(argv, **_kw):
            # second call fails
            name = argv[2]
            rc = 0 if name == "ANTHROPIC_BASE_URL" else 1
            return MagicMock(returncode=rc, stderr="boom")

        with (
            patch("lumen_argus_core.platform_env.platform.system", return_value="Darwin"),
            patch("lumen_argus_core.platform_env.shutil.which", return_value="/bin/launchctl"),
            patch("lumen_argus_core.platform_env.subprocess.run", side_effect=side_effect),
        ):
            result = clear_launchctl_env_vars(["ANTHROPIC_BASE_URL", "BROKEN"])
        self.assertEqual(result, ["ANTHROPIC_BASE_URL"])

    def test_oserror_is_swallowed_and_excluded(self):
        def side_effect(argv, **_kw):
            if argv[2] == "BAD":
                raise OSError("boom")
            return MagicMock(returncode=0, stderr="")

        with (
            patch("lumen_argus_core.platform_env.platform.system", return_value="Darwin"),
            patch("lumen_argus_core.platform_env.shutil.which", return_value="/bin/launchctl"),
            patch("lumen_argus_core.platform_env.subprocess.run", side_effect=side_effect),
        ):
            result = clear_launchctl_env_vars(["GOOD", "BAD"])
        self.assertEqual(result, ["GOOD"])

    def test_subprocess_timeout_is_swallowed_and_excluded(self):
        def side_effect(argv, **_kw):
            raise subprocess.TimeoutExpired(cmd=argv, timeout=5)

        with (
            patch("lumen_argus_core.platform_env.platform.system", return_value="Darwin"),
            patch("lumen_argus_core.platform_env.shutil.which", return_value="/bin/launchctl"),
            patch("lumen_argus_core.platform_env.subprocess.run", side_effect=side_effect),
        ):
            result = clear_launchctl_env_vars(["SLOW"])
        self.assertEqual(result, [])

    def test_non_identifier_names_are_skipped(self):
        """Shell-injection defence — var names must match [A-Za-z_][A-Za-z0-9_]*."""
        run = MagicMock(return_value=MagicMock(returncode=0, stderr=""))
        with (
            patch("lumen_argus_core.platform_env.platform.system", return_value="Darwin"),
            patch("lumen_argus_core.platform_env.shutil.which", return_value="/bin/launchctl"),
            patch("lumen_argus_core.platform_env.subprocess.run", run),
        ):
            result = clear_launchctl_env_vars(["OK", "BAD NAME", "; rm -rf /", "1BAD", ""])
        self.assertEqual(result, ["OK"])
        self.assertEqual(run.call_count, 1)

    def test_missing_launchctl_binary_returns_empty(self):
        """Defensive: a macOS machine without launchctl on PATH (extremely
        rare, but we must not crash) — no subprocess call, empty result.
        """
        run = MagicMock()
        with (
            patch("lumen_argus_core.platform_env.platform.system", return_value="Darwin"),
            patch("lumen_argus_core.platform_env.shutil.which", return_value=None),
            patch("lumen_argus_core.platform_env.subprocess.run", run),
        ):
            result = clear_launchctl_env_vars(["ANTHROPIC_BASE_URL"])
        self.assertEqual(result, [])
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
