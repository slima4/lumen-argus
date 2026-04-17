"""Tests for ``lumen_argus_core.env_template`` — dual-mode env file body.

Two lifecycle owners produce two body shapes:

* ``ManagedBy.CLI`` — unconditional exports, no liveness guard.  The
  user owns the lifecycle.
* ``ManagedBy.TRAY`` — exports wrapped in a self-healing guard that
  activates only when the tray-app bundle is present or the enrolled
  relay PID is alive.

Test layout:

* ``TestRenderBody`` — pure-function assertions on both modes.
* ``TestCliBodyBash`` — sources the CLI body in a real bash and
  confirms the exports are unconditional (present regardless of
  markers / missing markers).
* ``TestTrayBodyBash`` — sources the TRAY body in a real bash and
  walks the five activation-matrix scenarios from the A2 checklist of
  ``clean-uninstall-and-self-healing-spec.md``.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest

from lumen_argus_core.env_template import ManagedBy, parse_header_managed_by, render_body

_TAG = "# lumen-argus:managed"
_ENTRIES = [("ANTHROPIC_BASE_URL", "http://127.0.0.1:8070", "claude_code")]


# ---------------------------------------------------------------------------
# Pure function tests
# ---------------------------------------------------------------------------


class TestRenderBody(unittest.TestCase):
    # -- shared contract (both modes) ----------------------------------

    def test_empty_entries_return_empty_string_cli(self):
        self.assertEqual(render_body([], _TAG, managed_by=ManagedBy.CLI), "")

    def test_empty_entries_return_empty_string_tray(self):
        self.assertEqual(render_body([], _TAG, managed_by=ManagedBy.TRAY), "")

    def test_both_modes_mark_the_body_with_a_header(self):
        cli_body = render_body(_ENTRIES, _TAG, managed_by=ManagedBy.CLI)
        tray_body = render_body(_ENTRIES, _TAG, managed_by=ManagedBy.TRAY)
        self.assertIn("lumen-argus:managed-env", cli_body)
        self.assertIn("lumen-argus:managed-env", tray_body)

    def test_header_encodes_managed_by_mode(self):
        """The header string carries the mode so logs / status make sense."""
        self.assertIn("(cli)", render_body(_ENTRIES, _TAG, managed_by=ManagedBy.CLI))
        self.assertIn("(tray)", render_body(_ENTRIES, _TAG, managed_by=ManagedBy.TRAY))

    # -- CLI mode ------------------------------------------------------

    def test_cli_mode_has_no_guard(self):
        body = render_body(_ENTRIES, _TAG, managed_by=ManagedBy.CLI)
        for guard_token in ("_la_active", "kill -0", ".app-path", "enrollment.json", "relay.json"):
            self.assertNotIn(guard_token, body, f"CLI body must not contain guard token {guard_token!r}")

    def test_cli_mode_exports_are_unindented(self):
        """No wrapping ``if``, so exports sit at column 0."""
        body = render_body(_ENTRIES, _TAG, managed_by=ManagedBy.CLI)
        self.assertIn(
            "\nexport ANTHROPIC_BASE_URL=http://127.0.0.1:8070  # lumen-argus:managed client=claude_code\n", body
        )

    def test_cli_mode_preserves_orphan_format(self):
        body = render_body([("CUSTOM", "http://x", "")], _TAG, managed_by=ManagedBy.CLI)
        self.assertIn("\nexport CUSTOM=http://x  # lumen-argus:managed\n", body)
        self.assertNotIn("client=", body)

    # -- TRAY mode -----------------------------------------------------

    def test_tray_mode_has_full_guard(self):
        body = render_body(_ENTRIES, _TAG, managed_by=ManagedBy.TRAY)
        for expected in ("_la_active=0", "enrollment.json", "relay.json", ".app-path", "kill -0"):
            self.assertIn(expected, body)

    def test_tray_mode_exports_are_indented(self):
        """Inside the ``if ... ; then`` block exports are two-space indented."""
        body = render_body(_ENTRIES, _TAG, managed_by=ManagedBy.TRAY)
        self.assertIn(
            "\n  export ANTHROPIC_BASE_URL=http://127.0.0.1:8070  # lumen-argus:managed client=claude_code\n", body
        )

    def test_tray_guard_uses_no_subprocesses(self):
        """Hard requirement: zero subprocess invocations in the guard."""
        body = render_body(_ENTRIES, _TAG, managed_by=ManagedBy.TRAY)
        for forbidden in ("python", "python3", "grep", "sed", "awk", "curl", "jq", "cat"):
            self.assertNotIn(forbidden, body, f"tray guard must not spawn {forbidden!r}")

    def test_tray_mode_preserves_orphan_format(self):
        body = render_body([("CUSTOM", "http://x", "")], _TAG, managed_by=ManagedBy.TRAY)
        self.assertIn("\n  export CUSTOM=http://x  # lumen-argus:managed\n", body)
        self.assertNotIn("client=", body)

    def test_render_body_rejects_unknown_mode(self):
        """A non-``ManagedBy`` value must raise, not silently emit the
        CLI shape.  Otherwise a future mode added to the enum would
        strip the liveness guard from enrolled machines the moment any
        caller pointed it at ``render_body``.
        """

        class _Fake:
            value = "fleet"

        with self.assertRaises(ValueError):
            render_body(_ENTRIES, _TAG, managed_by=_Fake())  # type: ignore[arg-type]


class TestParseHeaderManagedBy(unittest.TestCase):
    """Parser must be symmetric with the rendered headers."""

    def test_cli_header_round_trips(self):
        body = render_body(_ENTRIES, _TAG, managed_by=ManagedBy.CLI)
        first_line = body.splitlines()[0] + "\n"
        self.assertEqual(parse_header_managed_by(first_line), ManagedBy.CLI)

    def test_tray_header_round_trips(self):
        body = render_body(_ENTRIES, _TAG, managed_by=ManagedBy.TRAY)
        first_line = body.splitlines()[0] + "\n"
        self.assertEqual(parse_header_managed_by(first_line), ManagedBy.TRAY)

    def test_empty_line_returns_none(self):
        self.assertIsNone(parse_header_managed_by(""))

    def test_unrelated_header_returns_none(self):
        self.assertIsNone(parse_header_managed_by("# just a comment\n"))

    def test_truncated_header_returns_none(self):
        """Header prefix matches but the closing paren is missing."""
        self.assertIsNone(parse_header_managed_by("# lumen-argus:managed-env (cli\n"))

    def test_unknown_mode_returns_none(self):
        """Forward-compat: an unrecognised mode is ignored rather than
        raising — a reader built against this schema should not crash on
        a file written by a newer schema."""
        self.assertIsNone(parse_header_managed_by("# lumen-argus:managed-env (fleet) — do not edit manually\n"))


# ---------------------------------------------------------------------------
# Real-bash integration tests
# ---------------------------------------------------------------------------


class _BashSourceCase(unittest.TestCase):
    """Shared helpers — subclasses pick the ``managed_by`` mode."""

    MANAGED_BY: ManagedBy = ManagedBy.CLI  # overridden

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.argus_dir = os.path.join(self.tmpdir, ".lumen-argus")
        os.makedirs(self.argus_dir, mode=0o700)
        self.env_file = os.path.join(self.argus_dir, "env")
        with open(self.env_file, "w", encoding="utf-8") as f:
            f.write(render_body(_ENTRIES, _TAG, managed_by=self.MANAGED_BY))

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _source(self, var: str) -> str:
        """Source the rendered env file in a clean bash and echo ``var``."""
        script = f'. "$HOME/.lumen-argus/env"; printf "%s" "${{{var}-}}"'
        env = {"HOME": self.tmpdir, "PATH": os.environ.get("PATH", "")}
        result = subprocess.run(
            ["bash", "-c", script],
            env=env,
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, msg=f"bash failed: {result.stderr!r}")
        return result.stdout

    def _write_relay_state(self, pid: int) -> None:
        state = {
            "port": 8070,
            "bind": "127.0.0.1",
            "upstream_url": "http://localhost:8080",
            "pid": pid,
            "started_at": "2026-04-17T00:00:00Z",
        }
        with open(os.path.join(self.argus_dir, "relay.json"), "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)

    def _write_enrollment(self) -> None:
        with open(os.path.join(self.argus_dir, "enrollment.json"), "w", encoding="utf-8") as f:
            json.dump({"org": "test"}, f)

    def _write_app_path(self, path: str) -> None:
        with open(os.path.join(self.argus_dir, ".app-path"), "w", encoding="utf-8") as f:
            f.write(path)

    # Larger than every Unix PID_MAX on the platforms we care about
    # (Linux ≤ 2^22, macOS ≤ 99999), so ``kill -0`` on it is guaranteed
    # to fail.  Used instead of reap-then-read to avoid PID recycling
    # flakiness on hot CI runners.
    _DEAD_PID = 999_999_999


class TestCliBodyBash(_BashSourceCase):
    """CLI body must always export — markers are irrelevant."""

    MANAGED_BY = ManagedBy.CLI

    def test_exports_active_with_no_markers(self):
        self.assertEqual(self._source("ANTHROPIC_BASE_URL"), "http://127.0.0.1:8070")

    def test_exports_active_even_if_app_path_is_dangling(self):
        """CLI mode deliberately ignores .app-path — user owns lifecycle."""
        self._write_app_path(os.path.join(self.tmpdir, "nowhere"))
        self.assertEqual(self._source("ANTHROPIC_BASE_URL"), "http://127.0.0.1:8070")

    def test_exports_active_regardless_of_enrollment_or_relay(self):
        self._write_enrollment()
        self._write_relay_state(self._DEAD_PID)
        self.assertEqual(self._source("ANTHROPIC_BASE_URL"), "http://127.0.0.1:8070")


class TestTrayBodyBash(_BashSourceCase):
    """TRAY body only exports when the liveness guard activates."""

    MANAGED_BY = ManagedBy.TRAY

    def test_no_markers_no_exports(self):
        self.assertEqual(self._source("ANTHROPIC_BASE_URL"), "")

    def test_app_path_pointing_to_deleted_dir_no_exports(self):
        self._write_app_path(os.path.join(self.tmpdir, "does-not-exist"))
        self.assertEqual(self._source("ANTHROPIC_BASE_URL"), "")

    def test_app_path_valid_exports_active(self):
        self._write_app_path(self.tmpdir)
        self.assertEqual(self._source("ANTHROPIC_BASE_URL"), "http://127.0.0.1:8070")

    def test_enrolled_with_live_relay_exports_active_even_without_app_path(self):
        self._write_enrollment()
        self._write_relay_state(os.getpid())
        self.assertEqual(self._source("ANTHROPIC_BASE_URL"), "http://127.0.0.1:8070")

    def test_enrolled_but_relay_dead_and_no_app_path_no_exports(self):
        self._write_enrollment()
        self._write_relay_state(self._DEAD_PID)
        self.assertEqual(self._source("ANTHROPIC_BASE_URL"), "")


if __name__ == "__main__":
    unittest.main()
