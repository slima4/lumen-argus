"""Workstation uninstall orchestrator.

Reverses every system change the agent made during ``setup`` /
``protection enable`` / ``enroll`` / MCP wrapping, and removes the
data files the agent itself writes to ``~/.lumen-argus/``.

Scope (what this module owns):

* Tool configs (AI CLI env vars, IDE settings, OpenCode providers) —
  delegated to :func:`lumen_argus_core.setup.undo.undo_setup`.
* MCP wrappers — delegated to
  :func:`lumen_argus_core.mcp_setup.undo_mcp_setup`.
* Shell env file + OpenCode overrides + launchctl vars — delegated to
  :func:`lumen_argus_core.setup.protection.disable_protection`.
* Agent-written state files (``env``, ``enrollment.json``,
  ``relay.json``) — removed here.

Out of scope (tray app / desktop-only — we deliberately do NOT touch):

* ``.app-path``, ``license.key``, ``trial.json``, ``bin/``,
  LaunchAgent plists, the application bundle, App Support / Logs
  directories.  These belong to the desktop installer.
* ``forward-proxy-aliases.sh`` is cleared by ``undo_setup`` (which
  the orchestrator calls), so no extra handling is needed here.

Ordering is load-bearing:

1. ``disable_protection`` runs first so it snapshots the managed env
   vars *before* anything truncates the env file, and then hands
   those names to ``launchctl unsetenv`` (macOS).  If this ran after
   ``undo_setup`` it would find an already-empty file and the GUI
   env would stay stale.
2. ``undo_mcp_setup`` next — independent of env state.
3. ``undo_setup`` last among the reverts — re-truncates the env file
   idempotently, removes shell-profile source blocks, restores IDE
   settings from backups.
4. Data file removal — after everything above has emitted its state,
   so a failure earlier still leaves a machine the next ``uninstall``
   run can clean up.

Each step is best-effort — a failure in one step is logged and the
orchestrator continues.  The returned dict carries a per-step status
(``ok`` / ``failed`` / ``skipped``) plus structured error messages so
callers (tray app, shell scripts) have machine-readable output without
having to parse stderr.  Exit-code mapping is the caller's job; this
module intentionally does not call ``sys.exit``.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass, field

from lumen_argus_agent.relay import RELAY_STATE_PATH
from lumen_argus_core.enrollment import ENROLLMENT_FILE
from lumen_argus_core.mcp_setup import undo_mcp_setup
from lumen_argus_core.setup._paths import _ENV_FILE, _ENV_LOCK
from lumen_argus_core.setup.protection import disable_protection
from lumen_argus_core.setup.undo import undo_setup

log = logging.getLogger("argus.agent.uninstall")


_AGENT_DATA_FILES: tuple[str, ...] = (
    _ENV_FILE,
    _ENV_LOCK,
    ENROLLMENT_FILE,
    RELAY_STATE_PATH,
)


@dataclass
class UninstallResult:
    """Structured outcome of an uninstall run.

    * ``steps`` — ordered per-step status keyed by stable identifiers
      (``protection_disable``, ``mcp_undo``, ``setup_undo``,
      ``data_files_removed``).  Values are one of ``ok`` / ``failed``
      / ``skipped``.
    * ``launchctl_vars_cleared`` — macOS-only audit list; empty on
      other platforms.
    * ``data_files_removed`` — absolute paths that existed before the
      run and no longer exist after it.
    * ``errors`` — human-readable error strings, one per failing step.
      A non-empty list drives the CLI exit code to 1.
    """

    steps: dict[str, str] = field(default_factory=dict)
    launchctl_vars_cleared: list[str] = field(default_factory=list)
    data_files_removed: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @property
    def ok(self) -> bool:
        """True when every step completed without raising."""
        return not self.errors


def uninstall_agent(*, keep_data: bool = False) -> UninstallResult:
    """Reverse every system change the agent made.

    ``keep_data=True`` skips removal of agent-written state files —
    the mode the desktop tray app uses when it plans to
    ``rm -rf ~/.lumen-argus/`` itself immediately afterwards.  CLI
    users (``pip``, ``brew``, source install) want the default
    (``keep_data=False``) so the filesystem is clean after the
    command returns.
    """
    result = UninstallResult()

    _run_step(result, "protection_disable", _step_protection_disable)
    _run_step(result, "mcp_undo", _step_mcp_undo)
    _run_step(result, "setup_undo", _step_setup_undo)

    if keep_data:
        result.steps["data_files_removed"] = "skipped"
    else:
        _run_step(result, "data_files_removed", _step_remove_data_files)

    return result


# ---------------------------------------------------------------------------
# Step implementations
# ---------------------------------------------------------------------------


def _step_protection_disable(result: UninstallResult) -> None:
    status = disable_protection()
    cleared = status.get("launchctl_vars_cleared", [])
    if isinstance(cleared, list):
        result.launchctl_vars_cleared = [str(n) for n in cleared]


def _step_mcp_undo(result: UninstallResult) -> None:
    count = undo_mcp_setup()
    log.info("unwrapped %d MCP server(s)", count)


def _step_setup_undo(result: UninstallResult) -> None:
    count = undo_setup()
    log.info("reverted %d setup change(s)", count)


def _step_remove_data_files(result: UninstallResult) -> None:
    for path in _AGENT_DATA_FILES:
        if not os.path.lexists(path):
            continue
        try:
            os.remove(path)
        except OSError as e:
            msg = "could not remove %s: %s" % (path, e)
            log.warning(msg)
            result.errors.append("data_files_removed: %s" % msg)
            continue
        result.data_files_removed.append(path)
        log.info("removed %s", path)


# ---------------------------------------------------------------------------
# Step runner
# ---------------------------------------------------------------------------


def emit_and_exit(result: UninstallResult) -> None:
    """Print the structured result as JSON and exit non-zero on any failure.

    Both CLI entry points share this so a caller gets the same stdout
    shape and exit-code mapping regardless of which binary they ran.
    """
    print(json.dumps(result.to_dict(), indent=2))
    if not result.ok:
        sys.exit(1)


def main() -> None:
    """Standalone ``lumen-argus-uninstall`` console_scripts entry point.

    Equivalent to ``lumen-argus-agent uninstall`` — exists so users who
    just ran ``pip uninstall lumen-argus-agent`` (and therefore no
    longer have the ``lumen-argus-agent`` binary) can still run
    cleanup by name discovery.  Same flags, same JSON output, same
    exit codes.
    """
    parser = argparse.ArgumentParser(
        prog="lumen-argus-uninstall",
        description=(
            "Reverse every system change the lumen-argus agent made: "
            "tool configurations, MCP wrappers, shell env file, "
            "launchctl env vars (macOS), and agent-owned state files."
        ),
    )
    parser.add_argument(
        "--keep-data",
        action="store_true",
        help=(
            "Skip removal of agent-owned state files "
            "(~/.lumen-argus/env, enrollment.json, relay.json). "
            "Use when the caller plans to remove ~/.lumen-argus/ itself."
        ),
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="(No-op — uninstall is always non-interactive. Flag accepted for script compatibility.)",
    )
    args = parser.parse_args()
    emit_and_exit(uninstall_agent(keep_data=args.keep_data))


def _run_step(result: UninstallResult, name: str, fn: Callable[[UninstallResult], None]) -> None:
    """Execute one step, recording success/failure on the result object.

    Catching ``Exception`` here is intentional: the orchestrator's
    contract is "best-effort, keep going" so that a partially-broken
    machine (e.g., unreadable IDE settings file) still gets its env
    file emptied and its launchctl state cleared.  A narrower
    ``except`` would let unexpected subclasses (``json.JSONDecodeError``
    from a corrupt config, ``PermissionError`` from a read-only file)
    abort the remaining steps.
    """
    try:
        fn(result)
        result.steps[name] = "ok"
    except Exception as e:
        result.steps[name] = "failed"
        result.errors.append("%s: %s" % (name, e))
        log.error("%s failed: %s", name, e, exc_info=True)
