"""Platform-specific persistent-environment operations.

On macOS, ``launchctl setenv`` / ``launchctl unsetenv`` control the
per-user environment inherited by processes started via launchd — the
GUI session, Spotlight, and any daemon or LaunchAgent.  Managed env
vars are mirrored into launchctl so AI tools launched from the Dock
(Claude Desktop, Cursor) see the same proxy base-URLs a terminal
shell would.

Design notes:

* **macOS-only by design.**  Linux systemd user environment and
  Windows user-env storage have different semantics and no product
  need today.  The function is a no-op on non-Darwin platforms so
  callers never branch.

* **Best-effort.**  ``launchctl unsetenv`` returns 0 for a name that
  was not set, so we cannot distinguish "successfully cleared" from
  "was never there".  The returned list therefore reflects the names
  we *attempted*, not strictly those that were present before the
  call.

* **No shell injection surface.**  Var names are joined into an argv
  list for a subprocess, so a strict POSIX-identifier whitelist is
  applied — anything outside ``[A-Za-z_][A-Za-z0-9_]*`` is skipped
  with a warning.

* **Domain alignment with the tray app.**  We invoke bare
  ``launchctl unsetenv`` without an ``asuser`` or ``gui/<uid>``
  target.  This is deliberate: the desktop tray sets the matching
  vars from its own process (login session) with bare
  ``launchctl setenv`` too, so both operations target the same
  domain.  If the tray ever switches to ``launchctl asuser`` or
  ``gui/<uid>`` for ``setenv``, this function must match — otherwise
  GUI apps stop seeing the unset and keep pointing at a dead proxy.
"""

from __future__ import annotations

import logging
import platform
import re
import shutil
import subprocess
from collections.abc import Iterable

log = logging.getLogger("argus.platform_env")

_VAR_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def clear_launchctl_env_vars(var_names: Iterable[str]) -> list[str]:
    """Run ``launchctl unsetenv`` for each name on macOS.

    Returns the list of names for which the ``launchctl`` invocation
    exited cleanly — useful as an audit record for structured output.
    On non-Darwin platforms, returns an empty list without touching
    anything.  An empty input returns an empty list without spawning
    any subprocess.

    Never raises.  Any ``OSError`` / non-zero exit is logged and the
    name is excluded from the returned list — callers that need
    strict cleanup can compare input and output sets.
    """
    names = [n for n in var_names if _VAR_NAME_RE.match(n)]
    skipped = [n for n in var_names if not _VAR_NAME_RE.match(n)]
    for bad in skipped:
        log.warning("skipping non-identifier var name: %r", bad)

    if not names:
        return []

    if platform.system() != "Darwin":
        log.debug("launchctl cleanup skipped: not macOS")
        return []

    launchctl = shutil.which("launchctl")
    if not launchctl:
        log.warning("launchctl not found on PATH — skipping env var cleanup")
        return []

    cleared: list[str] = []
    for name in names:
        try:
            result = subprocess.run(
                [launchctl, "unsetenv", name],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as e:
            log.warning("launchctl unsetenv %s failed: %s", name, e)
            continue
        if result.returncode != 0:
            log.warning(
                "launchctl unsetenv %s exited %d: %s",
                name,
                result.returncode,
                result.stderr.strip() or "<no stderr>",
            )
            continue
        cleared.append(name)
        log.info("launchctl unsetenv %s", name)

    return cleared
