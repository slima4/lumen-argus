"""Precmd hook — runs ``lumen-argus detect --check-quiet`` on every new shell."""

from __future__ import annotations

import logging
import os

from lumen_argus_core.setup._models import SetupChange
from lumen_argus_core.setup._paths import MANAGED_TAG
from lumen_argus_core.setup.manifest import _backup_file, _detect_shell_profile
from lumen_argus_core.time_utils import now_iso

log = logging.getLogger("argus.setup.shell_hook")

_SHELL_HOOK_LINE = 'eval "$(lumen-argus detect --check-quiet 2>/dev/null)"'
_SHELL_HOOK_TAG = "%s type=hook" % MANAGED_TAG


def install_shell_hook(profile_path: str = "", dry_run: bool = False) -> SetupChange | None:
    """Install a precmd hook that warns about unconfigured tools on every new shell.

    The hook completes in <100ms and prints to stderr only when
    unconfigured tools are found. Idempotent.
    """
    if not profile_path:
        profile_path = _detect_shell_profile()

    if os.path.isfile(profile_path):
        try:
            with open(profile_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            if "lumen-argus detect --check-quiet" in content:
                log.info("shell hook already installed in %s", profile_path)
                return None
        except OSError as e:
            log.error("could not read %s: %s", profile_path, e, exc_info=True)
            return None

    hook_line = "%s  %s" % (_SHELL_HOOK_LINE, _SHELL_HOOK_TAG)

    if dry_run:
        log.info("[dry-run] would add shell hook to %s", profile_path)
        return SetupChange(
            timestamp=now_iso(),
            client_id="__hook__",
            method="shell_profile",
            file=profile_path,
            detail=hook_line,
        )

    backup_path = ""
    if os.path.isfile(profile_path):
        try:
            backup_path = _backup_file(profile_path)
        except OSError as e:
            log.error("cannot proceed without backup for %s: %s", profile_path, e, exc_info=True)
            return None

    try:
        with open(profile_path, "a", encoding="utf-8") as f:
            f.write("\n# lumen-argus: auto-detect unconfigured AI tools on shell start\n")
            f.write("%s\n" % hook_line)
        log.info("shell hook installed in %s", profile_path)
    except OSError as e:
        log.error("could not write to %s: %s", profile_path, e, exc_info=True)
        return None

    return SetupChange(
        timestamp=now_iso(),
        client_id="__hook__",
        method="shell_profile",
        file=profile_path,
        detail=hook_line,
        backup_path=backup_path,
    )
