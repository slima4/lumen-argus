"""Shell-profile source block — the idempotent entry point for protection.

Every supported shell profile (zsh, bash, fish, PowerShell) gets a
``# lumen-argus:begin`` / ``# lumen-argus:end`` block that sources
``~/.lumen-argus/env`` (or a PowerShell equivalent). Written once, never
edited afterwards — the tray app toggles protection by writing or
truncating the env file, not by touching the profile.
"""

from __future__ import annotations

import logging
import os
import platform

from lumen_argus_core.setup._models import SetupChange
from lumen_argus_core.setup._paths import _SOURCE_BLOCK_BEGIN, _SOURCE_BLOCK_END
from lumen_argus_core.setup.manifest import _backup_file, _detect_shell_profile
from lumen_argus_core.time_utils import now_iso

log = logging.getLogger("argus.setup.source_block")


def _has_source_block(profile_path: str) -> bool:
    """Return True if the shell profile already contains the source block."""
    if not os.path.isfile(profile_path):
        return False
    try:
        with open(profile_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as e:
        # Treating "unreadable" as "absent" would cause idempotent callers
        # to re-append the block on every run.
        log.warning("could not read %s to check source block: %s", profile_path, e)
        return False
    return _SOURCE_BLOCK_BEGIN in content


def _source_block_lines(profile_path: str) -> str:
    """Return the block to append for ``profile_path`` (shell-specific)."""
    if platform.system() == "Windows" and profile_path.endswith(".ps1"):
        # ``env_file.write_env_file`` emits Unix ``export`` syntax — a
        # separate env.ps1 with ``$env:`` syntax is needed for a complete
        # PowerShell story. This block still sources it so the file name
        # stays stable across platforms.
        env_path = "$env:USERPROFILE\\.lumen-argus\\env.ps1"
        return '%s\nif (Test-Path "%s") { . "%s" }\n%s\n' % (_SOURCE_BLOCK_BEGIN, env_path, env_path, _SOURCE_BLOCK_END)
    return '%s\n[ -f "$HOME/.lumen-argus/env" ] && source "$HOME/.lumen-argus/env"\n%s\n' % (
        _SOURCE_BLOCK_BEGIN,
        _SOURCE_BLOCK_END,
    )


def install_source_block(profile_path: str = "", dry_run: bool = False) -> SetupChange | None:
    """Append the source block to a shell profile, idempotent.

    Returns a :class:`SetupChange` when the block is installed, ``None``
    when it was already present.
    """
    if not profile_path:
        profile_path = _detect_shell_profile()

    if _has_source_block(profile_path):
        log.debug("source block already present in %s", profile_path)
        return None

    block = _source_block_lines(profile_path)

    if dry_run:
        log.info("[dry-run] would add source block to %s", profile_path)
        return SetupChange(
            timestamp=now_iso(),
            client_id="__source_block__",
            method="shell_profile",
            file=profile_path,
            detail=block.strip(),
        )

    backup_path = ""
    if os.path.isfile(profile_path):
        try:
            backup_path = _backup_file(profile_path)
        except OSError as e:
            log.error("cannot proceed without backup for %s: %s", profile_path, e)
            return None

    try:
        with open(profile_path, "a", encoding="utf-8") as f:
            f.write("\n%s" % block)
        log.info("source block installed in %s", profile_path)
    except OSError as e:
        log.error("could not write to %s: %s", profile_path, e, exc_info=True)
        return None

    return SetupChange(
        timestamp=now_iso(),
        client_id="__source_block__",
        method="shell_profile",
        file=profile_path,
        detail=block.strip(),
        backup_path=backup_path,
    )
