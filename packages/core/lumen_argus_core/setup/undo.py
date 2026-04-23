"""``undo_setup`` — reverse everything the setup wizard has ever written.

Iterates five strategies in a deliberate order: shell profiles →
env file → IDE settings (manifest-backed) → forward-proxy aliases →
OpenCode overrides. Each strategy is best-effort — an error in one
step still allows the next to run so partial state is minimised.
"""

from __future__ import annotations

import logging
import os
import platform
import shutil

from lumen_argus_core.detect import _SHELL_PROFILES
from lumen_argus_core.forward_proxy import ALIASES_PATH as _ALIASES_PATH
from lumen_argus_core.setup import env_file as _env_file
from lumen_argus_core.setup._paths import _SOURCE_BLOCK_BEGIN, _SOURCE_BLOCK_END, MANAGED_TAG
from lumen_argus_core.setup.manifest import _backup_file, clear_manifest, load_manifest
from lumen_argus_core.setup.opencode import unconfigure_opencode

log = logging.getLogger("argus.setup.undo")


def undo_setup() -> int:
    """Remove every managed change: source blocks, managed env lines, env file, IDE settings.

    Returns the number of changes reverted.
    """
    reverted = 0

    # Strategy 1: shell profiles — strip source blocks + managed lines.
    shell_profiles = [p for profiles in _SHELL_PROFILES.values() for p in profiles]
    if platform.system() == "Windows":
        from lumen_argus_core.detect import _get_powershell_profiles

        shell_profiles.extend(_get_powershell_profiles())
    for profile in shell_profiles:
        expanded = os.path.expanduser(profile)
        if not os.path.isfile(expanded):
            continue
        try:
            with open(expanded, "r", encoding="utf-8") as f:
                lines = f.readlines()
            new_lines: list[str] = []
            in_source_block = False
            for line in lines:
                if _SOURCE_BLOCK_BEGIN in line:
                    in_source_block = True
                    reverted += 1
                    continue
                if _SOURCE_BLOCK_END in line:
                    in_source_block = False
                    continue
                if in_source_block:
                    continue
                if MANAGED_TAG in line:
                    reverted += 1
                    continue
                new_lines.append(line)
            removed = len(lines) - len(new_lines)
            if removed > 0:
                _backup_file(expanded)
                with open(expanded, "w", encoding="utf-8") as f:
                    f.writelines(new_lines)
                log.info("removed %d managed line(s) from %s", removed, profile)
        except OSError as e:
            log.error("could not clean %s: %s", profile, e, exc_info=True)

    # Strategy 2: truncate the env file.
    env_file_path = _env_file._ENV_FILE
    if os.path.isfile(env_file_path):
        try:
            with open(env_file_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if content:
                with open(env_file_path, "w", encoding="utf-8") as f:
                    f.write("")
                log.info("env file cleared: %s", env_file_path)
                reverted += 1
        except OSError as e:
            log.error("could not clear env file: %s", e, exc_info=True)

    # Strategy 3: restore IDE settings from manifest backups.
    manifest_changes = load_manifest()
    if manifest_changes:
        for change in manifest_changes:
            if change.get("method") == "ide_settings" and change.get("backup_path"):
                backup = change["backup_path"]
                target = os.path.expanduser(change["file"])
                if os.path.exists(backup):
                    try:
                        shutil.copy2(backup, target)
                        log.info("restored %s from backup", change["file"])
                        reverted += 1
                    except OSError as e:
                        log.error("could not restore %s: %s", change["file"], e, exc_info=True)
        clear_manifest()

    # Strategy 4: mark the forward-proxy aliases file disabled.
    if os.path.isfile(_ALIASES_PATH):
        try:
            with open(_ALIASES_PATH, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if content and "disabled" not in content:
                with open(_ALIASES_PATH, "w", encoding="utf-8") as f:
                    f.write("# lumen-argus forward proxy aliases (disabled)\n")
                log.info("forward proxy aliases cleared: %s", _ALIASES_PATH)
                reverted += 1
        except OSError as e:
            log.error("could not clear aliases file: %s", e, exc_info=True)

    # Strategy 5: remove OpenCode per-provider overrides.
    reverted += unconfigure_opencode()

    if reverted == 0:
        log.info("nothing to undo — no managed configuration found")
    else:
        log.info("undo complete: %d change(s) reverted", reverted)

    return reverted
