"""Manifest persistence, file backup, and shell-profile detection."""

from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import tempfile
from dataclasses import asdict

from lumen_argus_core.detect import _SHELL_PROFILES
from lumen_argus_core.setup._models import SetupChange
from lumen_argus_core.setup._paths import _BACKUP_DIR, _MANIFEST_PATH, _SETUP_DIR
from lumen_argus_core.time_utils import now_iso

log = logging.getLogger("argus.setup.manifest")


def _detect_shell_profile() -> str:
    """Return the primary shell profile path for the current user."""
    if platform.system() == "Windows":
        from lumen_argus_core.detect import _get_powershell_profiles

        ps_profiles = _get_powershell_profiles()
        if ps_profiles:
            for p in ps_profiles:
                if os.path.isfile(p):
                    log.debug("detected PowerShell profile: %s", p)
                    return p
            log.debug("using PowerShell 7 profile path: %s", ps_profiles[0])
            return ps_profiles[0]

    shell = os.path.basename(os.environ.get("SHELL", ""))
    profiles = _SHELL_PROFILES.get(shell, _SHELL_PROFILES.get("bash", ("~/.bashrc",)))
    profile = profiles[0] if profiles else "~/.bashrc"
    expanded = os.path.expanduser(profile)
    log.debug("detected shell: %s → profile: %s", shell or "unknown", profile)
    return expanded


def _backup_file(file_path: str) -> str:
    """Create a timestamped backup of a file. Returns backup path."""
    os.makedirs(_BACKUP_DIR, exist_ok=True)
    basename = os.path.basename(file_path).replace(".", "_")
    timestamp = now_iso().replace(":", "-").replace("T", "_")
    backup_name = "%s.%s" % (basename, timestamp)
    backup_path = os.path.join(_BACKUP_DIR, backup_name)
    try:
        shutil.copy2(file_path, backup_path)
        log.info("backup created: %s → %s", file_path, backup_path)
    except OSError as e:
        log.error("backup failed for %s: %s", file_path, e, exc_info=True)
        raise
    return backup_path


def _atomic_write_json(path: str, data: dict[str, object]) -> None:
    """Write JSON atomically via write-to-temp-then-rename."""
    dir_name = os.path.dirname(path)
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _save_manifest(changes: list[SetupChange]) -> None:
    """Append setup changes to the persistent manifest.

    A write failure is ``log.error``-ed and re-raised so callers can
    abort the enclosing setup step. Losing a manifest entry silently
    would strand a backup file that ``undo_setup`` can no longer find.
    """
    os.makedirs(_SETUP_DIR, exist_ok=True)
    existing: list[dict[str, object]] = []
    if os.path.exists(_MANIFEST_PATH):
        try:
            with open(_MANIFEST_PATH, "r", encoding="utf-8") as f:
                existing = json.load(f).get("changes", [])
        except (json.JSONDecodeError, OSError) as e:
            log.warning("could not read existing manifest: %s", e)

    existing.extend(asdict(c) for c in changes)

    try:
        with open(_MANIFEST_PATH, "w", encoding="utf-8") as f:
            json.dump({"changes": existing}, f, indent=2)
        log.debug("manifest updated: %d total changes", len(existing))
    except OSError:
        log.error("could not write manifest at %s", _MANIFEST_PATH, exc_info=True)
        raise


def load_manifest() -> list[dict[str, str]]:
    """Return the manifest ``changes`` list, or ``[]`` if absent or unreadable."""
    if not os.path.exists(_MANIFEST_PATH):
        return []
    try:
        with open(_MANIFEST_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f).get("changes", [])
    except (json.JSONDecodeError, OSError) as e:
        log.error("could not read manifest for undo: %s", e, exc_info=True)
        return []
    # Narrow to the documented shape. A malformed entry — e.g. written by
    # an older build — is dropped with a debug log rather than crashing undo.
    out: list[dict[str, str]] = []
    for entry in raw:
        if isinstance(entry, dict) and all(isinstance(v, str) for v in entry.values()):
            out.append({str(k): str(v) for k, v in entry.items()})
        else:
            log.debug("dropping malformed manifest entry: %r", entry)
    return out


def clear_manifest() -> None:
    """Remove the manifest file, best-effort."""
    try:
        os.remove(_MANIFEST_PATH)
        log.info("manifest cleared")
    except FileNotFoundError:
        log.debug("manifest already absent")
    except OSError as e:
        log.error("could not clear manifest: %s", e, exc_info=True)


def manifest_exists() -> bool:
    """Return True if the manifest file is present on disk."""
    return os.path.exists(_MANIFEST_PATH)
