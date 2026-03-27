"""Setup wizard — configure AI CLI agents to route through lumen-argus proxy.

Interactive (or non-interactive) tool configuration:
- Adds proxy env vars to shell profiles
- Updates IDE settings JSON files
- Creates backups before every modification
- Supports undo via tagged lines and manifest

All modifications are tagged with '# lumen-argus:managed' for easy identification.
"""

import json
import logging
import os
import re
import shutil
from dataclasses import asdict, dataclass

from lumen_argus.detect import _SHELL_PROFILES, InstallMethod, detect_installed_clients, load_jsonc
from lumen_argus.time_utils import now_iso

log = logging.getLogger("argus.setup")

# Tag added to managed lines for identification and undo
MANAGED_TAG = "# lumen-argus:managed"

# Backup directory
_SETUP_DIR = os.path.expanduser("~/.lumen-argus/setup")
_BACKUP_DIR = os.path.join(_SETUP_DIR, "backups")
_MANIFEST_PATH = os.path.join(_SETUP_DIR, "manifest.json")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class SetupChange:
    """Record of a single configuration change."""

    timestamp: str
    client_id: str
    method: str  # "shell_profile" | "ide_settings"
    file: str
    detail: str  # what was added/changed
    backup_path: str = ""


# ---------------------------------------------------------------------------
# Shell profile modification
# ---------------------------------------------------------------------------


def _detect_shell_profile() -> str:
    """Detect the current user's primary shell profile file."""
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


def _save_manifest(changes: list[SetupChange]) -> None:
    """Save setup changes manifest to disk."""
    os.makedirs(_SETUP_DIR, exist_ok=True)
    existing = []
    if os.path.exists(_MANIFEST_PATH):
        try:
            with open(_MANIFEST_PATH, "r", encoding="utf-8") as f:
                existing = json.load(f).get("changes", [])
        except (json.JSONDecodeError, OSError) as e:
            log.warning("could not read existing manifest: %s", e)

    existing.extend(asdict(c) for c in changes)

    with open(_MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump({"changes": existing}, f, indent=2)
    log.debug("manifest updated: %d total changes", len(existing))


def add_env_to_shell_profile(
    var_name: str,
    value: str,
    client_id: str,
    profile_path: str = "",
    dry_run: bool = False,
) -> SetupChange | None:
    """Add an export line to the user's shell profile.

    Returns SetupChange if successful, None if already present or failed.
    """
    if not profile_path:
        profile_path = _detect_shell_profile()

    # Check if already set
    if os.path.isfile(profile_path):
        try:
            with open(profile_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            # Already has this exact export
            if "export %s=%s" % (var_name, value) in content:
                log.info("already configured: %s=%s in %s", var_name, value, profile_path)
                return None
            # Has the var with a different value (warn but don't overwrite)
            if re.search(r"export\s+%s=" % re.escape(var_name), content):
                log.warning(
                    "%s already set in %s with a different value — skipping to avoid conflict",
                    var_name,
                    profile_path,
                )
                return None
        except OSError as e:
            log.error("could not read %s: %s", profile_path, e, exc_info=True)
            return None

    export_line = "export %s=%s  %s client=%s" % (var_name, value, MANAGED_TAG, client_id)

    if dry_run:
        log.info("[dry-run] would add to %s: %s", profile_path, export_line)
        return SetupChange(
            timestamp=now_iso(),
            client_id=client_id,
            method="shell_profile",
            file=profile_path,
            detail=export_line,
        )

    # Backup before modification
    backup_path = ""
    if os.path.isfile(profile_path):
        try:
            backup_path = _backup_file(profile_path)
        except OSError as e:
            log.error("cannot proceed without backup for %s: %s", profile_path, e)
            return None

    # Append export line
    try:
        with open(profile_path, "a", encoding="utf-8") as f:
            f.write("\n%s\n" % export_line)
        log.info("added to %s: %s", profile_path, export_line)
    except OSError as e:
        log.error("could not write to %s: %s", profile_path, e, exc_info=True)
        return None

    return SetupChange(
        timestamp=now_iso(),
        client_id=client_id,
        method="shell_profile",
        file=profile_path,
        detail=export_line,
        backup_path=backup_path,
    )


# ---------------------------------------------------------------------------
# IDE settings modification
# ---------------------------------------------------------------------------


def update_ide_settings(
    settings_path: str,
    key: str,
    value: str,
    client_id: str,
    dry_run: bool = False,
) -> SetupChange | None:
    """Add or update a key in a JSON settings file.

    Returns SetupChange if successful, None if already set or failed.
    """
    expanded = os.path.expanduser(settings_path)
    if not os.path.isfile(expanded):
        log.warning("IDE settings file not found: %s", settings_path)
        return None

    settings = load_jsonc(expanded)
    if not settings and os.path.isfile(expanded):
        log.error("could not parse %s — skipping", settings_path)
        return None

    # Check if already set to desired value
    if settings.get(key) == value:
        log.info("already configured: %s=%s in %s", key, value, settings_path)
        return None

    if dry_run:
        log.info("[dry-run] would set %s=%s in %s", key, value, settings_path)
        return SetupChange(
            timestamp=now_iso(),
            client_id=client_id,
            method="ide_settings",
            file=settings_path,
            detail="%s=%s" % (key, value),
        )

    # Backup
    try:
        backup_path = _backup_file(expanded)
    except OSError as e:
        log.error("cannot proceed without backup for %s: %s", expanded, e)
        return None

    # Update and write back
    settings[key] = value
    try:
        with open(expanded, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=4)
            f.write("\n")
        log.info("updated %s: %s=%s", settings_path, key, value)
    except OSError as e:
        log.error("could not write %s: %s", settings_path, e, exc_info=True)
        return None

    return SetupChange(
        timestamp=now_iso(),
        client_id=client_id,
        method="ide_settings",
        file=settings_path,
        detail="%s=%s" % (key, value),
        backup_path=backup_path,
    )


# ---------------------------------------------------------------------------
# Undo
# ---------------------------------------------------------------------------


def undo_setup() -> int:
    """Remove all lumen-argus:managed lines and restore IDE settings.

    Returns the number of changes reverted.
    """
    reverted = 0

    # Strategy 1: Find and remove tagged lines from all known shell profiles
    shell_profiles = [p for profiles in _SHELL_PROFILES.values() for p in profiles]
    for profile in shell_profiles:
        expanded = os.path.expanduser(profile)
        if not os.path.isfile(expanded):
            continue
        try:
            with open(expanded, "r", encoding="utf-8") as f:
                lines = f.readlines()
            new_lines = [line for line in lines if MANAGED_TAG not in line]
            removed = len(lines) - len(new_lines)
            if removed > 0:
                _backup_file(expanded)
                with open(expanded, "w", encoding="utf-8") as f:
                    f.writelines(new_lines)
                log.info("removed %d managed line(s) from %s", removed, profile)
                reverted += removed
        except OSError as e:
            log.error("could not clean %s: %s", profile, e, exc_info=True)

    # Strategy 2: Restore IDE settings from manifest backups
    if os.path.exists(_MANIFEST_PATH):
        try:
            with open(_MANIFEST_PATH, "r", encoding="utf-8") as f:
                manifest = json.load(f)
            for change in manifest.get("changes", []):
                if change.get("method") == "ide_settings" and change.get("backup_path"):
                    backup = change["backup_path"]
                    target = os.path.expanduser(change["file"])
                    if os.path.exists(backup):
                        shutil.copy2(backup, target)
                        log.info("restored %s from backup", change["file"])
                        reverted += 1
            # Clear manifest after undo
            os.remove(_MANIFEST_PATH)
            log.info("manifest cleared")
        except (json.JSONDecodeError, OSError) as e:
            log.error("could not process manifest for undo: %s", e, exc_info=True)

    if reverted == 0:
        log.info("nothing to undo — no managed configuration found")
    else:
        log.info("undo complete: %d change(s) reverted", reverted)

    return reverted


# ---------------------------------------------------------------------------
# Interactive wizard
# ---------------------------------------------------------------------------


def run_setup(
    proxy_url: str = "http://localhost:8080",
    client_id: str = "",
    non_interactive: bool = False,
    dry_run: bool = False,
) -> list[SetupChange]:
    """Run the setup wizard — detect tools and configure proxy routing.

    Args:
        proxy_url: Proxy URL to configure (default localhost:8080).
        client_id: Configure only this client (empty = all detected).
        non_interactive: Auto-configure without prompting.
        dry_run: Show what would change without modifying files.

    Returns list of changes made.
    """
    log.info(
        "setup wizard started (proxy=%s, client=%s, interactive=%s, dry_run=%s)",
        proxy_url,
        client_id or "all",
        not non_interactive,
        dry_run,
    )

    report = detect_installed_clients(proxy_url=proxy_url)

    # Filter to specific client if requested
    targets = [c for c in report.clients if c.installed and not c.proxy_configured]
    if client_id:
        targets = [c for c in targets if c.client_id == client_id]

    if not targets:
        already_configured = [c for c in report.clients if c.installed and c.proxy_configured]
        if already_configured:
            print("All %d detected tools are already configured for %s." % (len(already_configured), proxy_url))
        elif not any(c.installed for c in report.clients):
            print("No AI tools detected on this machine.")
            print("Run 'lumen-argus clients' to see supported tools and install instructions.")
        else:
            print("All detected tools are already configured.")
        return []

    print("Found %d tool(s) needing configuration:\n" % len(targets))
    for t in targets:
        ver = " %s" % t.version if t.version else ""
        print("  %s%s (%s)" % (t.display_name, ver, t.install_method))

    changes = []
    profile_path = _detect_shell_profile()

    for target in targets:
        print("\n-- %s %s" % (target.display_name, "-" * (40 - len(target.display_name))))

        # Determine setup method
        from lumen_argus.clients import get_client_by_id

        client_def = get_client_by_id(target.client_id)

        def _try_add_env_var() -> None:
            """Prompt and add env var to shell profile."""
            if non_interactive or _prompt_yes(
                "  Add 'export %s=%s' to %s?" % (target.env_var, proxy_url, profile_path)
            ):
                change = add_env_to_shell_profile(
                    target.env_var, proxy_url, target.client_id, profile_path, dry_run=dry_run
                )
                if change:
                    changes.append(change)
                    if not dry_run:
                        print("  Added to %s" % profile_path)
                else:
                    print("  Skipped (already set or conflict)")

        if target.install_method in (
            InstallMethod.BINARY,
            InstallMethod.PIP,
            InstallMethod.NPM,
            InstallMethod.BREW,
            InstallMethod.APP_BUNDLE,
            InstallMethod.NEOVIM_PLUGIN,
        ):
            _try_add_env_var()

        elif target.install_method in (InstallMethod.VSCODE_EXT, InstallMethod.JETBRAINS_PLUGIN):
            # IDE extension — update settings if proxy_settings_key available
            if client_def and client_def.proxy_settings_key:
                settings_file = _find_ide_settings(target.install_path)
                if settings_file:
                    if non_interactive or _prompt_yes(
                        "  Set '%s': '%s' in %s?" % (client_def.proxy_settings_key, proxy_url, settings_file)
                    ):
                        change = update_ide_settings(
                            settings_file, client_def.proxy_settings_key, proxy_url, target.client_id, dry_run=dry_run
                        )
                        if change:
                            changes.append(change)
                            if not dry_run:
                                print("  Updated %s" % settings_file)
                else:
                    _try_add_env_var()
            else:
                _try_add_env_var()

    # Save manifest
    if changes and not dry_run:
        _save_manifest(changes)
        print("\n%d tool(s) configured. Run: source %s" % (len(changes), profile_path))
    elif dry_run and changes:
        print("\n[dry-run] %d change(s) would be made." % len(changes))
    elif not changes:
        print("\nNo changes made.")

    return changes


def _prompt_yes(message: str) -> bool:
    """Prompt user for Y/n confirmation."""
    try:
        answer = input("%s [Y/n]: " % message).strip().lower()
        return answer in ("", "y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def _find_ide_settings(extension_path: str) -> str | None:
    """Find the IDE settings.json file that corresponds to an extension path."""
    from lumen_argus.detect import _VSCODE_VARIANTS

    # Determine which variant owns this extension path
    for variant in _VSCODE_VARIANTS:
        for ext_dir in variant.extensions:
            expanded = os.path.expanduser(ext_dir)
            if extension_path.startswith(expanded):
                # Found the variant — return first existing settings file
                for settings_path in variant.settings:
                    settings_expanded = os.path.expanduser(settings_path)
                    if os.path.isfile(settings_expanded):
                        return settings_expanded
                # Settings dir might not exist yet
                if variant.settings:
                    return os.path.expanduser(variant.settings[0])
    return None
