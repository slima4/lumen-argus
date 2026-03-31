"""Setup wizard — configure AI CLI agents to route through lumen-argus proxy.

Two-layer approach for toggleable protection:

1. Shell profile gets a source block (written once, never touched again):
   # lumen-argus:begin
   [ -f "$HOME/.lumen-argus/env" ] && source "$HOME/.lumen-argus/env"
   # lumen-argus:end

2. Env vars are written to ~/.lumen-argus/env:
   export OPENAI_BASE_URL=http://localhost:8080  # lumen-argus:managed client=aider

The tray app toggles protection by writing/truncating the env file.
CLI: `lumen-argus protection enable|disable|status`
"""

import json
import logging
import os
import platform
import re
import shutil
from dataclasses import asdict, dataclass

from lumen_argus.detect import _SHELL_PROFILES, detect_installed_clients, load_jsonc
from lumen_argus.time_utils import now_iso

log = logging.getLogger("argus.setup")

# Tag added to managed lines for identification and undo
MANAGED_TAG = "# lumen-argus:managed"

# Source block markers in shell profiles
_SOURCE_BLOCK_BEGIN = "# lumen-argus:begin"
_SOURCE_BLOCK_END = "# lumen-argus:end"

# Env file — the tray app toggles this
_ARGUS_DIR = os.path.expanduser("~/.lumen-argus")
_ENV_FILE = os.path.join(_ARGUS_DIR, "env")

# Backup directory
_SETUP_DIR = os.path.join(_ARGUS_DIR, "setup")
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
    method: str  # "shell_profile" | "ide_settings" | "env_file"
    file: str
    detail: str  # what was added/changed
    backup_path: str = ""


# ---------------------------------------------------------------------------
# Shell profile modification
# ---------------------------------------------------------------------------


def _detect_shell_profile() -> str:
    """Detect the current user's primary shell profile file."""
    # On Windows, use PowerShell profile
    if platform.system() == "Windows":
        from lumen_argus.detect import _get_powershell_profiles

        ps_profiles = _get_powershell_profiles()
        if ps_profiles:
            # Prefer PowerShell 7 profile, fallback to Windows PowerShell 5.1
            for p in ps_profiles:
                if os.path.isfile(p):
                    log.debug("detected PowerShell profile: %s", p)
                    return p
            # No existing profile — use PowerShell 7 path (will be created)
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

    try:
        with open(_MANIFEST_PATH, "w", encoding="utf-8") as f:
            json.dump({"changes": existing}, f, indent=2)
        log.debug("manifest updated: %d total changes", len(existing))
    except OSError as e:
        log.error("could not write manifest: %s", e, exc_info=True)


# ---------------------------------------------------------------------------
# Source block in shell profile
# ---------------------------------------------------------------------------


def _has_source_block(profile_path: str) -> bool:
    """Check if the shell profile already has the lumen-argus source block."""
    if not os.path.isfile(profile_path):
        return False
    try:
        with open(profile_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return _SOURCE_BLOCK_BEGIN in content
    except OSError:
        return False


def _source_block_lines(profile_path: str) -> str:
    """Generate the source block for a shell profile."""
    if platform.system() == "Windows" and profile_path.endswith(".ps1"):
        # TODO: write_env_file() produces Unix `export` syntax — needs a
        # separate env.ps1 with `$env:` syntax for PowerShell support.
        env_path = "$env:USERPROFILE\\.lumen-argus\\env.ps1"
        return '%s\nif (Test-Path "%s") { . "%s" }\n%s\n' % (_SOURCE_BLOCK_BEGIN, env_path, env_path, _SOURCE_BLOCK_END)
    return '%s\n[ -f "$HOME/.lumen-argus/env" ] && source "$HOME/.lumen-argus/env"\n%s\n' % (
        _SOURCE_BLOCK_BEGIN,
        _SOURCE_BLOCK_END,
    )


def install_source_block(profile_path: str = "", dry_run: bool = False) -> SetupChange | None:
    """Install the source block in a shell profile.

    The source block is idempotent — written once, never touched again.
    Returns SetupChange if installed, None if already present.
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

    # Backup before modification
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


# ---------------------------------------------------------------------------
# Env file operations (~/.lumen-argus/env)
# ---------------------------------------------------------------------------


def read_env_file() -> list[tuple[str, str, str]]:
    """Read the env file and return list of (var_name, value, client_id) tuples."""
    if not os.path.isfile(_ENV_FILE):
        return []
    entries = []
    try:
        with open(_ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Parse our own format: export VAR=value  # lumen-argus:managed client=<id>
                # (no quoted values — we control the write format via write_env_file)
                m = re.match(
                    r"export\s+(\w+)=(\S+)\s+.*client=(\S+)",
                    line,
                )
                if m:
                    entries.append((m.group(1), m.group(2), m.group(3)))
    except OSError as e:
        log.warning("could not read env file: %s", e)
    return entries


def write_env_file(entries: list[tuple[str, str, str]]) -> None:
    """Write env vars to ~/.lumen-argus/env atomically.

    Uses write-to-temp-then-rename to prevent corruption if the process
    is killed mid-write (SIGKILL, OOM).  File gets 0o600 permissions
    because it is sourced by the shell — a writable env file is an
    arbitrary code execution vector.

    Args:
        entries: list of (var_name, value, client_id) tuples.
    """
    import tempfile

    os.makedirs(_ARGUS_DIR, mode=0o700, exist_ok=True)
    lines = []
    for var_name, value, client_id in entries:
        lines.append("export %s=%s  %s client=%s" % (var_name, value, MANAGED_TAG, client_id))
    try:
        # Write to temp file in same directory, then atomic rename
        fd, tmp_path = tempfile.mkstemp(dir=_ARGUS_DIR, prefix=".env.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                if lines:
                    f.write("\n".join(lines))
                    f.write("\n")
            os.chmod(tmp_path, 0o600)
            os.rename(tmp_path, _ENV_FILE)
        except BaseException:
            # Clean up temp file on any failure
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        log.info("env file written: %d var(s)", len(lines))
    except OSError as e:
        log.error("could not write env file: %s", e, exc_info=True)


def add_env_to_env_file(
    var_name: str,
    value: str,
    client_id: str,
    dry_run: bool = False,
) -> SetupChange | None:
    """Add an env var to ~/.lumen-argus/env.

    Returns SetupChange if added, None if already present.
    """
    existing = read_env_file()

    # Check if already set with same value
    for ev, val, cid in existing:
        if ev == var_name and val == value and cid == client_id:
            log.info("already in env file: %s=%s (client=%s)", var_name, value, client_id)
            return None

    export_line = "export %s=%s  %s client=%s" % (var_name, value, MANAGED_TAG, client_id)

    if dry_run:
        log.info("[dry-run] would add to env file: %s", export_line)
        return SetupChange(
            timestamp=now_iso(),
            client_id=client_id,
            method="env_file",
            file=_ENV_FILE,
            detail=export_line,
        )

    # Remove any existing entry for this var+client before adding
    filtered = [(ev, val, cid) for ev, val, cid in existing if not (ev == var_name and cid == client_id)]
    filtered.append((var_name, value, client_id))
    write_env_file(filtered)

    return SetupChange(
        timestamp=now_iso(),
        client_id=client_id,
        method="env_file",
        file=_ENV_FILE,
        detail=export_line,
    )


def add_env_to_shell_profile(
    var_name: str,
    value: str,
    client_id: str,
    profile_path: str = "",
    dry_run: bool = False,
) -> SetupChange | None:
    """Add an env var for a client — writes to env file and ensures source block.

    Returns SetupChange if successful, None if already present.
    """
    if not profile_path:
        profile_path = _detect_shell_profile()

    # Ensure source block exists in the shell profile
    install_source_block(profile_path, dry_run=dry_run)

    # Write the env var to ~/.lumen-argus/env
    return add_env_to_env_file(var_name, value, client_id, dry_run=dry_run)


# ---------------------------------------------------------------------------
# Protection toggle (for tray app and CLI)
# ---------------------------------------------------------------------------


def enable_protection(proxy_url: str = "http://localhost:8080") -> dict[str, object]:
    """Write all configured tool env vars to ~/.lumen-argus/env.

    Returns status dict with enabled flag and tool count.
    """
    from lumen_argus.clients import CLIENT_REGISTRY, ProxyConfigType

    entries = []
    for client in CLIENT_REGISTRY:
        pc = client.proxy_config
        if pc.config_type == ProxyConfigType.ENV_VAR and pc.env_var:
            entries.append((pc.env_var, proxy_url, client.id))
            if pc.alt_config and pc.alt_config.config_type == ProxyConfigType.ENV_VAR and pc.alt_config.env_var:
                entries.append((pc.alt_config.env_var, proxy_url, client.id))

    write_env_file(entries)
    log.info("protection enabled: %d env var(s) for %s", len(entries), proxy_url)
    return {"enabled": True, "env_file": _ENV_FILE, "env_vars_set": len(entries)}


def disable_protection() -> dict[str, object]:
    """Truncate ~/.lumen-argus/env to disable all routing.

    Returns status dict.
    """
    # Write empty file atomically via write_env_file
    write_env_file([])
    return {"enabled": False, "env_file": _ENV_FILE, "env_vars_set": 0}


def protection_status() -> dict[str, object]:
    """Return current protection status as JSON-serializable dict."""
    entries = read_env_file()
    enabled = len(entries) > 0
    return {
        "enabled": enabled,
        "env_file": _ENV_FILE,
        "env_vars_set": len(entries),
    }


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
# Shell hook
# ---------------------------------------------------------------------------

# The shell hook line added to profiles for auto-detection
_SHELL_HOOK_LINE = 'eval "$(lumen-argus detect --check-quiet 2>/dev/null)"'
_SHELL_HOOK_TAG = "%s type=hook" % MANAGED_TAG


def install_shell_hook(profile_path: str = "", dry_run: bool = False) -> SetupChange | None:
    """Install a shell hook that warns about unconfigured tools on every new shell.

    The hook runs `lumen-argus detect --check-quiet` which completes in <100ms
    and prints a warning to stderr only if unconfigured tools are found.

    Returns SetupChange if installed, None if already present or failed.
    """
    if not profile_path:
        profile_path = _detect_shell_profile()

    # Check if already installed
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

    # Backup before modification
    backup_path = ""
    if os.path.isfile(profile_path):
        try:
            backup_path = _backup_file(profile_path)
        except OSError as e:
            log.error("cannot proceed without backup for %s: %s", profile_path, e)
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


# ---------------------------------------------------------------------------
# Undo
# ---------------------------------------------------------------------------


def undo_setup() -> int:
    """Remove all lumen-argus configuration: source blocks, managed lines, env file, IDE settings.

    Returns the number of changes reverted.
    """
    reverted = 0

    # Strategy 1: Remove source blocks and managed lines from all known shell profiles
    shell_profiles = [p for profiles in _SHELL_PROFILES.values() for p in profiles]
    # Include PowerShell profiles on Windows
    if platform.system() == "Windows":
        from lumen_argus.detect import _get_powershell_profiles

        shell_profiles.extend(_get_powershell_profiles())
    for profile in shell_profiles:
        expanded = os.path.expanduser(profile)
        if not os.path.isfile(expanded):
            continue
        try:
            with open(expanded, "r", encoding="utf-8") as f:
                lines = f.readlines()
            new_lines = []
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

    # Strategy 2: Truncate the env file
    if os.path.isfile(_ENV_FILE):
        try:
            with open(_ENV_FILE, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if content:
                with open(_ENV_FILE, "w", encoding="utf-8") as f:
                    f.write("")
                log.info("env file cleared: %s", _ENV_FILE)
                reverted += 1
        except OSError as e:
            log.error("could not clear env file: %s", e, exc_info=True)

    # Strategy 3: Restore IDE settings from manifest backups
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

        from lumen_argus.clients import ProxyConfigType, get_client_by_id

        client_def = get_client_by_id(target.client_id)
        if not client_def:
            log.warning("no client def for %s, skipping", target.client_id)
            continue

        pc = client_def.proxy_config

        if pc.config_type == ProxyConfigType.ENV_VAR:
            if non_interactive or _prompt_yes("  Add '%s=%s' to env file?" % (pc.env_var, proxy_url)):
                change = add_env_to_shell_profile(
                    pc.env_var, proxy_url, target.client_id, profile_path, dry_run=dry_run
                )
                if change:
                    changes.append(change)
                    if not dry_run:
                        print("  Added to %s" % _ENV_FILE)
                else:
                    print("  Skipped (already set)")

        elif pc.config_type == ProxyConfigType.IDE_SETTINGS:
            settings_file = _find_ide_settings(target.install_path)
            if settings_file:
                if non_interactive or _prompt_yes(
                    "  Set '%s': '%s' in %s?" % (pc.ide_settings_key, proxy_url, settings_file)
                ):
                    change = update_ide_settings(
                        settings_file, pc.ide_settings_key, proxy_url, target.client_id, dry_run=dry_run
                    )
                    if change:
                        changes.append(change)
                        if not dry_run:
                            print("  Updated %s" % settings_file)
            else:
                print("  Could not find IDE settings file.")
                print("  %s" % pc.setup_instructions)

        elif pc.config_type == ProxyConfigType.CONFIG_FILE:
            print("  %s" % pc.setup_instructions)

        elif pc.config_type == ProxyConfigType.MANUAL:
            print("  Requires manual configuration:")
            print("  %s" % pc.setup_instructions)

        elif pc.config_type == ProxyConfigType.UNSUPPORTED:
            print("  Reverse proxy not supported for this tool.")
            print("  %s" % pc.setup_instructions)

    # Save manifest
    if changes and not dry_run:
        _save_manifest(changes)
        print("\n%d tool(s) configured. Open a new terminal to apply." % len(changes))
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
    from lumen_argus.detect import _get_vscode_variants

    # Determine which variant owns this extension path
    for variant in _get_vscode_variants():
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
