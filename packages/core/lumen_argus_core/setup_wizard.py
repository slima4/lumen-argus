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
import tempfile
from dataclasses import asdict, dataclass

from lumen_argus_core.detect import _SHELL_PROFILES, _strip_jsonc_comments, detect_installed_clients, load_jsonc
from lumen_argus_core.time_utils import now_iso

log = logging.getLogger("argus.setup")

# Tag added to managed lines for identification and undo
MANAGED_TAG = "# lumen-argus:managed"

# Source block markers in shell profiles
_SOURCE_BLOCK_BEGIN = "# lumen-argus:begin"
_SOURCE_BLOCK_END = "# lumen-argus:end"

# Env file — the tray app toggles this
_ARGUS_DIR = os.path.expanduser("~/.lumen-argus")
_ENV_FILE = os.path.join(_ARGUS_DIR, "env")
_ENV_LOCK = os.path.join(_ARGUS_DIR, ".env.lock")

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
        from lumen_argus_core.detect import _get_powershell_profiles

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


def _atomic_write_json(path: str, data: dict[str, object]) -> None:
    """Write JSON to a file atomically via write-to-temp-then-rename."""
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


class _env_file_lock:
    """Context manager for exclusive access to the env file.

    Uses ``fcntl.flock`` on Unix to prevent concurrent read-modify-write
    races between the CLI and tray app.  No-op on Windows (the env file
    is Unix-only anyway).
    """

    def __init__(self) -> None:
        self._fd: int | None = None

    def __enter__(self) -> "_env_file_lock":
        os.makedirs(_ARGUS_DIR, mode=0o700, exist_ok=True)
        try:
            import fcntl

            self._fd = os.open(_ENV_LOCK, os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(self._fd, fcntl.LOCK_EX)
        except (ImportError, OSError):
            # Windows or lock failure — proceed without lock
            self._fd = None
        return self

    def __exit__(self, *args: object) -> None:
        if self._fd is not None:
            try:
                import fcntl

                fcntl.flock(self._fd, fcntl.LOCK_UN)
            except (ImportError, OSError):
                pass
            os.close(self._fd)
            self._fd = None


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
                    r"export\s+(\w+)=(\S+)\s+#\s+\S+\s+client=(\S+)",
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

    Uses file locking to prevent concurrent read-modify-write races
    between CLI and tray app.

    Returns SetupChange if added, None if already present.
    """
    export_line = "export %s=%s  %s client=%s" % (var_name, value, MANAGED_TAG, client_id)

    if dry_run:
        existing = read_env_file()
        for ev, val, cid in existing:
            if ev == var_name and val == value and cid == client_id:
                return None
        log.info("[dry-run] would add to env file: %s", export_line)
        return SetupChange(
            timestamp=now_iso(),
            client_id=client_id,
            method="env_file",
            file=_ENV_FILE,
            detail=export_line,
        )

    with _env_file_lock():
        existing = read_env_file()

        # Check if already set with same value
        for ev, val, cid in existing:
            if ev == var_name and val == value and cid == client_id:
                log.info("already in env file: %s=%s (client=%s)", var_name, value, client_id)
                return None

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

    Also writes per-provider baseURL overrides to opencode.json if OpenCode
    is installed.

    Returns status dict with enabled flag and tool count.
    """
    from lumen_argus_core.clients import CLIENT_REGISTRY, ProxyConfigType

    entries = []
    for client in CLIENT_REGISTRY:
        pc = client.proxy_config
        if pc.config_type == ProxyConfigType.ENV_VAR and pc.env_var:
            entries.append((pc.env_var, proxy_url, client.id))
            if pc.alt_config and pc.alt_config.config_type == ProxyConfigType.ENV_VAR and pc.alt_config.env_var:
                entries.append((pc.alt_config.env_var, proxy_url, client.id))

    write_env_file(entries)

    # Configure OpenCode per-provider baseURLs
    opencode_change = configure_opencode(proxy_url)
    if opencode_change:
        log.info("OpenCode providers configured for %s", proxy_url)

    log.info("protection enabled: %d env var(s) for %s", len(entries), proxy_url)
    return {"enabled": True, "env_file": _ENV_FILE, "env_vars_set": len(entries)}


def disable_protection() -> dict[str, object]:
    """Truncate ~/.lumen-argus/env and remove OpenCode overrides.

    Returns status dict.
    """
    # Write empty file atomically via write_env_file
    write_env_file([])
    # Remove OpenCode per-provider overrides
    unconfigure_opencode()
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
# OpenCode per-provider config
# ---------------------------------------------------------------------------

# Tracking file for provider IDs we configured (outside opencode.json to
# avoid schema validation errors — OpenCode rejects unknown keys).
_OPENCODE_TRACKING_FILE = os.path.join(os.path.expanduser("~"), ".lumen-argus", "opencode_providers.json")


def configure_opencode(
    proxy_url: str,
    dry_run: bool = False,
) -> SetupChange | None:
    """Write per-provider baseURL overrides to opencode.json.

    Merges provider entries into the existing config.  Preserves all
    user-defined keys.  Tracks which providers we configured in a
    separate file (``~/.lumen-argus/opencode_providers.json``) so
    undo can identify and remove only our overrides.

    Returns SetupChange on success, None if nothing changed.
    """
    from lumen_argus_core.opencode_providers import OPENCODE_CONFIG_PATH, build_provider_overrides

    expanded = os.path.expanduser(OPENCODE_CONFIG_PATH)

    # Load existing config (or start fresh).
    # Read directly instead of load_jsonc() to get proper error handling.
    data: dict[str, object] = {}
    if os.path.isfile(expanded):
        try:
            with open(expanded, "r", encoding="utf-8") as f:
                raw = f.read()
            # Strip JSONC comments (// and /* */) before parsing
            data = json.loads(_strip_jsonc_comments(raw))
            if not isinstance(data, dict):
                data = {}
        except (json.JSONDecodeError, OSError) as e:
            log.error("could not parse %s — skipping OpenCode config: %s", OPENCODE_CONFIG_PATH, e)
            return None

    overrides = build_provider_overrides(proxy_url)
    existing_providers = data.get("provider", {})
    if not isinstance(existing_providers, dict):
        existing_providers = {}

    tracked = _load_opencode_tracking()
    changed = False
    configured_ids: list[str] = []
    for provider_id, override in overrides.items():
        entry = existing_providers.get(provider_id, {})
        if not isinstance(entry, dict):
            entry = {}
        options = entry.get("options", {})
        if not isinstance(options, dict):
            options = {}
        override_options: dict[str, str] = override["options"]  # type: ignore[assignment]
        new_url = override_options["baseURL"]
        if options.get("baseURL") == new_url and provider_id in tracked:
            configured_ids.append(provider_id)
            continue  # already configured by us
        options["baseURL"] = new_url
        entry["options"] = options
        existing_providers[provider_id] = entry
        configured_ids.append(provider_id)
        changed = True

    if not changed:
        log.info("OpenCode providers already configured for %s", proxy_url)
        return None

    data["provider"] = existing_providers

    if dry_run:
        log.info("[dry-run] would write %d provider overrides to %s", len(overrides), OPENCODE_CONFIG_PATH)
        return SetupChange(
            timestamp=now_iso(),
            client_id="opencode",
            method="config_file",
            file=OPENCODE_CONFIG_PATH,
            detail="%d provider baseURL overrides" % len(overrides),
        )

    # Ensure parent directory exists
    os.makedirs(os.path.dirname(expanded), exist_ok=True)

    # Backup existing file (JSON comments will be lost — backup preserves original)
    backup_path = ""
    if os.path.isfile(expanded):
        try:
            backup_path = _backup_file(expanded)
            log.info("backed up %s (JSONC comments will not be preserved in rewrite)", expanded)
        except OSError as e:
            log.error("cannot proceed without backup for %s: %s", expanded, e)
            return None

    try:
        _atomic_write_json(expanded, data)
        log.info("wrote %d provider overrides to %s", len(overrides), expanded)
    except OSError as e:
        log.error("could not write %s: %s", expanded, e, exc_info=True)
        return None

    # Save tracking file
    _save_opencode_tracking(configured_ids, proxy_url)

    return SetupChange(
        timestamp=now_iso(),
        client_id="opencode",
        method="config_file",
        file=OPENCODE_CONFIG_PATH,
        detail="%d provider baseURL overrides" % len(overrides),
        backup_path=backup_path,
    )


def unconfigure_opencode() -> int:
    """Remove lumen-argus provider overrides from opencode.json.

    Only removes entries tracked in ``~/.lumen-argus/opencode_providers.json``.
    Returns the number of providers cleaned up.
    """
    from lumen_argus_core.opencode_providers import OPENCODE_CONFIG_PATH

    tracked = _load_opencode_tracking()
    if not tracked:
        return 0

    expanded = os.path.expanduser(OPENCODE_CONFIG_PATH)
    if not os.path.isfile(expanded):
        _remove_opencode_tracking()
        return 0

    data = load_jsonc(expanded)
    if not data:
        _remove_opencode_tracking()
        return 0

    providers = data.get("provider", {})
    if not isinstance(providers, dict):
        _remove_opencode_tracking()
        return 0

    cleaned = 0
    to_remove = []
    for provider_id in tracked:
        entry = providers.get(provider_id)
        if not isinstance(entry, dict):
            continue
        # Remove our baseURL override but keep other user settings
        options = entry.get("options", {})
        if isinstance(options, dict):
            options.pop("baseURL", None)
            if not options:
                entry.pop("options", None)
        # If nothing left in the entry, schedule for removal
        if not entry:
            to_remove.append(provider_id)
        cleaned += 1

    for pid in to_remove:
        del providers[pid]

    if not providers:
        data.pop("provider", None)

    if cleaned == 0:
        _remove_opencode_tracking()
        return 0

    try:
        _backup_file(expanded)
        _atomic_write_json(expanded, data)
        log.info("removed %d lumen-argus provider override(s) from %s", cleaned, expanded)
    except OSError as e:
        log.error("could not write %s during undo: %s", expanded, e, exc_info=True)
        return 0

    _remove_opencode_tracking()
    return cleaned


def _load_opencode_tracking() -> set[str]:
    """Load the set of provider IDs we configured."""
    try:
        with open(_OPENCODE_TRACKING_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return set(data.get("providers", []))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return set()


def _save_opencode_tracking(provider_ids: list[str], proxy_url: str) -> None:
    """Save the set of provider IDs we configured."""
    os.makedirs(os.path.dirname(_OPENCODE_TRACKING_FILE), exist_ok=True)
    try:
        with open(_OPENCODE_TRACKING_FILE, "w", encoding="utf-8") as f:
            json.dump({"providers": sorted(provider_ids), "proxy_url": proxy_url}, f, indent=2)
            f.write("\n")
    except OSError as e:
        log.warning("could not save OpenCode tracking file: %s", e)


def _remove_opencode_tracking() -> None:
    """Remove the tracking file."""
    try:
        os.remove(_OPENCODE_TRACKING_FILE)
    except FileNotFoundError:
        pass
    except OSError as e:
        log.warning("could not remove OpenCode tracking file: %s", e)


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
        from lumen_argus_core.detect import _get_powershell_profiles

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

    # Strategy 4: Remove OpenCode per-provider overrides
    opencode_cleaned = unconfigure_opencode()
    reverted += opencode_cleaned

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

        from lumen_argus_core.clients import ProxyConfigType, get_client_by_id

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

            # OpenCode: also configure per-provider baseURLs in opencode.json
            if target.client_id == "opencode":
                oc_change = configure_opencode(proxy_url, dry_run=dry_run)
                if oc_change:
                    changes.append(oc_change)
                    if not dry_run:
                        from lumen_argus_core.opencode_providers import OPENCODE_CONFIG_PATH

                        print("  Configured all providers in %s" % OPENCODE_CONFIG_PATH)

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
    from lumen_argus_core.detect_models import get_vscode_variants

    # Determine which variant owns this extension path
    for variant in get_vscode_variants():
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
