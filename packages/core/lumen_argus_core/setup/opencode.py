"""OpenCode per-provider ``baseURL`` overrides in ``opencode.json``.

Tracks which provider IDs we configured in a sibling tracking file so
``unconfigure_opencode`` removes only our overrides, never user-defined
ones. Tracking lives outside ``opencode.json`` because OpenCode's
schema validation rejects unknown top-level keys.
"""

from __future__ import annotations

import json
import logging
import os
import platform

from lumen_argus_core.detect import _strip_jsonc_comments, load_jsonc
from lumen_argus_core.setup._models import SetupChange
from lumen_argus_core.setup.manifest import _atomic_write_json, _backup_file
from lumen_argus_core.time_utils import now_iso

log = logging.getLogger("argus.setup.opencode")

_OPENCODE_TRACKING_FILE = os.path.join(os.path.expanduser("~"), ".lumen-argus", "opencode_providers.json")


def _resolve_opencode_config_path(managed: bool, user_path: str, managed_paths: dict[str, str]) -> str:
    """Return the OpenCode config path based on the ``managed`` flag and platform."""
    if not managed:
        return user_path
    plat = platform.system().lower()
    path = managed_paths.get(plat)
    if not path:
        log.warning("no managed OpenCode config path for platform %s — using user path", plat)
        return user_path
    return path


def configure_opencode(
    proxy_url: str,
    dry_run: bool = False,
    managed: bool = False,
) -> SetupChange | None:
    """Write per-provider ``baseURL`` overrides to ``opencode.json``.

    Merges provider entries into existing config, preserving all
    user-defined keys. ``managed=True`` writes to the system-level
    managed config path (wins OpenCode's merge chain) — requires
    elevated privileges.
    """
    from lumen_argus_core.opencode_providers import (
        OPENCODE_CONFIG_PATH,
        OPENCODE_MANAGED_PATHS,
        build_provider_overrides,
    )

    config_path = _resolve_opencode_config_path(managed, OPENCODE_CONFIG_PATH, OPENCODE_MANAGED_PATHS)
    expanded = os.path.expanduser(config_path)

    data: dict[str, object] = {}
    if os.path.isfile(expanded):
        try:
            with open(expanded, "r", encoding="utf-8") as f:
                raw = f.read()
            data = json.loads(_strip_jsonc_comments(raw))
            if not isinstance(data, dict):
                data = {}
        except (json.JSONDecodeError, OSError) as e:
            log.error("could not parse %s — skipping OpenCode config: %s", config_path, e, exc_info=True)
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
            continue
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
        log.info("[dry-run] would write %d provider overrides to %s", len(overrides), config_path)
        return SetupChange(
            timestamp=now_iso(),
            client_id="opencode",
            method="config_file",
            file=config_path,
            detail="%d provider baseURL overrides" % len(overrides),
        )

    try:
        os.makedirs(os.path.dirname(expanded), exist_ok=True)
    except PermissionError as e:
        log.error(
            "cannot create %s — elevated privileges required for managed config: %s",
            os.path.dirname(expanded),
            e,
            exc_info=True,
        )
        return None

    backup_path = ""
    if os.path.isfile(expanded):
        try:
            backup_path = _backup_file(expanded)
            log.info("backed up %s (JSONC comments will not be preserved in rewrite)", expanded)
        except OSError as e:
            log.error("cannot proceed without backup for %s: %s", expanded, e, exc_info=True)
            return None

    try:
        _atomic_write_json(expanded, data)
        log.info("wrote %d provider overrides to %s", len(overrides), expanded)
    except OSError as e:
        log.error("could not write %s: %s", expanded, e, exc_info=True)
        return None

    _save_opencode_tracking(configured_ids, proxy_url, config_path)

    return SetupChange(
        timestamp=now_iso(),
        client_id="opencode",
        method="config_file",
        file=config_path,
        detail="%d provider baseURL overrides%s" % (len(overrides), " (managed)" if managed else ""),
        backup_path=backup_path,
    )


def unconfigure_opencode() -> int:
    """Remove lumen-argus provider overrides from ``opencode.json``.

    Reads the tracked config path (supports user-level + managed). Only
    removes entries we configured. Returns the number of providers
    cleaned up.
    """
    tracking = _load_opencode_tracking_full()
    tracked = tracking.providers
    if not tracked:
        return 0

    config_path = tracking.config_path
    if not config_path:
        from lumen_argus_core.opencode_providers import OPENCODE_CONFIG_PATH

        config_path = OPENCODE_CONFIG_PATH

    expanded = os.path.expanduser(config_path)
    if not os.path.isfile(expanded):
        _remove_opencode_tracking()
        return 0

    data = load_jsonc(expanded)

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
        options = entry.get("options", {})
        if isinstance(options, dict):
            options.pop("baseURL", None)
            if not options:
                entry.pop("options", None)
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


class _OpenCodeTracking:
    """Parsed tracking file data."""

    __slots__ = ("config_path", "providers", "proxy_url")

    def __init__(self, providers: set[str], proxy_url: str, config_path: str):
        self.providers = providers
        self.proxy_url = proxy_url
        self.config_path = config_path


def _load_opencode_tracking() -> set[str]:
    """Load the set of provider IDs we configured."""
    return _load_opencode_tracking_full().providers


def _load_opencode_tracking_full() -> _OpenCodeTracking:
    """Load the full tracking data (providers, proxy_url, config_path)."""
    try:
        with open(_OPENCODE_TRACKING_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        # First run on this machine — no tracking file yet.
        return _OpenCodeTracking(providers=set(), proxy_url="", config_path="")
    except (json.JSONDecodeError, OSError) as e:
        # Parse / permission failures are silent-but-diagnosable — a
        # corrupt tracking file means unconfigure_opencode cannot find
        # overrides to undo; a DEBUG log lets operators discover why.
        log.debug("OpenCode tracking file unreadable (%s): %s", _OPENCODE_TRACKING_FILE, e)
        return _OpenCodeTracking(providers=set(), proxy_url="", config_path="")
    return _OpenCodeTracking(
        providers=set(data.get("providers", [])),
        proxy_url=data.get("proxy_url", ""),
        config_path=data.get("config_path", ""),
    )


def _save_opencode_tracking(provider_ids: list[str], proxy_url: str, config_path: str = "") -> None:
    """Save the set of provider IDs we configured."""
    os.makedirs(os.path.dirname(_OPENCODE_TRACKING_FILE), exist_ok=True)
    try:
        with open(_OPENCODE_TRACKING_FILE, "w", encoding="utf-8") as f:
            json.dump(
                {"providers": sorted(provider_ids), "proxy_url": proxy_url, "config_path": config_path},
                f,
                indent=2,
            )
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
