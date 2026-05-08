"""IDE ``settings.json`` mutation — VS Code / Cursor / Windsurf / etc."""

from __future__ import annotations

import json
import logging
import os

from lumen_argus_core.detect import load_jsonc
from lumen_argus_core.detect_models import get_vscode_variants
from lumen_argus_core.setup._models import SetupChange
from lumen_argus_core.setup.manifest import _backup_file
from lumen_argus_core.time_utils import now_iso

log = logging.getLogger("argus.setup.ide")


def update_ide_settings(
    settings_path: str,
    key: str,
    value: str,
    client_id: str,
    dry_run: bool = False,
) -> SetupChange | None:
    """Add or update a key in a JSON settings file. Idempotent."""
    expanded = os.path.expanduser(settings_path)
    if not os.path.isfile(expanded):
        log.warning("IDE settings file not found: %s", settings_path)
        return None

    settings = load_jsonc(expanded)
    if not settings and os.path.isfile(expanded):
        log.error("could not parse %s — skipping", settings_path)
        return None

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

    try:
        backup_path = _backup_file(expanded)
    except OSError as e:
        log.error("cannot proceed without backup for %s: %s", expanded, e, exc_info=True)
        return None

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


def _find_ide_settings(extension_path: str) -> str | None:
    """Return the ``settings.json`` path whose extensions dir owns ``extension_path``."""
    for variant in get_vscode_variants():
        for ext_dir in variant.extensions:
            expanded = os.path.expanduser(ext_dir)
            if extension_path.startswith(expanded):
                for settings_path in variant.settings:
                    settings_expanded = os.path.expanduser(settings_path)
                    if os.path.isfile(settings_expanded):
                        return settings_expanded
                # Settings dir may not exist yet — return the first candidate.
                if variant.settings:
                    return os.path.expanduser(variant.settings[0])
    return None
