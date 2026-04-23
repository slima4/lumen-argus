"""Shared filesystem paths and marker strings for setup operations."""

from __future__ import annotations

import os

MANAGED_TAG = "# lumen-argus:managed"

_SOURCE_BLOCK_BEGIN = "# lumen-argus:begin"
_SOURCE_BLOCK_END = "# lumen-argus:end"

_ARGUS_DIR = os.path.expanduser("~/.lumen-argus")
_ENV_FILE = os.path.join(_ARGUS_DIR, "env")
_ENV_LOCK = os.path.join(_ARGUS_DIR, ".env.lock")

_SETUP_DIR = os.path.join(_ARGUS_DIR, "setup")
_BACKUP_DIR = os.path.join(_SETUP_DIR, "backups")
_MANIFEST_PATH = os.path.join(_SETUP_DIR, "manifest.json")
