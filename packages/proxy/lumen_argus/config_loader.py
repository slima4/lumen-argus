"""Config loading helpers — analytics init, HMAC key, rules import, DB overrides.

Extracted from cli.py to follow Single Responsibility Principle.
Called at startup (_initialize_analytics) and on reload (_apply_config_overrides).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore
    from lumen_argus.config import Config
    from lumen_argus.extensions import ExtensionRegistry

log = logging.getLogger("argus.cli")


# ---------------------------------------------------------------------------
# HMAC key
# ---------------------------------------------------------------------------


def load_hmac_key() -> bytes:
    """Load or generate the HMAC key for value hashing.

    Stored at ~/.lumen-argus/hmac.key with 0o600 permissions.
    Auto-generated (32 bytes) on first run. If deleted, a new key is
    generated and old hashes become unmatchable (graceful degradation).
    HMAC-SHA-256 accepts any key length — no truncation applied.
    """
    key_path = os.path.expanduser("~/.lumen-argus/hmac.key")
    try:
        with open(key_path, "rb") as f:
            key = f.read()
        if len(key) >= 32:
            return key
    except FileNotFoundError:
        log.debug("HMAC key not found at %s, generating new key", key_path)
    # Generate new key — use exclusive create to avoid race conditions
    key = os.urandom(32)
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    try:
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, key)
        os.close(fd)
    except FileExistsError:
        # Another process created it first — read theirs
        with open(key_path, "rb") as f:
            key = f.read()
    return key


# ---------------------------------------------------------------------------
# Rules bundle loading
# ---------------------------------------------------------------------------


def load_rules_bundle(path: str | None = None, pro: bool = False) -> tuple[list[Any], str, str]:
    """Load a rules JSON bundle. Returns (rules_list, version, tier)."""
    if path:
        with open(path, encoding="utf-8") as f:
            bundle = json.loads(f.read())
        return bundle.get("rules", []), bundle.get("version", ""), bundle.get("tier", "custom")

    if pro:
        # Pro bundle loaded via entry point
        try:
            from importlib.resources import files as _files

            pro_path = str(_files("lumen_argus_pro.rules").joinpath("pro.json"))
        except ImportError:
            # Fallback for edge cases (frozen apps, etc.)
            import importlib.resources as _resources

            try:
                with _resources.open_text("lumen_argus_pro.rules", "pro.json") as f:
                    bundle = json.loads(f.read())
                return bundle.get("rules", []), bundle.get("version", ""), "pro"
            except (ModuleNotFoundError, FileNotFoundError):
                print("lumen-argus: Pro rules bundle not found. Is lumen-argus-pro installed?", file=sys.stderr)
                sys.exit(1)
        try:
            with open(pro_path, encoding="utf-8") as f:
                bundle = json.loads(f.read())
            return bundle.get("rules", []), bundle.get("version", ""), "pro"
        except FileNotFoundError:
            print("lumen-argus: Pro rules bundle not found. Is lumen-argus-pro installed?", file=sys.stderr)
            sys.exit(1)

    # Community bundle
    bundle_path = os.path.join(os.path.dirname(__file__), "rules", "community.json")
    with open(bundle_path, encoding="utf-8") as f:
        bundle = json.loads(f.read())
    return bundle.get("rules", []), bundle.get("version", ""), "community"


# ---------------------------------------------------------------------------
# Auto-analysis trigger
# ---------------------------------------------------------------------------


def trigger_auto_analysis(
    store: AnalyticsStore | None, extensions: ExtensionRegistry | None, config: Config | None = None
) -> None:
    """Run rule overlap analysis in background if crossfire is available and enabled."""
    if config and not config.rule_analysis.auto_on_import:
        return
    if not store:
        return
    try:
        from lumen_argus.rule_analysis import run_analysis_in_background
    except ImportError:
        return
    run_analysis_in_background(store, extensions, thread_name="rule-analysis-auto", config=config)


# ---------------------------------------------------------------------------
# Analytics store creation
# ---------------------------------------------------------------------------


def _create_or_get_store(
    config: Config, extensions: ExtensionRegistry, hmac_key: bytes | None
) -> AnalyticsStore | None:
    """Create community store or adopt plugin-provided one."""
    from lumen_argus.analytics.store import AnalyticsStore

    store: AnalyticsStore | None = extensions.get_analytics_store()
    if store is None and config.analytics.enabled:
        store = AnalyticsStore(db_path=config.analytics.db_path, hmac_key=hmac_key)
        extensions.set_analytics_store(store)
        store.start_cleanup_scheduler(config.analytics.retention_days)
    elif store is not None and hmac_key:
        store._hmac_key = hmac_key
    # Apply plugin-registered schema extensions regardless of which store
    # we ended up with. A plugin may inject its own AnalyticsStore subclass
    # via set_analytics_store; that path must still get other plugins'
    # DDL applied, and DDL is idempotent so this is safe to call even on
    # a freshly constructed community store.
    if store is not None:
        ddls = extensions.get_schema_extensions()
        if ddls:
            store.apply_schema_extensions(ddls)
    return store


# ---------------------------------------------------------------------------
# Rules reconciliation
# ---------------------------------------------------------------------------


def _auto_import_rules(
    store: AnalyticsStore, args: argparse.Namespace, config: Config, extensions: ExtensionRegistry
) -> None:
    """Auto-import community rules on first run if DB has zero rules."""
    if args.no_default_rules or not config.rules.auto_import:
        return
    if store.get_rules_count() == 0:
        rules, version, tier = load_rules_bundle()
        result = store.import_rules(rules, tier=tier)
        log.info("auto-imported %d community rules v%s", result["created"], version)
        trigger_auto_analysis(store, extensions, config=config)


def reconcile_yaml_rules(store: AnalyticsStore, config: Config) -> None:
    """Reconcile YAML custom_rules to DB (Kubernetes-style declarative sync)."""
    if not config.custom_rules:
        return
    yaml_rules = [
        {
            "name": r.name,
            "pattern": r.pattern,
            "severity": r.severity,
            "action": r.action,
            "detector": r.detector,
        }
        for r in config.custom_rules
    ]
    result = store.reconcile_yaml_rules(yaml_rules)
    for action_name in ("created", "updated", "deleted"):
        if result[action_name]:
            log.info("custom rules %s: %s", action_name, ", ".join(result[action_name]))


# ---------------------------------------------------------------------------
# DB config overrides
# ---------------------------------------------------------------------------

_OVERRIDE_INT_KEYS = {
    "proxy.timeout": "proxy.timeout",
    "proxy.connect_timeout": "proxy.connect_timeout",
    "proxy.retries": "proxy.retries",
}
_OVERRIDE_STR_KEYS = {"default_action": "default_action"}
_OVERRIDE_DETECTOR_ACTION = {
    "detectors.secrets.action": ("secrets", "action"),
    "detectors.pii.action": ("pii", "action"),
    "detectors.proprietary.action": ("proprietary", "action"),
}
_OVERRIDE_DETECTOR_ENABLED = {
    "detectors.secrets.enabled": "secrets",
    "detectors.pii.enabled": "pii",
    "detectors.proprietary.enabled": "proprietary",
}
_STAGE_BOOL_FIELDS = frozenset({"enabled", "base64", "hex", "url", "unicode"})
_STAGE_INT_FIELDS = frozenset({"max_depth", "min_decoded_length", "max_decoded_length"})


def apply_config_overrides(config: Config, store: AnalyticsStore, action_overrides: dict[str, str]) -> None:
    """Apply DB config overrides on top of YAML (dashboard-saved settings)."""
    try:
        db_overrides = store.get_config_overrides()
    except Exception:
        log.warning("failed to apply DB config overrides", exc_info=True)
        return
    for key, value in db_overrides.items():
        if key in _OVERRIDE_INT_KEYS:
            parent, attr = _OVERRIDE_INT_KEYS[key].rsplit(".", 1)
            setattr(getattr(config, parent), attr, int(value))
        elif key in _OVERRIDE_STR_KEYS:
            setattr(config, _OVERRIDE_STR_KEYS[key], value)
        elif key in _OVERRIDE_DETECTOR_ACTION:
            detector, field = _OVERRIDE_DETECTOR_ACTION[key]
            action_overrides[detector] = value
            setattr(getattr(config, detector), field, value)
        elif key in _OVERRIDE_DETECTOR_ENABLED:
            detector = _OVERRIDE_DETECTOR_ENABLED[key]
            setattr(getattr(config, detector), "enabled", value.lower() == "true")
        elif key == "pipeline.parallel_batching":
            config.pipeline.parallel_batching = value.lower() == "true"
        elif key.startswith("pipeline.stages."):
            _apply_stage_override(config, key, value)
    if db_overrides:
        log.info("applied %d config override(s) from DB", len(db_overrides))


def _apply_stage_override(config: Config, key: str, value: str) -> None:
    """Apply a single pipeline.stages.<stage>.<field> override."""
    parts = key.split(".")
    if len(parts) < 4:
        return
    stage_cfg = getattr(config.pipeline, parts[2], None)
    field = parts[3]
    if stage_cfg is None:
        return
    if field in _STAGE_BOOL_FIELDS:
        setattr(stage_cfg, field, value.lower() == "true")
    elif field in _STAGE_INT_FIELDS:
        setattr(stage_cfg, field, int(value))


# ---------------------------------------------------------------------------
# Top-level initializer
# ---------------------------------------------------------------------------


def initialize_analytics(
    config: Config, args: argparse.Namespace, extensions: ExtensionRegistry, action_overrides: dict[str, str]
) -> AnalyticsStore | None:
    """Initialize analytics store, auto-import rules, reconcile YAML, apply DB overrides.

    Returns the AnalyticsStore instance (or None if dashboard is disabled).
    Mutates config and action_overrides with DB overrides.
    """
    if not config.dashboard.enabled:
        return None

    hmac_key = load_hmac_key() if config.analytics.hash_secrets else None
    analytics_store = _create_or_get_store(config, extensions, hmac_key)
    if not analytics_store:
        return None

    _auto_import_rules(analytics_store, args, config, extensions)
    reconcile_yaml_rules(analytics_store, config)
    apply_config_overrides(config, analytics_store, action_overrides)

    return analytics_store
