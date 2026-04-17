"""Config, status, pipeline, license, and logs API handlers."""

from __future__ import annotations

import logging
import os
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore
    from lumen_argus.config import Config
    from lumen_argus.extensions import ExtensionRegistry

from lumen_argus import __version__
from lumen_argus.dashboard.api_helpers import (
    broadcast_sse,
    json_response,
    parse_json_body,
    require_store,
    send_sighup,
)

log = logging.getLogger("argus.dashboard.api")


def handle_config_update(
    body: bytes, config: Config | None, store: AnalyticsStore | None, extensions: ExtensionRegistry | None = None
) -> tuple[int, bytes]:
    """Handle PUT /api/v1/config — save community-editable settings to DB.

    Uses the shared ``config_overrides`` SQLite table, so settings
    survive license transitions without data loss.
    """
    changes = parse_json_body(body, "PUT /api/v1/config")
    if isinstance(changes, tuple):
        return changes
    if not changes:
        log.debug("PUT /api/v1/config: empty body")
        return json_response(400, {"error": "expected a JSON object with settings to update"})

    store = require_store(store, "PUT /api/v1/config")

    log.debug("PUT /api/v1/config: %d change(s) requested: %s", len(changes), list(changes.keys()))
    errors = []
    applied = {}

    for key, value in changes.items():
        try:
            store.set_config_override(key, str(value))
            applied[key] = value
        except ValueError as e:
            log.warning("config override rejected: %s = %s (%s)", key, value, e)
            errors.append({"key": key, "error": str(e)})

    if applied:
        summary = ", ".join("%s=%s" % (k, v) for k, v in applied.items())
        log.info("config update [settings]: %s", summary)
        send_sighup()
        broadcast_sse(extensions, "config")
        if "proxy.mode" in applied:
            broadcast_sse(extensions, "mode-changed", {"mode": str(applied["proxy.mode"])})

    if errors and not applied:
        return json_response(400, {"error": "; ".join(e["error"] for e in errors)})
    if errors:
        log.info("config update partial: %d applied, %d errors", len(applied), len(errors))
        return json_response(207, {"applied": applied, "errors": errors})
    return json_response(200, {"applied": applied})


def handle_status(
    store: AnalyticsStore | None, extensions: ExtensionRegistry | None = None, start_time: float = 0.0
) -> tuple[int, bytes]:
    uptime = time.monotonic() - start_time
    plugins = extensions.loaded_plugins() if extensions else []
    pro_version = ""
    for name, ver in plugins:
        if name == "pro":
            pro_version = ver
    # Resolve license state from the license checker, not from plugin
    # loadedness. A plugin that fails license validation still shows up
    # in loaded_plugins() because its entry point was called — but it
    # will not have activated any features. Reading the checker is the
    # only way to distinguish "installed but degraded" from "installed
    # and active". Licensed plugins register the checker unconditionally
    # for exactly this reason.
    checker = extensions.get_license_checker() if extensions else None
    try:
        license_active = bool(checker and checker.is_valid())
    except Exception as e:
        log.warning("GET /api/v1/status: license checker raised, reporting community tier: %s", e)
        license_active = False
    proxy_server = extensions.get_proxy_server() if extensions else None
    proxy_info = {}
    if proxy_server is not None:
        proxy_info = {
            "proxy_port": proxy_server.port,
            "proxy_bind": proxy_server.bind,
            "mode": getattr(proxy_server, "mode", "active"),
            "standalone": getattr(proxy_server, "standalone", True),
        }
    data = {
        "status": "operational",
        "version": __version__,
        "uptime_seconds": round(uptime, 1),
        "total_findings": store.get_total_count() if store else 0,
        "tier": "pro" if license_active else "community",
        "pro_version": pro_version,
        **proxy_info,
    }
    return json_response(200, data)


def handle_config(config: Config | None, store: AnalyticsStore | None = None) -> tuple[int, bytes]:
    """Return sanitized config with DB overrides applied."""
    if not config:
        return json_response(200, {"community": {}})

    # Start with YAML values
    timeout = config.proxy.timeout
    connect_timeout = config.proxy.connect_timeout
    retries = config.proxy.retries
    default_action = config.default_action
    secrets_action = config.secrets.action or config.default_action
    pii_action = config.pii.action or config.default_action
    proprietary_action = config.proprietary.action or config.default_action

    # Apply DB overrides on top (same values the running server uses)
    if store:
        try:
            overrides = store.get_config_overrides()
            if "proxy.timeout" in overrides:
                timeout = int(overrides["proxy.timeout"])
            if "proxy.connect_timeout" in overrides:
                connect_timeout = int(overrides["proxy.connect_timeout"])
            if "proxy.retries" in overrides:
                retries = int(overrides["proxy.retries"])
            if "default_action" in overrides:
                default_action = overrides["default_action"]
            if "detectors.secrets.action" in overrides:
                secrets_action = overrides["detectors.secrets.action"]
            if "detectors.pii.action" in overrides:
                pii_action = overrides["detectors.pii.action"]
            if "detectors.proprietary.action" in overrides:
                proprietary_action = overrides["detectors.proprietary.action"]
        except Exception as e:
            log.warning("GET /api/v1/config: could not load DB overrides: %s", e)

    data = {
        "community": {
            "proxy": {
                "port": config.proxy.port,
                "bind": config.proxy.bind,
                "timeout": timeout,
                "connect_timeout": connect_timeout,
                "retries": retries,
            },
            "default_action": default_action,
            "detectors": {
                "secrets": {"enabled": config.secrets.enabled, "action": secrets_action},
                "pii": {"enabled": config.pii.enabled, "action": pii_action},
                "proprietary": {"enabled": config.proprietary.enabled, "action": proprietary_action},
            },
        },
    }
    return json_response(200, data)


def handle_clients_list(extensions: ExtensionRegistry | None) -> tuple[int, bytes]:
    """Return catalog of supported AI CLI agents with setup instructions."""
    from lumen_argus_core.clients import get_all_clients

    extra = extensions.get_extra_clients() if extensions else []
    return json_response(200, {"clients": get_all_clients(extra_clients=extra)})


def handle_logs_tail(config: Config | None) -> tuple[int, bytes]:
    """Return last N lines from the application log."""
    if not config:
        return json_response(200, {"lines": []})

    log_dir = os.path.expanduser(config.logging_config.log_dir)
    log_file = os.path.join(log_dir, "lumen-argus.log")

    if not os.path.exists(log_file):
        return json_response(200, {"lines": []})

    lines = []
    try:
        with open(log_file, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
            lines = [line.rstrip("\n") for line in all_lines[-100:]]
    except OSError as exc:
        log.warning("failed to read log file %s: %s", log_file, exc)

    return json_response(200, {"lines": lines})


def handle_license_activation(body: bytes) -> tuple[int, bytes]:
    """POST /api/v1/license — save license key to disk."""
    data = parse_json_body(body, "POST /api/v1/license")
    if isinstance(data, tuple):
        return data
    key = data.get("key", "").strip()
    if not key:
        return json_response(400, {"error": "license key is required"})
    if len(key) > 4096:
        return json_response(400, {"error": "invalid license key format"})

    # Save to ~/.lumen-argus/license.key
    license_path = os.path.expanduser("~/.lumen-argus/license.key")
    try:
        os.makedirs(os.path.dirname(license_path), exist_ok=True)
        with open(license_path, "w", encoding="utf-8") as f:
            f.write(key)
        os.chmod(license_path, 0o600)
    except OSError as e:
        return json_response(500, {"error": "failed to save license: %s" % e})

    return json_response(
        200,
        {
            "status": "saved",
            "message": "License key saved. Restart the proxy to activate.",
            "path": license_path,
        },
    )


# ---------------------------------------------------------------------------
# Pipeline configuration
# ---------------------------------------------------------------------------

# Stage metadata — label, description, group, default enabled, availability
PIPELINE_STAGES = [
    {
        "name": "outbound_dlp",
        "label": "Outbound DLP",
        "description": "Secret, PII, and proprietary code detection on outbound requests",
        "group": "request",
        "default_enabled": True,
        "available": True,
        "has_sub_detectors": True,
    },
    {
        "name": "encoding_decode",
        "label": "Encoding Decode",
        "description": "Decode base64, hex, URL, and Unicode before scanning",
        "group": "request",
        "default_enabled": True,
        "available": True,
        "has_sub_detectors": False,
        "has_encoding_settings": True,
    },
    {
        "name": "response_secrets",
        "label": "Response Secrets",
        "description": "Detect secrets leaked in API responses (async, no latency impact)",
        "group": "response",
        "default_enabled": False,
        "available": True,
        "has_sub_detectors": False,
    },
    {
        "name": "response_injection",
        "label": "Response Injection",
        "description": "Detect prompt injection patterns in API responses (async, no latency impact)",
        "group": "response",
        "default_enabled": False,
        "available": True,
        "has_sub_detectors": False,
    },
    {
        "name": "mcp_arguments",
        "label": "MCP Arguments",
        "description": "Scan MCP tool call arguments for sensitive data",
        "group": "protocol",
        "default_enabled": True,
        "available": True,
        "has_sub_detectors": False,
    },
    {
        "name": "mcp_responses",
        "label": "MCP Responses",
        "description": "Scan MCP tool return values for sensitive data and injection",
        "group": "protocol",
        "default_enabled": True,
        "available": True,
        "has_sub_detectors": False,
    },
    {
        "name": "websocket_outbound",
        "label": "WebSocket Outbound",
        "description": "Scan outbound WebSocket frames for sensitive data",
        "group": "protocol",
        "default_enabled": False,
        "available": True,
        "has_sub_detectors": False,
    },
    {
        "name": "websocket_inbound",
        "label": "WebSocket Inbound",
        "description": "Scan inbound WebSocket frames for sensitive data",
        "group": "protocol",
        "default_enabled": False,
        "available": True,
        "has_sub_detectors": False,
    },
]


def handle_pipeline_get(config: Config | None, store: AnalyticsStore | None = None) -> tuple[int, bytes]:
    """Return pipeline stage configuration with stats."""
    log.debug("GET /api/v1/pipeline")
    if not config:
        log.warning("GET /api/v1/pipeline: no config available")
        return json_response(200, {"default_action": "alert", "stages": []})

    # Get DB overrides
    overrides = {}
    if store:
        try:
            overrides = store.get_config_overrides()
        except Exception as e:
            log.warning("GET /api/v1/pipeline: could not load DB overrides: %s", e)

    # Get finding stats per detector (for sub-detector counts)
    stats = {}
    if store:
        try:
            raw_stats = store.get_stats()
            stats = raw_stats.get("by_detector", {})
        except Exception:
            log.warning("GET /api/v1/pipeline: could not load detector stats", exc_info=True)

    default_action = overrides.get("default_action", config.default_action)

    stages = []
    for meta in PIPELINE_STAGES:
        name = str(meta["name"])
        stage_cfg = getattr(config.pipeline, name, None)

        # Apply DB override for enabled
        override_key = "pipeline.stages.%s.enabled" % name
        if override_key in overrides:
            enabled = overrides[override_key].lower() == "true"
        elif stage_cfg:
            enabled = stage_cfg.enabled
        else:
            enabled = meta["default_enabled"]

        stage: dict[str, Any] = {
            "name": name,
            "label": meta["label"],
            "description": meta["description"],
            "group": meta["group"],
            "enabled": enabled,
            "available": meta["available"],
        }

        # Sub-detectors for outbound_dlp
        if meta["has_sub_detectors"]:
            sub_detectors = []
            for det_name in ("secrets", "pii", "proprietary"):
                det_cfg = getattr(config, det_name, None)

                # Apply DB overrides
                det_enabled_key = "detectors.%s.enabled" % det_name
                det_action_key = "detectors.%s.action" % det_name
                det_enabled = (
                    overrides.get(det_enabled_key, str(det_cfg.enabled if det_cfg else True)).lower() == "true"
                )
                det_action = overrides.get(det_action_key, det_cfg.action if det_cfg else "") or "default"

                det_count = stats.get(det_name, 0)
                # RulesDetector uses pattern names, not detector category names —
                # sum all detector entries that aren't in the other categories
                if det_name == "secrets" and not det_count:
                    det_count = sum(v for k, v in stats.items() if k not in ("pii", "proprietary", "custom"))

                sub_detectors.append(
                    {
                        "name": det_name,
                        "enabled": det_enabled,
                        "action": det_action,
                        "finding_count": det_count,
                    }
                )
            stage["sub_detectors"] = sub_detectors
            stage["finding_count"] = sum(d["finding_count"] for d in sub_detectors)
        elif meta.get("has_encoding_settings"):
            # Encoding decode settings
            enc_cfg = getattr(config.pipeline, "encoding_decode", None)
            enc_settings: dict[str, Any] = {}
            for enc_name in ("base64", "hex", "url", "unicode"):
                override_key = "pipeline.stages.encoding_decode.%s" % enc_name
                if override_key in overrides:
                    enc_settings[enc_name] = overrides[override_key].lower() == "true"
                elif enc_cfg:
                    enc_settings[enc_name] = getattr(enc_cfg, enc_name, True)
                else:
                    enc_settings[enc_name] = True
            for int_key in ("max_depth", "min_decoded_length", "max_decoded_length"):
                override_key = "pipeline.stages.encoding_decode.%s" % int_key
                if override_key in overrides:
                    enc_settings[int_key] = int(overrides[override_key])
                elif enc_cfg:
                    enc_settings[int_key] = getattr(enc_cfg, int_key)
                else:
                    enc_settings[int_key] = {"max_depth": 2, "min_decoded_length": 8, "max_decoded_length": 10000}[
                        int_key
                    ]
            stage["encoding_settings"] = enc_settings
            stage["finding_count"] = 0
        else:
            stage["finding_count"] = 0

        # MCP tool list counts for mcp_arguments stage
        # DB includes both source='config' (reconciled from YAML) and source='api'
        # (dashboard-managed). Don't double-count by also adding config object entries.
        if name == "mcp_arguments" and store:
            try:
                tool_lists = store.get_mcp_tool_lists()
                allowed_count = len(tool_lists.get("allowed", []))
                blocked_count = len(tool_lists.get("blocked", []))
                # If DB is empty (no reconciliation yet), fall back to config
                if allowed_count == 0 and blocked_count == 0:
                    mcp_cfg = getattr(config, "mcp", None)
                    if mcp_cfg:
                        allowed_count = len(mcp_cfg.allowed_tools)
                        blocked_count = len(mcp_cfg.blocked_tools)
                stage["mcp_tools"] = {
                    "allowed_count": allowed_count,
                    "blocked_count": blocked_count,
                }
            except Exception:
                stage["mcp_tools"] = {"allowed_count": 0, "blocked_count": 0}

        stages.append(stage)

    # Parallel batching toggle
    parallel_key = "pipeline.parallel_batching"
    if parallel_key in overrides:
        parallel_batching = overrides[parallel_key].lower() == "true"
    else:
        parallel_batching = config.pipeline.parallel_batching

    return json_response(
        200,
        {
            "default_action": default_action,
            "parallel_batching": parallel_batching,
            "stages": stages,
        },
    )


def handle_pipeline_update(
    body: bytes, config: Config | None, store: AnalyticsStore | None, extensions: ExtensionRegistry | None = None
) -> tuple[int, bytes]:
    """Save pipeline configuration changes."""
    store = require_store(store, "PUT /api/v1/pipeline")

    changes = parse_json_body(body, "PUT /api/v1/pipeline")
    if isinstance(changes, tuple):
        return changes

    log.debug("PUT /api/v1/pipeline: %d section(s) requested: %s", len(changes), list(changes.keys()))

    errors: list[dict[str, str]] = []
    applied: dict[str, Any] = {}

    # Handle parallel_batching
    if "parallel_batching" in changes:
        try:
            store.set_config_override("pipeline.parallel_batching", str(changes["parallel_batching"]).lower())
            applied["parallel_batching"] = changes["parallel_batching"]
        except ValueError as e:
            log.warning("pipeline config rejected: parallel_batching = %s (%s)", changes["parallel_batching"], e)
            errors.append({"key": "parallel_batching", "error": str(e)})

    # Handle default_action
    if "default_action" in changes:
        try:
            store.set_config_override("default_action", str(changes["default_action"]))
            applied["default_action"] = changes["default_action"]
        except ValueError as e:
            log.warning("pipeline config rejected: default_action = %s (%s)", changes["default_action"], e)
            errors.append({"key": "default_action", "error": str(e)})

    # Handle stage toggles
    stages = changes.get("stages", {})
    if isinstance(stages, dict):
        for stage_name, stage_data in stages.items():
            if not isinstance(stage_data, dict):
                continue
            if "enabled" in stage_data:
                key = "pipeline.stages.%s.enabled" % stage_name
                try:
                    store.set_config_override(key, str(stage_data["enabled"]).lower())
                    applied[key] = stage_data["enabled"]
                except ValueError as e:
                    log.warning("pipeline config rejected: %s = %s (%s)", key, stage_data["enabled"], e)
                    errors.append({"key": key, "error": str(e)})

    # Handle encoding settings
    _ALLOWED_ENC_KEYS = {"base64", "hex", "url", "unicode", "max_depth", "min_decoded_length", "max_decoded_length"}
    enc = changes.get("encoding_settings", {})
    if isinstance(enc, dict):
        for enc_key, enc_val in enc.items():
            if enc_key not in _ALLOWED_ENC_KEYS:
                log.warning("pipeline config rejected: unknown encoding setting '%s'", enc_key)
                errors.append({"key": enc_key, "error": "unknown encoding setting"})
                continue
            key = "pipeline.stages.encoding_decode.%s" % enc_key
            try:
                store.set_config_override(key, str(enc_val))
                applied[key] = enc_val
            except ValueError as e:
                log.warning("pipeline config rejected: %s = %s (%s)", key, enc_val, e)
                errors.append({"key": key, "error": str(e)})

    # Handle detector toggles and action overrides
    detectors = changes.get("detectors", {})
    if isinstance(detectors, dict):
        for det_name, det_data in detectors.items():
            if not isinstance(det_data, dict):
                continue
            if "enabled" in det_data:
                key = "detectors.%s.enabled" % det_name
                try:
                    store.set_config_override(key, str(det_data["enabled"]).lower())
                    applied[key] = det_data["enabled"]
                except ValueError as e:
                    log.warning("pipeline config rejected: %s = %s (%s)", key, det_data["enabled"], e)
                    errors.append({"key": key, "error": str(e)})
            if "action" in det_data:
                key = "detectors.%s.action" % det_name
                action_val = str(det_data["action"])
                try:
                    if action_val == "default":
                        store.delete_config_override(key)
                        applied[key] = "default"
                    else:
                        store.set_config_override(key, action_val)
                        applied[key] = action_val
                except ValueError as e:
                    log.warning("pipeline config rejected: %s = %s (%s)", key, action_val, e)
                    errors.append({"key": key, "error": str(e)})

    if applied:
        send_sighup()
        broadcast_sse(extensions, "config")
        summary = ", ".join("%s=%s" % (k, v) for k, v in applied.items())
        if errors:
            log.info("pipeline update [dashboard]: %d applied, %d errors: %s", len(applied), len(errors), summary)
        else:
            log.info("pipeline update [dashboard]: %s", summary)

    status = 200 if not errors else 207
    return json_response(status, {"applied": applied, "errors": errors})
