"""Community dashboard API — read-only endpoints plus license activation.

All community API endpoints are GET-only (except POST /api/v1/license).
Known Pro endpoint paths return 402 instead of 404 when no Pro handler
is registered, giving API consumers a clear upgrade signal.
"""

import json
import logging
import os
import time

from lumen_argus import __version__

log = logging.getLogger("argus.dashboard.api")

# Pro endpoint prefixes — return 402 when Pro is not installed
_PRO_ENDPOINTS = (
    "/api/v1/rules",
    "/api/v1/patterns",
    "/api/v1/allowlist",
)

_SENSITIVE_FIELDS = frozenset({
    "webhook_url", "routing_key", "password", "url",
    "username", "api_key", "token", "api_token",
})

# Start time for uptime calculation
_start_time = time.monotonic()


def _parse_query(path: str) -> tuple:
    """Split path and query string, return (path, params_dict)."""
    query = ""
    if "?" in path:
        path, query = path.split("?", 1)
    params = {}
    if query:
        from urllib.parse import unquote_plus
        for part in query.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                params[unquote_plus(k)] = unquote_plus(v)
    return path, params


def _json_response(status: int, data) -> tuple:
    """Return (status, body_bytes) JSON response."""
    body = json.dumps(data).encode("utf-8")
    return status, body


def handle_community_api(path: str, method: str, body: bytes,
                         store, audit_reader=None, config=None,
                         extensions=None, request_user: str = "") -> tuple:
    """Handle a community API request.

    Args:
        request_user: Authenticated user identity for audit trail.
            "dashboard:admin" when password auth is active,
            "dashboard" when no auth, or "dashboard:<user_id>" from auth providers.

    Returns (status_code, response_body_bytes).
    """
    path, params = _parse_query(path)

    # --- GET endpoints ---

    if method == "GET":
        if path == "/api/v1/status":
            return _handle_status(store, extensions)

        if path == "/api/v1/findings":
            return _handle_findings_list(params, store)

        if path == "/api/v1/stats":
            return _handle_stats(store)

        if path == "/api/v1/config":
            return _handle_config(config)

        if path == "/api/v1/audit":
            return _handle_audit(params, audit_reader)

        if path == "/api/v1/logs/tail":
            return _handle_logs_tail(config)

        # Finding by ID: /api/v1/findings/123
        if path.startswith("/api/v1/findings/"):
            finding_id = path.split("/")[-1]
            try:
                finding_id = int(finding_id)
            except (ValueError, TypeError):
                return _json_response(400, {"error": "invalid finding ID"})
            return _handle_finding_detail(finding_id, store)

    # --- POST endpoints ---

    if method == "POST":
        if path == "/api/v1/license":
            return _handle_license_activation(body)

    # --- Notification endpoints (community-handled) ---

    if path.startswith("/api/v1/notifications"):
        result = _handle_notifications(path, method, body, store, extensions, request_user)
        if result is not None:
            return result

    # --- Tier gating: known Pro paths return 402 ---

    if method in ("POST", "PUT", "DELETE"):
        for prefix in _PRO_ENDPOINTS:
            if path.startswith(prefix):
                return _json_response(402, {
                    "error": "pro_required",
                    "message": "This feature requires a Pro license",
                    "upgrade_url": "https://lumen-argus.com/pro",
                })
        # PUT on config is also Pro-only
        if path == "/api/v1/config" and method == "PUT":
            return _json_response(402, {
                "error": "pro_required",
                "message": "Config changes require a Pro license",
                "upgrade_url": "https://lumen-argus.com/pro",
            })

    return _json_response(404, {"error": "not_found"})


# --- Handler implementations ---

def _handle_status(store, extensions=None) -> tuple:
    uptime = time.monotonic() - _start_time
    plugins = extensions.loaded_plugins() if extensions else []
    pro_active = any(name == "pro" for name, _ in plugins)
    pro_version = ""
    for name, ver in plugins:
        if name == "pro":
            pro_version = ver
    data = {
        "status": "operational",
        "version": __version__,
        "uptime_seconds": round(uptime, 1),
        "total_findings": store.get_total_count() if store else 0,
        "tier": "pro" if pro_active else "community",
        "pro_version": pro_version,
    }
    return _json_response(200, data)


def _handle_findings_list(params: dict, store) -> tuple:
    if not store:
        return _json_response(200, {"findings": [], "total": 0})

    try:
        limit = min(int(params.get("limit", 50)), 100)
        offset = max(int(params.get("offset", 0)), 0)
    except (ValueError, TypeError):
        return _json_response(400, {"error": "invalid pagination parameters"})
    severity = params.get("severity") or None
    detector = params.get("detector") or None
    provider = params.get("provider") or None

    findings, total = store.get_findings_page(
        limit=limit, offset=offset,
        severity=severity, detector=detector, provider=provider,
    )
    return _json_response(200, {"findings": findings, "total": total})


def _handle_finding_detail(finding_id: int, store) -> tuple:
    if not store:
        return _json_response(404, {"error": "not_found"})

    finding = store.get_finding_by_id(finding_id)
    if not finding:
        return _json_response(404, {"error": "finding not found"})
    return _json_response(200, finding)


def _handle_stats(store) -> tuple:
    if not store:
        return _json_response(200, {
            "total_findings": 0, "by_severity": {},
            "by_detector": {}, "daily_trend": [],
        })

    stats = store.get_stats()
    return _json_response(200, stats)


def _handle_config(config) -> tuple:
    """Return sanitized read-only config."""
    if not config:
        return _json_response(200, {"community": {}})

    data = {
        "community": {
            "proxy": {
                "port": config.proxy.port,
                "bind": config.proxy.bind,
                "timeout": config.proxy.timeout,
                "retries": config.proxy.retries,
            },
            "default_action": config.default_action,
            "detectors": {
                "secrets": {"enabled": config.secrets.enabled, "action": config.secrets.action or config.default_action},
                "pii": {"enabled": config.pii.enabled, "action": config.pii.action or config.default_action},
                "proprietary": {"enabled": config.proprietary.enabled, "action": config.proprietary.action or config.default_action},
            },
        },
    }
    return _json_response(200, data)


def _handle_audit(params: dict, audit_reader) -> tuple:
    if not audit_reader:
        return _json_response(200, {"entries": [], "total": 0, "providers": []})

    try:
        limit = min(int(params.get("limit", 50)), 100)
        offset = max(int(params.get("offset", 0)), 0)
    except (ValueError, TypeError):
        return _json_response(400, {"error": "invalid pagination parameters"})
    action = params.get("action") or None
    provider = params.get("provider") or None
    search = params.get("search") or None

    entries, total = audit_reader.read_entries(
        limit=limit, offset=offset,
        action=action, provider=provider, search=search,
    )
    providers = audit_reader.get_providers()
    return _json_response(200, {"entries": entries, "total": total, "providers": providers})


def _handle_logs_tail(config) -> tuple:
    """Return last N lines from the application log."""
    if not config:
        return _json_response(200, {"lines": []})

    log_dir = os.path.expanduser(config.logging_config.log_dir)
    log_file = os.path.join(log_dir, "lumen-argus.log")

    if not os.path.exists(log_file):
        return _json_response(200, {"lines": []})

    lines = []
    try:
        with open(log_file, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
            lines = [l.rstrip("\n") for l in all_lines[-100:]]
    except OSError:
        pass

    return _json_response(200, {"lines": lines})


def _handle_license_activation(body: bytes) -> tuple:
    """POST /api/v1/license — save license key to disk."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return _json_response(400, {"error": "invalid JSON"})

    key = data.get("key", "").strip()
    if not key:
        return _json_response(400, {"error": "license key is required"})
    if len(key) > 4096 or "\n" in key or "\r" in key:
        return _json_response(400, {"error": "invalid license key format"})

    # Save to ~/.lumen-argus/license.key
    license_path = os.path.expanduser("~/.lumen-argus/license.key")
    try:
        os.makedirs(os.path.dirname(license_path), exist_ok=True)
        with open(license_path, "w", encoding="utf-8") as f:
            f.write(key)
        os.chmod(license_path, 0o600)
    except OSError as e:
        return _json_response(500, {"error": "failed to save license: %s" % e})

    return _json_response(200, {
        "status": "saved",
        "message": "License key saved. Restart the proxy to activate.",
        "path": license_path,
    })


# --- Notification channel handlers ---

def _mask_channel(channel: dict) -> dict:
    """Mask sensitive fields in channel config for API responses."""
    ch = dict(channel)
    config = ch.get("config", {})
    if isinstance(config, str):
        config = json.loads(config)
    masked = dict(config)
    for key in _SENSITIVE_FIELDS:
        if key in masked and masked[key]:
            val = str(masked[key])
            masked[key] = val[:4] + "****" + val[-4:] if len(val) > 8 else "****"
    ch["config_masked"] = masked
    ch.pop("config", None)
    return ch


def _rebuild_dispatcher(extensions):
    """Rebuild the notification dispatcher after channel CRUD."""
    dispatcher = extensions.get_dispatcher() if extensions else None
    if dispatcher and hasattr(dispatcher, "rebuild"):
        try:
            dispatcher.rebuild()
        except Exception as e:
            log.warning("dispatcher rebuild failed: %s", e)


def _handle_notifications(path, method, body, store, extensions, request_user=""):
    """Community notification API — CRUD, types, test, batch."""

    # GET /api/v1/notifications/types
    if path == "/api/v1/notifications/types" and method == "GET":
        types = extensions.get_channel_types() if extensions else {}
        limit = extensions.get_channel_limit() if extensions else 1
        count = store.count_notification_channels() if store else 0
        return _json_response(200, {
            "types": types,
            "channel_limit": limit,
            "channel_count": count,
        })

    # No channel types registered — Pro not loaded (source install)
    # Still return DB channels (from YAML reconciliation) so users can see them
    if not extensions or not extensions.get_channel_types():
        if method == "GET" and path == "/api/v1/notifications/channels":
            channels = []
            count = 0
            if store:
                channels = [_mask_channel(ch) for ch in store.list_notification_channels()]
                count = len(channels)
            return _json_response(200, {
                "channels": channels,
                "channel_limit": 1,
                "channel_count": count,
                "notifications_unavailable": True,
                "message": "Notification dispatch requires the published package. "
                           "Install from PyPI: pip install lumen-argus",
            })
        return None  # fall through for unknown paths

    if not store:
        return _json_response(503, {"error": "analytics store not available"})

    # GET /api/v1/notifications/channels
    if path == "/api/v1/notifications/channels" and method == "GET":
        channels = store.list_notification_channels()
        safe = [_mask_channel(ch) for ch in channels]
        limit = extensions.get_channel_limit()
        return _json_response(200, {
            "channels": safe,
            "channel_limit": limit,
            "channel_count": len(channels),
        })

    # POST /api/v1/notifications/channels
    if path == "/api/v1/notifications/channels" and method == "POST":
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return _json_response(400, {"error": "invalid JSON"})
        if not isinstance(data, dict):
            return _json_response(400, {"error": "invalid JSON"})
        # Validate channel type
        allowed_types = extensions.get_channel_types()
        if data.get("type") not in allowed_types:
            return _json_response(400, {"error": "unknown channel type"})
        # Create with atomic limit check (count + insert under same lock)
        limit = extensions.get_channel_limit()
        data["created_by"] = request_user or "dashboard"
        try:
            channel = store.create_notification_channel(
                data, channel_limit=limit,
            )
        except ValueError as e:
            err = str(e)
            if err == "channel_limit_reached":
                count = store.count_notification_channels()
                return _json_response(409, {
                    "error": "channel_limit_reached",
                    "message": "Free tier allows %d channel(s). "
                               "Upgrade to Pro for unlimited." % (limit or 0),
                    "limit": limit,
                    "count": count,
                })
            return _json_response(400, {"error": err})
        _rebuild_dispatcher(extensions)
        log.info("notification channel created: %s (type=%s)",
                 channel.get("name"), channel.get("type"))
        return _json_response(201, _mask_channel(channel))

    # POST /api/v1/notifications/channels/batch
    if path == "/api/v1/notifications/channels/batch" and method == "POST":
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return _json_response(400, {"error": "invalid JSON"})
        action = data.get("action", "")
        raw_ids = data.get("ids", [])
        if not isinstance(raw_ids, list):
            return _json_response(400, {"error": "ids must be a list"})
        ids = []
        for i in raw_ids:
            if isinstance(i, int):
                ids.append(i)
        if action not in ("enable", "disable", "delete") or not ids or len(ids) > 100:
            return _json_response(400, {"error": "invalid batch action"})
        count = store.bulk_update_channels(ids, action)
        _rebuild_dispatcher(extensions)
        return _json_response(200, {"affected": count})

    # Routes with channel ID: /api/v1/notifications/channels/:id[/test]
    parts = path.rstrip("/").split("/")
    # /api/v1/notifications/channels/:id → 6 parts
    # /api/v1/notifications/channels/:id/test → 7 parts
    if (len(parts) in (6, 7)
            and parts[4] == "channels"
            and parts[5].isdigit()):
        channel_id = int(parts[5])
        sub = parts[6] if len(parts) == 7 else None

        # POST /api/v1/notifications/channels/:id/test
        if sub == "test" and method == "POST":
            return _handle_notification_test(channel_id, store, extensions)

        # GET /api/v1/notifications/channels/:id
        # Returns full unmasked config — needed for edit form pre-population.
        # Protected by dashboard auth (password/session when configured).
        if method == "GET" and sub is None:
            channel = store.get_notification_channel(channel_id)
            if not channel:
                return _json_response(404, {"error": "not found"})
            return _json_response(200, channel)

        # PUT /api/v1/notifications/channels/:id
        if method == "PUT" and sub is None:
            try:
                data = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                return _json_response(400, {"error": "invalid JSON"})
            if not isinstance(data, dict):
                return _json_response(400, {"error": "invalid JSON"})
            data["updated_by"] = request_user or "dashboard"
            try:
                result = store.update_notification_channel(channel_id, data)
            except ValueError as e:
                return _json_response(400, {"error": str(e)})
            if result is None:
                return _json_response(404, {"error": "not found"})
            _rebuild_dispatcher(extensions)
            log.info("notification channel updated: id=%d name=%s",
                     channel_id, result.get("name"))
            return _json_response(200, _mask_channel(result))

        # DELETE /api/v1/notifications/channels/:id
        if method == "DELETE" and sub is None:
            # Get name before deleting for the log
            ch = store.get_notification_channel(channel_id)
            if store.delete_notification_channel(channel_id):
                _rebuild_dispatcher(extensions)
                log.info("notification channel deleted: id=%d name=%s",
                         channel_id, ch["name"] if ch else "?")
                return _json_response(200, {"deleted": channel_id})
            return _json_response(404, {"error": "not found"})

    return None  # fall through to Pro handler for extended endpoints


def _handle_notification_test(channel_id, store, extensions):
    """POST /api/v1/notifications/channels/:id/test"""
    channel = store.get_notification_channel(channel_id)
    if not channel:
        return _json_response(404, {"error": "not found"})

    builder = extensions.get_notifier_builder() if extensions else None
    if not builder:
        return _json_response(400, {
            "error": "notifications_unavailable",
            "message": "Install from PyPI: pip install lumen-argus",
        })

    notifier = builder(channel)
    if not notifier:
        return _json_response(400, {"error": "invalid channel configuration"})

    from lumen_argus.models import Finding
    test_finding = Finding(
        detector="test", type="test_notification", severity="info",
        location="test", value_preview="****", matched_value="", action="alert",
    )
    try:
        notifier.notify([test_finding], provider="lumen-argus", model="test")
        return _json_response(200, {"status": "sent", "channel_id": channel_id})
    except Exception as e:
        return _json_response(502, {"status": "failed", "error": str(e)})
