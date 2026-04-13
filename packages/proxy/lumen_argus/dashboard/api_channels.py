"""Notification channel API handlers — CRUD, types, test, batch."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore
    from lumen_argus.extensions import ExtensionRegistry

from lumen_argus.dashboard.api_helpers import (
    json_response,
    mask_channel,
    parse_json_body,
)

log = logging.getLogger("argus.dashboard.api")


def _rebuild_dispatcher(extensions: ExtensionRegistry | None) -> None:
    """Rebuild the notification dispatcher after channel CRUD."""
    dispatcher = extensions.get_dispatcher() if extensions else None
    if dispatcher and hasattr(dispatcher, "rebuild"):
        try:
            dispatcher.rebuild()
        except Exception as e:
            log.warning("dispatcher rebuild failed: %s", e)


def handle_notifications(
    path: str,
    method: str,
    body: bytes,
    store: AnalyticsStore | None,
    extensions: ExtensionRegistry | None,
    request_user: str = "",
) -> tuple[int, bytes] | None:
    """Community notification API — CRUD, types, test, batch."""

    # GET /api/v1/notifications/types
    if path == "/api/v1/notifications/types" and method == "GET":
        types = extensions.get_channel_types() if extensions else {}
        return json_response(200, {"types": types})

    # No channel types registered — dispatcher plugin not loaded (source install)
    # Still return DB channels (from YAML reconciliation) so users can see them
    if not extensions or not extensions.get_channel_types():
        if method == "GET" and path == "/api/v1/notifications/channels":
            channels = []
            if store:
                channels = [mask_channel(ch) for ch in store.list_notification_channels()]
            return json_response(
                200,
                {
                    "channels": channels,
                    "notifications_unavailable": True,
                    "message": "Notification dispatch requires the published package. "
                    "Install from PyPI: pip install lumen-argus",
                },
            )
        return None  # fall through for unknown paths

    if not store:
        return json_response(503, {"error": "analytics store not available"})

    # GET /api/v1/notifications/channels
    if path == "/api/v1/notifications/channels" and method == "GET":
        channels = store.list_notification_channels()
        safe = [mask_channel(ch) for ch in channels]
        # Enrich with last dispatch status from dispatcher (in-memory)
        dispatcher = extensions.get_dispatcher() if extensions else None
        if dispatcher and hasattr(dispatcher, "get_last_status"):
            try:
                statuses = dispatcher.get_last_status()
                for ch in safe:
                    st = statuses.get(ch.get("id"))
                    if st:
                        ch["last_status"] = st["status"]
                        ch["last_status_at"] = st["timestamp"]
                        ch["last_error"] = st["error"]
            except Exception:
                log.debug("failed to enrich channels with dispatch status", exc_info=True)
        return json_response(200, {"channels": safe})

    # POST /api/v1/notifications/channels
    if path == "/api/v1/notifications/channels" and method == "POST":
        data = parse_json_body(body, "POST /api/v1/notifications/channels")
        if isinstance(data, tuple):
            return data
        # Validate channel type
        allowed_types = extensions.get_channel_types()
        if data.get("type") not in allowed_types:
            return json_response(400, {"error": "unknown channel type"})
        # Create with atomic limit check (count + insert under same lock)
        limit = extensions.get_channel_limit()
        data["created_by"] = request_user or "dashboard"
        try:
            channel = store.create_notification_channel(
                data,
                channel_limit=limit,
            )
        except ValueError as e:
            err = str(e)
            if err == "channel_limit_reached":
                count = store.count_notification_channels()
                return json_response(
                    409,
                    {
                        "error": "channel_limit_reached",
                        "message": "Channel limit reached.",
                        "limit": limit,
                        "count": count,
                    },
                )
            return json_response(400, {"error": err})
        _rebuild_dispatcher(extensions)
        if not channel:
            return json_response(500, {"error": "failed to create notification channel"})
        log.info("notification channel created: %s (type=%s)", channel.get("name"), channel.get("type"))
        return json_response(201, mask_channel(channel))

    # POST /api/v1/notifications/channels/batch
    if path == "/api/v1/notifications/channels/batch" and method == "POST":
        data = parse_json_body(body, "POST /api/v1/notifications/channels/batch")
        if isinstance(data, tuple):
            return data
        action = data.get("action", "")
        raw_ids = data.get("ids", [])
        if not isinstance(raw_ids, list):
            return json_response(400, {"error": "ids must be a list"})
        ids = [i for i in raw_ids if isinstance(i, int)]
        if action not in ("enable", "disable", "delete") or not ids or len(ids) > 100:
            return json_response(400, {"error": "invalid batch action"})
        count = store.bulk_update_channels(ids, action)
        _rebuild_dispatcher(extensions)
        return json_response(200, {"affected": count})

    # Routes with channel ID: /api/v1/notifications/channels/:id[/test]
    parts = path.rstrip("/").split("/")
    # /api/v1/notifications/channels/:id → 6 parts
    # /api/v1/notifications/channels/:id/test → 7 parts
    if len(parts) in (6, 7) and parts[4] == "channels" and parts[5].isdigit():
        channel_id = int(parts[5])
        sub = parts[6] if len(parts) == 7 else None

        # POST /api/v1/notifications/channels/:id/test
        if sub == "test" and method == "POST":
            return handle_notification_test(channel_id, store, extensions)

        # GET /api/v1/notifications/channels/:id
        # Returns full unmasked config — needed for edit form pre-population.
        # Protected by dashboard auth (password/session when configured).
        if method == "GET" and sub is None:
            channel = store.get_notification_channel(channel_id)
            if not channel:
                return json_response(404, {"error": "not found"})
            return json_response(200, channel)

        # PUT /api/v1/notifications/channels/:id
        if method == "PUT" and sub is None:
            data = parse_json_body(body, "PUT /api/v1/notifications/channels/%d" % channel_id)
            if isinstance(data, tuple):
                return data
            data["updated_by"] = request_user or "dashboard"
            try:
                result = store.update_notification_channel(channel_id, data)
            except ValueError as e:
                return json_response(400, {"error": str(e)})
            if result is None:
                return json_response(404, {"error": "not found"})
            _rebuild_dispatcher(extensions)
            log.info("notification channel updated: id=%d name=%s", channel_id, result.get("name"))
            return json_response(200, mask_channel(result))

        # DELETE /api/v1/notifications/channels/:id
        if method == "DELETE" and sub is None:
            # Get name before deleting for the log
            del_ch: dict[str, Any] | None = store.get_notification_channel(channel_id)
            if store.delete_notification_channel(channel_id):
                _rebuild_dispatcher(extensions)
                ch_name = del_ch.get("name", "?") if del_ch else "?"
                log.info("notification channel deleted: id=%d name=%s", channel_id, ch_name)
                return json_response(200, {"deleted": channel_id})
            return json_response(404, {"error": "not found"})

    return None  # fall through to Pro handler for extended endpoints


def handle_notification_test(
    channel_id: int, store: AnalyticsStore | None, extensions: ExtensionRegistry | None
) -> tuple[int, bytes]:
    """POST /api/v1/notifications/channels/:id/test"""
    if not store:
        return json_response(500, {"error": "analytics store not available"})
    channel = store.get_notification_channel(channel_id)
    if not channel:
        return json_response(404, {"error": "not found"})

    builder = extensions.get_notifier_builder() if extensions else None
    if not builder:
        return json_response(
            400,
            {
                "error": "notifications_unavailable",
                "message": "Install from PyPI: pip install lumen-argus",
            },
        )

    notifier = builder(channel)
    if not notifier:
        return json_response(400, {"error": "invalid channel configuration"})

    from lumen_argus.models import Finding

    test_finding = Finding(
        detector="test",
        type="test_notification",
        severity="critical",
        location="test",
        value_preview="****",
        matched_value="",
        action="block",
    )
    try:
        notifier.notify([test_finding], provider="lumen-argus", model="test")
        return json_response(200, {"status": "sent", "channel_id": channel_id})
    except Exception as e:
        return json_response(502, {"status": "failed", "error": str(e)})
