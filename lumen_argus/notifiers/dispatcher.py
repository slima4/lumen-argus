"""Basic notification dispatcher — fire-and-forget."""

from __future__ import annotations

import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore

from lumen_argus_core.time_utils import now_iso

log = logging.getLogger("argus.notifiers.dispatcher")


def _parse_events(events: Any) -> list[str]:
    """Ensure events is a list (may be JSON string from DB)."""
    if isinstance(events, str):
        try:
            result: list[str] = json.loads(events)
            return result
        except Exception:
            return []
    return events or []


class BasicDispatcher:
    """Fire-and-forget notification dispatcher.

    Sends to all enabled channels in a bounded thread pool.
    Pro replaces this with NotificationDispatcher (retry, circuit breaker, dedup).
    """

    def __init__(
        self, store: AnalyticsStore | None = None, builder: Callable[..., Any] | None = None, max_workers: int = 4
    ) -> None:
        self._store = store
        self._builder = builder
        self._lock = threading.Lock()
        self._notifiers: dict[int, tuple[dict[str, Any], Any, list[str]]] = {}
        self._last_status: dict[int, dict[str, str]] = {}
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="argus-notify")

    def rebuild(self) -> None:
        """Rebuild notifier instances from DB channels."""
        if not self._store or not self._builder:
            log.debug("dispatcher rebuild skipped: store=%s, builder=%s", bool(self._store), bool(self._builder))
            return
        try:
            channels = self._store.list_notification_channels()
            new_notifiers = {}
            for ch in channels:
                if not ch.get("enabled", True):
                    continue
                notifier = self._builder(ch)
                if notifier:
                    events = _parse_events(ch.get("events"))
                    new_notifiers[ch["id"]] = (ch, notifier, events)
            with self._lock:
                self._notifiers = new_notifiers
                self._last_status = {}
            log.debug("dispatcher rebuilt: %d active notifiers", len(new_notifiers))
        except Exception:
            log.warning("failed to rebuild dispatcher", exc_info=True)

    def dispatch(self, findings: list[Any], provider: str = "", model: str = "", **kwargs: Any) -> None:
        """Send findings to all matching channels via thread pool.

        Args:
            findings: List of Finding objects.
            provider: API provider name.
            model: Model name if available.
            **kwargs: Forward compatibility (e.g. session_id from pipeline).
        """
        if not findings:
            return
        with self._lock:
            notifiers = self._notifiers
        if not notifiers:
            return
        for channel_id, (channel, notifier, events) in notifiers.items():
            if events:
                matching = [f for f in findings if f.action in events]
            else:
                matching = list(findings)
            if not matching:
                continue
            self._pool.submit(self._safe_notify, channel_id, channel, notifier, matching, provider, model)

    def _safe_notify(
        self, channel_id: int, channel: dict[str, Any], notifier: Any, findings: list[Any], provider: str, model: str
    ) -> None:
        try:
            notifier.notify(findings, provider=provider, model=model)
            with self._lock:
                self._last_status[channel_id] = {
                    "status": "sent",
                    "error": "",
                    "timestamp": now_iso(),
                }
            log.info(
                "notification sent: %s (%s) — %d findings",
                channel.get("name", "?"),
                channel.get("type", "?"),
                len(findings),
            )
        except Exception as e:
            with self._lock:
                self._last_status[channel_id] = {
                    "status": "failed",
                    "error": str(e),
                    "timestamp": now_iso(),
                }
            log.warning(
                "notification failed: %s (%s): %s",
                channel.get("name", "?"),
                channel.get("type", "?"),
                e,
                exc_info=True,
            )

    def get_last_status(self) -> dict[int, dict[str, str]]:
        """Return snapshot of last dispatch status per channel.

        Returns dict: {channel_id: {"status", "error", "timestamp"}}
        In-memory only — resets on restart and rebuild.
        """
        with self._lock:
            return dict(self._last_status)
