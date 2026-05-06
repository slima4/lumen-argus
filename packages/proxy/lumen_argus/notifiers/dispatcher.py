"""Basic notification dispatcher — fire-and-forget."""

from __future__ import annotations

import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore
    from lumen_argus.models import SessionContext

from lumen_argus.models import FindingOrigin
from lumen_argus.notifiers._rate_limit import TokenBucket
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

    Sends to all enabled channels in a bounded thread pool. Applies a
    per-(detector, type) `TokenBucket` to FRAMEWORK-origin findings so a
    request-deterministic infrastructure fault cannot saturate channels;
    DETECTOR-origin findings (real DLP signal) bypass the gate.
    Pro replaces this with NotificationDispatcher (per-channel retry,
    circuit breaker, cross-channel dedup).
    """

    def __init__(
        self,
        store: AnalyticsStore | None = None,
        builder: Callable[..., Any] | None = None,
        max_workers: int = 4,
        framework_bucket: TokenBucket | None = None,
    ) -> None:
        self._store = store
        self._builder = builder
        self._lock = threading.Lock()
        self._notifiers: dict[int, tuple[dict[str, Any], Any, list[str]]] = {}
        self._last_status: dict[int, dict[str, str]] = {}
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="argus-notify")
        # Rate-limit for FRAMEWORK-origin findings — protects channels from
        # request-deterministic infrastructure faults (scan_error storm,
        # mode_changed flap). DETECTOR-origin findings bypass this gate;
        # legitimate detection volume is the operator's signal, not noise.
        self._framework_bucket = framework_bucket

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
            # Channel reconfiguration restarts the suppression window so
            # operators reading `notification_suppressed` see post-rebuild
            # gap, not stale lifetime accumulation.
            if self._framework_bucket is not None:
                self._framework_bucket.reset()
            log.debug("dispatcher rebuilt: %d active notifiers", len(new_notifiers))
        except Exception:
            log.warning("failed to rebuild dispatcher", exc_info=True)

    def dispatch(
        self,
        findings: list[Any],
        provider: str = "",
        model: str = "",
        session: "SessionContext | None" = None,
        **kwargs: Any,
    ) -> None:
        """Send findings to all matching channels via thread pool.

        Args:
            findings: List of Finding objects.
            provider: API provider name.
            model: Model name if available.
            session: Full SessionContext for the scanned request. Forwarded to
                every notifier's ``notify()`` as ``session=session`` so Pro
                notifiers (and future community ones) can enrich payloads with
                hostname, working_directory, intercept_mode, original_host,
                etc. BasicDispatcher itself reads no fields from it — it only
                plumbs the reference through.
            **kwargs: Absorbed at this boundary, NOT forwarded to notifiers.
                Retained on the signature so that a caller passing an unknown
                keyword (e.g. the pipeline still sends ``session_id`` alongside
                ``session`` for backward-compat with Pro dispatchers pinned to
                older community versions) does not raise ``TypeError``. The
                full SessionContext reference is the canonical per-request
                payload — if a future field needs to reach notifiers, promote
                it to an explicit parameter like ``session``.

        Thread safety: ``session`` is submitted to a daemon worker thread.
        Pro notifiers running inside that worker must treat it as read-only;
        the same instance is still reachable on the calling thread via the
        SSE broadcast and post-scan hook, both of which are read-only today,
        so mutation from a worker would race with those readers.
        """
        if not findings:
            return
        with self._lock:
            notifiers = self._notifiers
        if not notifiers:
            # No subscribers — skip rate-limit gate so suppression counters
            # don't tick for findings nobody could have received anyway.
            return
        # Pre-filter against the union of channel-events subscriptions so the
        # rate-limit gate doesn't burn tokens (and inflate suppression counts)
        # for findings every channel would have dropped on its own filter.
        # An empty events list on any channel = wildcard ⇒ all findings reach
        # at least one channel ⇒ skip pre-filter.
        wildcard = any(not events for _, _, events in notifiers.values())
        if wildcard:
            reachable = findings
        else:
            allowed_actions: set[str] = set()
            for _, _, events in notifiers.values():
                allowed_actions.update(events)
            reachable = [f for f in findings if f.action in allowed_actions]
            if not reachable:
                return
        admitted = self._apply_framework_rate_limit(reachable)
        if not admitted:
            return
        for channel_id, (channel, notifier, events) in notifiers.items():
            if events:
                matching = [f for f in admitted if f.action in events]
            else:
                matching = list(admitted)
            if not matching:
                continue
            self._pool.submit(self._safe_notify, channel_id, channel, notifier, matching, provider, model, session)

    def _apply_framework_rate_limit(self, findings: list[Any]) -> list[Any]:
        """Drop FRAMEWORK-origin findings that exceed the per-(detector,type)
        token bucket. Returns the surviving list (DETECTOR origins always
        survive). When no bucket is configured, returns findings unchanged.
        """
        if self._framework_bucket is None:
            return findings
        admitted: list[Any] = []
        for f in findings:
            if f.origin != FindingOrigin.FRAMEWORK:
                admitted.append(f)
                continue
            if self._framework_bucket.try_acquire((f.detector, f.type)):
                admitted.append(f)
        return admitted

    def get_suppression_counts(self) -> dict[str, int]:
        """Return per-(detector,type) suppression counts for FRAMEWORK
        findings as a dict of ``"{detector}:{type}" -> count``. Empty when
        no bucket is configured or no suppressions have occurred.
        """
        if self._framework_bucket is None:
            return {}
        snap = self._framework_bucket.snapshot()
        out: dict[str, int] = {}
        for key, count in snap.items():
            if isinstance(key, tuple) and len(key) == 2:
                out["%s:%s" % (key[0], key[1])] = count
            else:
                out[str(key)] = count
        return out

    def _safe_notify(
        self,
        channel_id: int,
        channel: dict[str, Any],
        notifier: Any,
        findings: list[Any],
        provider: str,
        model: str,
        session: "SessionContext | None" = None,
    ) -> None:
        try:
            notifier.notify(findings, provider=provider, model=model, session=session)
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
