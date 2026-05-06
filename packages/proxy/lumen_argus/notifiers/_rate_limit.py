"""Per-key token bucket for notification rate-limiting.

A request-deterministic infrastructure fault (bad rules import, plugin hook
regression, analytics DB lock) can produce one synthetic Finding per request.
Without an upstream gate, every alert reaches a notification channel; a
fleet under sustained crash saturates Slack/PagerDuty webhooks and drowns
real DLP findings.

The bucket trades fidelity for survivability — the operator sees one alert
per ``(detector, type)`` per ``refill_seconds`` plus the suppressed count,
which is the same signal at a fraction of the volume.
"""

from __future__ import annotations

import threading
import time
from typing import Hashable


class TokenBucket:
    """Thread-safe per-key fixed-rate bucket.

    Each unique ``key`` gets an independent bucket of ``capacity`` tokens
    that refills linearly at ``capacity / refill_seconds`` tokens per
    second. ``try_acquire`` is non-blocking: returns True and consumes one
    token when available, returns False and increments the per-key
    suppression count otherwise. ``snapshot`` returns the current
    suppression counts; ``reset`` clears all bucket state.

    Buckets are created lazily on first ``try_acquire`` for a key — no
    pre-registration needed, callers can use any hashable key.
    """

    def __init__(self, capacity: int, refill_seconds: float) -> None:
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        if refill_seconds <= 0:
            raise ValueError("refill_seconds must be > 0")
        self._capacity = capacity
        self._refill_rate = capacity / refill_seconds
        self._lock = threading.Lock()
        self._tokens: dict[Hashable, float] = {}
        self._last_refill: dict[Hashable, float] = {}
        self._suppressed: dict[Hashable, int] = {}

    def try_acquire(self, key: Hashable) -> bool:
        now = time.monotonic()
        with self._lock:
            last = self._last_refill.get(key)
            if last is None:
                # First touch — bucket starts full.
                self._tokens[key] = self._capacity - 1
                self._last_refill[key] = now
                return True
            elapsed = now - last
            tokens = min(self._capacity, self._tokens[key] + elapsed * self._refill_rate)
            self._last_refill[key] = now
            if tokens >= 1.0:
                self._tokens[key] = tokens - 1.0
                return True
            self._tokens[key] = tokens
            self._suppressed[key] = self._suppressed.get(key, 0) + 1
            return False

    def snapshot(self) -> dict[Hashable, int]:
        """Return a copy of {key: suppressed_count}. Counts accumulate
        across the bucket lifetime; reset() zeroes them."""
        with self._lock:
            return dict(self._suppressed)

    def reset(self) -> None:
        """Clear all bucket state — tokens, refill timestamps, suppression
        counts. Used on dispatcher rebuild and in tests."""
        with self._lock:
            self._tokens.clear()
            self._last_refill.clear()
            self._suppressed.clear()
