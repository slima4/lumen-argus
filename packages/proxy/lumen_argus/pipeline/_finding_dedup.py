"""Finding-level TTL dedup — prevent duplicate recording across requests.

Changes when: dedup strategy, TTL policy, or shard count changes.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time

from lumen_argus.models import Finding

log = logging.getLogger("argus.pipeline")


class FindingDedup:
    """Cross-request finding deduplication with TTL.

    Tracks recently recorded (detector, type, matched_value_hash) tuples.
    If a finding was already recorded within the TTL window, skip recording
    but still include it in ScanResult for policy evaluation.

    Thread-safe with sharded locks for low contention.
    """

    _NUM_SHARDS = 16

    def __init__(self, ttl_seconds: int = 1800):
        self._ttl = ttl_seconds
        self._shards: list[dict[tuple[str, str, str, str], float]] = [{} for _ in range(self._NUM_SHARDS)]
        self._locks = [threading.Lock() for _ in range(self._NUM_SHARDS)]
        self._cleanup_timer: threading.Timer | None = None

    def _shard_for(self, key: tuple[str, str, str, str]) -> int:
        return hash(key) & (self._NUM_SHARDS - 1)

    def is_new(self, finding: Finding, session_id: str = "") -> bool:
        """Return True if this finding hasn't been seen within the TTL window.

        Empty ``session_id`` bypasses the cache entirely — keying on it
        would collapse every sessionless request from every user into a
        single bucket.
        """
        if not session_id:
            return True
        value_hash = hashlib.sha256(finding.matched_value.encode()).hexdigest()[:16]
        key = (finding.detector, finding.type, value_hash, session_id)
        idx = self._shard_for(key)
        now = time.monotonic()

        with self._locks[idx]:
            entry = self._shards[idx].get(key)
            if entry is not None and (now - entry) < self._ttl:
                return False
            self._shards[idx][key] = now
            return True

    def filter_new(self, findings: list[Finding], session_id: str = "") -> list[Finding]:
        """Return only findings that haven't been recorded within the TTL window."""
        if not session_id:
            return list(findings)
        return [f for f in findings if self.is_new(f, session_id=session_id)]

    def cleanup(self) -> int:
        """Remove expired entries. Returns count removed."""
        now = time.monotonic()
        total = 0
        for idx in range(self._NUM_SHARDS):
            with self._locks[idx]:
                expired = [k for k, ts in self._shards[idx].items() if now - ts > self._ttl]
                for k in expired:
                    del self._shards[idx][k]
                total += len(expired)
        return total

    def start_cleanup_scheduler(self, interval: float = 300.0) -> None:
        """Start background thread to clean expired entries."""
        if self._cleanup_timer is not None:
            return

        def _run() -> None:
            removed = self.cleanup()
            if removed:
                log.debug("finding dedup: evicted %d expired entries", removed)
            timer = threading.Timer(interval, _run)
            timer.daemon = True
            timer.start()
            self._cleanup_timer = timer

        timer = threading.Timer(interval, _run)
        timer.daemon = True
        timer.start()
        self._cleanup_timer = timer
