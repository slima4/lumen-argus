"""Content fingerprinting — skip already-scanned fields across requests.

Changes when: cache strategy, hash algorithm, eviction policy, or shard count changes.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time

from lumen_argus.models import ScanField

log = logging.getLogger("argus.pipeline")


class _ConversationCache:
    """Per-conversation set of seen content hashes."""

    __slots__ = ("last_access", "seen_hashes")

    def __init__(self) -> None:
        self.seen_hashes: set[str] = set()  # set of str (SHA-256 prefix)
        self.last_access = time.monotonic()


class ContentFingerprint:
    """Process-wide cache mapping conversation keys to seen content hashes.

    Thread-safe. Sharded by conversation key for low lock contention.

    Uses SHA-256 (truncated to 16 hex chars) for deterministic, cross-process
    hashing. Python's built-in hash() is non-deterministic across restarts
    (PYTHONHASHSEED randomization). SHA-256[:16] gives 64-bit collision
    resistance — sufficient for dedup.
    """

    NUM_SHARDS = 16

    def __init__(
        self, conversation_ttl: int = 1800, max_conversations: int = 10_000, max_hashes_per_conversation: int = 5_000
    ):
        if max_conversations < self.NUM_SHARDS:
            raise ValueError(
                "max_conversations must be >= %d (one per shard); got %d. "
                "Set dedup.max_conversations to a positive integer at least %d in config."
                % (self.NUM_SHARDS, max_conversations, self.NUM_SHARDS)
            )
        if max_hashes_per_conversation < 1:
            raise ValueError("max_hashes_per_conversation must be >= 1; got %d." % max_hashes_per_conversation)
        if conversation_ttl < 0:
            raise ValueError("conversation_ttl must be >= 0; got %d." % conversation_ttl)
        self._ttl = conversation_ttl
        self._max_conversations = max_conversations
        self._max_hashes = max_hashes_per_conversation
        self._shard_limit = max_conversations // self.NUM_SHARDS
        self._shards: list[dict[str, _ConversationCache]] = [{} for _ in range(self.NUM_SHARDS)]
        self._locks = [threading.Lock() for _ in range(self.NUM_SHARDS)]
        self._cleanup_timer: threading.Timer | None = None
        log.info(
            "content fingerprint: max_conversations=%d (shard_limit=%d across %d shards), "
            "max_hashes_per_conversation=%d, ttl=%ds",
            max_conversations,
            self._shard_limit,
            self.NUM_SHARDS,
            max_hashes_per_conversation,
            conversation_ttl,
        )

    @staticmethod
    def _hash_text(text: str) -> str:
        """SHA-256 truncated to 16 hex chars (64-bit)."""
        return hashlib.sha256(text.encode()).hexdigest()[:16]

    def _shard_for(self, key: str) -> int:
        return hash(key) & (self.NUM_SHARDS - 1)

    def filter_new_fields(
        self, conversation_key: str, fields: list[ScanField]
    ) -> tuple[list[ScanField], tuple[str, list[str]]]:
        """Return only fields whose content hasn't been seen before.

        Does NOT commit hashes yet — call commit_hashes() after confirming
        the request won't be blocked. This prevents blocked content from
        being fingerprinted, which would allow it through on retry.

        Returns:
            (new_fields, pending_hashes) — pending_hashes is an opaque token
            to pass to commit_hashes().
        """
        idx = self._shard_for(conversation_key)
        now = time.monotonic()

        # Compute hashes outside the lock (SHA-256 is CPU-bound)
        field_hashes = [self._hash_text(f.text) for f in fields]

        with self._locks[idx]:
            shard = self._shards[idx]
            existing = shard.get(conversation_key)
            is_new_conv = existing is None
            if existing is not None:
                conv_cache = existing
            else:
                conv_cache = _ConversationCache()
                shard[conversation_key] = conv_cache
            conv_cache.last_access = now

            new_fields = []
            new_hashes = []
            for f, h in zip(fields, field_hashes):
                if h not in conv_cache.seen_hashes:
                    new_fields.append(f)
                    new_hashes.append(h)

            # LRU eviction: if adding a new conversation exceeded the
            # per-shard limit, evict the least-recently-accessed entry.
            if is_new_conv and len(shard) > self._shard_limit:
                lru_key = min(
                    (k for k in shard if k != conversation_key),
                    key=lambda k: shard[k].last_access,
                )
                del shard[lru_key]

        pending = (conversation_key, new_hashes)
        return new_fields, pending

    def commit_hashes(self, pending: tuple[str, list[str]]) -> None:
        """Commit previously computed hashes to the seen set.

        Call this only when the request was NOT blocked, so that blocked
        content will be re-scanned on retry.
        """
        conversation_key, new_hashes = pending
        if not new_hashes:
            return
        idx = self._shard_for(conversation_key)
        with self._locks[idx]:
            shard = self._shards[idx]
            cache = shard.get(conversation_key)
            if cache is None:
                return
            remaining = self._max_hashes - len(cache.seen_hashes)
            if remaining > 0:
                cache.seen_hashes.update(new_hashes[:remaining])

    def cleanup(self) -> int:
        """Remove expired conversations. Called periodically."""
        now = time.monotonic()
        total_removed = 0
        for idx in range(self.NUM_SHARDS):
            with self._locks[idx]:
                expired = [k for k, v in self._shards[idx].items() if now - v.last_access > self._ttl]
                for k in expired:
                    del self._shards[idx][k]
                total_removed += len(expired)
        return total_removed

    def start_cleanup_scheduler(self, interval: float = 300.0) -> None:
        """Start background thread to clean expired conversations."""
        if self._cleanup_timer is not None:
            return

        def _run() -> None:
            removed = self.cleanup()
            if removed:
                log.debug("content fingerprint: evicted %d idle conversations", removed)
            timer = threading.Timer(interval, _run)
            timer.daemon = True
            timer.start()
            self._cleanup_timer = timer

        timer = threading.Timer(interval, _run)
        timer.daemon = True
        timer.start()
        self._cleanup_timer = timer

    def stats(self) -> dict[str, int]:
        """Return cache statistics."""
        conversations = 0
        total_hashes = 0
        for idx in range(self.NUM_SHARDS):
            with self._locks[idx]:
                for cache in self._shards[idx].values():
                    conversations += 1
                    total_hashes += len(cache.seen_hashes)
        return {"conversations": conversations, "total_hashes": total_hashes}
