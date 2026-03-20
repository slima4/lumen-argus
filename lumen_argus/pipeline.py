"""Scanner pipeline: orchestrates extraction, detection, and policy evaluation."""

import hashlib
import logging
import threading
import time
from typing import List

from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.detectors.custom import CustomDetector
from lumen_argus.detectors.pii import PIIDetector
from lumen_argus.detectors.proprietary import ProprietaryDetector
from lumen_argus.detectors.secrets import SecretsDetector
from lumen_argus.extensions import ExtensionRegistry
from lumen_argus.extractor import RequestExtractor
from lumen_argus.models import Finding, ScanField, ScanResult, SessionContext
from lumen_argus.policy import PolicyEngine

log = logging.getLogger("argus.pipeline")


# ---------------------------------------------------------------------------
# Layer 1: Content Fingerprinting — skip already-scanned fields
# ---------------------------------------------------------------------------


class _ConversationCache:
    """Per-conversation set of seen content hashes."""

    __slots__ = ("seen_hashes", "last_access", "hash_count")

    def __init__(self):
        self.seen_hashes = set()  # set of str (SHA-256 prefix)
        self.last_access = time.monotonic()
        self.hash_count = 0


class ContentFingerprint:
    """Process-wide cache mapping conversation keys to seen content hashes.

    Thread-safe. Sharded by conversation key for low lock contention.

    Uses SHA-256 (truncated to 16 hex chars) for deterministic, cross-process
    hashing. Python's built-in hash() is non-deterministic across restarts
    (PYTHONHASHSEED randomization). SHA-256[:16] gives 64-bit collision
    resistance — sufficient for dedup.
    """

    _NUM_SHARDS = 16

    def __init__(
        self, conversation_ttl: int = 1800, max_conversations: int = 10_000, max_hashes_per_conversation: int = 5_000
    ):
        self._ttl = conversation_ttl
        self._max_conversations = max_conversations
        self._max_hashes = max_hashes_per_conversation
        self._shards = [{} for _ in range(self._NUM_SHARDS)]
        self._locks = [threading.Lock() for _ in range(self._NUM_SHARDS)]
        self._cleanup_timer = None

    @staticmethod
    def _hash_text(text: str) -> str:
        """SHA-256 truncated to 16 hex chars (64-bit)."""
        return hashlib.sha256(text.encode()).hexdigest()[:16]

    def _shard_for(self, key: str) -> int:
        return hash(key) & (self._NUM_SHARDS - 1)

    def filter_new_fields(self, conversation_key: str, fields: list) -> list:
        """Return only fields whose content hasn't been seen before.

        Updates the conversation's seen set with new hashes.
        """
        idx = self._shard_for(conversation_key)
        now = time.monotonic()

        # Compute hashes outside the lock (SHA-256 is CPU-bound)
        field_hashes = [self._hash_text(f.text) for f in fields]

        with self._locks[idx]:
            shard = self._shards[idx]
            cache = shard.get(conversation_key)
            if cache is None:
                cache = _ConversationCache()
                shard[conversation_key] = cache
            cache.last_access = now

            new_fields = []
            new_hashes = []
            for f, h in zip(fields, field_hashes):
                if h not in cache.seen_hashes:
                    new_fields.append(f)
                    new_hashes.append(h)

            # Add new hashes, cap total to prevent memory blowup
            remaining = self._max_hashes - cache.hash_count
            if remaining > 0:
                hashes_to_add = new_hashes[:remaining]
                cache.seen_hashes.update(hashes_to_add)
                cache.hash_count += len(hashes_to_add)

        return new_fields

    def cleanup(self) -> int:
        """Remove expired conversations. Called periodically."""
        now = time.monotonic()
        total_removed = 0
        for idx in range(self._NUM_SHARDS):
            with self._locks[idx]:
                expired = [k for k, v in self._shards[idx].items() if now - v.last_access > self._ttl]
                for k in expired:
                    del self._shards[idx][k]
                total_removed += len(expired)
        return total_removed

    def start_cleanup_scheduler(self, interval: float = 300.0):
        """Start background thread to clean expired conversations."""
        if self._cleanup_timer is not None:
            return

        def _run():
            removed = self.cleanup()
            if removed:
                log.debug("content fingerprint: evicted %d idle conversations", removed)
            self._cleanup_timer = threading.Timer(interval, _run)
            self._cleanup_timer.daemon = True
            self._cleanup_timer.start()

        self._cleanup_timer = threading.Timer(interval, _run)
        self._cleanup_timer.daemon = True
        self._cleanup_timer.start()

    def stats(self) -> dict:
        """Return cache statistics."""
        conversations = 0
        total_hashes = 0
        for idx in range(self._NUM_SHARDS):
            with self._locks[idx]:
                for cache in self._shards[idx].values():
                    conversations += 1
                    total_hashes += cache.hash_count
        return {"conversations": conversations, "total_hashes": total_hashes}


# ---------------------------------------------------------------------------
# Layer 2: Finding-Level TTL Cache — prevent duplicate recording
# ---------------------------------------------------------------------------


class _FindingDedup:
    """Cross-request finding deduplication with TTL.

    Tracks recently recorded (detector, type, matched_value_hash) tuples.
    If a finding was already recorded within the TTL window, skip recording
    but still include it in ScanResult for policy evaluation.

    Thread-safe with sharded locks for low contention.
    """

    _NUM_SHARDS = 16

    def __init__(self, ttl_seconds: int = 1800):
        self._ttl = ttl_seconds
        self._shards = [{} for _ in range(self._NUM_SHARDS)]
        self._locks = [threading.Lock() for _ in range(self._NUM_SHARDS)]
        self._cleanup_timer = None

    def _shard_for(self, key: tuple) -> int:
        return hash(key) & (self._NUM_SHARDS - 1)

    def is_new(self, finding, session_id: str = "") -> bool:
        """Return True if this finding hasn't been seen within the TTL window.

        Session-scoped: same finding in different sessions is always new.
        """
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

    def filter_new(self, findings: list, session_id: str = "") -> list:
        """Return only findings that haven't been recorded within the TTL window."""
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

    def start_cleanup_scheduler(self, interval: float = 300.0):
        """Start background thread to clean expired entries."""
        if self._cleanup_timer is not None:
            return

        def _run():
            removed = self.cleanup()
            if removed:
                log.debug("finding dedup: evicted %d expired entries", removed)
            self._cleanup_timer = threading.Timer(interval, _run)
            self._cleanup_timer.daemon = True
            self._cleanup_timer.start()

        self._cleanup_timer = threading.Timer(interval, _run)
        self._cleanup_timer.daemon = True
        self._cleanup_timer.start()


# Maximum total text bytes to scan per request. Fields beyond this are
# skipped (with a warning finding). This keeps scan time bounded even on
# very large payloads. 200KB covers the most recent/largest fields in
# a typical session while keeping scan time well under 50ms.
MAX_SCAN_TEXT_BYTES = 200_000


class ScannerPipeline:
    """Runs the full scan pipeline: extract → detect → evaluate policy."""

    def __init__(
        self,
        default_action: str = "alert",
        action_overrides: dict = None,
        allowlist: AllowlistMatcher = None,
        entropy_threshold: float = 4.5,
        extensions: ExtensionRegistry = None,
        max_scan_bytes: int = MAX_SCAN_TEXT_BYTES,
        custom_rules: list = None,
        dedup_config: dict = None,
    ):
        self._extractor = RequestExtractor()
        self._allowlist = allowlist or AllowlistMatcher()
        self._policy = PolicyEngine(
            default_action=default_action,
            action_overrides=action_overrides,
        )
        self._max_scan_bytes = max_scan_bytes
        self._extensions = extensions

        # Build detector chain
        self._detectors = []  # type: List[BaseDetector]
        self._detectors.append(SecretsDetector(entropy_threshold=entropy_threshold))
        self._detectors.append(PIIDetector())
        self._detectors.append(ProprietaryDetector())

        # Custom regex rules from config (reloaded on SIGHUP)
        self._custom_detector = CustomDetector(custom_rules)
        self._detectors.append(self._custom_detector)

        # Add any pro/enterprise extension detectors
        if extensions:
            self._detectors.extend(extensions.extra_detectors())

        # Cross-request dedup (Layers 1 + 2)
        dc = dedup_config or {}
        conv_ttl = int(dc.get("conversation_ttl_minutes", 30)) * 60
        finding_ttl = int(dc.get("finding_ttl_minutes", 30)) * 60
        max_convs = int(dc.get("max_conversations", 10_000))
        max_hashes = int(dc.get("max_hashes_per_conversation", 5_000))
        self._fingerprint = ContentFingerprint(
            conversation_ttl=conv_ttl,
            max_conversations=max_convs,
            max_hashes_per_conversation=max_hashes,
        )
        self._fingerprint.start_cleanup_scheduler()
        self._finding_dedup = _FindingDedup(ttl_seconds=finding_ttl)
        self._finding_dedup.start_cleanup_scheduler()

    def reload(
        self, allowlist: AllowlistMatcher, default_action: str, action_overrides: dict = None, custom_rules: list = None
    ) -> None:
        """Reload policy, allowlist, and custom rules from new config.

        Builds replacement objects then swaps references atomically
        (single assignment under CPython GIL) to avoid races with
        request handler threads.
        """
        new_policy = PolicyEngine(
            default_action=default_action,
            action_overrides=action_overrides,
        )
        # Atomic swaps — each is a single reference assignment
        self._allowlist = allowlist
        self._policy = new_policy
        if custom_rules is not None:
            self._custom_detector.update_rules(custom_rules)

    def scan(self, body: bytes, provider: str, model: str = "", session: SessionContext = None) -> ScanResult:
        """Run the full scan pipeline on a request body.

        Args:
            body: Raw request body bytes (JSON).
            provider: Provider name for extraction format.
            model: Model name from request body (for analytics/notifications).
            session: Session context extracted from request headers/body.

        Returns:
            ScanResult with findings, timing, and resolved action.
        """
        t0 = time.monotonic()

        # Extract scannable fields
        fields = self._extractor.extract(body, provider)
        log.debug("extracted %d fields from %s request (%d bytes)", len(fields), provider, len(body))

        # Filter out allowlisted paths
        fields = [f for f in fields if not (f.source_filename and self._allowlist.is_allowed_path(f.source_filename))]

        # Layer 1: Content fingerprinting — skip fields already scanned
        # in a previous request within this conversation.
        conv_key = session.session_id if session else ""
        if conv_key:
            original_count = len(fields)
            fields = self._fingerprint.filter_new_fields(conv_key, fields)
            skipped = original_count - len(fields)
            if skipped:
                log.debug(
                    "fingerprint: skipped %d/%d already-scanned fields",
                    skipped,
                    original_count,
                )

        # Prioritize scanning: reverse order so newest messages (end of
        # conversation) are scanned first, then cap total text to keep
        # scan time bounded. In a typical AI session, older messages were
        # already scanned in previous requests.
        fields_to_scan = []
        total_text = 0
        for field in reversed(fields):
            if total_text + len(field.text) > self._max_scan_bytes:
                # Include truncated field up to the budget
                remaining = self._max_scan_bytes - total_text
                if remaining > 100:
                    fields_to_scan.append(
                        ScanField(
                            path=field.path,
                            text=field.text[:remaining],
                            source_filename=field.source_filename,
                        )
                    )
                break
            fields_to_scan.append(field)
            total_text += len(field.text)

        log.debug(
            "scanning %d fields (%d chars, budget %d)",
            len(fields_to_scan),
            total_text,
            self._max_scan_bytes,
        )

        # Run all detectors
        all_findings = []  # type: List[Finding]
        for detector in self._detectors:
            det_findings = detector.scan(fields_to_scan, self._allowlist)
            if det_findings:
                log.debug(
                    "%s: %d findings",
                    detector.__class__.__name__,
                    len(det_findings),
                )
            all_findings.extend(det_findings)

        # Deduplicate findings — same (detector, type, matched_value) collapsed
        # into one finding with a count. Reduces noise from repeated secrets
        # in conversation history.
        all_findings = self._deduplicate(all_findings)

        # Evaluate policy — plugins can override via evaluate hook
        eval_hook = self._extensions.get_evaluate_hook() if self._extensions else None
        if eval_hook:
            try:
                decision = eval_hook(all_findings, self._policy)
            except Exception:
                log.warning("evaluate_hook raised, falling back to default policy")
                decision = self._policy.evaluate(all_findings)
        else:
            decision = self._policy.evaluate(all_findings)

        elapsed_ms = (time.monotonic() - t0) * 1000

        if elapsed_ms > 50:
            log.warning(
                "slow scan: %.1fms (%d fields, %dKB, budget %dKB)",
                elapsed_ms,
                len(fields_to_scan),
                total_text // 1024,
                self._max_scan_bytes // 1024,
            )

        result = ScanResult(
            findings=decision.findings,
            scan_duration_ms=elapsed_ms,
            action=decision.action,
        )

        # Layer 2: Finding-level dedup — filter before recording but after
        # policy eval. All findings stay in ScanResult for action enforcement.
        # Session-scoped: same finding in different sessions is always new.
        sess_id = session.session_id if session else ""
        new_findings = self._finding_dedup.filter_new(result.findings, session_id=sess_id) if result.findings else []

        # Record only NEW findings in analytics store (community dashboard)
        if new_findings and self._extensions:
            store = self._extensions.get_analytics_store()
            if store:
                try:
                    store.record_findings(
                        new_findings,
                        provider=provider,
                        model=model,
                        session=session,
                    )
                except Exception:
                    log.warning("analytics store record_findings failed", exc_info=False)

        # Dispatch notifications — pass ALL findings (dispatcher has its own dedup)
        if result.findings and self._extensions:
            dispatcher = self._extensions.get_dispatcher()
            if dispatcher:
                try:
                    dispatcher.dispatch(
                        result.findings,
                        provider=provider,
                        model=model,
                        session_id=session.session_id if session else "",
                    )
                except Exception:
                    log.warning("notification dispatch failed", exc_info=False)

        # Fire post-scan hook for plugins (analytics, SSE, etc.)
        if self._extensions:
            hook = self._extensions.get_post_scan_hook()
            if hook:
                try:
                    hook(result, body, provider, session=session)
                except Exception:
                    pass  # Never let plugin errors break the proxy

        return result

    @staticmethod
    def _deduplicate(findings: List[Finding]) -> List[Finding]:
        """Collapse duplicate findings into one with a count.

        Same (detector, type, matched_value) → keep first occurrence, set count.
        Creates new Finding objects to avoid mutating detector output.
        """
        from dataclasses import replace

        seen = {}  # type: dict[tuple, int]
        first = {}  # type: dict[tuple, Finding]
        for f in findings:
            key = (f.detector, f.type, f.matched_value)
            if key in seen:
                seen[key] += 1
            else:
                seen[key] = 1
                first[key] = f
        return [replace(first[k], count=c) for k, c in seen.items()]
