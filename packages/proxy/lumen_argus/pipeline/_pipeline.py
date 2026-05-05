"""Scanner pipeline: orchestrates extraction, detection, and policy evaluation.

Changes when: pipeline stages, stage ordering, or orchestration logic changes.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import replace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore

from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.decoders import ContentDecoder
from lumen_argus.detectors import BaseDetector
from lumen_argus.detectors.custom import CustomDetector
from lumen_argus.detectors.pii import PIIDetector
from lumen_argus.detectors.proprietary import ProprietaryDetector
from lumen_argus.detectors.rules import RulesDetector
from lumen_argus.detectors.secrets import SecretsDetector
from lumen_argus.extensions import ExtensionRegistry
from lumen_argus.extractor import RequestExtractor
from lumen_argus.models import Finding, ScanField, ScanResult, SessionContext
from lumen_argus.pipeline._finding_dedup import FindingDedup
from lumen_argus.pipeline._fingerprint import ContentFingerprint
from lumen_argus.policy import ActionDecision, PolicyEngine
from lumen_argus.text_utils import sanitize_text

log = logging.getLogger("argus.pipeline")

# Maximum total text bytes to scan per request. Fields beyond this are
# skipped (with a warning finding). This keeps scan time bounded even on
# very large payloads. 200KB covers the most recent/largest fields in
# a typical session while keeping scan time well under 50ms.
MAX_SCAN_TEXT_BYTES = 200_000


class ScannerPipeline:
    """Runs the full scan pipeline: extract -> detect -> evaluate policy."""

    def __init__(
        self,
        default_action: str = "alert",
        action_overrides: dict[str, str] | None = None,
        allowlist: AllowlistMatcher | None = None,
        entropy_threshold: float = 4.5,
        extensions: ExtensionRegistry | None = None,
        max_scan_bytes: int = MAX_SCAN_TEXT_BYTES,
        custom_rules: list[Any] | None = None,
        dedup_config: dict[str, Any] | None = None,
        pipeline_config: dict[str, Any] | None = None,
        rebuild_delay: float = 2.0,
    ):
        self._extractor = RequestExtractor()
        self._reload_lock = threading.Lock()  # Protects reference swaps for free-threaded Python
        self._allowlist = allowlist or AllowlistMatcher()
        self._policy = PolicyEngine(
            default_action=default_action,
            action_overrides=action_overrides,
        )
        self._max_scan_bytes = max_scan_bytes
        self._extensions = extensions

        # Pipeline stage toggles
        pc = pipeline_config or {}
        self._outbound_dlp_enabled = bool(pc.get("outbound_dlp_enabled", True))
        self._encoding_decode_enabled = bool(pc.get("encoding_decode_enabled", True))
        if not self._outbound_dlp_enabled:
            log.info("pipeline stage outbound_dlp is DISABLED — scanning will be skipped")
        if not self._encoding_decode_enabled:
            log.info("pipeline stage encoding_decode is DISABLED")

        # Content decoder (encoding-aware scanning)
        self._decoder = self._build_decoder(pc) if self._encoding_decode_enabled else None

        # Build detector chain.
        # If DB has rules, use RulesDetector (replaces Secrets/PII/Custom).
        # ProprietaryDetector always runs (file-pattern + keyword based, not regex rules).
        # Fallback to hardcoded detectors if no rules in DB.
        self._detectors: list[BaseDetector] = []
        self._rules_detector: RulesDetector | None = None
        store: AnalyticsStore | None = extensions.get_analytics_store() if extensions else None
        has_rules = False
        if store and hasattr(store, "get_rules_count"):
            try:
                count = store.get_rules_count()
                if isinstance(count, int) and count > 0:
                    has_rules = True
            except Exception:
                log.warning("failed to check rules count from store", exc_info=True)
        if has_rules and store:
            self._rules_detector = RulesDetector(
                store=store,
                license_checker=extensions.get_license_checker() if extensions else None,
                metrics_collector=extensions.get_rule_metrics_collector() if extensions else None,
                accelerator_factory=extensions.get_accelerator_factory() if extensions else None,
                rebuild_delay=rebuild_delay,
            )
            self._detectors.append(self._rules_detector)
            store.set_rules_change_callback(self._rules_detector.on_rules_changed)
            if extensions:
                skip = extensions.get_rule_skip_list()
                if skip:
                    self._rules_detector.set_skip_list(skip)
                extensions.set_rule_skip_list_callback(self._rules_detector.set_skip_list)
            log.info("using DB-backed rules detector (%d rules)", count)
        # Note: if DB starts empty (fallback path), callback is not registered.
        # Rules imported while running won't take effect until restart/SIGHUP.
        else:
            # Fallback: hardcoded pattern files (no rules imported yet)
            self._detectors.append(SecretsDetector(entropy_threshold=entropy_threshold))
            self._detectors.append(PIIDetector())
            self._custom_detector = CustomDetector(custom_rules)
            self._detectors.append(self._custom_detector)

        self._detectors.append(ProprietaryDetector())

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
        self._finding_dedup = FindingDedup(ttl_seconds=finding_ttl)
        self._finding_dedup.start_cleanup_scheduler()

    def fingerprint_stats(self) -> dict[str, int]:
        """Return content-fingerprint cache stats for /metrics export."""
        return self._fingerprint.stats()

    def commit_pending(self, result: ScanResult) -> None:
        """Commit deferred fingerprint hashes from a blocked-then-stripped request.

        Call this after history stripping succeeds — the stripped content has
        been handled, so future requests can skip re-scanning it.
        """
        pending = result._pending_hashes
        if pending:
            conv_key, hashes = pending
            log.debug(
                "commit_pending: committing %d hashes for session %s after strip",
                len(hashes),
                conv_key[:16] if conv_key else "",
            )
            self._fingerprint.commit_hashes(pending)
            result._pending_hashes = None

    def reload(
        self,
        allowlist: AllowlistMatcher,
        default_action: str,
        action_overrides: dict[str, str] | None = None,
        custom_rules: list[Any] | None = None,
        pipeline_config: dict[str, Any] | None = None,
    ) -> None:
        """Reload policy, allowlist, custom rules, and pipeline config.

        Builds replacement objects then swaps references under lock.
        Lock ensures free-threaded Python (3.13+ no-GIL) sees consistent
        state — scan() snapshots references under the same lock.
        """
        new_policy = PolicyEngine(
            default_action=default_action,
            action_overrides=action_overrides,
        )
        new_decoder = None
        new_outbound_dlp = self._outbound_dlp_enabled
        new_encoding_decode = self._encoding_decode_enabled
        if pipeline_config is not None:
            new_outbound_dlp = bool(pipeline_config.get("outbound_dlp_enabled", True))
            new_encoding_decode = bool(pipeline_config.get("encoding_decode_enabled", True))
            if new_encoding_decode:
                new_decoder = self._build_decoder(pipeline_config)
            log.debug(
                "pipeline reload: outbound_dlp=%s encoding_decode=%s",
                "enabled" if new_outbound_dlp else "disabled",
                "enabled" if new_encoding_decode else "disabled",
            )

        with self._reload_lock:
            self._allowlist = allowlist
            self._policy = new_policy
            self._outbound_dlp_enabled = new_outbound_dlp
            self._encoding_decode_enabled = new_encoding_decode
            if pipeline_config is not None:
                self._decoder = new_decoder

        # Reload rules from DB if using RulesDetector, otherwise update custom rules
        if self._rules_detector:
            self._rules_detector.reload()
        elif custom_rules is not None and hasattr(self, "_custom_detector"):
            self._custom_detector.update_rules(custom_rules)

    @staticmethod
    def _build_decoder(pc: dict[str, Any]) -> ContentDecoder:
        """Build a ContentDecoder from pipeline config dict."""
        return ContentDecoder(
            enable_base64=bool(pc.get("encoding_base64", True)),
            enable_hex=bool(pc.get("encoding_hex", True)),
            enable_url=bool(pc.get("encoding_url", True)),
            enable_unicode=bool(pc.get("encoding_unicode", True)),
            max_depth=int(pc.get("encoding_max_depth", 2)),
            min_decoded_length=int(pc.get("encoding_min_decoded_length", 8)),
            max_decoded_length=int(pc.get("encoding_max_decoded_length", 10_000)),
        )

    def scan(self, body: bytes, provider: str, model: str = "", session: SessionContext | None = None) -> ScanResult:
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
        stage_timings: dict[str, float] = {}

        # Snapshot mutable references under lock — ensures consistency
        # when reload() swaps them from another thread (free-threaded Python).
        with self._reload_lock:
            allowlist = self._allowlist
            policy = self._policy
            decoder = self._decoder
            detectors = self._detectors
            outbound_dlp_enabled = self._outbound_dlp_enabled

        # Extract scannable fields
        t_stage = time.monotonic()
        fields = self._extractor.extract(body, provider)
        log.debug("extracted %d fields from %s request (%d bytes)", len(fields), provider, len(body))

        # Filter out allowlisted paths
        fields = [f for f in fields if not (f.source_filename and allowlist.is_allowed_path(f.source_filename))]
        stage_timings["extraction"] = (time.monotonic() - t_stage) * 1000

        # Sanitize — strip zero-width chars and normalize Unicode homoglyphs
        # Runs before all decoders and detectors to defeat evasion techniques.
        t_stage = time.monotonic()
        for i, field in enumerate(fields):
            cleaned = sanitize_text(field.text)
            if cleaned != field.text:
                fields[i] = ScanField(path=field.path, text=cleaned, source_filename=field.source_filename)
        stage_timings["sanitize"] = (time.monotonic() - t_stage) * 1000

        # Encoding decode stage — expand fields with decoded variants
        if decoder:
            t_stage = time.monotonic()
            expanded = []
            for field in fields:
                variants = decoder.decode_field(field.text)
                for v in variants:
                    # Sanitize decoded variants — encoded payloads may contain
                    # zero-width chars that would evade detection after decoding
                    text = sanitize_text(v.text) if v.encoding != "raw" else v.text
                    expanded.append(
                        ScanField(
                            path=field.path if v.encoding == "raw" else "%s[%s]" % (field.path, v.encoding),
                            text=text,
                            source_filename=field.source_filename,
                        )
                    )
            if len(expanded) > len(fields):
                log.debug(
                    "encoding decode: %d fields -> %d fields (+%d decoded)",
                    len(fields),
                    len(expanded),
                    len(expanded) - len(fields),
                )
            fields = expanded
            stage_timings["encoding_decode"] = (time.monotonic() - t_stage) * 1000

        # Layer 1: Content fingerprinting — skip fields already scanned
        # in a previous request within this conversation.
        # Two-phase: filter first, commit hashes only if not blocked.
        # This ensures blocked content is re-scanned on retry.
        t_stage = time.monotonic()
        conv_key = session.session_id if session else ""
        pending_hashes: tuple[str, list[str]] | None = None
        if conv_key:
            original_count = len(fields)
            fields, pending_hashes = self._fingerprint.filter_new_fields(conv_key, fields)
            skipped = original_count - len(fields)
            if skipped:
                log.debug(
                    "fingerprint: skipped %d/%d already-scanned fields",
                    skipped,
                    original_count,
                )
                # Bump seen_count for existing findings in this session.
                # Safe to always bump: runs before record_findings(), so
                # new findings from this request aren't in the DB yet and
                # won't be double-counted (they INSERT with seen_count=1).
                if self._extensions:
                    _store: AnalyticsStore | None = self._extensions.get_analytics_store()
                    if _store:
                        try:
                            _store.bump_seen_counts(conv_key)
                        except Exception:
                            log.warning("failed to bump seen_counts for session %s", conv_key, exc_info=True)

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
        stage_timings["fingerprint"] = (time.monotonic() - t_stage) * 1000

        # Run all detectors (gated by outbound_dlp stage toggle)
        t_stage = time.monotonic()
        all_findings: list[Finding] = []
        if outbound_dlp_enabled:
            for detector in detectors:
                det_findings = detector.scan(fields_to_scan, allowlist)
                if det_findings:
                    log.debug(
                        "%s: %d findings",
                        detector.__class__.__name__,
                        len(det_findings),
                    )
                all_findings.extend(det_findings)
        else:
            log.debug("outbound_dlp stage disabled — skipping all detectors")
        stage_timings["outbound_dlp"] = (time.monotonic() - t_stage) * 1000

        # Deduplicate findings — same (detector, type, matched_value) collapsed
        # into one finding with a count. Reduces noise from repeated secrets
        # in conversation history.
        all_findings = self._deduplicate(all_findings)

        # Evaluate policy — plugins can override via evaluate hook
        eval_hook = self._extensions.get_evaluate_hook() if self._extensions else None
        if eval_hook:
            try:
                decision = eval_hook(all_findings, policy)
            except Exception:
                log.warning("evaluate_hook raised, falling back to default policy", exc_info=True)
                decision = policy.evaluate(all_findings)
            else:
                if not isinstance(decision, ActionDecision):
                    log.error(
                        "evaluate_hook returned %s, expected ActionDecision — falling back to default policy",
                        type(decision).__name__,
                    )
                    decision = policy.evaluate(all_findings)
        else:
            decision = policy.evaluate(all_findings)

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
            stage_timings=stage_timings,
        )

        # Commit fingerprint hashes only for safe pass-through actions.
        # - block: must re-scan on retry to prevent bypass
        # - redact: next request contains ORIGINAL text in conversation history
        #   (Claude Code re-sends the unredacted user input), must re-scan
        # On block, store pending_hashes so the proxy can commit after strip.
        if pending_hashes and result.action not in ("block", "redact"):
            self._fingerprint.commit_hashes(pending_hashes)
        elif pending_hashes and result.action == "block":
            result._pending_hashes = pending_hashes

        # Layer 2: Finding-level dedup — filter before recording but after
        # policy eval. All findings stay in ScanResult for action enforcement.
        # Session-scoped: same finding in different sessions is always new.
        sess_id = session.session_id if session else ""
        new_findings = self._finding_dedup.filter_new(result.findings, session_id=sess_id) if result.findings else []

        # Record only NEW findings in analytics store (community dashboard)
        if new_findings and self._extensions:
            rec_store: AnalyticsStore | None = self._extensions.get_analytics_store()
            if rec_store:
                try:
                    rec_store.record_findings(
                        new_findings,
                        provider=provider,
                        model=model,
                        session=session,
                    )
                except Exception:
                    log.warning("analytics store record_findings failed", exc_info=True)

        # Dispatch notifications — pass ALL findings (dispatcher has its own dedup).
        # The full SessionContext is forwarded so dispatchers that enrich payloads
        # with hostname / working_directory / intercept_mode / etc. have a direct
        # reference to it. Pro's NotificationDispatcher opts in via a config flag;
        # community's BasicDispatcher ignores the extra argument except to forward
        # it to notifiers, which currently don't consume it.
        if result.findings and self._extensions:
            dispatcher: Any = self._extensions.get_dispatcher()
            if dispatcher:
                try:
                    dispatcher.dispatch(
                        result.findings,
                        provider=provider,
                        model=model,
                        session_id=session.session_id if session else "",
                        session=session,
                    )
                except Exception:
                    log.warning("notification dispatch failed", exc_info=True)

        # Broadcast SSE events for real-time dashboard/tray updates
        if self._extensions:
            self._broadcast_sse(result, new_findings, provider, session)

        # Fire post-scan hook for plugins (analytics, SSE, etc.)
        if self._extensions:
            hook = self._extensions.get_post_scan_hook()
            if hook:
                try:
                    hook(result, body, provider, session=session)
                except Exception:
                    log.debug("post_scan_hook failed, suppressing", exc_info=True)

        return result

    def _broadcast_sse(
        self,
        result: ScanResult,
        new_findings: list[Finding],
        provider: str,
        session: SessionContext | None,
    ) -> None:
        """Broadcast scan and finding events to SSE clients."""
        broadcaster = self._extensions.get_sse_broadcaster() if self._extensions else None
        if not broadcaster:
            return

        from lumen_argus_core.time_utils import now_iso

        timestamp = now_iso()
        client = session.client_name if session else ""
        intercept_mode = session.intercept_mode if session else "reverse"
        original_host = session.original_host if session else ""

        # Broadcast scan event for every scanned request
        try:
            broadcaster.broadcast(
                "scan",
                {
                    "action": result.action,
                    "client": client,
                    "provider": provider,
                    "findings_count": len(result.findings),
                    "timestamp": timestamp,
                },
            )
        except Exception:
            log.debug("SSE scan broadcast failed", exc_info=True)

        # Broadcast individual finding events (new findings only, no matched_value)
        for f in new_findings:
            try:
                broadcaster.broadcast(
                    "finding",
                    {
                        "detector": f.detector,
                        "type": f.type,
                        "severity": f.severity,
                        "location": f.location,
                        "value_preview": f.value_preview,
                        "action": f.action,
                        "client": client,
                        "provider": provider,
                        "intercept_mode": intercept_mode,
                        "original_host": original_host,
                        "timestamp": timestamp,
                    },
                )
            except Exception:
                log.debug("SSE finding broadcast failed", exc_info=True)

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        """Collapse duplicate findings into one with a count.

        Same (detector, type, matched_value) -> keep first occurrence, set count.
        Creates new Finding objects to avoid mutating detector output.
        """
        seen: dict[tuple[str, str, str], int] = {}
        first: dict[tuple[str, str, str], Finding] = {}
        for f in findings:
            key = (f.detector, f.type, f.matched_value)
            if key in seen:
                seen[key] += 1
            else:
                seen[key] = 1
                first[key] = f
        return [replace(first[k], count=c) for k, c in seen.items()]
