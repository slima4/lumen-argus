"""DB-backed rules detector with Aho-Corasick pre-filtering.

Loads compiled regex patterns from the rules DB table. Runs alongside
(or eventually replaces) the hardcoded SecretsDetector and PIIDetector.

Performance layers:
1. Aho-Corasick pre-filter: O(n) single pass narrows 1,700+ rules to ~15 candidates
2. Early termination: stop after first match when action is "block"
3. Hot-first ordering: sort rules by hit_count DESC for faster common matches

License-aware: rules with tier='pro' are skipped when the license
checker reports invalid/expired.
"""

from __future__ import annotations

import asyncio
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore

from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.detectors import BaseDetector
from lumen_argus.detectors.accelerator import AhoCorasickAccelerator
from lumen_argus.models import Finding, ScanField
from lumen_argus.validators import validate_iban, validate_ip_not_private, validate_luhn, validate_ssn

log = logging.getLogger("argus.detectors.rules")

# Registry of named validator functions. Validators return True if
# the match is valid. Referenced by name in the rules DB.
_VALIDATORS: dict[str, Callable[[str], bool]] = {}

# Flush hit counts to DB every 60 seconds
_HIT_COUNT_FLUSH_INTERVAL = 60


def register_validator(name: str, fn: Callable[[str], bool]) -> None:
    """Register a named validator function."""
    _VALIDATORS[name] = fn


# Register built-in validators from shared module
register_validator("ssn_range", validate_ssn)
register_validator("luhn", validate_luhn)
register_validator("exclude_private_ips", validate_ip_not_private)
register_validator("iban_mod97", validate_iban)


class RulesDetector(BaseDetector):
    """Unified detector that runs all DB-backed rules.

    Loads rules from the analytics store, compiles regex patterns,
    and runs them against scan fields. License-aware for Pro rules.

    Performance:
    - Aho-Corasick pre-filter reduces candidate rules per field by >95%
    - Hot-first ordering puts frequent matches first
    - Early termination stops on first match for block actions
    - In-memory hit count accumulation with periodic batch flush
    """

    # Minimum candidates to trigger parallel evaluation.
    # Below this threshold, thread pool overhead outweighs the benefit.
    _PARALLEL_THRESHOLD = 50

    def __init__(
        self,
        store: AnalyticsStore | None = None,
        license_checker: Any = None,
        metrics_collector: Any = None,
        parallel: bool = False,
        accelerator_factory: Callable[[], Any] | None = None,
        rebuild_delay: float = 2.0,
    ) -> None:
        self._store = store
        self._license = license_checker
        self._metrics = metrics_collector
        self._accelerator_factory = accelerator_factory
        self._skip_list: set[str] = set()
        self._parallel = parallel
        self._pool: ThreadPoolExecutor | None = None
        if parallel:
            self._pool = ThreadPoolExecutor(max_workers=4)
        self._compiled_rules: list[dict[str, Any]] = []
        self._accelerator = self._new_accelerator()
        # In-memory hit count accumulation: {rule_name: count}
        self._hit_counts: dict[str, int] = {}
        self._hit_counts_lock = threading.Lock()
        self._last_flush = time.monotonic()
        # Debounced async rebuild state
        self._rebuild_delay = float(rebuild_delay)
        self._dirty = False
        self._rebuild_lock = threading.Lock()  # prevents concurrent rebuild threads
        self._debounce_lock = threading.Lock()  # protects _debounce_handle and _dirty
        self._debounce_handle: Any = None  # asyncio TimerHandle or threading.Timer
        # Protects _accelerator/_compiled_rules swap for no-GIL Python 3.13+.
        # scan() snapshots both under this lock; reload() writes both under it.
        self._swap_lock = threading.Lock()
        if store:
            self.reload()

    def _new_accelerator(self) -> Any:
        """Create a new accelerator via factory or default AhoCorasickAccelerator.

        The returned object must implement:
          build(compiled_rules: List[dict]) -> None
          filter(text: str) -> Set[int]
          filter_ratio(candidates: Set[int]) -> float
          available: bool (property)
          stats: dict (property)
        """
        factory = self._accelerator_factory
        if factory:
            try:
                return factory()
            except Exception as exc:
                log.warning("accelerator_factory raised %s, falling back to AhoCorasickAccelerator", exc)
        return AhoCorasickAccelerator()

    def reload(self) -> None:
        """Reload rules from DB, compile patterns, and rebuild accelerator."""
        if not self._store:
            return
        # Flush pending hit counts before reload
        self._flush_hit_counts()

        rules = self._store.get_active_rules()
        compiled = []
        for r in rules:
            if r["tier"] == "pro":
                if self._license is None or not self._license.is_valid():
                    continue
            try:
                pattern = re.compile(r["pattern"])
            except re.error:
                log.warning("rule '%s': invalid regex, skipping", r["name"])
                continue
            validator = None
            if r.get("validator"):
                validator = _VALIDATORS.get(r["validator"])
                if validator is None:
                    log.debug("rule '%s': unknown validator '%s'", r["name"], r["validator"])
            compiled.append(
                {
                    "name": r["name"],
                    "compiled": pattern,
                    "detector": r["detector"],
                    "severity": r["severity"],
                    "action": r.get("action", ""),
                    "validator": validator,
                    "hit_count": r.get("hit_count", 0),
                }
            )

        # Hot-first ordering: rules with more hits are evaluated first
        compiled.sort(key=lambda r: r["hit_count"], reverse=True)

        # Build new accelerator, then swap both under lock.
        # scan() snapshots both under the same lock — they must be consistent.
        # Lock required for free-threaded Python 3.13+ (no-GIL).
        new_acc = self._new_accelerator()
        new_acc.build(compiled)
        with self._swap_lock:
            self._accelerator = new_acc
            self._compiled_rules = compiled
        log.debug(
            "rules detector: loaded %d rules (accelerator: %s)",
            len(compiled),
            "enabled" if self._accelerator.available else "disabled",
        )

    def _flush_hit_counts(self) -> None:
        """Flush accumulated hit counts to DB in a single batch."""
        with self._hit_counts_lock:
            if not self._hit_counts:
                return
            snapshot = self._hit_counts
            self._hit_counts = {}
            self._last_flush = time.monotonic()

        if not self._store:
            return

        try:
            with self._store._lock:
                conn = self._store._connect()
                for rule_name, count in snapshot.items():
                    conn.execute(
                        "UPDATE rules SET hit_count = hit_count + ? WHERE name = ?",
                        (count, rule_name),
                    )
                conn.commit()
            log.debug("hit counts flushed: %d rules updated", len(snapshot))
        except Exception as e:
            log.warning("hit count flush failed: %s", e)

    def _record_hit(self, rule_name: str) -> None:
        """Accumulate a hit in memory. Flush periodically."""
        should_flush = False
        with self._hit_counts_lock:
            self._hit_counts[rule_name] = self._hit_counts.get(rule_name, 0) + 1
            if time.monotonic() - self._last_flush >= _HIT_COUNT_FLUSH_INTERVAL:
                should_flush = True
        if should_flush:
            self._flush_hit_counts()

    @property
    def rule_count(self) -> int:
        """Return the number of compiled rules (thread-safe)."""
        with self._swap_lock:
            return len(self._compiled_rules)

    def set_parallel(self, enabled: bool) -> None:
        """Enable or disable parallel rule evaluation at runtime.

        Pro toggles this via the Pipeline dashboard page.
        """
        if enabled and self._pool is None:
            self._pool = ThreadPoolExecutor(max_workers=4)
        elif not enabled and self._pool is not None:
            self._pool.shutdown(wait=False)
            self._pool = None
        self._parallel = enabled
        log.debug("parallel rule evaluation: %s", "enabled" if enabled else "disabled")

    def set_skip_list(self, names: Any) -> None:
        """Update the set of rule names to skip during scanning."""
        self._skip_list = set(names) if names else set()
        log.info("rule skip list updated: %d rules", len(self._skip_list))

    def on_rules_changed(self, change_type: str, rule_name: str | None = None) -> None:
        """Handle rule changes from store callback.

        Schedules a debounced async rebuild instead of rebuilding synchronously.
        The old accelerator and compiled rules stay active during the rebuild —
        scans never block. Multiple rapid changes (e.g., bulk import firing
        per-rule callbacks) are coalesced into a single rebuild.

        Uses asyncio.call_later() when an event loop is running (normal proxy
        operation), falls back to threading.Timer otherwise (tests, CLI).
        """
        with self._debounce_lock:
            self._dirty = True
        self._schedule_rebuild()

    def _schedule_rebuild(self) -> None:
        """Start or reset the debounce timer for async rebuild.

        Thread-safe: protects _debounce_handle under _debounce_lock.
        Uses asyncio.call_later when an event loop is running (proxy runtime),
        falls back to threading.Timer otherwise (tests, CLI).
        """
        with self._debounce_lock:
            # Cancel any pending timer
            if self._debounce_handle is not None:
                try:
                    self._debounce_handle.cancel()
                except Exception:
                    log.debug("failed to cancel debounce handle", exc_info=True)
                self._debounce_handle = None

            delay = self._rebuild_delay
            log.debug("rules detector: scheduling rebuild in %.1fs", delay)

            # Try asyncio event loop first (proxy runtime), fall back to threading.Timer
            try:
                loop = asyncio.get_running_loop()
                self._debounce_handle = loop.call_later(delay, self._trigger_rebuild)
            except RuntimeError:
                # No running event loop — use threading.Timer (tests, CLI, background threads)
                timer = threading.Timer(delay, self._trigger_rebuild)
                timer.daemon = True
                timer.start()
                self._debounce_handle = timer

    def _trigger_rebuild(self) -> None:
        """Called when debounce timer fires. Spawns background thread for rebuild."""
        if not self._rebuild_lock.acquire(blocking=False):
            # Another rebuild is running — it will check _dirty after swap
            return
        try:
            thread = threading.Thread(target=self._background_rebuild, daemon=True)
            thread.start()
        except Exception:
            self._rebuild_lock.release()
            log.warning("rules detector: failed to start rebuild thread")

    def _background_rebuild(self) -> None:
        """Run full reload() in background thread. Check _dirty after swap.

        Uses _debounce_lock to atomically clear _dirty before reload and
        check it after — avoids TOCTOU race where changes arriving between
        the dirty-check and lock-release would be silently dropped.
        """
        try:
            with self._debounce_lock:
                self._dirty = False
            self.reload()
        finally:
            self._rebuild_lock.release()
        # Check _dirty AFTER releasing _rebuild_lock — any concurrent
        # _trigger_rebuild that failed to acquire the lock has now returned,
        # and if it set _dirty, we pick it up here.
        needs_reschedule = False
        with self._debounce_lock:
            if self._dirty:
                needs_reschedule = True
        if needs_reschedule:
            self._schedule_rebuild()

    def _eval_rule(
        self, rule: dict[str, Any], field: ScanField, allowlist: AllowlistMatcher, metrics: Any
    ) -> list[Finding]:
        """Evaluate a single rule against a field. Returns list of findings.

        Extracted for reuse by both sequential and parallel scan paths.
        """
        findings = []
        t0 = time.monotonic() if metrics else 0

        for match in rule["compiled"].finditer(field.text):
            matched = (match.group(1) if match.lastindex else None) or match.group(0)
            if not matched:
                continue
            if rule["validator"] and not rule["validator"](matched):
                continue
            if rule["detector"] == "secrets" and allowlist.is_allowed_secret(matched):
                continue
            if rule["detector"] == "pii" and allowlist.is_allowed_pii(matched):
                continue
            preview = matched[:4] + "****" if len(matched) > 4 else "****"
            findings.append(
                Finding(
                    detector=rule["detector"],
                    type=rule["name"],
                    severity=rule["severity"],
                    location=field.path,
                    value_preview=preview,
                    matched_value=matched,
                    action=rule["action"],
                )
            )
            self._record_hit(rule["name"])

            if metrics:
                elapsed_ms = (time.monotonic() - t0) * 1000
                try:
                    metrics.record(rule["name"], elapsed_ms)
                except Exception:
                    log.debug("failed to record metrics for rule '%s'", rule["name"], exc_info=True)

        return findings

    def _eval_group(
        self,
        indices: list[int],
        compiled_rules: list[dict[str, Any]],
        field: ScanField,
        allowlist: AllowlistMatcher,
        metrics: Any,
    ) -> list[Finding]:
        """Evaluate a group of rule indices against a field. Used by parallel path."""
        group_findings = []
        for idx in indices:
            if idx >= len(compiled_rules):
                continue
            group_findings.extend(self._eval_rule(compiled_rules[idx], field, allowlist, metrics))
        return group_findings

    def scan(self, fields: list[ScanField], allowlist: AllowlistMatcher) -> list[Finding]:
        """Scan fields against compiled rules with Aho-Corasick pre-filtering.

        Performance path:
        1. Pre-filter: Aho-Corasick narrows candidates per field
        2. Hot-first: rules sorted by hit_count DESC (set at reload)
        3. Early termination: stop on first match for block action (sequential),
           or skip remaining fields after block detected (parallel)
        4. Parallel batching: when enabled and candidates > threshold,
           group by detector category and evaluate concurrently.
           Note: parallel early termination is post-hoc — all groups for the
           current field run to completion before block is detected.
        """
        findings = []
        with self._swap_lock:
            compiled_rules = self._compiled_rules  # snapshot for thread safety
            accelerator = self._accelerator
            skip_list = self._skip_list  # snapshot for no-GIL safety
        metrics = self._metrics
        use_parallel = self._parallel

        for field in fields:
            candidates = accelerator.filter(field.text)

            if log.isEnabledFor(logging.DEBUG):
                ratio = accelerator.filter_ratio(candidates)
                log.debug(
                    "pre-filter: %d rules -> %d candidates (%.1f%% filtered) for %s",
                    len(compiled_rules),
                    len(candidates),
                    ratio * 100,
                    field.path,
                )

            # Parallel path: group candidates by detector, evaluate concurrently
            if use_parallel and len(candidates) > self._PARALLEL_THRESHOLD:
                field_findings = self._scan_field_parallel(
                    candidates, compiled_rules, field, allowlist, metrics, skip_list
                )
                findings.extend(field_findings)
                # Check for early termination on block
                if any(f.action == "block" for f in field_findings):
                    log.debug("early termination: block found in parallel scan for %s", field.path)
                    continue
            else:
                # Sequential path (default)
                field_blocked = False
                for idx in candidates:
                    if idx >= len(compiled_rules):
                        continue
                    rule = compiled_rules[idx]
                    if skip_list and rule["name"] in skip_list:
                        continue
                    rule_findings = self._eval_rule(rule, field, allowlist, metrics)

                    if rule_findings:
                        findings.extend(rule_findings)
                        if rule["action"] == "block":
                            log.debug(
                                "early termination: block after match on '%s'",
                                rule["name"],
                            )
                            field_blocked = True
                            break
                if field_blocked:
                    continue

        return findings

    def _scan_field_parallel(
        self,
        candidates: set[int],
        compiled_rules: list[dict[str, Any]],
        field: ScanField,
        allowlist: AllowlistMatcher,
        metrics: Any,
        skip_list: set[str],
    ) -> list[Finding]:
        """Evaluate candidate rules in parallel, grouped by detector category.

        Python's re module releases the GIL during C-level regex matching,
        so threading provides real speedup for regex evaluation.
        Free-threaded Python 3.13+ gives full parallelism.

        Note: all groups run to completion — early termination is post-hoc
        (block detected after groups finish, prevents scanning next field).
        """
        groups: dict[str, list[int]] = {}
        for idx in candidates:
            if idx >= len(compiled_rules):
                continue
            if skip_list and compiled_rules[idx]["name"] in skip_list:
                continue
            det = compiled_rules[idx].get("detector", "other")
            if det not in groups:
                groups[det] = []
            groups[det].append(idx)

        all_findings: list[Finding] = []
        pool = self._pool
        if pool is None:
            log.error("parallel scan requested but ThreadPoolExecutor not initialized")
            return all_findings
        futures = [
            pool.submit(self._eval_group, group_indices, compiled_rules, field, allowlist, metrics)
            for group_indices in groups.values()
            if group_indices
        ]
        for f in futures:
            try:
                all_findings.extend(f.result())
            except Exception as e:
                log.warning("parallel rule evaluation failed: %s", e)

        if log.isEnabledFor(logging.DEBUG) and all_findings:
            log.debug(
                "parallel scan: %d findings from %d candidates (%d groups) for %s",
                len(all_findings),
                len(candidates),
                len(groups),
                field.path,
            )

        return all_findings
