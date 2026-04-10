"""Rule overlap analysis via crossfire-rules (optional dependency).

When crossfire-rules is installed, provides corpus-based overlap detection
for rules: duplicates, subsets, and partial overlaps. Results cached
in the analytics DB for the dashboard Rule Analysis page.

Install: pip install lumen-argus-proxy[rules-analysis]
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore
    from lumen_argus.config import Config
    from lumen_argus.extensions import ExtensionRegistry

from lumen_argus_core.time_utils import now_iso

log = logging.getLogger("argus.rule_analysis")

try:
    from crossfire.classifier import Classifier
    from crossfire.evaluator import Evaluator
    from crossfire.generator import CorpusGenerator
    from crossfire.models import Relationship
    from crossfire.models import Rule as CrossfireRule
    from crossfire.quality import assess_quality

    HAS_CROSSFIRE = True
    log.info("crossfire available — rule overlap analysis enabled")
except ImportError:
    HAS_CROSSFIRE = False
    log.info(
        "crossfire-rules not installed — rule overlap analysis disabled. "
        "Install with: pip install lumen-argus-proxy[rules-analysis]"
    )


def _rules_to_crossfire(db_rules: list[dict[str, Any]]) -> tuple[list[Any], dict[str, dict[str, Any]]]:
    """Convert DB rule dicts to Crossfire Rule objects.

    Skips rules with invalid or empty patterns.
    Returns list of CrossfireRule and a name→db_rule lookup dict.
    """
    import re as re_mod

    cf_rules: list[Any] = []
    lookup: dict[str, dict[str, Any]] = {}
    for r in db_rules:
        name = r.get("name", "")
        pattern = r.get("pattern", "")
        if not name or not pattern:
            continue
        try:
            compiled = re_mod.compile(pattern)
        except re_mod.error as exc:
            log.debug("skipping rule %r: invalid pattern: %s", name, exc)
            continue
        cf_rules.append(
            CrossfireRule(
                name=name,
                pattern=pattern,
                compiled=compiled,
                source=r.get("tier", "community"),
                detector=r.get("detector", ""),
                severity=r.get("severity", ""),
                tags=r.get("tags", []) if isinstance(r.get("tags"), list) else [],
                priority=_tier_priority(r.get("tier", "community")),
            )
        )
        lookup[name] = r
    return cf_rules, lookup


def _tier_priority(tier: str) -> int:
    """Map rule tier to priority (higher = keep in conflicts)."""
    return {"community": 100, "custom": 90, "pro": 80}.get(tier, 50)


def _overlap_to_dict(result: Any, lookup: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Convert a crossfire OverlapResult to a JSON-serializable dict."""
    rule_a_info = lookup.get(result.rule_a, {})
    rule_b_info = lookup.get(result.rule_b, {})
    return {
        "rule_a": result.rule_a,
        "rule_b": result.rule_b,
        "relationship": str(result.relationship.value)
        if hasattr(result.relationship, "value")
        else str(result.relationship),
        "recommendation": str(result.recommendation.value)
        if hasattr(result.recommendation, "value")
        else str(result.recommendation),
        "reason": result.reason,
        "jaccard": round(result.jaccard, 4),
        "overlap_a_to_b": round(result.overlap_a_to_b, 4),
        "overlap_b_to_a": round(result.overlap_b_to_a, 4),
        "tier_a": rule_a_info.get("tier", ""),
        "tier_b": rule_b_info.get("tier", ""),
        "severity_a": rule_a_info.get("severity", ""),
        "severity_b": rule_b_info.get("severity", ""),
    }


def _cluster_to_dict(cluster: Any) -> dict[str, Any]:
    """Convert a crossfire ClusterInfo to a JSON-serializable dict."""
    return {
        "id": cluster.id,
        "rules": list(cluster.rules),
        "keep": cluster.keep,
        "reason": cluster.reason,
    }


def _rule_quality_to_dict(rq: Any) -> dict[str, Any]:
    """Convert a crossfire RuleQuality to a JSON-serializable dict."""
    return {
        "name": rq.name,
        "source": rq.source,
        "specificity": rq.specificity,
        "false_positive_potential": rq.false_positive_potential,
        "pattern_complexity": rq.pattern_complexity,
        "unique_coverage": rq.unique_coverage,
        "is_broad": rq.is_broad,
        "overlap_count": rq.overlap_count,
        "flags": rq.flags,
    }


def _quality_to_dict(report: Any) -> dict[str, Any]:
    """Convert a crossfire QualityReport to a JSON-serializable dict."""
    return {
        "broad_patterns": [_rule_quality_to_dict(r) for r in report.broad_patterns],
        "low_specificity": [_rule_quality_to_dict(r) for r in report.low_specificity],
        "fully_redundant": [_rule_quality_to_dict(r) for r in report.fully_redundant],
        "summary": report.summary,
    }


def _empty_result(total_rules: int, *, duration_s: float = 0.0) -> dict[str, Any]:
    """Build a complete-but-empty result dict for the trivial-input cases."""
    return {
        "status": "complete",
        "timestamp": now_iso(),
        "duration_s": duration_s,
        "total_rules": total_rules,
        "summary": {"duplicates": 0, "subsets": 0, "overlaps": 0, "clusters": 0},
        "duplicates": [],
        "subsets": [],
        "overlaps": [],
        "clusters": [],
        "quality": {},
    }


def run_analysis(
    store: AnalyticsStore, *, samples: int = 50, threshold: float = 0.8, seed: int = 42
) -> dict[str, Any] | None:
    """Run overlap analysis on all active rules (synchronous).

    Returns results dict, or None if crossfire is not installed or analysis fails.
    """
    if not HAS_CROSSFIRE:
        log.warning("run_analysis called but crossfire is not installed")
        return None
    return _run_analysis_with_status(store, samples=samples, threshold=threshold, seed=seed)


def save_and_return(store: AnalyticsStore, result: dict[str, Any] | None) -> dict[str, Any] | None:
    """Save analysis result to DB and return it.

    Filters out dismissed findings before returning.
    """
    if result is None:
        return None

    results_json = json.dumps(
        {
            "duplicates": result["duplicates"],
            "subsets": result["subsets"],
            "overlaps": result["overlaps"],
            "clusters": result["clusters"],
            "quality": result["quality"],
        }
    )

    store.rule_analysis.save_analysis(
        timestamp=result["timestamp"],
        duration_s=result["duration_s"],
        total_rules=result["total_rules"],
        duplicates=result["summary"]["duplicates"],
        subsets=result["summary"]["subsets"],
        overlaps=result["summary"]["overlaps"],
        results_json=results_json,
    )
    log.info("analysis results saved to DB")

    # Filter dismissed findings
    dismissed = store.rule_analysis.get_dismissed_findings()
    if dismissed:
        result = filter_dismissed(result, dismissed)

    return result


def filter_dismissed(result: dict[str, Any], dismissed_pairs: list[list[str]]) -> dict[str, Any]:
    """Remove dismissed pairs from analysis results."""
    dismissed_set = {(a, b) for a, b in dismissed_pairs}

    def _keep(item: dict[str, Any]) -> bool:
        pair = (item["rule_a"], item["rule_b"])
        reverse = (item["rule_b"], item["rule_a"])
        return pair not in dismissed_set and reverse not in dismissed_set

    result = dict(result)  # shallow copy
    result["duplicates"] = [d for d in result["duplicates"] if _keep(d)]
    result["subsets"] = [s for s in result["subsets"] if _keep(s)]
    result["overlaps"] = [o for o in result["overlaps"] if _keep(o)]
    return result


_analysis_lock = threading.Lock()
_analysis_log_lines: list[str] = []  # log lines for UI streaming
_MAX_LOG_LINES = 5000

# Phase names that appear in status["phase"], log markers, and the watchdog
# diagnostics. Keep them stable — clients (dashboard, integration tests, future
# Pro extensions) match on these strings.
PHASE_STARTING = "starting"
PHASE_GENERATING = "generating"
PHASE_EVALUATING = "evaluating"
PHASE_CLASSIFYING = "classifying"
PHASE_QUALITY = "quality"
PHASE_SAVING = "saving"
PHASE_COMPLETE = "complete"
PHASE_FAILED = "failed"

_analysis_status: dict[str, Any] = {
    "running": False,
    "phase": "",
    "progress": "",
    "started_at": "",
    # last_phase_change_at: monotonic timestamp (float) of the most recent phase
    # transition. Used by the watchdog to detect "stuck in one phase" hangs.
    # Internal — not serialized to clients.
    "last_phase_change_at": 0.0,
    # error: populated when analysis fails (exception, watchdog timeout, etc.).
    # Format: {"type": "ExceptionClass", "message": "...", "phase": "evaluating"}
    # Cleared at the start of each new run. Dashboard renders a banner when set.
    "error": None,
}


def get_analysis_status(since: int = 0) -> dict[str, Any]:
    """Return current analysis status with log lines since offset (thread-safe).

    Args:
        since: return only log lines from this index onward (0 = all).
    """
    with _analysis_lock:
        # Drop the internal `last_phase_change_at` from the client view — it's
        # only meaningful inside this module for watchdog scheduling.
        result = {k: v for k, v in _analysis_status.items() if k != "last_phase_change_at"}
        result["log"] = _analysis_log_lines[since:]
        result["log_offset"] = len(_analysis_log_lines)
    return result


def _set_status(
    running: bool,
    phase: str = "",
    progress: str = "",
    *,
    reset_started_at: bool = False,
    clear_error: bool = False,
) -> None:
    """Update analysis status atomically.

    Args:
        running: Whether analysis is currently in flight.
        phase: Phase name (one of the PHASE_* constants, or empty).
        progress: Human-readable progress text shown to the dashboard.
        reset_started_at: When True, reinitialize started_at and clear the
            log buffer. Use only at the start of a new analysis run.
        clear_error: When True, clear the error field. Use at the start of a
            new run so old errors don't persist into a successful re-run.
    """
    with _analysis_lock:
        prev_phase = _analysis_status["phase"]
        _analysis_status["running"] = running
        _analysis_status["phase"] = phase
        _analysis_status["progress"] = progress
        if running and reset_started_at:
            _analysis_status["started_at"] = now_iso()
            _analysis_log_lines.clear()
        if not running:
            _analysis_status["started_at"] = ""
        if clear_error:
            _analysis_status["error"] = None
        # Bump phase-change heartbeat whenever the phase actually changes (or
        # at the very first transition to running). Used by the watchdog.
        if phase != prev_phase or (running and _analysis_status["last_phase_change_at"] == 0.0):
            _analysis_status["last_phase_change_at"] = time.monotonic()


def _set_error(exc_type: str, message: str, phase: str) -> None:
    """Record a structured error and flip status to not-running atomically."""
    with _analysis_lock:
        _analysis_status["running"] = False
        _analysis_status["phase"] = PHASE_FAILED
        _analysis_status["progress"] = f"{exc_type}: {message}"
        _analysis_status["started_at"] = ""
        _analysis_status["error"] = {
            "type": exc_type,
            "message": message,
            "phase": phase,
        }


def _append_log(line: str) -> None:
    """Append a log line to the buffer (thread-safe, bounded to _MAX_LOG_LINES)."""
    with _analysis_lock:
        _analysis_log_lines.append(line)
        if len(_analysis_log_lines) > _MAX_LOG_LINES:
            del _analysis_log_lines[: len(_analysis_log_lines) - _MAX_LOG_LINES]


class _AnalysisLogHandler(logging.Handler):
    """Captures log output from crossfire and argus.rule_analysis into the UI log buffer.

    Per-phase progress is no longer driven from log records — it's pushed
    explicitly by the `_phase` context manager in _do_analysis. This handler
    is now a pure log forwarder: every formatted record reaches the dashboard's
    log stream regardless of which logger emitted it (parent process, worker
    process, evaluator, classifier, etc.). The previous "match log message
    text and increment counter" approach was fragile and broke whenever
    crossfire emitted records from a worker process whose logging state was
    independent of the parent.

    Thread scoping: the handler is attached to the process-wide `crossfire`
    logger tree, which is a singleton. If any other code path in the process
    happens to emit records on a `crossfire.*` logger during an analysis run
    (e.g. rule import calling crossfire validators from the event loop), those
    records would leak into the UI log buffer. We filter by the owning thread
    ident so only records emitted from the analysis worker reach the buffer.
    """

    def __init__(self, owner_thread_ident: int) -> None:
        super().__init__()
        self._owner_thread_ident = owner_thread_ident

    def emit(self, record: logging.LogRecord) -> None:
        if record.thread != self._owner_thread_ident:
            return
        try:
            msg = self.format(record)
            _append_log(msg)
        except Exception:
            self.handleError(record)


def is_analysis_running() -> bool:
    """Check if analysis is currently running (thread-safe)."""
    with _analysis_lock:
        return bool(_analysis_status["running"])


def _last_phase_change_at() -> float:
    """Return the monotonic timestamp of the most recent phase transition."""
    with _analysis_lock:
        return float(_analysis_status["last_phase_change_at"])


class _Phase:
    """Context manager that emits structured phase markers and updates status.

    Yields the start time so the caller can compute per-phase metrics. Wraps the
    body in try/except so any exception is captured into the structured error
    field with the active phase name attached, then re-raised so the caller's
    own try/except can decide how to react.

    Log format:
        phase=<name> start
        phase=<name> end duration=<s>s [extra=...]
        phase=<name> failed duration=<s>s exception=<ClassName>: <message>

    The "phase=" prefix is the single grep key for diagnosing where an
    analysis got stuck. If you don't see "phase=evaluating end" after
    "phase=evaluating start", the evaluator hung.
    """

    def __init__(self, name: str, progress: str = "") -> None:
        self.name = name
        self.progress = progress or name.capitalize() + "..."
        self.start_monotonic: float = 0.0

    def __enter__(self) -> _Phase:
        self.start_monotonic = time.monotonic()
        _set_status(True, self.name, self.progress)
        log.info("phase=%s start", self.name)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        duration = time.monotonic() - self.start_monotonic
        if exc_type is None or exc_val is None:
            log.info("phase=%s end duration=%.2fs", self.name, duration)
            return
        # Don't capture KeyboardInterrupt / SystemExit into error field —
        # those mean the host wants to shut down.
        if issubclass(exc_type, (KeyboardInterrupt, SystemExit)):
            return
        log.error(
            "phase=%s failed duration=%.2fs exception=%s: %s",
            self.name,
            duration,
            exc_type.__name__,
            exc_val,
            exc_info=(exc_type, exc_val, exc_tb),
        )
        _set_error(exc_type.__name__, str(exc_val), self.name)


def run_analysis_in_background(
    store: AnalyticsStore,
    extensions: ExtensionRegistry | None = None,
    *,
    thread_name: str = "rule-analysis",
    samples: int = 50,
    threshold: float = 0.8,
    seed: int = 42,
    config: Config | None = None,
) -> bool:
    """Run overlap analysis in a background thread with SSE broadcast on completion.

    Shared by both the API trigger endpoint and CLI auto-analysis after import.
    When `config` is provided, samples/threshold/seed and watchdog timeouts are
    read from it (overriding defaults). Returns False if analysis is already
    running or crossfire is not installed.
    """
    if not HAS_CROSSFIRE:
        return False

    watchdog_total_s = 300.0
    watchdog_phase_s = 120.0
    if config:
        samples = config.rule_analysis.samples
        threshold = config.rule_analysis.threshold
        seed = config.rule_analysis.seed
        watchdog_total_s = config.rule_analysis.watchdog_total_s
        watchdog_phase_s = config.rule_analysis.watchdog_phase_s

    # Concurrent-run check in its own tiny critical section. The full
    # initialization happens in _set_status below, which is the single source
    # of truth for all status transitions (running flag, phase, started_at,
    # last_phase_change_at, error clearing). Rule analysis is user-triggered
    # and infrequent, so the microsecond window between this check and
    # _set_status is not worth a reentrant-lock solution.
    with _analysis_lock:
        if _analysis_status["running"]:
            log.warning("analysis already running — skipping duplicate request")
            return False

    _set_status(
        True,
        PHASE_STARTING,
        "Loading rules...",
        reset_started_at=True,
        clear_error=True,
    )

    worker_done = threading.Event()

    def _run() -> None:
        thread = threading.current_thread()
        log.info(
            "phase=run start thread=%s ident=%s samples=%d threshold=%.2f seed=%d",
            thread.name,
            thread.ident,
            samples,
            threshold,
            seed,
        )
        try:
            result = _run_analysis_with_status(store, samples=samples, threshold=threshold, seed=seed)
            if result:
                with _Phase(PHASE_SAVING, "Saving results..."):
                    save_and_return(store, result)
                if extensions:
                    broadcaster = extensions.get_sse_broadcaster()
                    if broadcaster:
                        broadcaster.broadcast(
                            "rule_analysis_complete",
                            {
                                "summary": result.get("summary", {}),
                                "timestamp": result.get("timestamp", ""),
                            },
                        )
                _set_status(False, PHASE_COMPLETE, "Analysis complete")
                log.info(
                    "phase=run end thread=%s status=success duration=%.2fs",
                    thread.name,
                    result.get("duration_s", 0.0),
                )
            else:
                # _run_analysis_with_status already populated status.error in
                # the failing _Phase context, so we just confirm here.
                log.warning("phase=run end thread=%s status=no_result", thread.name)
        except Exception as exc:
            # Last-resort capture for anything _Phase didn't catch (errors
            # outside any phase context, e.g. store.rules.get_active itself).
            log.exception("phase=run end thread=%s status=error", thread.name)
            _set_error(type(exc).__name__, str(exc), "outside_phase")
        finally:
            worker_done.set()

    worker_thread = threading.Thread(target=_run, daemon=True, name=thread_name)
    worker_thread.start()
    log.info("analysis started in background thread: %s", thread_name)

    # Watchdog: separate daemon thread polls the heartbeat and the worker's
    # liveness. It only enforces deadlines; it doesn't try to kill the worker
    # (Python can't safely cancel a thread that's blocked in C). On timeout it
    # flips status to failed so the dashboard stops reporting running:true and
    # the operator gets a structured error.
    if watchdog_total_s > 0 or watchdog_phase_s > 0:
        watchdog_thread = threading.Thread(
            target=_watchdog,
            args=(worker_thread, worker_done, watchdog_total_s, watchdog_phase_s),
            daemon=True,
            name=f"{thread_name}-watchdog",
        )
        watchdog_thread.start()

    return True


def _watchdog(
    worker: threading.Thread,
    worker_done: threading.Event,
    total_s: float,
    phase_s: float,
) -> None:
    """Enforce a wall-clock deadline on the analysis worker.

    Polls every 5 seconds (or sooner if the deadline is short). Two checks:

    1. Total deadline: how long since the worker started, regardless of phase.
       Catches anything that runs longer than the operator is willing to wait.
    2. Per-phase deadline: how long since the last phase transition. Catches
       a single phase that hangs (e.g. evaluator stuck on a pathological rule)
       earlier than the total deadline.

    On timeout the watchdog logs a structured error and flips status to failed.
    The worker thread is left running — Python cannot safely cancel a thread
    blocked in C extensions, but the dashboard no longer hangs on running:true.
    """
    started = time.monotonic()
    poll_interval = max(1.0, min(5.0, (total_s or phase_s) / 10.0))
    log.info(
        "phase=watchdog start total_s=%.0f phase_s=%.0f poll_s=%.1f",
        total_s,
        phase_s,
        poll_interval,
    )

    while not worker_done.is_set():
        if worker_done.wait(timeout=poll_interval):
            break
        now = time.monotonic()
        elapsed_total = now - started
        elapsed_phase = now - _last_phase_change_at()

        if total_s > 0 and elapsed_total > total_s:
            # TOCTOU guard: the worker may have finished between our wait()
            # returning and this check, already writing a more specific error
            # via _set_error. Read phase + running under the lock and skip the
            # overwrite if the worker has flipped running to False on its own.
            with _analysis_lock:
                if not _analysis_status["running"]:
                    log.info("phase=watchdog end status=worker_finished_during_check reason=total")
                    return
                current_phase = str(_analysis_status["phase"])
            msg = (
                f"analysis exceeded total deadline of {total_s:.0f}s "
                f"(elapsed={elapsed_total:.0f}s, phase={current_phase})"
            )
            log.error("phase=watchdog timeout reason=total %s", msg)
            _set_error("WatchdogTotalTimeout", msg, current_phase)
            return

        if phase_s > 0 and elapsed_phase > phase_s:
            # Same TOCTOU guard as the total-deadline branch above.
            with _analysis_lock:
                if not _analysis_status["running"]:
                    log.info("phase=watchdog end status=worker_finished_during_check reason=phase")
                    return
                current_phase = str(_analysis_status["phase"])
            msg = (
                f"analysis stuck in phase '{current_phase}' for {elapsed_phase:.0f}s "
                f"(per-phase deadline={phase_s:.0f}s)"
            )
            log.error("phase=watchdog timeout reason=phase %s", msg)
            _set_error("WatchdogPhaseTimeout", msg, current_phase)
            return

    log.info(
        "phase=watchdog end status=worker_finished thread=%s alive=%s",
        worker.name,
        worker.is_alive(),
    )


def _run_analysis_with_status(
    store: AnalyticsStore, *, samples: int = 50, threshold: float = 0.8, seed: int = 42
) -> dict[str, Any] | None:
    """Run analysis with log capture for UI streaming.

    Wires up an _AnalysisLogHandler to forward records from `argus.rule_analysis`
    and the `crossfire` logger tree into the dashboard's log buffer. The handler
    is removed in finally so it never accumulates across runs. The handler is
    bound to the current thread's ident so crossfire records emitted from other
    threads (unrelated to this run) are ignored.
    """
    handler = _AnalysisLogHandler(owner_thread_ident=threading.get_ident())
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.setLevel(logging.DEBUG)
    captured_loggers = [
        logging.getLogger("argus.rule_analysis"),
        logging.getLogger("crossfire"),  # catches all crossfire.* sub-loggers
    ]
    saved_levels: dict[str, int] = {}
    for lg in captured_loggers:
        lg.addHandler(handler)
        saved_levels[lg.name] = lg.level
        if lg.level == logging.NOTSET or lg.level > logging.DEBUG:
            lg.setLevel(logging.DEBUG)

    try:
        return _do_analysis(store, samples=samples, threshold=threshold, seed=seed)
    finally:
        for lg in captured_loggers:
            lg.removeHandler(handler)
            if lg.name in saved_levels:
                lg.setLevel(saved_levels[lg.name])


def _do_analysis(
    store: AnalyticsStore,
    *,
    samples: int = 50,
    threshold: float = 0.8,
    seed: int = 42,
) -> dict[str, Any] | None:
    """Core analysis logic. Phase markers and timing live here.

    Each phase is wrapped in a `_Phase` context manager that logs structured
    `phase=<name> start` / `phase=<name> end duration=...` markers and captures
    any exception into the structured `error` field with the active phase name.
    On any phase failure we return None — the caller (run_analysis_in_background)
    sees the populated error and broadcasts accordingly.
    """
    log.info(
        "starting rule overlap analysis samples=%d threshold=%.2f seed=%d",
        samples,
        threshold,
        seed,
    )
    start = time.monotonic()

    db_rules = store.rules.get_active()
    if not db_rules:
        log.info("no active rules to analyze")
        _set_status(False, PHASE_COMPLETE, "No rules to analyze")
        return _empty_result(0)

    cf_rules, lookup = _rules_to_crossfire(db_rules)
    log.info("converted %d/%d rules to crossfire format", len(cf_rules), len(db_rules))

    if len(cf_rules) < 2:
        log.info("fewer than 2 valid rules — nothing to compare")
        _set_status(False, PHASE_COMPLETE, "Not enough valid rules")
        return _empty_result(len(cf_rules), duration_s=round(time.monotonic() - start, 2))

    from collections import Counter

    # Phase 1: corpus generation. Sequential mode (parallel=False) is the
    # call-site fix for the fork-from-thread hang — we are running inside a
    # background thread, and ProcessPoolExecutor (even with mp_context=spawn)
    # adds startup latency from per-worker re-imports that isn't worth it for
    # community-scale rule sets (< 200 rules). Crossfire 0.2.1+ honors this.
    try:
        with _Phase(PHASE_GENERATING, f"Generating corpus for {len(cf_rules)} rules..."):
            gen = CorpusGenerator(samples_per_rule=samples, seed=seed, parallel=False)
            corpus = gen.generate(cf_rules, skip_invalid=True)
            log.info(
                "phase=generating result strings=%d skipped=%d",
                len(corpus),
                len(cf_rules) - len({e.source_rule for e in corpus}),
            )
    except Exception:
        return None

    corpus_sizes = Counter(e.source_rule for e in corpus if not e.is_negative)

    # Phase 2: cross-evaluation.
    try:
        with _Phase(PHASE_EVALUATING, f"Cross-evaluating {len(cf_rules)} rules..."):
            evaluator = Evaluator(workers=0, partition_by="detector")
            matrix = evaluator.evaluate(cf_rules, corpus)
    except Exception:
        return None

    # Phase 3: classification.
    try:
        with _Phase(PHASE_CLASSIFYING, "Classifying overlaps..."):
            classifier = Classifier(threshold=threshold)
            results, clusters = classifier.classify(matrix, cf_rules, corpus_sizes)
    except Exception:
        return None

    duplicates: list[dict[str, Any]] = []
    subsets: list[dict[str, Any]] = []
    overlaps: list[dict[str, Any]] = []
    for r in results:
        entry = _overlap_to_dict(r, lookup)
        rel = r.relationship
        if rel == Relationship.DUPLICATE:
            duplicates.append(entry)
        elif rel in (Relationship.SUBSET, Relationship.SUPERSET):
            subsets.append(entry)
        elif rel == Relationship.OVERLAP:
            overlaps.append(entry)

    cluster_list = [_cluster_to_dict(c) for c in clusters]
    log.info(
        "phase=classifying result dups=%d subsets=%d overlaps=%d clusters=%d",
        len(duplicates),
        len(subsets),
        len(overlaps),
        len(cluster_list),
    )

    # Phase 4: quality assessment (non-fatal — empty dict on failure).
    quality: dict[str, Any] = {}
    try:
        with _Phase(PHASE_QUALITY, "Assessing rule quality..."):
            quality_report = assess_quality(cf_rules, corpus, matrix, corpus_sizes, seed=seed)
            quality = _quality_to_dict(quality_report)
    except Exception:
        # _Phase already captured the error, but we want quality to be
        # non-fatal for the run as a whole. Go through _set_status so the
        # phase-change heartbeat bumps and error clears atomically — a bare
        # lock write would leave last_phase_change_at stale and could trip
        # the watchdog with a misleading WatchdogPhaseTimeout for a phase
        # that actually completed (non-fatally).
        log.warning("phase=quality non-fatal failure — continuing with empty quality report")
        _set_status(
            True,
            PHASE_QUALITY,
            "Quality assessment skipped (non-fatal)",
            clear_error=True,
        )

    duration = round(time.monotonic() - start, 2)
    log.info(
        "phase=complete duration=%.2fs dups=%d subsets=%d overlaps=%d clusters=%d",
        duration,
        len(duplicates),
        len(subsets),
        len(overlaps),
        len(cluster_list),
    )

    return {
        "status": "complete",
        "timestamp": now_iso(),
        "duration_s": duration,
        "total_rules": len(cf_rules),
        "summary": {
            "duplicates": len(duplicates),
            "subsets": len(subsets),
            "overlaps": len(overlaps),
            "clusters": len(cluster_list),
        },
        "duplicates": duplicates,
        "subsets": subsets,
        "overlaps": overlaps,
        "clusters": cluster_list,
        "quality": quality,
    }
