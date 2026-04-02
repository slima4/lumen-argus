"""Rule overlap analysis via Crossfire (optional dependency).

When crossfire is installed, provides corpus-based overlap detection
for rules: duplicates, subsets, and partial overlaps. Results cached
in the analytics DB for the dashboard Rule Analysis page.

Install: pip install lumen-argus[rules-analysis]
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
    log.info("crossfire not installed — rule overlap analysis disabled. Install with: pip install crossfire")


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
_analysis_status = {
    "running": False,
    "phase": "",  # "generating", "evaluating", "classifying", "saving"
    "progress": "",  # human-readable progress text
    "started_at": "",
}


def get_analysis_status(since: int = 0) -> dict[str, Any]:
    """Return current analysis status with log lines since offset (thread-safe).

    Args:
        since: return only log lines from this index onward (0 = all).
    """
    with _analysis_lock:
        result = dict(_analysis_status)
        result["log"] = _analysis_log_lines[since:]
        result["log_offset"] = len(_analysis_log_lines)
    return result


def _set_status(running: bool, phase: str = "", progress: str = "") -> None:
    with _analysis_lock:
        _analysis_status["running"] = running
        _analysis_status["phase"] = phase
        _analysis_status["progress"] = progress
        if running and not _analysis_status["started_at"]:
            _analysis_status["started_at"] = now_iso()
            _analysis_log_lines.clear()
        if not running:
            _analysis_status["started_at"] = ""


def _append_log(line: str) -> None:
    """Append a log line to the buffer (thread-safe, bounded to _MAX_LOG_LINES)."""
    with _analysis_lock:
        _analysis_log_lines.append(line)
        if len(_analysis_log_lines) > _MAX_LOG_LINES:
            del _analysis_log_lines[: len(_analysis_log_lines) - _MAX_LOG_LINES]


class _AnalysisLogHandler(logging.Handler):
    """Captures log output from crossfire and argus.rule_analysis into the UI buffer.

    Also tracks per-rule progress during corpus generation and evaluation
    to update the status bar dynamically (e.g., "Generating corpus: 10 of 1736 rules").
    """

    def __init__(self) -> None:
        super().__init__()
        self._gen_count = 0
        self._gen_total = 0
        self._eval_chunks_done = 0

    def set_total_rules(self, total: int) -> None:
        self._gen_count = 0
        self._gen_total = total

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            _append_log(msg)
            # Track per-rule corpus generation progress
            if self._gen_total and record.name == "crossfire.generator":
                if ": generated " in msg or "generation failed" in msg:
                    self._gen_count += 1
                    _set_status(
                        True, "generating", "Generating corpus: %d of %d rules..." % (self._gen_count, self._gen_total)
                    )
                elif "Corpus generation complete" in msg:
                    _set_status(True, "evaluating", "Corpus ready. Starting evaluation...")
            # Track evaluation partition progress
            if record.name == "crossfire.evaluator":
                if "Evaluating partition" in msg:
                    self._eval_chunks_done += 1
                    _set_status(True, "evaluating", msg)
                elif "Progress:" in msg:
                    _set_status(True, "evaluating", msg)
        except Exception:
            self.handleError(record)


def is_analysis_running() -> bool:
    """Check if analysis is currently running (thread-safe)."""
    with _analysis_lock:
        return bool(_analysis_status["running"])


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
    When config is provided, samples/threshold/seed are read from it (overriding defaults).
    Returns False if analysis is already running or crossfire not installed.
    """
    if not HAS_CROSSFIRE:
        return False

    if config:
        samples = config.rule_analysis.samples
        threshold = config.rule_analysis.threshold
        seed = config.rule_analysis.seed

    # Atomic check-and-set to prevent concurrent analysis threads
    with _analysis_lock:
        if _analysis_status["running"]:
            log.warning("analysis already running — skipping duplicate request")
            return False
        _analysis_status["running"] = True
        _analysis_status["started_at"] = now_iso()
        _analysis_log_lines.clear()

    _set_status(True, "starting", "Loading rules...")

    def _run() -> None:
        try:
            result = _run_analysis_with_status(store, samples=samples, threshold=threshold, seed=seed)
            if result:
                _set_status(True, "saving", "Saving results...")
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
                log.info("background analysis complete (%s)", thread_name)
            else:
                log.warning("analysis returned no result — check logs for errors (%s)", thread_name)
        except Exception as exc:
            log.error("background analysis failed (%s): %s", thread_name, exc, exc_info=True)
        finally:
            _set_status(False)

    t = threading.Thread(target=_run, daemon=True, name=thread_name)
    t.start()
    log.info("analysis started in background thread: %s", thread_name)
    return True


def _run_analysis_with_status(
    store: AnalyticsStore, *, samples: int = 50, threshold: float = 0.8, seed: int = 42
) -> dict[str, Any] | None:
    """Run analysis with status updates and log capture for UI streaming."""
    handler = _AnalysisLogHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.setLevel(logging.DEBUG)
    captured_loggers = [
        logging.getLogger("argus.rule_analysis"),
        logging.getLogger("crossfire"),  # catches all crossfire.* sub-loggers
    ]
    saved_levels: dict[str, int] = {}
    for lg in captured_loggers:
        lg.addHandler(handler)
        # Ensure DEBUG messages reach our handler regardless of root logger level
        saved_levels[lg.name] = lg.level
        if lg.level > logging.DEBUG:
            lg.setLevel(logging.DEBUG)

    try:
        return _do_analysis(store, handler=handler, samples=samples, threshold=threshold, seed=seed)
    finally:
        for lg in captured_loggers:
            lg.removeHandler(handler)
            if lg.name in saved_levels:
                lg.setLevel(saved_levels[lg.name])


def _do_analysis(
    store: AnalyticsStore,
    *,
    handler: _AnalysisLogHandler | None = None,
    samples: int = 50,
    threshold: float = 0.8,
    seed: int = 42,
) -> dict[str, Any] | None:
    """Core analysis logic with status updates."""
    log.info("starting rule overlap analysis (samples=%d, threshold=%.2f, seed=%d)", samples, threshold, seed)
    start = time.monotonic()

    db_rules = store.rules.get_active()
    if not db_rules:
        log.info("no active rules to analyze")
        return {
            "status": "complete",
            "timestamp": now_iso(),
            "duration_s": 0.0,
            "total_rules": 0,
            "summary": {"duplicates": 0, "subsets": 0, "overlaps": 0, "clusters": 0},
            "duplicates": [],
            "subsets": [],
            "overlaps": [],
            "clusters": [],
        }

    cf_rules, lookup = _rules_to_crossfire(db_rules)
    log.info("converted %d/%d rules to crossfire format", len(cf_rules), len(db_rules))

    if len(cf_rules) < 2:
        log.info("fewer than 2 valid rules — nothing to compare")
        return {
            "status": "complete",
            "timestamp": now_iso(),
            "duration_s": round(time.monotonic() - start, 2),
            "total_rules": len(cf_rules),
            "summary": {"duplicates": 0, "subsets": 0, "overlaps": 0, "clusters": 0},
            "duplicates": [],
            "subsets": [],
            "overlaps": [],
            "clusters": [],
        }

    from collections import Counter

    _set_status(True, "generating", "Generating corpus: 0 of %d rules..." % len(cf_rules))
    if handler:
        handler.set_total_rules(len(cf_rules))
    gen = CorpusGenerator(samples_per_rule=samples, seed=seed)
    try:
        corpus = gen.generate(cf_rules, skip_invalid=True)
    except Exception as exc:
        log.error("corpus generation failed: %s", exc, exc_info=True)
        return None
    log.info("generated %d corpus strings for %d rules", len(corpus), len(cf_rules))

    corpus_sizes = Counter(e.source_rule for e in corpus if not e.is_negative)

    _set_status(True, "evaluating", "Cross-evaluating %d rules..." % len(cf_rules))
    evaluator = Evaluator(workers=0, partition_by="detector")
    try:
        matrix = evaluator.evaluate(cf_rules, corpus)
    except Exception as exc:
        log.error("evaluation failed: %s", exc, exc_info=True)
        return None
    log.info("evaluation complete — %d rules cross-compared", len(cf_rules))

    _set_status(True, "classifying", "Classifying overlaps...")
    classifier = Classifier(threshold=threshold)
    try:
        results, clusters = classifier.classify(matrix, cf_rules, corpus_sizes)
    except Exception as exc:
        log.error("classification failed: %s", exc, exc_info=True)
        return None

    duplicates = []
    subsets = []
    overlaps = []
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

    _set_status(True, "quality", "Assessing rule quality...")
    try:
        quality_report = assess_quality(cf_rules, corpus, matrix, corpus_sizes, seed=seed)
        quality = _quality_to_dict(quality_report)
    except Exception as exc:
        log.warning("quality assessment failed (non-fatal): %s", exc, exc_info=True)
        quality = {}

    duration = round(time.monotonic() - start, 2)

    log.info(
        "analysis complete in %.1fs: %d duplicates, %d subsets, %d overlaps, %d clusters",
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
