"""Tests for `ScannerPipeline.emit_findings` — the post-scan side-effects
façade extracted in A1+ so synthetic / wrapper-emitted findings reach the
same fan-out (record + dispatch + SSE + post_scan_hook) as scan-produced
ones. Issue #81 storm protection depends on this façade actually firing
for FRAMEWORK-origin findings.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from lumen_argus.models import Finding, FindingOrigin, ScanResult, SessionContext
from lumen_argus.pipeline import ScannerPipeline


def _make_finding(origin=FindingOrigin.FRAMEWORK, type_="scan_error"):
    return Finding(
        detector="proxy",
        type=type_,
        severity="critical",
        location="pipeline",
        value_preview="x",
        matched_value="",
        action="alert",
        origin=origin,
    )


def _build_extensions():
    """Build a minimal extensions stub that records calls to each side-effect
    seam. emit_findings should hit every one of them."""
    calls = {"record": [], "dispatch": [], "sse_findings": [], "sse_scans": [], "hook": []}

    class _Store:
        def record_findings(self, findings, provider="", model="", session=None):
            calls["record"].append((list(findings), provider, model, session))

    class _Dispatcher:
        def dispatch(self, findings, provider="", model="", session_id="", session=None):
            calls["dispatch"].append((list(findings), provider, model, session_id, session))

    class _SSE:
        def broadcast(self, event_type, payload):
            if event_type == "finding":
                calls["sse_findings"].append(payload)
            elif event_type == "scan":
                calls["sse_scans"].append(payload)

    def _hook(result, body, provider, session=None):
        calls["hook"].append((result, body, provider, session))

    ext = SimpleNamespace(
        get_analytics_store=lambda: _Store(),
        get_dispatcher=lambda: _Dispatcher(),
        get_sse_broadcaster=lambda: _SSE(),
        get_post_scan_hook=lambda: _hook,
    )
    return ext, calls


def _build_pipeline(extensions=None) -> ScannerPipeline:
    p = ScannerPipeline()
    p._extensions = extensions
    return p


class TestEmitFindingsFanOut(unittest.TestCase):
    def test_calls_all_four_effects(self):
        ext, calls = _build_extensions()
        p = _build_pipeline(ext)
        f = _make_finding()
        result = ScanResult(action="pass", findings=[f])
        p.emit_findings(
            result,
            provider="anthropic",
            model="opus",
            session=SessionContext(session_id="s1"),
            body=b"{}",
        )
        self.assertEqual(len(calls["record"]), 1)
        self.assertEqual(len(calls["dispatch"]), 1)
        self.assertEqual(len(calls["sse_findings"]), 1)
        self.assertEqual(len(calls["sse_scans"]), 1)
        self.assertEqual(len(calls["hook"]), 1)

    def test_default_new_findings_is_all_findings(self):
        ext, calls = _build_extensions()
        p = _build_pipeline(ext)
        f1 = _make_finding(type_="scan_error")
        f2 = _make_finding(type_="scan_skipped_oversized")
        p.emit_findings(ScanResult(action="pass", findings=[f1, f2]))
        recorded = calls["record"][0][0]
        self.assertEqual([f.type for f in recorded], ["scan_error", "scan_skipped_oversized"])
        # SSE per-finding events: one per new finding
        self.assertEqual(len(calls["sse_findings"]), 2)

    def test_explicit_new_findings_subset_recorded(self):
        ext, calls = _build_extensions()
        p = _build_pipeline(ext)
        f1 = _make_finding(type_="a")
        f2 = _make_finding(type_="b")
        p.emit_findings(
            ScanResult(action="pass", findings=[f1, f2]),
            new_findings=[f1],
        )
        # Only f1 recorded (dedup-filtered subset)
        self.assertEqual([f.type for f in calls["record"][0][0]], ["a"])
        # Dispatcher still gets ALL findings
        self.assertEqual([f.type for f in calls["dispatch"][0][0]], ["a", "b"])
        # SSE per-finding: one event for new only
        self.assertEqual(len(calls["sse_findings"]), 1)

    def test_no_extensions_is_noop(self):
        p = _build_pipeline(None)
        # Must not raise
        p.emit_findings(ScanResult(action="pass", findings=[_make_finding()]))

    def test_empty_findings_skips_record_and_dispatch_but_runs_sse_scan_event(self):
        ext, calls = _build_extensions()
        p = _build_pipeline(ext)
        p.emit_findings(ScanResult(action="pass", findings=[]))
        self.assertEqual(len(calls["record"]), 0)
        self.assertEqual(len(calls["dispatch"]), 0)
        # SSE always broadcasts the "scan" event for visibility
        self.assertEqual(len(calls["sse_scans"]), 1)
        # post_scan_hook still fires (it's the plugin extension point — runs
        # for every scan completion, finding count irrelevant)
        self.assertEqual(len(calls["hook"]), 1)

    def test_one_effect_failure_does_not_suppress_others(self):
        ext, calls = _build_extensions()

        # Replace dispatcher with one that raises
        class _BadDispatcher:
            def dispatch(self, *a, **kw):
                raise RuntimeError("downstream channel exploded")

        ext.get_dispatcher = lambda: _BadDispatcher()
        p = _build_pipeline(ext)
        p.emit_findings(ScanResult(action="pass", findings=[_make_finding()]))
        # record + SSE + hook still fired despite dispatcher failure
        self.assertEqual(len(calls["record"]), 1)
        self.assertEqual(len(calls["sse_findings"]), 1)
        self.assertEqual(len(calls["hook"]), 1)

    def test_body_defaults_to_empty_bytes_for_framework_emitters(self):
        ext, calls = _build_extensions()
        p = _build_pipeline(ext)
        # mode_changed style emitter: no request body
        p.emit_findings(ScanResult(action="pass", findings=[_make_finding(type_="mode_changed")]))
        _result, body, _provider, _session = calls["hook"][0]
        self.assertEqual(body, b"")


class TestSSEFindingBroadcastIncludesOrigin(unittest.TestCase):
    """CLAUDE.md §14 invariant: finding-level fields land in SSE + JSONL +
    REST consistently. Pin that `origin` reaches the SSE event stream so
    dashboards can distinguish FRAMEWORK from DETECTOR findings live."""

    def test_sse_finding_event_carries_origin_field(self):
        ext, calls = _build_extensions()
        p = _build_pipeline(ext)
        framework_f = _make_finding(origin=FindingOrigin.FRAMEWORK, type_="scan_error")
        detector_f = _make_finding(origin=FindingOrigin.DETECTOR, type_="aws_access_key")
        detector_f.detector = "secrets"
        p.emit_findings(ScanResult(action="alert", findings=[framework_f, detector_f]))
        self.assertEqual(len(calls["sse_findings"]), 2)
        self.assertEqual(calls["sse_findings"][0]["origin"], "framework")
        self.assertEqual(calls["sse_findings"][1]["origin"], "detector")


if __name__ == "__main__":
    unittest.main()
