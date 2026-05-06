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


class TestEmitFindingsEndToEndStormProtection(unittest.TestCase):
    """End-to-end integration: real ScannerPipeline + real BasicDispatcher +
    real TokenBucket + real AnalyticsStore + real ExtensionRegistry. Pin the
    bug A1+ closes — synthetic findings reaching dispatcher's storm gate
    *and* the analytics store *and* the suppression telemetry — without any
    mocks at the seam between emit_findings and dispatcher.

    Pre-A1+ regression risk: a refactor that drops emit_findings forwarding
    `findings.origin` into dispatcher.dispatch (or that re-introduces an
    extension-guard branch bypassing dispatcher) would silently turn off
    issue #81 storm protection. The mocked unit tests would still pass; this
    integration test would fail because the dispatcher's real bucket would
    not be ticked.
    """

    def test_framework_storm_gated_with_real_dispatcher_and_store(self):
        import os
        import shutil
        import tempfile
        import time as _time

        from lumen_argus.analytics.store import AnalyticsStore
        from lumen_argus.extensions import ExtensionRegistry
        from lumen_argus.notifiers._rate_limit import TokenBucket
        from lumen_argus.notifiers.dispatcher import BasicDispatcher
        from lumen_argus.pipeline import ScannerPipeline

        tmpdir = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmpdir, ignore_errors=True))
        store = AnalyticsStore(db_path=os.path.join(tmpdir, "test.db"))
        self.addCleanup(store._adapter.close)

        notified: list = []

        class _RecNotifier:
            def notify(self, findings, **kw):
                notified.append(list(findings))

        # Channel record so dispatcher.rebuild() picks it up — wildcard events
        # so the per-channel filter never drops anything (we want only the
        # rate-limit gate to reduce 100 → 1).
        store.create_notification_channel({"name": "real-wh", "type": "webhook", "config": {"url": "http://x/"}})

        ext = ExtensionRegistry()
        ext.set_analytics_store(store)
        bucket = TokenBucket(capacity=1, refill_seconds=60.0)
        dispatcher = BasicDispatcher(store=store, builder=lambda ch: _RecNotifier(), framework_bucket=bucket)
        dispatcher.rebuild()
        ext.set_dispatcher(dispatcher)

        pipeline = ScannerPipeline(extensions=ext)

        framework_finding = Finding(
            detector="proxy",
            type="scan_error",
            severity="critical",
            location="pipeline",
            value_preview="x",
            matched_value="",
            action="alert",
            origin=FindingOrigin.FRAMEWORK,
        )
        result = ScanResult(action="pass", findings=[framework_finding])

        for _ in range(100):
            pipeline.emit_findings(
                result,
                provider="anthropic",
                model="opus",
                session=SessionContext(session_id="s1"),
                body=b"",
            )

        # Wait for thread-pool dispatch to land. Poll instead of fixed sleep
        # to keep the test snappy on fast CI and tolerant on slow CI.
        deadline = _time.monotonic() + 3.0
        while _time.monotonic() < deadline and len(notified) < 1:
            _time.sleep(0.02)

        # 1 admitted by the bucket, 99 suppressed
        self.assertEqual(len(notified), 1)
        self.assertEqual(dispatcher.get_suppression_counts()["proxy:scan_error"], 99)

        # Storage path also exercised. The 100 emit_findings calls share the
        # same (content_hash, session_id) so the ON CONFLICT clause collapses
        # them into one row with seen_count = 100. This is by design (Layer-1
        # dedup) — what the assertion pins is that suppression is at the
        # dispatcher seam, not the store seam: every emit_findings reached
        # the store's UPDATE path even though only one reached the notifier.
        rows, total = store.get_findings_page(origin="framework", limit=200)
        self.assertEqual(total, 1)
        self.assertEqual(rows[0]["seen_count"], 100)


if __name__ == "__main__":
    unittest.main()
