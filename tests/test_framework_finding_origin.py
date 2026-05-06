"""Pin the contract that framework-emitted Findings carry origin=FRAMEWORK.

This is the discriminator that BasicDispatcher uses to decide whether to
rate-limit (#81). If a future refactor flips a synthetic finding back to
origin=DETECTOR (default), the storm protection silently turns off — this
test guards against that regression.
"""

from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace

from lumen_argus.async_proxy._request_scanning import scan_request_body
from lumen_argus.models import FindingOrigin, ScanResult, SessionContext


def _fake_server(mode: str = "active", max_body_size: int = 1024):
    """Build a minimal server stub. pipeline.emit_findings records calls so
    tests can assert synthetic findings reach the post-scan effects pipeline
    (the bug A1+ fixes — without emit_findings, FRAMEWORK findings never
    reached dispatcher / SSE / post_scan_hook)."""
    emitted: list = []

    def _emit(result, **kwargs):
        emitted.append((result, kwargs))

    pipeline = SimpleNamespace(
        scan=lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("detector bug")),
        emit_findings=_emit,
    )
    server = SimpleNamespace(mode=mode, max_body_size=max_body_size, pipeline=pipeline)
    server._emitted = emitted  # type: ignore[attr-defined]
    return server


class TestSyntheticFindingOrigin(unittest.TestCase):
    def test_scan_error_finding_is_framework_origin(self):
        server = _fake_server()
        result = asyncio.run(scan_request_body(server, 1, b'{"x":1}', "anthropic", "m", SessionContext()))
        self.assertIsInstance(result, ScanResult)
        self.assertEqual(result.action, "pass")
        self.assertEqual(len(result.findings), 1)
        f = result.findings[0]
        self.assertEqual(f.detector, "proxy")
        self.assertEqual(f.type, "scan_error")
        self.assertEqual(f.action, "alert")
        self.assertEqual(f.origin, FindingOrigin.FRAMEWORK)

    def test_oversized_skip_finding_is_framework_origin(self):
        server = _fake_server(max_body_size=4)
        # Suppress display attribute access — fake_server has no display
        server.display = SimpleNamespace(show_error=lambda *a, **kw: None)
        result = asyncio.run(scan_request_body(server, 1, b'{"big_body":"yes"}', "anthropic", "m", SessionContext()))
        self.assertEqual(result.action, "pass")
        self.assertEqual(len(result.findings), 1)
        f = result.findings[0]
        self.assertEqual(f.detector, "proxy")
        self.assertEqual(f.type, "scan_skipped_oversized")
        self.assertEqual(f.origin, FindingOrigin.FRAMEWORK)

    def test_mode_change_finding_is_framework_origin(self):
        from lumen_argus.reload import _record_mode_finding

        captured: list = []

        class _FakePipeline:
            def emit_findings(self, result, **kwargs):
                captured.extend(result.findings)

        server = SimpleNamespace(pipeline=_FakePipeline())
        _record_mode_finding(server, "active", "passthrough")
        self.assertEqual(len(captured), 1)
        f = captured[0]
        self.assertEqual(f.detector, "proxy")
        self.assertEqual(f.type, "mode_changed")
        self.assertEqual(f.origin, FindingOrigin.FRAMEWORK)


class TestSyntheticFindingsReachEmitFindings(unittest.TestCase):
    """Pin the A1+ fix for issue #81. Pre-fix: synthetic findings emitted in
    scan_request_body / reload bypassed dispatcher.dispatch entirely (called
    only from pipeline.scan) — the rate-limit infrastructure was dead code.
    Post-fix: every synthetic finding routes through pipeline.emit_findings,
    which fans out to record + dispatch + SSE + post_scan_hook."""

    def test_scan_error_routes_through_emit_findings(self):
        server = _fake_server()
        asyncio.run(scan_request_body(server, 1, b'{"x":1}', "anthropic", "m", SessionContext(session_id="s")))
        self.assertEqual(len(server._emitted), 1)
        result, kwargs = server._emitted[0]
        self.assertEqual(result.findings[0].type, "scan_error")
        self.assertEqual(result.findings[0].origin, FindingOrigin.FRAMEWORK)
        self.assertEqual(kwargs["provider"], "anthropic")
        self.assertEqual(kwargs["model"], "m")

    def test_oversized_skip_routes_through_emit_findings(self):
        server = _fake_server(max_body_size=4)
        server.display = SimpleNamespace(show_error=lambda *a, **kw: None)
        asyncio.run(
            scan_request_body(server, 1, b'{"big_body":"yes"}', "anthropic", "m", SessionContext(session_id="s"))
        )
        self.assertEqual(len(server._emitted), 1)
        result, _ = server._emitted[0]
        self.assertEqual(result.findings[0].type, "scan_skipped_oversized")
        self.assertEqual(result.findings[0].origin, FindingOrigin.FRAMEWORK)

    def test_mode_change_routes_through_emit_findings(self):
        from lumen_argus.reload import _record_mode_finding

        emitted: list = []

        class _FakePipeline:
            def emit_findings(self, result, **kwargs):
                emitted.append((result, kwargs))

        server = SimpleNamespace(pipeline=_FakePipeline())
        _record_mode_finding(server, "active", "passthrough")
        self.assertEqual(len(emitted), 1)
        result, _ = emitted[0]
        self.assertEqual(result.findings[0].type, "mode_changed")
        self.assertEqual(result.findings[0].origin, FindingOrigin.FRAMEWORK)


class TestDetectorFindingDefaultsToDetectorOrigin(unittest.TestCase):
    """Real detectors should not need to set origin — default keeps them
    classified as DETECTOR so they bypass the rate-limit gate."""

    def test_secrets_detector_finding_default_origin(self):
        from lumen_argus.detectors.secrets import SecretsDetector
        from lumen_argus.models import ScanField

        det = SecretsDetector()
        findings = det.scan([ScanField(path="msg.content", text="AKIAIOSFODNN7EXAMPLE")], None)
        self.assertGreater(len(findings), 0)
        for f in findings:
            self.assertEqual(f.origin, FindingOrigin.DETECTOR)


if __name__ == "__main__":
    unittest.main()
