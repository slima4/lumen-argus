"""Integration test pinning the block→strip→commit_pending→retry contract.

Regression guard: a refactor that moves `try_strip_blocked_history` out of
`_request_scanning.evaluate_block_policy` must keep the
`pipeline.commit_pending(scan_result)` call. Without it, Layer-1 fingerprint
dedup never arms for stripped content, and every retry of a stripped
conversation re-runs the full detector pass.
"""

from __future__ import annotations

import json
import tempfile
import unittest

from lumen_argus.async_proxy._request_scanning import evaluate_block_policy
from lumen_argus.async_proxy._server import AsyncArgusProxy
from lumen_argus.audit import AuditLogger
from lumen_argus.display import TerminalDisplay
from lumen_argus.models import SessionContext
from lumen_argus.pipeline import ScannerPipeline
from lumen_argus.provider import ProviderRouter

_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def _build_proxy(tmpdir: str) -> AsyncArgusProxy:
    pipeline = ScannerPipeline(
        default_action="alert",
        action_overrides={"secrets": "block"},
        dedup_config={"conversation_ttl_minutes": 30, "finding_ttl_minutes": 30},
    )
    router = ProviderRouter(upstreams={"anthropic": "http://127.0.0.1:1"})
    audit = AuditLogger(log_dir=tmpdir)
    display = TerminalDisplay(no_color=True)
    return AsyncArgusProxy(
        bind="127.0.0.1",
        port=1,
        pipeline=pipeline,
        router=router,
        audit=audit,
        display=display,
    )


class TestStripCommitsPendingHashes(unittest.TestCase):
    """Pin the contract that evaluate_block_policy commits fingerprint hashes after strip."""

    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.proxy = _build_proxy(self._tmp)

    def test_stripped_request_skips_rescan_on_retry(self) -> None:
        """After strip, second scan of the original body must hit Layer-1 cache.

        If `evaluate_block_policy` forgets to call `pipeline.commit_pending`,
        the second scan re-runs detectors and re-blocks — failing this test.
        """
        session = SessionContext(session_id="sess-strip-commit")
        req_data = {
            "model": "claude-opus-4-6",
            "messages": [
                {"role": "user", "content": "Old message with key: " + _AWS_KEY},
                {"role": "assistant", "content": "I cannot help with that."},
                {"role": "user", "content": "What is 2 + 2?"},
            ],
        }
        body = json.dumps(req_data).encode()

        scan_result = self.proxy.pipeline.scan(body, "anthropic", session=session)
        self.assertEqual(scan_result.action, "block")
        self.assertIsNotNone(
            scan_result.pending_commit_token,
            "block result must carry pending_commit_token for the proxy to commit after strip",
        )

        new_result, new_body, block_resp = evaluate_block_policy(
            self.proxy,
            request_id=1,
            scan_result=scan_result,
            req_data=req_data,
            body=body,
            method="POST",
            path="/v1/messages",
            provider="anthropic",
            model="claude-opus-4-6",
            is_streaming=False,
            t0=0.0,
            session=session,
        )

        self.assertIsNone(block_resp, "strip path must not return a 400 block response")
        self.assertEqual(new_result.action, "pass")
        self.assertNotEqual(new_body, body, "strip path must replace the body")

        # Second scan of the *original* body — Layer-1 fingerprint must skip
        # the now-committed hashes. If commit_pending was dropped from the
        # strip path, this re-detects the secret and re-blocks.
        retry_result = self.proxy.pipeline.scan(body, "anthropic", session=session)
        self.assertEqual(
            retry_result.action,
            "pass",
            "retry of original body must hit Layer-1 cache after commit_pending; "
            "if this fails, evaluate_block_policy likely dropped the commit_pending call",
        )
        self.assertEqual(len(retry_result.findings), 0)


if __name__ == "__main__":
    unittest.main()
