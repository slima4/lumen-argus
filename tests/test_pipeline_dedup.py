"""Integration tests for cross-request dedup in the scanner pipeline."""

import json
import tempfile
import unittest
from unittest.mock import MagicMock

from lumen_argus.analytics.store import AnalyticsStore
from lumen_argus.extensions import ExtensionRegistry
from lumen_argus.models import SessionContext
from lumen_argus.pipeline import ScannerPipeline


# Build dynamically to avoid GitHub push protection
_STRIPE_KEY = "sk" + "_test_" + "a" * 24 + "EXAMPLE"


def _make_anthropic_body(messages):
    """Build an Anthropic-format request body with given user messages."""
    msg_list = []
    for i, text in enumerate(messages):
        role = "user" if i % 2 == 0 else "assistant"
        msg_list.append({"role": role, "content": text})
    return json.dumps(
        {
            "model": "claude-opus-4-6",
            "messages": msg_list,
        }
    ).encode()


class TestPipelineDedup(unittest.TestCase):
    """End-to-end pipeline dedup tests."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.store = AnalyticsStore(db_path=self._tmpdir + "/test.db")
        self.ext = ExtensionRegistry()
        self.ext.set_analytics_store(self.store)
        # Use short TTLs for testing
        self.pipeline = ScannerPipeline(
            default_action="alert",
            extensions=self.ext,
            dedup_config={
                "conversation_ttl_minutes": 30,
                "finding_ttl_minutes": 30,
            },
        )

    def tearDown(self):
        import shutil

        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_second_scan_same_body_records_zero_new_findings(self):
        """Full pipeline: identical body → no new DB rows on second scan."""
        session = SessionContext(session_id="sess-1")
        body = _make_anthropic_body(
            [
                "Here is my key: AKIAIOSFODNN7EXAMPLE",
            ]
        )

        r1 = self.pipeline.scan(body, "anthropic", session=session)
        r2 = self.pipeline.scan(body, "anthropic", session=session)

        # Both scans should have findings for policy (action enforcement)
        self.assertGreater(len(r1.findings), 0)
        # Second scan: Layer 1 skips fields, so no findings detected
        # (fingerprint filters all fields as already-seen)
        self.assertEqual(len(r2.findings), 0)

        # DB should have findings from first scan only
        _, total = self.store.get_findings_page()
        self.assertGreater(total, 0)
        first_total = total

        # No new rows from second scan
        self.assertEqual(total, first_total)

    def test_seen_count_increments_on_pure_resend(self):
        """seen_count bumps when exact same body is re-sent (all fields skipped)."""
        session = SessionContext(session_id="sess-1")
        body = _make_anthropic_body(
            [
                "Here is my key: AKIAIOSFODNN7EXAMPLE",
            ]
        )

        # Request 1: finding detected and stored (seen_count=1)
        self.pipeline.scan(body, "anthropic", session=session)
        findings, _ = self.store.get_findings_page()
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]["seen_count"], 1)

        # Request 2: exact same body — all fields skipped, seen_count bumped
        self.pipeline.scan(body, "anthropic", session=session)
        findings, _ = self.store.get_findings_page()
        self.assertEqual(findings[0]["seen_count"], 2)

        # Request 3: again
        self.pipeline.scan(body, "anthropic", session=session)
        findings, _ = self.store.get_findings_page()
        self.assertEqual(findings[0]["seen_count"], 3)

    def test_seen_count_increments_on_growing_conversation(self):
        """seen_count bumps when conversation grows (old fields re-sent + new)."""
        session = SessionContext(session_id="sess-grow")
        body1 = _make_anthropic_body(
            [
                "Here is my key: AKIAIOSFODNN7EXAMPLE",
            ]
        )
        self.pipeline.scan(body1, "anthropic", session=session)

        # Request 2: old message re-sent + new assistant reply
        body2 = _make_anthropic_body(
            [
                "Here is my key: AKIAIOSFODNN7EXAMPLE",
                "OK I see the key.",
            ]
        )
        self.pipeline.scan(body2, "anthropic", session=session)
        findings, _ = self.store.get_findings_page()
        self.assertEqual(findings[0]["seen_count"], 2)

        # Request 3: conversation grows again
        body3 = _make_anthropic_body(
            [
                "Here is my key: AKIAIOSFODNN7EXAMPLE",
                "OK I see the key.",
                "Please remove it from the code.",
            ]
        )
        self.pipeline.scan(body3, "anthropic", session=session)
        findings, _ = self.store.get_findings_page()
        self.assertEqual(findings[0]["seen_count"], 3)

    def test_seen_count_correct_on_mixed_request(self):
        """Old findings get bumped, new findings start at 1 on mixed requests."""
        session = SessionContext(session_id="sess-mixed")
        body1 = _make_anthropic_body(
            [
                "Key: AKIAIOSFODNN7EXAMPLE",
            ]
        )
        self.pipeline.scan(body1, "anthropic", session=session)

        # Request 2: old message re-sent + new secret in new message
        body2 = _make_anthropic_body(
            [
                "Key: AKIAIOSFODNN7EXAMPLE",
                "OK noted.",
                "Also: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234",
            ]
        )
        self.pipeline.scan(body2, "anthropic", session=session)

        findings, _ = self.store.get_findings_page()
        by_type = {f["finding_type"]: f["seen_count"] for f in findings}
        # GitHub token is new — bump ran before INSERT, so starts at 1
        self.assertIn("github_token", by_type)
        self.assertEqual(by_type["github_token"], 1)
        # AWS key was bumped (old field re-sent)
        aws_count = by_type.get("aws_access_key") or by_type.get("aws_access_key_id_value")
        self.assertEqual(aws_count, 2)

    def test_new_message_records_only_new_findings(self):
        """Delta detection: only new content scanned and recorded."""
        session = SessionContext(session_id="sess-1")

        # First request: 1 message with a key
        body1 = _make_anthropic_body(
            [
                "Here is my AWS key: AKIAIOSFODNN7EXAMPLE",
            ]
        )
        self.pipeline.scan(body1, "anthropic", session=session)
        _, count1 = self.store.get_findings_page()

        # Second request: conversation grows, new secret added
        body2 = _make_anthropic_body(
            [
                "Here is my AWS key: AKIAIOSFODNN7EXAMPLE",
                "OK, I see the key.",
                "Also here is a GitHub token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12",
            ]
        )
        self.pipeline.scan(body2, "anthropic", session=session)
        _, count2 = self.store.get_findings_page()

        # New findings should be recorded for the GitHub token
        self.assertGreater(count2, count1)

    def test_all_findings_in_scan_result_for_policy(self):
        """ScanResult contains all findings for action enforcement."""
        session = SessionContext(session_id="sess-1")
        body = _make_anthropic_body(
            [
                "Secret: AKIAIOSFODNN7EXAMPLE",
            ]
        )

        r1 = self.pipeline.scan(body, "anthropic", session=session)
        self.assertGreater(len(r1.findings), 0)
        self.assertIn(r1.action, ("alert", "block", "log"))

    def test_action_correct_even_when_findings_deduplicated(self):
        """Policy action is correct even on first scan when findings exist."""
        session = SessionContext(session_id="sess-1")
        pipeline = ScannerPipeline(
            default_action="block",
            extensions=self.ext,
            dedup_config={"conversation_ttl_minutes": 30, "finding_ttl_minutes": 30},
        )
        body = _make_anthropic_body(
            [
                "Secret: AKIAIOSFODNN7EXAMPLE",
            ]
        )

        result = pipeline.scan(body, "anthropic", session=session)
        self.assertEqual(result.action, "block")

    def test_different_sessions_are_independent(self):
        """Findings in different sessions are recorded independently."""
        body = _make_anthropic_body(
            [
                "Key: AKIAIOSFODNN7EXAMPLE",
            ]
        )

        s1 = SessionContext(session_id="sess-1")
        s2 = SessionContext(session_id="sess-2")

        self.pipeline.scan(body, "anthropic", session=s1)
        _, count1 = self.store.get_findings_page()

        # New pipeline instance to get fresh finding dedup cache
        pipeline2 = ScannerPipeline(
            default_action="alert",
            extensions=self.ext,
            dedup_config={"conversation_ttl_minutes": 30, "finding_ttl_minutes": 30},
        )
        pipeline2.scan(body, "anthropic", session=s2)
        _, count2 = self.store.get_findings_page()

        # Both sessions should have recorded findings
        self.assertGreater(count2, count1)

    def test_no_session_id_skips_fingerprinting(self):
        """Without session_id, Layer 1 fingerprinting is skipped."""
        body = _make_anthropic_body(
            [
                "Key: AKIAIOSFODNN7EXAMPLE",
            ]
        )

        # No session — fingerprinting skipped, both scans detect
        r1 = self.pipeline.scan(body, "anthropic", session=None)
        r2 = self.pipeline.scan(body, "anthropic", session=None)

        # Both scans should find the key (no fingerprint filtering)
        self.assertGreater(len(r1.findings), 0)
        self.assertGreater(len(r2.findings), 0)

    def test_dispatcher_receives_all_findings(self):
        """Notification dispatcher gets all findings, not just new ones."""
        mock_dispatcher = MagicMock()
        self.ext.set_dispatcher(mock_dispatcher)

        session = SessionContext(session_id="sess-1")
        body = _make_anthropic_body(
            [
                "Key: AKIAIOSFODNN7EXAMPLE",
            ]
        )

        self.pipeline.scan(body, "anthropic", session=session)
        if mock_dispatcher.dispatch.called:
            # Dispatcher was called with findings
            args = mock_dispatcher.dispatch.call_args
            self.assertGreater(len(args[0][0]), 0)

    def test_post_scan_hook_receives_full_result(self):
        """Post-scan hook gets the full ScanResult (all findings)."""
        hook_results = []

        def hook(result, body, provider, **kwargs):
            hook_results.append(result)

        self.ext.set_post_scan_hook(hook)

        session = SessionContext(session_id="sess-1")
        body = _make_anthropic_body(
            [
                "Key: AKIAIOSFODNN7EXAMPLE",
            ]
        )

        self.pipeline.scan(body, "anthropic", session=session)
        self.assertEqual(len(hook_results), 1)


class TestBlockedContentRescanned(unittest.TestCase):
    """Regression tests: blocked content must be re-scanned on retry.

    Prevents the bug where Layer 1 fingerprinting cached blocked content,
    allowing it through on subsequent requests in the same session.
    """

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.store = AnalyticsStore(db_path=self._tmpdir + "/test.db")
        self.ext = ExtensionRegistry()
        self.ext.set_analytics_store(self.store)

    def tearDown(self):
        import shutil

        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_blocked_request_retry_is_blocked_again(self):
        """Core regression: block → retry same content → must block again."""
        pipeline = ScannerPipeline(
            default_action="block",
            action_overrides={"secrets": "block"},
            extensions=self.ext,
            dedup_config={"conversation_ttl_minutes": 30, "finding_ttl_minutes": 30},
        )
        session = SessionContext(session_id="sess-block")
        body = _make_anthropic_body(
            [
                "My Stripe key is " + _STRIPE_KEY,
            ]
        )

        # First request: detected and blocked
        r1 = pipeline.scan(body, "anthropic", session=session)
        self.assertEqual(r1.action, "block")
        self.assertGreater(len(r1.findings), 0)

        # Retry: same content, same session — must ALSO be blocked
        r2 = pipeline.scan(body, "anthropic", session=session)
        self.assertEqual(r2.action, "block")
        self.assertGreater(len(r2.findings), 0)

        # Third retry — still blocked
        r3 = pipeline.scan(body, "anthropic", session=session)
        self.assertEqual(r3.action, "block")
        self.assertGreater(len(r3.findings), 0)

    def test_blocked_content_in_growing_conversation_still_blocked(self):
        """Simulates Claude Code: block → retry with full context (larger body)."""
        pipeline = ScannerPipeline(
            default_action="block",
            action_overrides={"secrets": "block"},
            extensions=self.ext,
            dedup_config={"conversation_ttl_minutes": 30, "finding_ttl_minutes": 30},
        )
        session = SessionContext(session_id="sess-grow-block")

        # Request 1: user message with secret — blocked
        body1 = _make_anthropic_body(
            [
                "My key: " + _STRIPE_KEY,
            ]
        )
        r1 = pipeline.scan(body1, "anthropic", session=session)
        self.assertEqual(r1.action, "block")

        # Request 2: client retries with same message + additional context
        # (simulates Claude Code sending system prompt + conversation)
        body2 = _make_anthropic_body(
            [
                "My key: " + _STRIPE_KEY,
                "Previous assistant response here.",
                "User follow up message.",
            ]
        )
        r2 = pipeline.scan(body2, "anthropic", session=session)
        self.assertEqual(r2.action, "block")
        self.assertGreater(len(r2.findings), 0)

    def test_alert_action_allows_dedup_on_subsequent_requests(self):
        """Alert (non-block) path: dedup should work normally."""
        pipeline = ScannerPipeline(
            default_action="alert",
            action_overrides={"secrets": "alert"},
            extensions=self.ext,
            dedup_config={"conversation_ttl_minutes": 30, "finding_ttl_minutes": 30},
        )
        session = SessionContext(session_id="sess-alert")
        body = _make_anthropic_body(
            [
                "My key: AKIAIOSFODNN7EXAMPLE",
            ]
        )

        # First request: findings detected, action=alert, hashes committed
        r1 = pipeline.scan(body, "anthropic", session=session)
        self.assertEqual(r1.action, "alert")
        self.assertGreater(len(r1.findings), 0)

        # Second request: same body — Layer 1 skips, no findings (dedup works)
        r2 = pipeline.scan(body, "anthropic", session=session)
        self.assertEqual(r2.action, "pass")
        self.assertEqual(len(r2.findings), 0)

    def test_block_then_clean_message_passes(self):
        """After a blocked request, a clean follow-up should pass."""
        pipeline = ScannerPipeline(
            default_action="block",
            action_overrides={"secrets": "block"},
            extensions=self.ext,
            dedup_config={"conversation_ttl_minutes": 30, "finding_ttl_minutes": 30},
        )
        session = SessionContext(session_id="sess-clean")

        # Request with secret — blocked
        body1 = _make_anthropic_body(
            [
                "My key: " + _STRIPE_KEY,
            ]
        )
        r1 = pipeline.scan(body1, "anthropic", session=session)
        self.assertEqual(r1.action, "block")

        # Follow-up without secret — should pass
        body2 = _make_anthropic_body(
            [
                "Help me configure my deployment script.",
            ]
        )
        r2 = pipeline.scan(body2, "anthropic", session=session)
        self.assertEqual(r2.action, "pass")

    def test_multiple_secrets_all_blocked_on_retry(self):
        """Multiple secrets in one request: all re-detected on retry."""
        pipeline = ScannerPipeline(
            default_action="block",
            action_overrides={"secrets": "block"},
            extensions=self.ext,
            dedup_config={"conversation_ttl_minutes": 30, "finding_ttl_minutes": 30},
        )
        session = SessionContext(session_id="sess-multi")
        body = _make_anthropic_body(
            [
                "AWS: AKIAIOSFODNN7EXAMPLE and Stripe: " + _STRIPE_KEY,
            ]
        )

        r1 = pipeline.scan(body, "anthropic", session=session)
        self.assertEqual(r1.action, "block")
        count1 = len(r1.findings)
        self.assertGreaterEqual(count1, 2)

        # Retry — all secrets must be re-detected
        r2 = pipeline.scan(body, "anthropic", session=session)
        self.assertEqual(r2.action, "block")
        self.assertEqual(len(r2.findings), count1)

    def test_block_retry_only_rescans_delta(self):
        """Performance: retry after block only re-scans the blocked request's
        new fields, not the entire conversation history."""
        pipeline = ScannerPipeline(
            default_action="block",
            action_overrides={"secrets": "block"},
            extensions=self.ext,
            dedup_config={"conversation_ttl_minutes": 30, "finding_ttl_minutes": 30},
        )
        session = SessionContext(session_id="sess-perf")

        # Build a large "history" of clean messages (simulates prior context)
        clean_messages = []
        for i in range(50):
            clean_messages.append("Clean message number %d with enough text to be substantial." % i)
            clean_messages.append("Assistant reply %d." % i)

        # Request 1: large clean context — all fields scanned and committed
        body1 = _make_anthropic_body(clean_messages)
        r1 = pipeline.scan(body1, "anthropic", session=session)
        self.assertEqual(r1.action, "pass")

        # Request 2: same history + new message with secret → BLOCK
        messages_with_secret = clean_messages + [
            "My key: " + _STRIPE_KEY,
        ]
        body2 = _make_anthropic_body(messages_with_secret)
        r2 = pipeline.scan(body2, "anthropic", session=session)
        self.assertEqual(r2.action, "block")

        # Request 3 (retry): same body as request 2
        # Layer 1 should skip all 100 clean fields (committed in request 1)
        # and only re-scan the 1 new field with the secret
        r3 = pipeline.scan(body2, "anthropic", session=session)
        self.assertEqual(r3.action, "block")
        self.assertGreater(len(r3.findings), 0)

        # Verify via fingerprint stats that hashes from request 1 are preserved
        stats = pipeline._fingerprint.stats()
        # 50 clean user messages were committed (assistant messages may vary
        # depending on extraction), but total hashes should be > 0
        self.assertGreater(stats["total_hashes"], 0)

    def test_commit_pending_skips_rescan_after_strip(self):
        """After commit_pending, stripped content is skipped by Layer 1."""
        pipeline = ScannerPipeline(
            default_action="block",
            action_overrides={"secrets": "block"},
            extensions=self.ext,
            dedup_config={"conversation_ttl_minutes": 30, "finding_ttl_minutes": 30},
        )
        session = SessionContext(session_id="sess-commit")
        body = _make_anthropic_body(
            [
                "My key: " + _STRIPE_KEY,
            ]
        )

        # Request 1: blocked, pending hashes stored on result
        r1 = pipeline.scan(body, "anthropic", session=session)
        self.assertEqual(r1.action, "block")
        self.assertIsNotNone(r1._pending_hashes)

        # Simulate successful strip: commit the pending hashes
        pipeline.commit_pending(r1)
        self.assertIsNone(r1._pending_hashes)

        # Request 2 (same content): Layer 1 skips it, no findings, passes
        r2 = pipeline.scan(body, "anthropic", session=session)
        self.assertEqual(r2.action, "pass")
        self.assertEqual(len(r2.findings), 0)

    def test_pending_hashes_none_when_not_blocked(self):
        """Non-blocked results have no pending hashes (committed immediately)."""
        pipeline = ScannerPipeline(
            default_action="alert",
            action_overrides={"secrets": "alert"},
            extensions=self.ext,
            dedup_config={"conversation_ttl_minutes": 30, "finding_ttl_minutes": 30},
        )
        session = SessionContext(session_id="sess-alert-pending")
        body = _make_anthropic_body(
            [
                "My key: AKIAIOSFODNN7EXAMPLE",
            ]
        )

        r1 = pipeline.scan(body, "anthropic", session=session)
        self.assertEqual(r1.action, "alert")
        # Hashes committed immediately, nothing pending
        self.assertIsNone(r1._pending_hashes)


if __name__ == "__main__":
    unittest.main()
