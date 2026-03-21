"""Tests for cross-request deduplication (Layers 1, 2, and 3)."""

import hashlib
import threading
import time
import unittest

from lumen_argus.models import Finding, ScanField, SessionContext
from lumen_argus.pipeline import ContentFingerprint, _FindingDedup


class TestContentFingerprint(unittest.TestCase):
    """Layer 1: Content fingerprinting tests."""

    def setUp(self):
        self.fp = ContentFingerprint(conversation_ttl=60, max_conversations=100)

    def _filter_and_commit(self, fp, conv_key, fields):
        """Helper: filter new fields and immediately commit hashes (non-block path)."""
        new_fields, pending = fp.filter_new_fields(conv_key, fields)
        fp.commit_hashes(pending)
        return new_fields

    def test_first_request_returns_all_fields(self):
        fields = [
            ScanField(path="messages[0]", text="hello world", source_filename=""),
            ScanField(path="messages[1]", text="secret key here", source_filename=""),
        ]
        result = self._filter_and_commit(self.fp, "conv-1", fields)
        self.assertEqual(len(result), 2)

    def test_second_request_skips_identical_fields(self):
        fields = [
            ScanField(path="messages[0]", text="hello world", source_filename=""),
            ScanField(path="messages[1]", text="secret key here", source_filename=""),
        ]
        self._filter_and_commit(self.fp, "conv-1", fields)

        # Same fields again — should all be skipped
        result = self._filter_and_commit(self.fp, "conv-1", fields)
        self.assertEqual(len(result), 0)

    def test_modified_field_is_rescanned(self):
        fields = [
            ScanField(path="messages[0]", text="original text", source_filename=""),
        ]
        self._filter_and_commit(self.fp, "conv-1", fields)

        # Modified text — new hash, should be returned
        modified = [
            ScanField(path="messages[0]", text="modified text", source_filename=""),
        ]
        result = self._filter_and_commit(self.fp, "conv-1", modified)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].text, "modified text")

    def test_new_field_returned_with_existing(self):
        """Second request with old + new fields returns only new."""
        old = [ScanField(path="m[0]", text="old msg", source_filename="")]
        self._filter_and_commit(self.fp, "conv-1", old)

        combined = [
            ScanField(path="m[0]", text="old msg", source_filename=""),
            ScanField(path="m[1]", text="new msg", source_filename=""),
        ]
        result = self._filter_and_commit(self.fp, "conv-1", combined)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].text, "new msg")

    def test_different_conversations_are_independent(self):
        fields = [ScanField(path="m[0]", text="shared text", source_filename="")]
        self._filter_and_commit(self.fp, "conv-1", fields)

        # Different conversation — same text should still be returned
        result = self._filter_and_commit(self.fp, "conv-2", fields)
        self.assertEqual(len(result), 1)

    def test_ttl_eviction(self):
        fp = ContentFingerprint(conversation_ttl=0, max_conversations=100)
        fields = [ScanField(path="m[0]", text="text", source_filename="")]
        self._filter_and_commit(fp, "conv-1", fields)

        # TTL=0 means immediately expired
        removed = fp.cleanup()
        self.assertEqual(removed, 1)

        # After eviction, same text is treated as new
        result = self._filter_and_commit(fp, "conv-1", fields)
        self.assertEqual(len(result), 1)

    def test_conversation_key_collision_is_safe(self):
        """Two convs sharing a key just means shared dedup — safe failure mode."""
        fields_a = [ScanField(path="m[0]", text="same text", source_filename="")]
        fields_b = [ScanField(path="m[0]", text="same text", source_filename="")]

        self._filter_and_commit(self.fp, "shared-key", fields_a)
        result = self._filter_and_commit(self.fp, "shared-key", fields_b)
        # Same text deduped — correct behavior
        self.assertEqual(len(result), 0)

    def test_max_hashes_per_conversation_cap(self):
        fp = ContentFingerprint(conversation_ttl=60, max_conversations=100, max_hashes_per_conversation=3)

        fields = [ScanField(path="m[%d]" % i, text="text-%d" % i, source_filename="") for i in range(5)]
        result = self._filter_and_commit(fp, "conv-1", fields)
        # All 5 are new (never seen), but only 3 hashes stored
        self.assertEqual(len(result), 5)

        # On second call, only the 3 stored hashes are recognized
        result2 = self._filter_and_commit(fp, "conv-1", fields)
        # 3 are skipped (stored), 2 are "new" (not stored due to cap)
        self.assertEqual(len(result2), 2)

    def test_blocked_content_not_fingerprinted(self):
        """If hashes are not committed (block path), content is re-scanned on retry."""
        fields = [ScanField(path="m[0]", text="secret key", source_filename="")]

        # Filter but do NOT commit (simulates block)
        new_fields, pending = self.fp.filter_new_fields("conv-1", fields)
        self.assertEqual(len(new_fields), 1)
        # Don't call commit_hashes — request was blocked

        # Retry — same content should be returned again (not skipped)
        result = self._filter_and_commit(self.fp, "conv-1", fields)
        self.assertEqual(len(result), 1)

    def test_lru_eviction_on_max_conversations(self):
        """When max_conversations is exceeded, LRU conversation is evicted."""
        # 16 shards, max 32 conversations = 2 per shard
        fp = ContentFingerprint(conversation_ttl=60, max_conversations=32, max_hashes_per_conversation=100)

        # Force 3 conversations into the same shard by finding keys that hash to shard 0
        keys = []
        for i in range(1000):
            k = "conv-%d" % i
            if fp._shard_for(k) == 0:
                keys.append(k)
            if len(keys) == 3:
                break

        fields = [ScanField(path="m[0]", text="hello", source_filename="")]

        # Add first 2 conversations — within limit
        self._filter_and_commit(fp, keys[0], fields)
        self._filter_and_commit(fp, keys[1], fields)
        stats = fp.stats()
        self.assertEqual(stats["conversations"], 2)

        # Add 3rd — exceeds shard limit (2), LRU (keys[0]) should be evicted
        self._filter_and_commit(fp, keys[2], fields)
        stats = fp.stats()
        self.assertEqual(stats["conversations"], 2)  # Still 2, not 3

        # keys[0] was evicted — its fields are treated as new again
        result = self._filter_and_commit(fp, keys[0], fields)
        self.assertEqual(len(result), 1)  # "hello" is new again

    def test_lru_evicts_oldest_not_newest(self):
        """LRU eviction removes the least recently accessed conversation."""
        fp = ContentFingerprint(conversation_ttl=60, max_conversations=32, max_hashes_per_conversation=100)

        keys = []
        for i in range(1000):
            k = "conv-%d" % i
            if fp._shard_for(k) == 0:
                keys.append(k)
            if len(keys) == 3:
                break

        fields = [ScanField(path="m[0]", text="hello", source_filename="")]

        # Add keys[0] first (oldest), then keys[1]
        self._filter_and_commit(fp, keys[0], fields)
        self._filter_and_commit(fp, keys[1], fields)

        # Touch keys[0] again — now keys[1] is LRU
        self._filter_and_commit(fp, keys[0], [ScanField(path="m[1]", text="world", source_filename="")])

        # Add keys[2] — keys[1] should be evicted (it's LRU), not keys[0]
        self._filter_and_commit(fp, keys[2], fields)

        # keys[0] should still have its hashes (not evicted)
        result = self._filter_and_commit(fp, keys[0], fields)
        self.assertEqual(len(result), 0)  # "hello" still remembered

        # keys[1] was evicted — "hello" is new
        result = self._filter_and_commit(fp, keys[1], fields)
        self.assertEqual(len(result), 1)

    def test_thread_safety(self):
        fp = ContentFingerprint(conversation_ttl=60, max_conversations=1000)
        errors = []

        def worker(conv_id):
            try:
                for i in range(50):
                    fields = [
                        ScanField(
                            path="m[%d]" % i,
                            text="conv-%s-text-%d" % (conv_id, i),
                            source_filename="",
                        )
                    ]
                    self._filter_and_commit(fp, conv_id, fields)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(str(i),)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])

    def test_stats(self):
        fields = [ScanField(path="m[0]", text="text", source_filename="")]
        self._filter_and_commit(self.fp, "conv-1", fields)
        self._filter_and_commit(
            self.fp,
            "conv-2",
            [
                ScanField(path="m[0]", text="a", source_filename=""),
                ScanField(path="m[1]", text="b", source_filename=""),
            ],
        )
        stats = self.fp.stats()
        self.assertEqual(stats["conversations"], 2)
        self.assertEqual(stats["total_hashes"], 3)

    def test_hash_determinism(self):
        """Same input produces same hash (SHA-256 is deterministic)."""
        h1 = ContentFingerprint._hash_text("my secret key")
        h2 = ContentFingerprint._hash_text("my secret key")
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 16)

    def test_empty_fields_list(self):
        result, pending = self.fp.filter_new_fields("conv-1", [])
        self.assertEqual(result, [])


class TestFindingDedup(unittest.TestCase):
    """Layer 2: Finding-level TTL cache tests."""

    def _make_finding(self, detector="secrets", ftype="aws_access_key", matched="AKIAIOSFODNN7EXAMPLE"):
        return Finding(
            detector=detector,
            type=ftype,
            severity="critical",
            location="messages[0]",
            value_preview=matched[:4] + "****",
            matched_value=matched,
        )

    def test_first_finding_is_new(self):
        dedup = _FindingDedup(ttl_seconds=60)
        f = self._make_finding()
        self.assertTrue(dedup.is_new(f))

    def test_same_finding_within_ttl_is_not_new(self):
        dedup = _FindingDedup(ttl_seconds=60)
        f = self._make_finding()
        dedup.is_new(f)
        self.assertFalse(dedup.is_new(f))

    def test_same_finding_after_ttl_is_new_again(self):
        dedup = _FindingDedup(ttl_seconds=0)
        f = self._make_finding()
        dedup.is_new(f)
        # TTL=0 means immediately expired
        time.sleep(0.01)
        self.assertTrue(dedup.is_new(f))

    def test_different_type_is_always_new(self):
        dedup = _FindingDedup(ttl_seconds=60)
        f1 = self._make_finding(ftype="aws_access_key")
        f2 = self._make_finding(ftype="aws_secret_key", matched="wJalrXUtnFEMI/SECRET")
        dedup.is_new(f1)
        self.assertTrue(dedup.is_new(f2))

    def test_different_detector_is_always_new(self):
        dedup = _FindingDedup(ttl_seconds=60)
        f1 = self._make_finding(detector="secrets")
        f2 = self._make_finding(detector="custom")
        dedup.is_new(f1)
        self.assertTrue(dedup.is_new(f2))

    def test_same_finding_different_session_is_new(self):
        """Same finding in different sessions should both be recorded."""
        dedup = _FindingDedup(ttl_seconds=60)
        f = self._make_finding()
        self.assertTrue(dedup.is_new(f, session_id="sess-1"))
        # Same finding, different session — should be new
        self.assertTrue(dedup.is_new(f, session_id="sess-2"))
        # Same finding, same session — should NOT be new
        self.assertFalse(dedup.is_new(f, session_id="sess-1"))

    def test_filter_new_returns_subset(self):
        dedup = _FindingDedup(ttl_seconds=60)
        f1 = self._make_finding(ftype="aws_access_key")
        f2 = self._make_finding(ftype="github_token", matched="ghp_1234567890abcdef")
        # Record f1 as seen
        dedup.is_new(f1)

        # Filter list containing both
        result = dedup.filter_new([f1, f2])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].type, "github_token")

    def test_cleanup_removes_expired(self):
        dedup = _FindingDedup(ttl_seconds=0)
        f = self._make_finding()
        dedup.is_new(f)
        time.sleep(0.01)
        removed = dedup.cleanup()
        self.assertGreaterEqual(removed, 1)

    def test_thread_safety(self):
        dedup = _FindingDedup(ttl_seconds=60)
        errors = []

        def worker(thread_id):
            try:
                for i in range(50):
                    f = self._make_finding(
                        ftype="type_%d_%d" % (thread_id, i),
                        matched="value_%d_%d" % (thread_id, i),
                    )
                    dedup.is_new(f)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])


class TestStoreLevelDedup(unittest.TestCase):
    """Layer 3: Store-level unique constraint tests."""

    def setUp(self):
        import tempfile
        from lumen_argus.analytics.store import AnalyticsStore

        self._tmpdir = tempfile.mkdtemp()
        self.store = AnalyticsStore(db_path=self._tmpdir + "/test.db")

    def tearDown(self):
        import shutil

        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_finding(self, detector="secrets", ftype="aws_access_key", preview="AKIA****"):
        return Finding(
            detector=detector,
            type=ftype,
            severity="critical",
            location="messages[0]",
            value_preview=preview,
            matched_value="AKIAIOSFODNN7EXAMPLE",
        )

    def test_duplicate_increments_seen_count(self):
        session = SessionContext(session_id="sess-1")
        f = self._make_finding()
        self.store.record_findings([f], provider="anthropic", session=session)
        self.store.record_findings([f], provider="anthropic", session=session)
        self.store.record_findings([f], provider="anthropic", session=session)

        findings, total = self.store.get_findings_page()
        self.assertEqual(total, 1)
        self.assertEqual(findings[0]["seen_count"], 3)

    def test_same_hash_different_session_is_allowed(self):
        f = self._make_finding()
        self.store.record_findings([f], provider="anthropic", session=SessionContext(session_id="sess-1"))
        self.store.record_findings([f], provider="anthropic", session=SessionContext(session_id="sess-2"))

        findings, total = self.store.get_findings_page()
        self.assertEqual(total, 2)

    def test_empty_content_hash_is_not_constrained(self):
        """Legacy rows with empty content_hash are excluded from unique constraint."""
        # Directly insert rows with empty content_hash
        import sqlite3

        conn = sqlite3.connect(self._tmpdir + "/test.db")
        for _ in range(3):
            conn.execute(
                "INSERT INTO findings "
                "(timestamp, detector, finding_type, severity, location, "
                "session_id, content_hash) "
                "VALUES ('2026-01-01', 'secrets', 'key', 'high', 'm[0]', "
                "'sess-1', '')"
            )
        conn.commit()
        conn.close()

        findings, total = self.store.get_findings_page()
        self.assertEqual(total, 3)

    def test_content_hash_is_deterministic(self):
        """Same finding produces same content_hash."""
        session = SessionContext(session_id="sess-1")
        f = self._make_finding()

        self.store.record_findings([f], provider="anthropic", session=session)

        findings, _ = self.store.get_findings_page()
        hash1 = findings[0]["content_hash"]

        # Compute expected hash — uses hash(matched_value), not value_preview
        value_hash = hashlib.sha256(f.matched_value.encode()).hexdigest()[:16]
        expected = hashlib.sha256(("%s|%s|%s" % (f.detector, f.type, value_hash)).encode()).hexdigest()[:16]
        self.assertEqual(hash1, expected)

    def test_different_findings_different_hash(self):
        session = SessionContext(session_id="sess-1")
        f1 = self._make_finding(ftype="aws_access_key", preview="AKIA****")
        f2 = self._make_finding(ftype="github_token", preview="ghp_****")
        self.store.record_findings([f1, f2], provider="anthropic", session=session)

        findings, total = self.store.get_findings_page()
        self.assertEqual(total, 2)
        hashes = {f["content_hash"] for f in findings}
        self.assertEqual(len(hashes), 2)

    def test_different_secrets_same_preview_get_separate_rows(self):
        """Two different secrets with the same masked preview are NOT collapsed."""
        session = SessionContext(session_id="sess-1")
        f1 = Finding(
            detector="secrets",
            type="aws_secret_key",
            severity="critical",
            location="m[0]",
            value_preview="wJal****",
            matched_value="wJalrXUtnFEMI_K7MDENG_bPxRfiCYEXAMPLEKEY",
        )
        f2 = Finding(
            detector="secrets",
            type="aws_secret_key",
            severity="critical",
            location="m[2]",
            value_preview="wJal****",
            matched_value="wJalrXUtnFEMI_K7MDENG_bPxRfiCYDIFFERENTKEY",
        )
        self.store.record_findings([f1], provider="anthropic", session=session)
        self.store.record_findings([f2], provider="anthropic", session=session)

        findings, total = self.store.get_findings_page()
        self.assertEqual(total, 2)  # Two separate rows, not collapsed

    def test_process_restart_layer3_catches_duplicates(self):
        """After cache loss (process restart), Layer 3 prevents DB duplicates but increments seen_count."""
        session = SessionContext(session_id="sess-1")
        f = self._make_finding()

        # First "process" records the finding
        self.store.record_findings([f], provider="anthropic", session=session)

        # "Restart" — Layer 1+2 caches gone, same finding recorded again
        self.store.record_findings([f], provider="anthropic", session=session)

        findings, total = self.store.get_findings_page()
        self.assertEqual(total, 1)  # No duplicate row
        self.assertEqual(findings[0]["seen_count"], 2)  # But seen_count incremented

    def test_seen_count_default_is_one(self):
        """New findings start with seen_count=1."""
        session = SessionContext(session_id="sess-1")
        f = self._make_finding()
        self.store.record_findings([f], provider="anthropic", session=session)

        findings, _ = self.store.get_findings_page()
        self.assertEqual(findings[0]["seen_count"], 1)


class TestValueHash(unittest.TestCase):
    """HMAC-SHA-256 value_hash tests."""

    def setUp(self):
        import tempfile
        from lumen_argus.analytics.store import AnalyticsStore

        self._tmpdir = tempfile.mkdtemp()
        self._hmac_key = b"\x00" * 32  # 32-byte test key
        self.store = AnalyticsStore(db_path=self._tmpdir + "/test.db", hmac_key=self._hmac_key)

    def tearDown(self):
        import shutil

        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_finding(self, matched="AKIAIOSFODNN7EXAMPLE"):
        return Finding(
            detector="secrets",
            type="aws_access_key",
            severity="critical",
            location="m[0]",
            value_preview="AKIA****",
            matched_value=matched,
        )

    def test_value_hash_populated_when_key_set(self):
        session = SessionContext(session_id="sess-1")
        self.store.record_findings([self._make_finding()], provider="anthropic", session=session)

        findings, _ = self.store.get_findings_page()
        self.assertEqual(len(findings[0]["value_hash"]), 64)  # full SHA-256

    def test_value_hash_deterministic(self):
        """Same secret produces same value_hash."""
        session = SessionContext(session_id="sess-1")
        f = self._make_finding()
        self.store.record_findings([f], provider="anthropic", session=session)
        # Different session so it's not deduped
        self.store.record_findings([f], provider="anthropic", session=SessionContext(session_id="sess-2"))

        findings, _ = self.store.get_findings_page()
        self.assertEqual(findings[0]["value_hash"], findings[1]["value_hash"])

    def test_different_secrets_different_value_hash(self):
        session = SessionContext(session_id="sess-1")
        f1 = self._make_finding(matched="secret_one_value")
        f2 = self._make_finding(matched="secret_two_value")
        self.store.record_findings([f1, f2], provider="anthropic", session=session)

        findings, _ = self.store.get_findings_page()
        self.assertNotEqual(findings[0]["value_hash"], findings[1]["value_hash"])

    def test_value_hash_empty_when_no_key(self):
        """Without HMAC key, value_hash is empty string."""
        import tempfile
        from lumen_argus.analytics.store import AnalyticsStore

        tmpdir = tempfile.mkdtemp()
        store = AnalyticsStore(db_path=tmpdir + "/test.db")  # no hmac_key
        session = SessionContext(session_id="sess-1")
        store.record_findings([self._make_finding()], provider="anthropic", session=session)

        findings, _ = store.get_findings_page()
        self.assertEqual(findings[0]["value_hash"], "")

        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)

    def test_value_hash_is_hmac_not_plain_sha256(self):
        """value_hash should differ from a plain SHA-256 (proves HMAC keying)."""
        session = SessionContext(session_id="sess-1")
        f = self._make_finding()
        self.store.record_findings([f], provider="anthropic", session=session)

        findings, _ = self.store.get_findings_page()
        plain_sha = hashlib.sha256(f.matched_value.encode()).hexdigest()
        self.assertNotEqual(findings[0]["value_hash"], plain_sha)


if __name__ == "__main__":
    unittest.main()
