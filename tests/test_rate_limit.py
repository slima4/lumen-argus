"""Tests for the per-key TokenBucket used by BasicDispatcher."""

import threading
import time
import unittest

from lumen_argus.notifiers._rate_limit import TokenBucket


class TestTokenBucket(unittest.TestCase):
    def test_first_acquire_succeeds(self):
        bucket = TokenBucket(capacity=1, refill_seconds=60)
        self.assertTrue(bucket.try_acquire("a"))

    def test_capacity_exhausts(self):
        bucket = TokenBucket(capacity=3, refill_seconds=60)
        self.assertTrue(bucket.try_acquire("a"))
        self.assertTrue(bucket.try_acquire("a"))
        self.assertTrue(bucket.try_acquire("a"))
        self.assertFalse(bucket.try_acquire("a"))
        self.assertFalse(bucket.try_acquire("a"))

    def test_per_key_isolation(self):
        bucket = TokenBucket(capacity=1, refill_seconds=60)
        self.assertTrue(bucket.try_acquire("a"))
        self.assertFalse(bucket.try_acquire("a"))
        self.assertTrue(bucket.try_acquire("b"))
        self.assertFalse(bucket.try_acquire("b"))

    def test_tuple_key_isolation(self):
        bucket = TokenBucket(capacity=1, refill_seconds=60)
        self.assertTrue(bucket.try_acquire(("proxy", "scan_error")))
        self.assertTrue(bucket.try_acquire(("proxy", "scan_skipped_oversized")))
        self.assertFalse(bucket.try_acquire(("proxy", "scan_error")))

    def test_refill_after_window(self):
        bucket = TokenBucket(capacity=1, refill_seconds=0.2)
        self.assertTrue(bucket.try_acquire("a"))
        self.assertFalse(bucket.try_acquire("a"))
        time.sleep(0.25)
        self.assertTrue(bucket.try_acquire("a"))

    def test_partial_refill_below_one_token_blocks(self):
        bucket = TokenBucket(capacity=1, refill_seconds=10.0)
        self.assertTrue(bucket.try_acquire("a"))
        time.sleep(0.05)
        self.assertFalse(bucket.try_acquire("a"))

    def test_suppression_count_accumulates(self):
        bucket = TokenBucket(capacity=1, refill_seconds=60)
        bucket.try_acquire("a")
        for _ in range(99):
            bucket.try_acquire("a")
        snap = bucket.snapshot()
        self.assertEqual(snap["a"], 99)

    def test_suppression_count_per_key(self):
        bucket = TokenBucket(capacity=1, refill_seconds=60)
        bucket.try_acquire(("proxy", "scan_error"))
        for _ in range(50):
            bucket.try_acquire(("proxy", "scan_error"))
        bucket.try_acquire(("proxy", "scan_skipped_oversized"))
        for _ in range(10):
            bucket.try_acquire(("proxy", "scan_skipped_oversized"))
        snap = bucket.snapshot()
        self.assertEqual(snap[("proxy", "scan_error")], 50)
        self.assertEqual(snap[("proxy", "scan_skipped_oversized")], 10)

    def test_snapshot_excludes_keys_with_zero_suppressions(self):
        bucket = TokenBucket(capacity=1, refill_seconds=60)
        bucket.try_acquire("a")
        snap = bucket.snapshot()
        self.assertNotIn("a", snap)

    def test_reset_clears_state(self):
        bucket = TokenBucket(capacity=1, refill_seconds=60)
        bucket.try_acquire("a")
        for _ in range(5):
            bucket.try_acquire("a")
        bucket.reset()
        self.assertEqual(bucket.snapshot(), {})
        # Bucket starts full again after reset
        self.assertTrue(bucket.try_acquire("a"))

    def test_thread_safety_concurrent_acquires(self):
        """Concurrent try_acquire calls on same key must net to capacity admits
        and (n - capacity) suppressions — no double-count, no lost updates."""
        bucket = TokenBucket(capacity=10, refill_seconds=60)
        admits = []
        n_threads = 200
        barrier = threading.Barrier(n_threads)

        def worker():
            barrier.wait()
            if bucket.try_acquire("k"):
                admits.append(1)

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sum(admits), 10)
        self.assertEqual(bucket.snapshot().get("k", 0), n_threads - 10)

    def test_invalid_capacity_raises(self):
        with self.assertRaises(ValueError):
            TokenBucket(capacity=0, refill_seconds=60)

    def test_invalid_refill_raises(self):
        with self.assertRaises(ValueError):
            TokenBucket(capacity=1, refill_seconds=0)


if __name__ == "__main__":
    unittest.main()
