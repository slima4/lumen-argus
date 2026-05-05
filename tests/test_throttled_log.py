"""Unit tests for ThrottledWarning — the rate-limited logging helper."""

from __future__ import annotations

import logging
import threading
import time
import unittest

from lumen_argus._throttled_log import ThrottledWarning


class TestThrottledWarning(unittest.TestCase):
    def setUp(self) -> None:
        self.logger = logging.getLogger("argus.test.throttled_log")
        # Each test gets a fresh handler so captured.output isolates per-case.
        self.logger.setLevel(logging.WARNING)

    def _make(self, interval: float = 60.0, message: str = "x=%s y=%d sup=%d int=%.0f") -> ThrottledWarning:
        return ThrottledWarning(self.logger, message, interval)

    def test_first_emit_logs(self):
        tw = self._make()
        with self.assertLogs(self.logger, level="WARNING") as captured:
            tw.emit("hello", 1)
        self.assertEqual(len(captured.records), 1)
        self.assertIn("x=hello", captured.records[0].getMessage())

    def test_second_emit_inside_window_is_suppressed(self):
        tw = self._make(interval=60.0)
        with self.assertLogs(self.logger, level="WARNING") as captured:
            tw.emit("a", 1)
            tw.emit("b", 2)
            tw.emit("c", 3)
        # Only the first call escapes; rest are counted.
        self.assertEqual(len(captured.records), 1)
        self.assertEqual(tw._suppressed, 2)

    def test_emit_after_window_includes_suppressed_count(self):
        # Sub-second interval lets the test cross the window with sleep().
        # Margin (sleep 0.25 vs interval 0.20) keeps it stable on busy CI
        # runners where a Python wakeup can overshoot by tens of ms.
        tw = self._make(interval=0.20)
        with self.assertLogs(self.logger, level="WARNING") as captured:
            tw.emit("a", 1)  # emits, suppressed=0
            tw.emit("b", 2)  # suppressed=1
            tw.emit("c", 3)  # suppressed=2
            time.sleep(0.25)
            tw.emit("d", 4)  # emits, includes suppressed=2 from prior window
        self.assertEqual(len(captured.records), 2)
        # First record reports 0 suppressed (no prior calls).
        self.assertIn("sup=0", captured.records[0].getMessage())
        # Second record reports 2 suppressed (b, c).
        self.assertIn("sup=2", captured.records[1].getMessage())
        # Counter reset after the second emission.
        self.assertEqual(tw._suppressed, 0)

    def test_message_template_receives_fields_then_suppressed_then_interval(self):
        tw = self._make(interval=42.0, message="provider=%s findings=%d sup=%d window=%.0f")
        with self.assertLogs(self.logger, level="WARNING") as captured:
            tw.emit("anthropic", 7)
        msg = captured.records[0].getMessage()
        self.assertEqual(msg, "provider=anthropic findings=7 sup=0 window=42")

    def test_no_fields_emit(self):
        # Helper must work for templates with no caller-supplied fields.
        tw = self._make(message="empty sup=%d window=%.0f")
        with self.assertLogs(self.logger, level="WARNING") as captured:
            tw.emit()
        self.assertEqual(captured.records[0].getMessage(), "empty sup=0 window=60")

    def test_concurrent_emits_safe(self):
        """No lost updates to the suppressed counter under contention.

        ``interval=60s`` is load-bearing: 1600 lock-serialized increments
        complete in <1s on any host, so no worker can cross the window
        and re-emit. Lower the interval and the strict equality below
        breaks.
        """
        tw = self._make(interval=60.0)
        # Burn the first emission so all worker calls land inside the window.
        with self.assertLogs(self.logger, level="WARNING"):
            tw.emit("seed", 0)
        self.assertEqual(tw._suppressed, 0)

        threads_n = 8
        per_thread = 200
        barrier = threading.Barrier(threads_n)
        errors: list[BaseException] = []

        def worker():
            try:
                barrier.wait()
                for _ in range(per_thread):
                    tw.emit("x", 1)
            except BaseException as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(threads_n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(tw._suppressed, threads_n * per_thread)

    def test_independent_instances_do_not_share_state(self):
        a = self._make(interval=60.0, message="A %s sup=%d int=%.0f")
        b = self._make(interval=60.0, message="B %s sup=%d int=%.0f")
        with self.assertLogs(self.logger, level="WARNING") as captured:
            a.emit("first")
            b.emit("first")  # b's first emission — must NOT be suppressed by a.
        self.assertEqual(len(captured.records), 2)
        self.assertIn("A first", captured.records[0].getMessage())
        self.assertIn("B first", captured.records[1].getMessage())


if __name__ == "__main__":
    unittest.main()
