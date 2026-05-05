"""Rate-limited logging helper.

A condition that can fire on every request (e.g. an upstream regression)
must not flood the log: a single signal per minute carries the same
diagnostic value at a fraction of the volume. The suppressed count is
rolled into the next emission so the operator sees magnitude.
"""

from __future__ import annotations

import logging
import threading
import time


class ThrottledWarning:
    """Emit a logger.warning at most once per ``interval_seconds``.

    Thread-safe. The first call always emits. Subsequent calls inside the
    window increment a suppressed-count and return without logging; the
    next emission outside the window includes the suppressed count.

    The message is formatted as ``message_template % (*fields, suppressed,
    interval_seconds)`` — callers control the leading fields, the helper
    appends the throttle metadata.
    """

    def __init__(
        self,
        logger: logging.Logger,
        message_template: str,
        interval_seconds: float,
    ) -> None:
        self._logger = logger
        self._template = message_template
        self._interval = interval_seconds
        self._lock = threading.Lock()
        self._last: float = 0.0
        self._suppressed: int = 0

    def emit(self, *fields: object) -> None:
        """Log if outside the throttle window, else increment suppressed."""
        now = time.monotonic()
        with self._lock:
            if (now - self._last) < self._interval and self._last > 0.0:
                self._suppressed += 1
                return
            suppressed = self._suppressed
            self._suppressed = 0
            self._last = now
        self._logger.warning(self._template, *fields, suppressed, self._interval)
