"""Rolling-window health tracker for upstream proxy reachability.

The agent relay deliberately does not probe the upstream proxy out-of-band
— a probe would couple the two packages on a stringly path contract, and
a future rename or removal would surface as 404 (indistinguishable from
offline) and silently fail the fleet open.

Instead, every real ``forward()`` outcome feeds this rolling window:
``record(True)`` when the upstream returns any response, ``record(False)``
on ``ClientError`` / ``TimeoutError``. ``state()`` returns the three-state
indicator surfaced on ``GET /health`` for sidecar consumers.
"""

from __future__ import annotations

from collections import deque


class UpstreamHealth:
    """Rolling window of recent forward() outcomes.

    Empty window defaults to ``healthy`` (no traffic = no evidence of
    failure). The HTTP status code is the proxy's call, not a
    relay-reachability signal — only network failures count against the
    score.
    """

    def __init__(self, window: int = 10) -> None:
        self._outcomes: deque[bool] = deque(maxlen=window)

    def record(self, ok: bool) -> None:
        self._outcomes.append(ok)

    def state(self) -> str:
        if not self._outcomes:
            return "healthy"
        ok = sum(self._outcomes)
        if ok == len(self._outcomes):
            return "healthy"
        if ok == 0:
            return "unhealthy"
        return "degraded"
