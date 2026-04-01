"""SSE (Server-Sent Events) broadcaster for real-time dashboard updates.

Async pub/sub for streaming findings to connected dashboard clients.
Each client gets an asyncio.Queue; broadcast() pushes to all queues
via put_nowait (thread-safe, callable from asyncio.to_thread context).
A heartbeat task prevents idle connection timeouts.
"""

import asyncio
import json
import logging
import time
from typing import Any

log = logging.getLogger("argus.sse")

_MAX_QUEUE_SIZE = 256


class SSEBroadcaster:
    """Async SSE broadcaster with per-client queues."""

    def __init__(self, heartbeat_interval: int = 30) -> None:
        self._clients: list[asyncio.Queue[str]] = []
        self._heartbeat_interval = heartbeat_interval
        self._heartbeat_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """Start the heartbeat background task."""
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop(), name="sse-heartbeat")

    async def stop(self) -> None:
        """Cancel the heartbeat task."""
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
            self._heartbeat_task = None

    def subscribe(self) -> asyncio.Queue[str]:
        """Create and return a queue for a new SSE client."""
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=_MAX_QUEUE_SIZE)
        self._clients.append(queue)
        log.debug("SSE client connected (%d total)", len(self._clients))
        return queue

    def unsubscribe(self, queue: asyncio.Queue[str]) -> None:
        """Remove a disconnected SSE client's queue."""
        self._clients = [q for q in self._clients if q is not queue]
        log.debug("SSE client disconnected (%d remaining)", len(self._clients))

    @property
    def client_count(self) -> int:
        return len(self._clients)

    def broadcast(self, event_type: str, data: dict[str, Any]) -> None:
        """Send an event to all connected SSE clients.

        Thread-safe: uses put_nowait on asyncio.Queue which is safe to call
        from any thread. This is important because api.py helpers call
        broadcast() from asyncio.to_thread() context.
        """
        if not self._clients:
            return

        payload = "event: %s\ndata: %s\n\n" % (event_type, json.dumps(data))

        dead: list[asyncio.Queue[str]] = []
        for queue in list(self._clients):
            try:
                queue.put_nowait(payload)
            except asyncio.QueueFull:
                dead.append(queue)
                log.warning("SSE client queue full, dropping client")

        if dead:
            self._clients = [q for q in self._clients if q not in dead]

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeat events to keep connections alive."""
        while True:
            await asyncio.sleep(self._heartbeat_interval)
            self.broadcast("heartbeat", {"time": time.time()})
