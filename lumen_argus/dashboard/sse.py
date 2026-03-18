"""SSE (Server-Sent Events) broadcaster for real-time dashboard updates.

Thread-safe pub/sub for streaming findings to connected dashboard clients.
Each connected client holds a thread (from ThreadingHTTPServer) until
disconnected. A heartbeat thread prevents idle connection timeouts.
"""

import json
import logging
import threading
import time
from typing import List

log = logging.getLogger("argus.sse")


class SSEBroadcaster:
    """Thread-safe registry of SSE clients with broadcast capability."""

    def __init__(self, heartbeat_interval: int = 30):
        self._clients = []  # type: List[object]
        self._lock = threading.Lock()
        self._heartbeat_interval = heartbeat_interval
        self._start_heartbeat()

    def register(self, wfile) -> None:
        """Register a new SSE client."""
        with self._lock:
            self._clients.append(wfile)
        log.debug("SSE client connected (%d total)", len(self._clients))

    def unregister(self, wfile) -> None:
        """Unregister a disconnected SSE client."""
        with self._lock:
            self._clients = [c for c in self._clients if c is not wfile]
        log.debug("SSE client disconnected (%d remaining)", len(self._clients))

    @property
    def client_count(self) -> int:
        with self._lock:
            return len(self._clients)

    def broadcast(self, event_type: str, data: dict) -> None:
        """Send an event to all connected SSE clients."""
        if not self._clients:
            return

        payload = "event: %s\ndata: %s\n\n" % (event_type, json.dumps(data))
        payload_bytes = payload.encode("utf-8")

        with self._lock:
            clients = list(self._clients)

        dead = []
        for wfile in clients:
            try:
                wfile.write(payload_bytes)
                wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                dead.append(wfile)

        if dead:
            with self._lock:
                self._clients = [c for c in self._clients if c not in dead]
                log.debug("removed %d dead SSE clients", len(dead))

    def _start_heartbeat(self) -> None:
        """Start background heartbeat thread to keep connections alive."""
        def _heartbeat_loop():
            while True:
                time.sleep(self._heartbeat_interval)
                self.broadcast("heartbeat", {"time": time.time()})

        t = threading.Thread(target=_heartbeat_loop, daemon=True, name="sse-heartbeat")
        t.start()
