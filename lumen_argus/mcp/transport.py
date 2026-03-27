"""MCP transport implementations — pluggable I/O for JSON-RPC messages.

Each transport handles reading/writing JSON-RPC messages over a specific
protocol. The scanning loop in proxy.py operates on transport pairs
(client, server) and is transport-agnostic.

Wire format for stdio: newline-delimited JSON-RPC 2.0 (one message per line).
"""

import asyncio
import logging
import sys
from typing import Any

log = logging.getLogger("argus.mcp")


class StdioTransport:
    """Read/write newline-delimited JSON-RPC via stdin/stdout pipes.

    Used for both process stdin/stdout (client side) and subprocess
    pipes (server side in stdio subprocess mode).
    """

    def __init__(self, reader: Any, writer: Any, label: str = "stdio") -> None:
        self._reader = reader
        self._writer = writer
        self._label = label

    async def read_message(self) -> bytes | None:
        """Read next newline-delimited JSON-RPC message. Returns None at EOF."""
        line = await self._reader.readline()
        if not line:
            return None
        stripped = line.rstrip(b"\r\n")
        if not stripped:
            return None
        return stripped  # type: ignore[no-any-return]

    async def write_message(self, data: bytes) -> None:
        """Write a JSON-RPC message followed by newline."""
        self._writer.write(data + b"\n")
        await self._writer.drain()

    async def close(self) -> None:
        """Close the writer."""
        try:
            self._writer.close()
            # wait_closed may not exist on all writer types
            if hasattr(self._writer, "wait_closed"):
                await self._writer.wait_closed()
        except Exception:
            log.debug("transport writer close failed", exc_info=True)

    @classmethod
    async def from_process_stdio(cls) -> "StdioTransport":
        """Create a StdioTransport connected to the current process stdin/stdout."""
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)

        # stdout writer — use a simple wrapper
        writer = _StdoutWriter()
        return cls(reader, writer, label="client-stdio")

    @classmethod
    async def from_subprocess(cls, proc: Any) -> "tuple[StdioTransport, StdioTransport]":
        """Create client/server transports from a subprocess.

        Returns (server_stdin_transport, server_stdout_transport).
        """
        stdin_transport = cls(reader=None, writer=proc.stdin, label="server-stdin")
        stdout_transport = cls(reader=proc.stdout, writer=None, label="server-stdout")
        return stdin_transport, stdout_transport


class _StdoutWriter:
    """Minimal async writer wrapping sys.stdout.buffer."""

    def write(self, data: bytes) -> None:
        sys.stdout.buffer.write(data)

    async def drain(self) -> None:
        sys.stdout.buffer.flush()

    def close(self) -> None:
        pass


class HTTPClientTransport:
    """Send JSON-RPC over HTTP POST to upstream, read response.

    Each message is a separate HTTP request-response cycle.
    Uses aiohttp.ClientSession for connection pooling.
    """

    def __init__(self, session: Any, upstream_url: str) -> None:
        self._session = session
        self._url = upstream_url
        self._session_id: str | None = None  # Mcp-Session-Id from server
        self._pending_response: bytes | None = None  # buffered response body

    async def send_and_receive(self, data: bytes) -> bytes | None:
        """POST a JSON-RPC message and return the response body."""
        headers = {"Content-Type": "application/json"}
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id

        async with self._session.post(self._url, data=data, headers=headers) as resp:
            # Capture session ID from server
            sid = resp.headers.get("Mcp-Session-Id")
            if sid:
                self._session_id = sid

            if resp.status == 202:
                return None  # accepted, no body
            if resp.status >= 400:
                body = await resp.read()
                log.warning("mcp http upstream returned %d: %s", resp.status, body[:200])
                return body  # type: ignore[no-any-return]

            body = await resp.read()
            return body if body else None

    async def terminate_session(self) -> None:
        """Send DELETE to terminate the MCP session."""
        if not self._session_id:
            return
        headers = {"Mcp-Session-Id": self._session_id}
        try:
            async with self._session.delete(self._url, headers=headers) as resp:
                log.debug("mcp session terminate: %d", resp.status)
        except Exception as e:
            log.debug("mcp session terminate failed: %s", e)

    async def close(self) -> None:
        """Close the HTTP session."""
        await self.terminate_session()
        await self._session.close()


class WebSocketClientTransport:
    """Send/receive JSON-RPC over WebSocket text frames.

    Uses aiohttp.ClientSession.ws_connect() for the upstream connection.
    """

    def __init__(self, ws: Any) -> None:
        self._ws = ws

    async def read_message(self) -> bytes | None:
        """Read next WebSocket text frame as bytes. Returns None on close."""
        import aiohttp

        msg = await self._ws.receive()
        if msg.type == aiohttp.WSMsgType.TEXT:
            data: str = msg.data
            return data.encode("utf-8")
        if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSED):
            return None
        if msg.type == aiohttp.WSMsgType.BINARY:
            log.warning("mcp ws: rejecting binary frame (MCP requires text)")
            return None
        if msg.type == aiohttp.WSMsgType.ERROR:
            log.warning("mcp ws error: %s", self._ws.exception())
            return None
        return None

    async def write_message(self, data: bytes) -> None:
        """Send a WebSocket text frame."""
        await self._ws.send_str(data.decode("utf-8"))

    async def close(self) -> None:
        """Close the WebSocket connection."""
        await self._ws.close()
