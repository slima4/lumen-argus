"""MCP stdio wrapper — scan tool calls and responses over stdio transport.

Sits between the AI tool (client) and an MCP server (subprocess), scanning
JSON-RPC messages bidirectionally. Uses MCPScanner from mcp_scanner.py
(shared with the HTTP proxy).

Wire format: newline-delimited JSON-RPC 2.0 (one message per line).

Usage:
    lumen-argus mcp-wrap -- npx @modelcontextprotocol/server-filesystem /path

Security note: The subprocess command is provided by the user via CLI args,
not from untrusted input. asyncio.create_subprocess_exec is used (no shell).
"""

import asyncio
import json
import logging
import sys
from typing import List

from lumen_argus.mcp_scanner import MCPScanner  # noqa: F401 — re-export for cli.py

log = logging.getLogger("argus.mcp")


async def _run_wrapper(
    command: List[str],
    scanner: MCPScanner,
) -> int:
    """Run the MCP wrapper: spawn subprocess, relay and scan messages.

    The subprocess command comes from CLI args (user-provided, not untrusted).
    Uses asyncio.create_subprocess_exec (no shell) to avoid injection.

    Returns exit code of the subprocess.
    """
    action = scanner._action
    log.info("mcp-wrap: starting %s", " ".join(command))

    proc = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    # Track request IDs to map responses back to methods
    pending_requests = {}  # type: dict  # id -> method

    async def _relay_stdin():
        """Read from our stdin, scan, forward to subprocess stdin."""
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)

        while True:
            line = await reader.readline()
            if not line:
                break
            line_str = line.decode("utf-8", errors="ignore").rstrip("\r\n")
            if not line_str:
                continue

            try:
                msg = json.loads(line_str)
            except json.JSONDecodeError:
                # Forward unparseable lines transparently
                proc.stdin.write(line)
                await proc.stdin.drain()
                continue

            # Handle batch messages
            messages = msg if isinstance(msg, list) else [msg]
            forward = []  # messages to forward to subprocess

            for m in messages:
                if not isinstance(m, dict):
                    forward.append(m)
                    continue

                method = m.get("method", "")
                msg_id = m.get("id")

                if method == "tools/call":
                    findings = scanner.scan_request(m)
                    if findings and action == "block":
                        # Send error response back to client, don't forward
                        error_resp = {
                            "jsonrpc": "2.0",
                            "id": msg_id,
                            "error": {
                                "code": -32600,
                                "message": "Request blocked by lumen-argus: sensitive data detected",
                            },
                        }
                        sys.stdout.buffer.write(json.dumps(error_resp).encode() + b"\n")
                        sys.stdout.buffer.flush()
                    else:
                        # Track and forward
                        if msg_id is not None:
                            pending_requests[msg_id] = "tools/call"
                        forward.append(m)
                else:
                    if msg_id is not None and method:
                        pending_requests[msg_id] = method
                    forward.append(m)

            # Forward non-blocked messages
            if forward:
                if len(forward) == 1 and not isinstance(msg, list):
                    # Single message — forward original line to preserve formatting
                    proc.stdin.write(line)
                else:
                    # Batch or filtered — re-serialize
                    out = forward[0] if len(forward) == 1 else forward
                    proc.stdin.write(json.dumps(out).encode() + b"\n")
                await proc.stdin.drain()

        # Client closed stdin — close subprocess stdin
        proc.stdin.close()

    async def _relay_stdout():
        """Read from subprocess stdout, scan, forward to our stdout."""
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            line_str = line.decode("utf-8", errors="ignore").rstrip("\r\n")
            if not line_str:
                continue

            try:
                msg = json.loads(line_str)
            except json.JSONDecodeError:
                sys.stdout.buffer.write(line)
                sys.stdout.buffer.flush()
                continue

            messages = msg if isinstance(msg, list) else [msg]

            for m in messages:
                if isinstance(m, dict) and "result" in m:
                    msg_id = m.get("id")
                    req_method = pending_requests.pop(msg_id, "")
                    if req_method == "tools/call":
                        findings = scanner.scan_response(m, req_method)
                        if findings:
                            log.debug("mcp response findings: %d", len(findings))

            # Always forward responses (async mode — alert, don't block)
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()

    async def _relay_stderr():
        """Pipe subprocess stderr through to our stderr."""
        while True:
            line = await proc.stderr.readline()
            if not line:
                break
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()

    # Run all three relays concurrently
    try:
        await asyncio.gather(
            _relay_stdin(),
            _relay_stdout(),
            _relay_stderr(),
        )
    except Exception as e:
        log.error("mcp-wrap relay error: %s", e)

    await proc.wait()
    log.info("mcp-wrap: subprocess exited with code %d", proc.returncode)
    return proc.returncode
