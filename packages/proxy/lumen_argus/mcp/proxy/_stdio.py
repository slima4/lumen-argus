"""Stdio subprocess transport — spawn MCP server, relay stdin/stdout with scanning.

Changes when: subprocess management, pipe handling, or stdio relay logic changes.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any

from lumen_argus.mcp.proxy._scanning import _check_tools_call, _handle_response, _track_outbound
from lumen_argus.mcp.scanner import MCPScanner
from lumen_argus.mcp.transport import StdioTransport

log = logging.getLogger("argus.mcp")


async def run_stdio_proxy(
    command: list[str],
    scanner: MCPScanner,
    env: dict[str, str] | None = None,
    policy_engine: Any = None,
    escalation_fn: Any = None,
    tool_policy_evaluator: Any = None,
    approval_gate: Any = None,
    server_id: str = "",
    sse_broadcaster: Any = None,
    audit_logger: Any = None,
) -> int:
    """Run MCP proxy in stdio subprocess mode.

    Spawns the MCP server as a child process, relays stdin/stdout
    bidirectionally with scanning. Returns child exit code.

    The subprocess command is provided by the user via CLI args,
    not from untrusted input. asyncio.create_subprocess_exec is used
    (no shell) to prevent command injection.

    Args:
        command: MCP server command to spawn.
        scanner: Configured MCPScanner instance.
        env: Environment dict for subprocess (None = inherit current).
    """
    action = scanner._action
    log.info("mcp: starting subprocess %s", " ".join(command))

    proc = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )

    pending_requests: dict[Any, Any] = {}  # id -> method
    _stdout_lock = asyncio.Lock()

    async def _write_stdout(data: bytes) -> None:
        """Write to stdout with lock to prevent interleaved writes."""
        async with _stdout_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    async def _relay_stdin() -> None:
        """Read from client stdin, scan, forward to subprocess."""
        client = await StdioTransport.from_process_stdio()

        while True:
            data = await client.read_message()
            if data is None:
                break
            line_str = data.decode("utf-8", errors="ignore")
            if not line_str:
                continue

            try:
                msg = json.loads(line_str)
            except json.JSONDecodeError:
                # Forward unparseable lines transparently
                if proc.stdin is None:
                    log.error("mcp: subprocess stdin pipe closed, cannot forward data")
                    break
                proc.stdin.write(data + b"\n")
                await proc.stdin.drain()
                continue

            messages = msg if isinstance(msg, list) else [msg]
            forward = []

            for m in messages:
                if not isinstance(m, dict):
                    forward.append(m)
                    continue

                method = m.get("method", "")

                if method == "tools/call":
                    error = await _check_tools_call(
                        m,
                        scanner,
                        action,
                        policy_engine,
                        escalation_fn,
                        tool_policy_evaluator=tool_policy_evaluator,
                        approval_gate=approval_gate,
                        server_id=server_id,
                        sse_broadcaster=sse_broadcaster,
                        audit_logger=audit_logger,
                    )
                    if error:
                        await _write_stdout(json.dumps(error).encode() + b"\n")
                        continue

                _track_outbound(m, pending_requests, scanner)
                forward.append(m)

            if forward:
                if proc.stdin is None:
                    log.error("mcp: subprocess stdin pipe closed, cannot forward messages")
                    break
                if len(forward) == 1 and not isinstance(msg, list):
                    proc.stdin.write(data + b"\n")
                else:
                    out = forward[0] if len(forward) == 1 else forward
                    proc.stdin.write(json.dumps(out).encode() + b"\n")
                await proc.stdin.drain()

        if proc.stdin is not None:
            proc.stdin.close()

    async def _relay_stdout() -> None:
        """Read from subprocess stdout, scan, forward to client."""
        if proc.stdout is None:
            log.error("mcp: subprocess stdout pipe not available")
            return
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
                await _write_stdout(line)
                continue

            # MCP uses single messages per line (not JSON-RPC batches)
            if not isinstance(msg, dict):
                await _write_stdout(line)
                continue

            if not _handle_response(msg, pending_requests, scanner, escalation_fn):
                continue  # drop unsolicited response

            await _write_stdout(line)

    async def _relay_stderr() -> None:
        """Pipe subprocess stderr to our stderr."""
        if proc.stderr is None:
            log.error("mcp: subprocess stderr pipe not available")
            return
        while True:
            line = await proc.stderr.readline()
            if not line:
                break
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()

    try:
        async with asyncio.TaskGroup() as tg:
            tg.create_task(_relay_stdin())
            tg.create_task(_relay_stdout())
            tg.create_task(_relay_stderr())
    except* Exception as eg:
        for exc in eg.exceptions:
            log.error("mcp relay error", exc_info=exc)

    await proc.wait()
    exit_code = proc.returncode or 1
    log.info("mcp: subprocess exited with code %d", exit_code)
    return exit_code
