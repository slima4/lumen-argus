"""MCP stdio wrapper — scan tool calls and responses for sensitive data.

Sits between the AI tool (client) and an MCP server (subprocess), scanning
JSON-RPC messages bidirectionally over stdio. The wrapper acts as a
transparent MCP server that spawns the real server as a child process.

Wire format: newline-delimited JSON-RPC 2.0 (one message per line).
Scan targets: tools/call arguments (outbound) and result.content text (inbound).
All other messages (handshake, notifications, non-tool methods) pass through.

Usage:
    lumen-argus mcp-wrap -- npx @modelcontextprotocol/server-filesystem /path

Security note: The subprocess command is provided by the user via CLI args,
not from untrusted input. asyncio.create_subprocess_exec is used (no shell).
"""

import asyncio
import json
import logging
import sys
from typing import List, Optional, Set

from lumen_argus.models import Finding, ScanField
from lumen_argus.text_utils import sanitize_text

log = logging.getLogger("argus.mcp")


def _extract_text_from_content(content: list) -> str:
    """Extract scannable text from MCP result content array."""
    parts = []
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text":
            text = item.get("text", "")
            if text:
                parts.append(text)
    return "\n".join(parts)


class MCPScanner:
    """Scans MCP JSON-RPC messages for sensitive data.

    Uses the same detectors as request scanning for consistency.
    Injection patterns from the response scanner for tool responses.
    """

    def __init__(
        self,
        detectors: list = None,
        allowlist=None,
        response_scanner=None,
        scan_arguments: bool = True,
        scan_responses: bool = True,
        allowed_tools: Optional[Set[str]] = None,
        blocked_tools: Optional[Set[str]] = None,
        action: str = "alert",
    ):
        self._detectors = detectors or []
        self._allowlist = allowlist
        self._response_scanner = response_scanner
        self._scan_arguments = scan_arguments
        self._scan_responses = scan_responses
        self._allowed_tools = allowed_tools
        self._blocked_tools = blocked_tools
        self._action = action

    def _is_tool_allowed(self, tool_name: str) -> bool:
        """Check if a tool is allowed based on allow/block lists."""
        if self._blocked_tools and tool_name in self._blocked_tools:
            return False
        if self._allowed_tools and tool_name not in self._allowed_tools:
            return False
        return True

    def scan_request(self, msg: dict) -> List[Finding]:
        """Scan a tools/call request for secrets in arguments."""
        if not self._scan_arguments:
            return []

        method = msg.get("method", "")
        if method != "tools/call":
            return []

        params = msg.get("params", {})
        tool_name = params.get("name", "")

        if not self._is_tool_allowed(tool_name):
            log.info("mcp: blocked tool '%s'", tool_name)
            return [
                Finding(
                    detector="mcp",
                    type="blocked_tool",
                    severity="high",
                    location="mcp.tools/call.%s" % tool_name,
                    value_preview=tool_name,
                    matched_value=tool_name,
                    action=self._action,
                )
            ]

        arguments = params.get("arguments", {})
        if not arguments:
            return []

        # Serialize arguments to text for scanning
        text = json.dumps(arguments, ensure_ascii=False)
        text = sanitize_text(text)

        fields = [ScanField(path="mcp.tools/call.%s.arguments" % tool_name, text=text)]
        findings = []
        for detector in self._detectors:
            try:
                det_findings = detector.scan(fields, self._allowlist)
                for f in det_findings:
                    f.location = "mcp.%s" % f.location
                findings.extend(det_findings)
            except Exception as e:
                log.warning("mcp argument detector %s failed: %s", detector.__class__.__name__, e)

        if findings:
            log.info("mcp: %d finding(s) in tools/call '%s' arguments", len(findings), tool_name)

        return findings

    def scan_response(self, msg: dict, request_method: str = "") -> List[Finding]:
        """Scan a tool response for secrets and injection in content."""
        if not self._scan_responses:
            return []

        result = msg.get("result")
        if not isinstance(result, dict):
            return []

        content = result.get("content", [])
        if not isinstance(content, list):
            return []

        text = _extract_text_from_content(content)
        if not text:
            return []

        text = sanitize_text(text)

        findings = []

        # Secret detection via detectors
        fields = [ScanField(path="mcp.response.content", text=text)]
        for detector in self._detectors:
            try:
                det_findings = detector.scan(fields, self._allowlist)
                for f in det_findings:
                    f.location = "mcp.%s" % f.location
                findings.extend(det_findings)
            except Exception as e:
                log.warning("mcp response detector %s failed: %s", detector.__class__.__name__, e)

        # Injection detection via response scanner
        if self._response_scanner:
            try:
                inj_findings = self._response_scanner._scan_injection_patterns(text)
                for f in inj_findings:
                    f.location = "mcp.response.content"
                findings.extend(inj_findings)
            except Exception as e:
                log.warning("mcp injection scan failed: %s", e)

        if findings:
            log.info("mcp: %d finding(s) in tool response", len(findings))

        return findings


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
