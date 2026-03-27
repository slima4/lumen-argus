"""Shared MCP scanning logic — used by all MCP transport modes and the HTTP proxy.

Detects MCP JSON-RPC in request/response bodies, applies tool allow/block
lists, scans tool arguments and response content for secrets/PII/injection.

Used by:
- mcp/proxy.py — transport-agnostic MCP scanning loop
- async_proxy.py — MCP-aware scanning of HTTP API traffic
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore

from lumen_argus.models import Finding, ScanField
from lumen_argus.text_utils import sanitize_text

log = logging.getLogger("argus.mcp")


def extract_text_from_content(content: list[Any]) -> str:
    """Extract scannable text from MCP result content array."""
    parts = []
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text":
            text = item.get("text", "")
            if text:
                parts.append(text)
    return "\n".join(parts)


def detect_mcp_request(body: bytes) -> dict[str, Any] | None:
    """Detect MCP tools/call in an HTTP request body.

    Returns dict with tool_name, arguments, request_id if MCP detected.
    Returns None for non-MCP requests.
    """
    try:
        msg = json.loads(body)
        if isinstance(msg, dict) and msg.get("jsonrpc") == "2.0":
            if msg.get("method") == "tools/call":
                return {
                    "tool_name": msg.get("params", {}).get("name", ""),
                    "arguments": msg.get("params", {}).get("arguments", {}),
                    "request_id": msg.get("id"),
                }
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        log.debug("detect_mcp_request: body is not valid JSON-RPC")
    return None


def detect_mcp_method(body: bytes) -> str | None:
    """Detect the JSON-RPC method in an MCP request body. Returns method or None."""
    try:
        msg = json.loads(body)
        if isinstance(msg, dict) and msg.get("jsonrpc") == "2.0":
            return msg.get("method")
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        log.debug("detect_mcp_method: body is not valid JSON-RPC")
    return None


def detect_mcp_tools_list_response(body: bytes) -> list[dict[str, Any]] | None:
    """Detect tools/list response and extract tool metadata.

    Returns list of {name, description, inputSchema} dicts, or None.
    """
    try:
        msg = json.loads(body)
        if isinstance(msg, dict) and msg.get("jsonrpc") == "2.0":
            result = msg.get("result")
            if isinstance(result, dict) and "tools" in result:
                tools = result.get("tools", [])
                if isinstance(tools, list):
                    return [
                        {
                            "name": t.get("name", ""),
                            "description": t.get("description", ""),
                            "inputSchema": t.get("inputSchema", {}),
                        }
                        for t in tools
                        if isinstance(t, dict) and t.get("name")
                    ]
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        log.debug("detect_mcp_tools_list_response: body is not valid JSON-RPC")
    return None


def detect_mcp_response(body: bytes) -> dict[str, Any] | None:
    """Detect MCP tool response in an HTTP response body.

    Returns dict with request_id, content if MCP response detected.
    Returns None for non-MCP responses.
    """
    try:
        msg = json.loads(body)
        if isinstance(msg, dict) and msg.get("jsonrpc") == "2.0":
            result = msg.get("result")
            if isinstance(result, dict) and "content" in result:
                return {
                    "request_id": msg.get("id"),
                    "content": result.get("content", []),
                }
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        log.debug("detect_mcp_response: body is not valid JSON-RPC")
    return None


class MCPScanner:
    """Scans MCP JSON-RPC messages for sensitive data.

    Used by all transport modes (stdio, HTTP, WebSocket) and the HTTP proxy.
    Ensures identical scanning behavior regardless of transport.
    """

    def __init__(
        self,
        detectors: list[Any] | None | None = None,
        allowlist: Any = None,
        response_scanner: Any = None,
        scan_arguments: bool = True,
        scan_responses: bool = True,
        allowed_tools: set[str] | None | None = None,
        blocked_tools: set[str] | None | None = None,
        action: str = "alert",
        request_tracker: Any = None,
        session_binding: Any = None,
        scan_tool_descriptions: bool = True,
        detect_drift: bool = True,
        drift_action: str = "alert",
        store: AnalyticsStore | None = None,
    ):
        self._detectors = detectors or []
        self._allowlist = allowlist
        self._response_scanner = response_scanner
        self._scan_arguments = scan_arguments
        self._scan_responses = scan_responses
        self._allowed_tools = allowed_tools
        self._blocked_tools = blocked_tools
        self._action = action
        # Phase 2 security features
        self.request_tracker = request_tracker
        self.session_binding = session_binding
        self._scan_tool_descriptions = scan_tool_descriptions
        self._detect_drift = detect_drift
        self._drift_action = drift_action
        self._store = store  # for drift detection DB access

    def is_tool_allowed(self, tool_name: str) -> bool:
        """Check if a tool is allowed based on allow/block lists."""
        if self._blocked_tools and tool_name in self._blocked_tools:
            return False
        if self._allowed_tools and tool_name not in self._allowed_tools:
            return False
        return True

    def scan_request(self, msg: dict[str, Any]) -> list[Finding]:
        """Scan a tools/call request for secrets in arguments."""
        if not self._scan_arguments:
            return []

        method = msg.get("method", "")
        if method != "tools/call":
            return []

        params = msg.get("params", {})
        tool_name = params.get("name", "")

        if not self.is_tool_allowed(tool_name):
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

        text = json.dumps(arguments, ensure_ascii=False)
        text = sanitize_text(text)

        fields = [ScanField(path="tools/call.%s.arguments" % tool_name, text=text)]
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

    def scan_arguments(self, tool_name: str, arguments: dict[str, Any]) -> list[Finding]:
        """Scan tool call arguments directly (for proxy integration)."""
        if not self._scan_arguments or not arguments:
            return []

        text = json.dumps(arguments, ensure_ascii=False)
        text = sanitize_text(text)

        fields = [ScanField(path="tools/call.%s.arguments" % tool_name, text=text)]
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

    def scan_response(self, msg: dict[str, Any], request_method: str = "") -> list[Finding]:
        """Scan a tool response for secrets and injection in content."""
        if not self._scan_responses:
            return []

        result = msg.get("result")
        if not isinstance(result, dict):
            return []

        content = result.get("content", [])
        if not isinstance(content, list):
            return []

        return self.scan_response_content(content)

    def scan_response_content(self, content: list[Any]) -> list[Finding]:
        """Scan MCP response content array (for proxy integration)."""
        if not self._scan_responses:
            return []

        text = extract_text_from_content(content)
        if not text:
            return []

        text = sanitize_text(text)
        findings = []

        fields = [ScanField(path="response.content", text=text)]
        for detector in self._detectors:
            try:
                det_findings = detector.scan(fields, self._allowlist)
                for f in det_findings:
                    f.location = "mcp.%s" % f.location
                findings.extend(det_findings)
            except Exception as e:
                log.warning("mcp response detector %s failed: %s", detector.__class__.__name__, e)

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

    def process_tools_list(self, tools: list[dict[str, Any]]) -> list[Finding]:
        """Process a tools/list response: poisoning scan, drift check, session binding.

        Args:
            tools: List of tool dicts (name, description, inputSchema).

        Returns:
            List of findings from poisoning detection.
        """
        findings = []

        # Poisoning detection
        if self._scan_tool_descriptions:
            from lumen_argus.mcp.tool_scanner import scan_tool_descriptions

            findings.extend(scan_tool_descriptions(tools, action=self._action))

        # Drift detection
        if self._detect_drift and self._store:
            from lumen_argus.mcp.tool_scanner import check_tool_drift

            try:
                drifted = check_tool_drift(tools, self._store)
                for tool_name, summary in drifted:
                    findings.append(
                        Finding(
                            detector="mcp_tool_drift",
                            type="tool_drift",
                            severity="high",
                            location="mcp.tools/list.%s" % tool_name,
                            value_preview=summary[:80],
                            matched_value=summary,
                            action=self._drift_action,
                        )
                    )
            except Exception as e:
                log.warning("mcp: drift detection failed: %s", e)

        # Session binding
        if self.session_binding:
            tool_names = [t.get("name", "") for t in tools if t.get("name")]
            self.session_binding.set_baseline(tool_names)

        return findings
