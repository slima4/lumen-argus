"""Shared MCP scanning protocol — request validation, response handling, escalation.

Changes when: MCP scanning protocol, policy engine interface, or escalation logic changes.
Used by all 4 transport modes.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any

from lumen_argus.mcp.scanner import MCPScanner

log = logging.getLogger("argus.mcp")


def _run_policy_engine(policy_engine: Any, tool_name: str, arguments: dict[str, Any]) -> list[Any]:
    """Run Pro policy engine on a tools/call request. Returns findings list.

    Returns empty list if no engine registered or engine raises.
    """
    if policy_engine is None:
        return []
    try:
        return policy_engine.evaluate(tool_name, arguments)  # type: ignore[no-any-return]
    except Exception as exc:
        log.warning("mcp: policy engine raised %s", exc)
        return []


def _run_tool_policy_evaluator(
    evaluator: Any,
    tool_name: str,
    arguments: dict[str, Any],
    server_id: str,
    context: dict[str, Any],
) -> Any | None:
    """Run ABAC tool policy evaluator. Returns PolicyDecision or None.

    Returns None if no evaluator registered or evaluator raises.
    """
    if evaluator is None:
        return None
    try:
        return evaluator.evaluate(tool_name, arguments, server_id, context)
    except Exception as exc:
        log.warning("mcp: tool policy evaluator raised %s", exc)
        return None


async def _run_approval_gate(
    gate: Any,
    tool_name: str,
    arguments: dict[str, Any],
    server_id: str,
    session_id: str,
    identity: str,
    client_name: str,
    policy: Any,
) -> Any | None:
    """Request approval via the approval gate. Returns ApprovalDecision or None.

    Returns None if no gate registered or gate raises.
    """
    if gate is None:
        return None
    try:
        return await gate.request_approval(tool_name, arguments, server_id, session_id, identity, client_name, policy)
    except Exception as exc:
        log.error("mcp: approval gate raised %s — tool call allowed (fail-open)", exc)
        return None


def _signal_escalation(
    escalation_fn: Any, signal_type: str, session_id: str, details: dict[str, Any] | None = None
) -> str | None:
    """Feed a threat signal to Pro's adaptive enforcement. Returns enforcement level.

    Returns None if no escalation function registered or it raises.
    The session_id may be empty for stdio-based modes that have no session
    concept — Pro's escalation engine should treat empty session_id as a
    single implicit session.
    """
    if escalation_fn is None:
        return None
    try:
        level = escalation_fn(signal_type, session_id, details or {})
        if level and level != "normal":
            log.info("mcp: session escalation level: %s (signal=%s)", level, signal_type)
        return str(level) if level else None
    except Exception as exc:
        log.warning("mcp: session escalation raised %s", exc)
        return None


def _broadcast_mcp_event(
    broadcaster: Any,
    event_type: str,
    tool_name: str,
    decision: str,
    server_id: str = "",
    session_id: str = "",
    policy_name: str = "",
    approval_id: str = "",
    findings_count: int = 0,
) -> None:
    """Broadcast an MCP tool call event to SSE clients.

    Event types: mcp_tool_call, mcp_approval_requested, mcp_approval_decided.
    Safe to call when broadcaster is None (no-op).
    Payload fields are explicitly enumerated — no open dict to prevent
    accidental leakage of sensitive data (arguments, env, matched_value).
    """
    if broadcaster is None:
        return
    try:
        from lumen_argus_core.time_utils import now_iso

        payload: dict[str, Any] = {
            "tool_name": tool_name,
            "decision": decision,
            "server_id": server_id,
            "session_id": session_id,
            "timestamp": now_iso(),
        }
        if policy_name:
            payload["policy_name"] = policy_name
        if approval_id:
            payload["approval_id"] = approval_id
        if findings_count:
            payload["findings_count"] = findings_count
        broadcaster.broadcast(event_type, payload)
    except Exception:
        log.debug("mcp: SSE broadcast failed for %s", event_type, exc_info=True)


def _audit_mcp_tool_call(
    audit_logger: Any,
    tool_name: str,
    decision: str,
    server_id: str = "",
    session_id: str = "",
    policy_name: str = "",
    risk_level: str = "",
    approval_id: str = "",
    decided_by: str = "",
    arguments: dict[str, Any] | None = None,
    latency_ms: float = 0.0,
    findings_count: int = 0,
) -> None:
    """Write an MCP tool call decision to the JSONL audit log.

    Safe to call when audit_logger is None (no-op).
    Arguments are hashed (SHA-256) — never written in plaintext.
    """
    if audit_logger is None:
        return
    try:
        from lumen_argus_core.time_utils import now_iso

        # Hash arguments — never store raw arguments in audit log
        args_hash = ""
        if arguments:
            args_hash = hashlib.sha256(json.dumps(arguments, sort_keys=True).encode()).hexdigest()

        entry: dict[str, Any] = {
            "action": "mcp_tool_call",
            "tool_name": tool_name,
            "decision": decision,
            "timestamp": now_iso(),
        }
        # Include optional fields only when populated (keeps JSONL compact)
        if server_id:
            entry["server_id"] = server_id
        if session_id:
            entry["session_id"] = session_id
        if policy_name:
            entry["policy_name"] = policy_name
        if risk_level:
            entry["risk_level"] = risk_level
        if approval_id:
            entry["approval_id"] = approval_id
        if decided_by:
            entry["decided_by"] = decided_by
        if args_hash:
            entry["arguments_hash"] = args_hash
        if latency_ms > 0:
            entry["latency_ms"] = round(latency_ms, 1)
        if findings_count:
            entry["findings_count"] = findings_count

        audit_logger.log_dict(entry)
    except Exception:
        log.debug("mcp: audit log write failed", exc_info=True)


def _jsonrpc_error(msg_id: Any, message: str) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 error response."""
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32600, "message": message},
    }


async def _check_tools_call(
    msg: dict[str, Any],
    scanner: MCPScanner,
    action: str,
    policy_engine: Any,
    escalation_fn: Any,
    session_id: str = "",
    tool_policy_evaluator: Any = None,
    approval_gate: Any = None,
    server_id: str = "",
    sse_broadcaster: Any = None,
    audit_logger: Any = None,
) -> dict[str, Any] | None:
    """Validate a tools/call request through the full scanning pipeline.

    Pipeline order:
    1. Session binding check (existing)
    2. ABAC tool policy evaluation (Pro — via tool_policy_evaluator hook)
    3. Approval gate if policy action == "approval" (Pro — via approval_gate hook)
    4. Legacy policy engine check (existing Pro hook)
    5. DLP argument scanning (existing)

    Returns a JSON-RPC error dict if the call should be blocked, or None if
    it should be forwarded. Fires escalation signals as side effects.

    All 4 transport modes call this for tools/call requests.
    """
    msg_id = msg.get("id")
    tool_name = msg.get("params", {}).get("name", "")
    arguments = msg.get("params", {}).get("arguments", {})
    _t0 = time.monotonic()

    # Helper to broadcast + audit + return error in one step
    def _block(reason: str, policy: str = "", sse_decision: str = "blocked") -> dict[str, Any]:
        _broadcast_mcp_event(
            sse_broadcaster,
            "mcp_tool_call",
            tool_name,
            sse_decision,
            server_id=server_id,
            session_id=session_id,
            policy_name=policy,
        )
        _audit_mcp_tool_call(
            audit_logger,
            tool_name,
            sse_decision,
            server_id=server_id,
            session_id=session_id,
            policy_name=policy,
            arguments=arguments,
            latency_ms=(time.monotonic() - _t0) * 1000,
        )
        return _jsonrpc_error(msg_id, reason)

    # 1. Session binding check
    if scanner.session_binding and not scanner.session_binding.validate_tool(tool_name):
        _signal_escalation(escalation_fn, "unknown_tool", session_id, {"tool": tool_name})
        if scanner.session_binding.should_block:
            return _block("Tool '%s' not in session baseline" % tool_name, sse_decision="blocked")

    # Track whether an SSE decision event was already broadcast (e.g., by approval gate)
    # to avoid redundant mcp_tool_call/allowed at the end.
    sse_decision_broadcast = False

    # 2. ABAC tool policy evaluation
    decision = _run_tool_policy_evaluator(
        tool_policy_evaluator,
        tool_name,
        arguments,
        server_id=server_id,
        context={"session_id": session_id},
    )
    if decision is not None:
        decision_action = getattr(decision, "action", None)
        policy_name = getattr(decision, "policy_name", "")
        reason = getattr(decision, "reason", "")

        if decision_action == "block":
            log.info("mcp: tool call blocked by policy %r: %s (%s)", policy_name, tool_name, reason)
            _signal_escalation(escalation_fn, "block", session_id, {"tool": tool_name, "policy": policy_name})
            return _block(reason or ("Blocked by policy: %s" % policy_name), policy_name)

        if decision_action == "alert":
            log.warning("mcp: tool call alert: %s (policy: %s, reason: %s)", tool_name, policy_name, reason)
            _broadcast_mcp_event(
                sse_broadcaster,
                "mcp_tool_call",
                tool_name,
                "alerted",
                server_id=server_id,
                session_id=session_id,
                policy_name=policy_name,
            )

        # 3. Approval gate
        if decision_action == "approval":
            matched_policy = getattr(decision, "matched_policy", None) or policy_name
            if approval_gate is None:
                log.warning(
                    "mcp: policy %r requires approval for %s but no gate registered — allowing (fail-open)",
                    policy_name,
                    tool_name,
                )
            else:
                _broadcast_mcp_event(
                    sse_broadcaster,
                    "mcp_approval_requested",
                    tool_name,
                    "pending",
                    server_id=server_id,
                    session_id=session_id,
                    policy_name=policy_name,
                )
                approval = await _run_approval_gate(
                    approval_gate,
                    tool_name,
                    arguments,
                    server_id=server_id,
                    session_id=session_id,
                    identity="",
                    client_name="",
                    policy=matched_policy,
                )
                if approval is None:
                    log.error(
                        "mcp: approval gate failed for %s — allowing (fail-open)",
                        tool_name,
                    )
                else:
                    approval_status = getattr(approval, "status", "denied")
                    approval_id = getattr(approval, "approval_id", "")
                    _broadcast_mcp_event(
                        sse_broadcaster,
                        "mcp_approval_decided",
                        tool_name,
                        approval_status,
                        server_id=server_id,
                        session_id=session_id,
                        policy_name=policy_name,
                        approval_id=approval_id,
                    )
                    sse_decision_broadcast = True
                    if approval_status != "approved":
                        log.info("mcp: tool call %s: %s (approval %s)", approval_status, tool_name, approval_id)
                        _audit_mcp_tool_call(
                            audit_logger,
                            tool_name,
                            approval_status,
                            server_id=server_id,
                            session_id=session_id,
                            policy_name=policy_name,
                            approval_id=approval_id,
                            arguments=arguments,
                            latency_ms=(time.monotonic() - _t0) * 1000,
                        )
                        return _jsonrpc_error(
                            msg_id,
                            "Tool call %s: %s (approval %s)" % (approval_status, tool_name, approval_id),
                        )
                    log.info("mcp: tool call approved: %s (approval %s)", tool_name, approval_id)
                    _audit_mcp_tool_call(
                        audit_logger,
                        tool_name,
                        "approved",
                        server_id=server_id,
                        session_id=session_id,
                        policy_name=policy_name,
                        approval_id=approval_id,
                        decided_by=getattr(approval, "decided_by", ""),
                        arguments=arguments,
                        latency_ms=(time.monotonic() - _t0) * 1000,
                    )

    # 4. Legacy policy engine check
    policy_findings = _run_policy_engine(policy_engine, tool_name, arguments)
    if policy_findings and any(f.action == "block" for f in policy_findings):
        _signal_escalation(escalation_fn, "block", session_id, {"tool": tool_name})
        return _block("Request blocked by policy: %s" % policy_findings[0].type)

    # 5. DLP argument scanning
    findings = scanner.scan_request(msg)
    if findings and action == "block":
        _signal_escalation(escalation_fn, "block", session_id, {"tool": tool_name})
        return _block("Request blocked by lumen-argus: sensitive data detected", sse_decision="blocked")

    # Not blocked — signal near_miss or clean, broadcast + audit
    latency = (time.monotonic() - _t0) * 1000
    if findings:
        _signal_escalation(escalation_fn, "near_miss", session_id, {"tool": tool_name})
        if not sse_decision_broadcast:
            _broadcast_mcp_event(
                sse_broadcaster,
                "mcp_tool_call",
                tool_name,
                "alerted",
                server_id=server_id,
                session_id=session_id,
                findings_count=len(findings),
            )
        _audit_mcp_tool_call(
            audit_logger,
            tool_name,
            "alerted",
            server_id=server_id,
            session_id=session_id,
            arguments=arguments,
            latency_ms=latency,
            findings_count=len(findings),
        )
    else:
        _signal_escalation(escalation_fn, "clean", session_id, {"tool": tool_name})
        if not sse_decision_broadcast:
            _broadcast_mcp_event(
                sse_broadcaster,
                "mcp_tool_call",
                tool_name,
                "allowed",
                server_id=server_id,
                session_id=session_id,
            )
        if not sse_decision_broadcast:
            # Only audit "allowed" if not already audited by approval gate
            _audit_mcp_tool_call(
                audit_logger,
                tool_name,
                "allowed",
                server_id=server_id,
                session_id=session_id,
                arguments=arguments,
                latency_ms=latency,
            )
    return None


def _handle_response(
    msg: dict[str, Any],
    pending_requests: dict[Any, Any],
    scanner: MCPScanner,
    escalation_fn: Any,
    session_id: str = "",
) -> bool:
    """Process an MCP response: confused deputy check, response scan, tools/list handling.

    Returns True if the response should be forwarded, False if it should be dropped.

    All 4 transport modes call this for response messages.
    """
    msg_id = msg.get("id")

    # Confused deputy check
    if scanner.request_tracker and "result" in msg:
        if not scanner.request_tracker.validate(msg_id):
            if scanner.request_tracker.should_block:
                return False  # drop unsolicited response

    if "result" in msg:
        req_method = pending_requests.pop(msg_id, "")
        if req_method == "tools/call":
            findings = scanner.scan_response(msg, req_method)
            if findings:
                log.debug("mcp response findings: %d", len(findings))
        elif req_method == "tools/list":
            tools = msg.get("result", {}).get("tools", [])
            if isinstance(tools, list):
                log.debug("mcp: tools/list response: %d tools", len(tools))
                tl_findings = scanner.process_tools_list(tools)
                for f in tl_findings:
                    if f.type == "tool_drift":
                        _signal_escalation(escalation_fn, "drift", session_id, {"tool": f.location.rsplit(".", 1)[-1]})

    return True  # forward


def _track_outbound(msg: dict[str, Any], pending_requests: dict[Any, Any], scanner: MCPScanner) -> None:
    """Track an outbound request for confused deputy protection and method correlation."""
    method = msg.get("method", "")
    msg_id = msg.get("id")
    if msg_id is not None and method:
        pending_requests[msg_id] = method
    if scanner.request_tracker:
        scanner.request_tracker.track(msg_id)
