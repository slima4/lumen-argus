from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import TYPE_CHECKING, Any

from aiohttp import web

from lumen_argus.actions import build_block_response, should_forward, try_strip_blocked_history
from lumen_argus.async_proxy._audit import _log_audit
from lumen_argus.models import Finding, ScanResult, SessionContext

if TYPE_CHECKING:
    from lumen_argus.async_proxy._server import AsyncArgusProxy

log = logging.getLogger("argus.proxy")


async def scan_request_body(
    server: "AsyncArgusProxy",
    request_id: int,
    body: bytes,
    provider: str,
    model: str,
    session: SessionContext,
    span: Any = None,
) -> ScanResult:
    if server.mode == "passthrough":
        log.debug("#%d passthrough mode — scanning skipped", request_id)
        return ScanResult(action="pass", findings=[])

    if body and len(body) <= server.max_body_size:
        try:
            scan_result = await asyncio.to_thread(
                server.pipeline.scan,
                body,
                provider,
                model=model,
                session=session,
            )
            log.debug(
                "#%d scan: %d findings, action=%s, %.1fms",
                request_id,
                len(scan_result.findings),
                scan_result.action,
                scan_result.scan_duration_ms,
            )
            if span and hasattr(span, "set_attribute"):
                span.set_attribute("findings.count", len(scan_result.findings))
                span.set_attribute("action", scan_result.action)
                span.set_attribute("scan.duration_ms", scan_result.scan_duration_ms)
            if scan_result.action in ("block", "redact") and scan_result.findings:
                types = ", ".join(f.type for f in scan_result.findings)
                log.info(
                    "#%d %s %s (%d findings)",
                    request_id,
                    scan_result.action.upper(),
                    types,
                    len(scan_result.findings),
                )
            return scan_result
        except Exception:
            log.error("#%d scan failed — forwarding request (fail-open)", request_id, exc_info=True)
            return ScanResult(
                action="pass",
                findings=[
                    Finding(
                        detector="proxy",
                        type="scan_error",
                        severity="critical",
                        location="pipeline",
                        value_preview="scan failed — request forwarded unscanned",
                        matched_value="",
                        action="log",
                    )
                ],
            )
    elif len(body) > server.max_body_size:
        log.warning(
            "#%d oversized body skipped scanning (%d bytes > %d limit)",
            request_id,
            len(body),
            server.max_body_size,
        )
        server.display.show_error(
            request_id,
            "body too large to scan (%d bytes > %d limit)" % (len(body), server.max_body_size),
        )
        return ScanResult(
            action="pass",
            findings=[
                Finding(
                    detector="proxy",
                    type="scan_skipped_oversized",
                    severity="warning",
                    location="request_body",
                    value_preview="%d bytes" % len(body),
                    matched_value="",
                    action="log",
                )
            ],
        )

    return ScanResult()


def scan_mcp_request(
    server: "AsyncArgusProxy",
    request_id: int,
    body: bytes,
    scan_result: ScanResult,
    session: SessionContext,
    provider: str,
    model: str,
    method: str,
    path: str,
    t0: float,
) -> tuple[ScanResult, dict[str, Any] | None, str | None, web.Response | None]:
    _mcp_info = None
    _mcp_method = None

    if not (body and server.mcp_scanner and server.mode != "passthrough"):
        return scan_result, _mcp_info, _mcp_method, None

    from lumen_argus.mcp.scanner import detect_mcp_method, detect_mcp_request

    try:
        _mcp_method = detect_mcp_method(body)
        _mcp_info = detect_mcp_request(body) if _mcp_method == "tools/call" else None
    except Exception:
        log.error("#%d MCP detection failed (fail-open)", request_id, exc_info=True)

    if not _mcp_info:
        return scan_result, _mcp_info, _mcp_method, None

    tool_name = _mcp_info["tool_name"]
    log.debug("#%d MCP tools/call detected: %s", request_id, tool_name)

    # Track tool usage
    if server.extensions:
        store = server.extensions.get_analytics_store()
        if store:
            try:
                store.record_mcp_tool_seen(tool_name)
            except Exception:
                log.debug("failed to record MCP tool '%s'", tool_name, exc_info=True)

    # Check tool allow/block lists
    if not server.mcp_scanner.is_tool_allowed(tool_name):
        log.info("#%d MCP tool '%s' blocked by policy", request_id, tool_name)
        blocked_finding = Finding(
            detector="mcp",
            type="blocked_tool",
            severity="high",
            location="mcp.tools/call.%s" % tool_name,
            value_preview=tool_name,
            matched_value=tool_name,
            action="block",
        )
        block_result = ScanResult(
            action="block",
            findings=[blocked_finding],
            scan_duration_ms=scan_result.scan_duration_ms,
        )
        block_body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": _mcp_info["request_id"],
                "error": {
                    "code": -32600,
                    "message": "Tool blocked by lumen-argus: %s" % tool_name,
                },
            }
        ).encode()
        server.display.show_request(
            request_id,
            method,
            path,
            model,
            len(body),
            len(block_body),
            (time.monotonic() - t0) * 1000,
            block_result,
        )
        _log_audit(server, request_id, path, provider, model, block_result, len(body), False, session)
        server.stats.record(provider, len(body), block_result)
        # Log tool call (blocked)
        if server.extensions:
            _s = server.extensions.get_analytics_store()
            if _s:
                try:
                    _s.record_mcp_tool_call(
                        tool_name,
                        session.session_id if session else "",
                        status="blocked",
                        finding_count=1,
                        source="proxy",
                    )
                except Exception:
                    log.debug("failed to record blocked MCP tool call '%s'", tool_name, exc_info=True)
        return (
            scan_result,
            _mcp_info,
            _mcp_method,
            web.Response(body=block_body, status=400, content_type="application/json"),
        )

    # Scan tool arguments
    try:
        mcp_findings = server.mcp_scanner.scan_arguments(tool_name, _mcp_info["arguments"])
    except Exception:
        log.error("#%d MCP argument scan failed (fail-open)", request_id, exc_info=True)
        mcp_findings = []
    if mcp_findings:
        scan_result.findings.extend(mcp_findings)
        log.info("#%d MCP argument scan: %d finding(s) in '%s'", request_id, len(mcp_findings), tool_name)

    # Record MCP argument findings to analytics store
    # (pipeline.scan() already called record_findings() before MCP scanning,
    # so MCP findings need their own explicit write)
    if mcp_findings and server.extensions:
        _s = server.extensions.get_analytics_store()
        if _s:
            try:
                _s.record_findings(
                    findings=mcp_findings,
                    provider=provider,
                    model=model,
                    session=session,
                )
            except Exception:
                log.warning("failed to record MCP argument findings", exc_info=True)

    # Log tool call (allowed/alert)
    if server.extensions:
        _s = server.extensions.get_analytics_store()
        if _s:
            try:
                _s.record_mcp_tool_call(
                    tool_name,
                    session.session_id if session else "",
                    status="alert" if mcp_findings else "allowed",
                    finding_count=len(mcp_findings) if mcp_findings else 0,
                    source="proxy",
                )
            except Exception:
                log.debug("failed to record MCP tool call '%s'", tool_name, exc_info=True)

    return scan_result, _mcp_info, _mcp_method, None


def evaluate_block_policy(
    server: "AsyncArgusProxy",
    request_id: int,
    scan_result: ScanResult,
    req_data: dict[str, Any] | None,
    body: bytes,
    method: str,
    path: str,
    provider: str,
    model: str,
    is_streaming: bool,
    t0: float,
    session: SessionContext,
) -> tuple[ScanResult, bytes, web.Response | None]:
    if not should_forward(scan_result):
        stripped_body = (
            try_strip_blocked_history(req_data, scan_result.findings) if isinstance(req_data, dict) else None
        )
        if stripped_body is not None:
            types = ", ".join(f.type for f in scan_result.findings)
            log.info(
                "#%d stripping %d blocked message(s) from history (%d→%d bytes): %s",
                request_id,
                len(scan_result.findings),
                len(body),
                len(stripped_body),
                types,
            )
            _log_audit(
                server,
                request_id,
                path,
                provider,
                model,
                ScanResult(
                    action="strip", findings=scan_result.findings, scan_duration_ms=scan_result.scan_duration_ms
                ),
                len(body),
                True,
                session,
            )
            server.pipeline.commit_pending(scan_result)
            body = stripped_body
            scan_result = ScanResult(action="pass", findings=[], scan_duration_ms=scan_result.scan_duration_ms)
        else:
            types = ", ".join(f.type for f in scan_result.findings)
            block_body = build_block_response(scan_result)
            log.info(
                "#%d blocking request (400, streaming=%s, %d bytes): %s",
                request_id,
                is_streaming,
                len(block_body),
                types,
            )
            server.display.show_request(
                request_id,
                method,
                path,
                model,
                len(body),
                len(block_body),
                (time.monotonic() - t0) * 1000,
                scan_result,
            )
            _log_audit(server, request_id, path, provider, model, scan_result, len(body), False, session)
            server.stats.record(provider, len(body), scan_result)
            return scan_result, body, web.Response(body=block_body, status=400, content_type="application/json")

    # Apply redaction if action is "redact" and a hook is registered
    if scan_result.action == "redact":
        if server.redact_hook is not None:
            try:
                original_len = len(body)
                body = server.redact_hook(body, scan_result.findings)
                types = ", ".join(f.type for f in scan_result.findings)
                log.info(
                    "#%d REDACT %d finding(s) (%s), body %d→%d bytes",
                    request_id,
                    len(scan_result.findings),
                    types,
                    original_len,
                    len(body),
                )
            except Exception as e:
                log.error("#%d redaction hook failed, forwarding unmodified: %s", request_id, e)
        else:
            log.warning(
                "#%d redact action but no redact hook registered — forwarding unmodified (Pro redaction not loaded?)",
                request_id,
            )

    return scan_result, body, None
