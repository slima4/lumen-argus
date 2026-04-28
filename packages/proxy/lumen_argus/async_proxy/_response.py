from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import TYPE_CHECKING, Any

from aiohttp import web

from lumen_argus._logging import log_hook_fail_open
from lumen_argus.actions import build_block_response
from lumen_argus.async_proxy._audit import _log_audit
from lumen_argus.models import ScanResult, SessionContext

if TYPE_CHECKING:
    import aiohttp as aiohttp_mod

    from lumen_argus.async_proxy._server import AsyncArgusProxy

log = logging.getLogger("argus.proxy")


async def handle_response_scan_hook(
    server: "AsyncArgusProxy",
    request_id: int,
    upstream_resp: "aiohttp_mod.ClientResponse",
    resp_headers: dict[str, str],
    body: bytes,
    method: str,
    path: str,
    provider: str,
    model: str,
    t0: float,
    scan_result: ScanResult,
    session: SessionContext,
    response_hook: Any,
) -> tuple[web.StreamResponse | None, int, str]:
    data = await upstream_resp.read()
    resp_text = data.decode("utf-8", errors="ignore")
    try:
        hook_action, hook_findings = response_hook(resp_text, provider, model, session)
        if hook_action == "block" and hook_findings:
            log.info(
                "#%d response blocked by scan hook: %d finding(s)",
                request_id,
                len(hook_findings),
            )
            hook_result = ScanResult(action="block", findings=hook_findings)
            block_body_bytes = build_block_response(hook_result)
            resp_size = len(block_body_bytes)
            server.display.show_request(
                request_id,
                method,
                path,
                model,
                len(body),
                resp_size,
                (time.monotonic() - t0) * 1000,
                hook_result,
            )
            _log_audit(server, request_id, path, provider, model, hook_result, len(body), False, session)
            server.stats.record(provider, len(body), hook_result)
            return (
                web.Response(
                    body=block_body_bytes,
                    status=400,
                    content_type="application/json",
                ),
                resp_size,
                "",
            )
    except Exception as e:
        log.warning("#%d response scan hook failed: %s", request_id, e)
    # Hook passed — forward the response normally
    resp_size = len(data)
    resp_text_out = ""  # hook handled — skip async scan
    response: web.StreamResponse = web.Response(
        body=data,
        status=upstream_resp.status,
        headers=resp_headers,
    )
    return response, resp_size, resp_text_out


async def stream_sse_response(
    request: web.Request,
    upstream_resp: "aiohttp_mod.ClientResponse",
    resp_headers: dict[str, str],
    request_id: int,
    should_accumulate: bool,
    session: SessionContext,
    chunk_hook: Any = None,
) -> tuple[web.StreamResponse, int, str]:
    response = web.StreamResponse(
        status=upstream_resp.status,
        headers=resp_headers,
    )
    await response.prepare(request)

    text_parts = []
    resp_size = 0
    try:
        async for chunk in upstream_resp.content.iter_any():
            if not chunk:
                continue
            if chunk_hook is not None:
                try:
                    chunk = chunk_hook(chunk, session)
                except Exception:
                    log_hook_fail_open("response chunk hook", request_id=request_id)
            try:
                await response.write(chunk)
            except (ConnectionResetError, ConnectionAbortedError):
                break
            resp_size += len(chunk)
            if should_accumulate:
                text_parts.append(chunk)
    except asyncio.TimeoutError:
        # Socket idle past sock_read. Headers already flushed, so we can't
        # emit a fresh 504 JSON body — close the SSE stream cleanly instead.
        log.error("#%d upstream SSE idle timeout after %d bytes", request_id, resp_size)

    resp_text = ""
    if should_accumulate and text_parts:
        resp_text = b"".join(text_parts).decode("utf-8", errors="ignore")

    try:
        await response.write_eof()
    except (ConnectionResetError, BrokenPipeError, OSError):
        log.debug("#%d client disconnected during write_eof", request_id)

    return response, resp_size, resp_text


async def handle_buffered_response(
    upstream_resp: "aiohttp_mod.ClientResponse",
    resp_headers: dict[str, str],
    should_accumulate: bool,
) -> tuple[web.StreamResponse, int, str]:
    data = await upstream_resp.read()
    resp_size = len(data)
    resp_text = ""
    if should_accumulate:
        resp_text = data.decode("utf-8", errors="ignore")

    response = web.Response(
        body=data,
        status=upstream_resp.status,
        headers=resp_headers,
    )
    return response, resp_size, resp_text


def fire_async_response_scan(
    server: "AsyncArgusProxy",
    request_id: int,
    text: str,
    provider: str,
    model: str,
    session: SessionContext | None = None,
) -> None:
    """Run response scanning in a background task (async mode)."""

    async def _scan() -> None:
        try:
            findings = await asyncio.to_thread(server.response_scanner.scan, text, provider, model)
            if not findings:
                return
            log.info("#%d response scan: %d finding(s)", request_id, len(findings))
            # DB write in thread pool — don't block event loop with SQLite I/O
            if server.extensions:
                store = server.extensions.get_analytics_store()
                if store:
                    await asyncio.to_thread(
                        store.record_findings,
                        findings,
                        provider=provider,
                        model=model,
                        session=session,
                    )
            # Post-scan hook in thread pool — may do CPU work (notifications)
            post_scan = server.extensions.get_post_scan_hook() if server.extensions else None
            if post_scan:
                resp_result = ScanResult(findings=findings, action="alert")
                try:
                    await asyncio.to_thread(
                        post_scan,
                        result=resp_result,
                        body=b"",
                        provider=provider,
                        session=session,
                        model=model,
                    )
                except Exception:
                    log.warning("#%d post-scan hook failed for response", request_id, exc_info=True)
        except Exception as e:
            log.warning("#%d response scan failed: %s", request_id, e)

    task = asyncio.ensure_future(_scan())
    # Store reference in set to prevent GC of pending tasks
    server._background_tasks.add(task)
    task.add_done_callback(server._background_tasks.discard)


def scan_mcp_response(
    server: "AsyncArgusProxy",
    request_id: int,
    resp_text: str,
    mcp_info: dict[str, Any] | None,
    mcp_method: str | None,
    provider: str,
    model: str,
    session: SessionContext,
) -> None:
    # MCP response scanning
    if mcp_info and server.mcp_scanner and resp_text:
        from lumen_argus.mcp.scanner import detect_mcp_response

        mcp_resp = detect_mcp_response(resp_text.encode("utf-8", errors="ignore"))
        if mcp_resp and mcp_resp.get("content"):
            mcp_resp_findings = server.mcp_scanner.scan_response_content(mcp_resp["content"])
            if mcp_resp_findings:
                log.info("#%d MCP response scan: %d finding(s)", request_id, len(mcp_resp_findings))
                if server.extensions:
                    _store = server.extensions.get_analytics_store()
                    if _store:
                        try:
                            _store.record_findings(
                                findings=mcp_resp_findings,
                                provider=provider,
                                model=model,
                                session=session,
                            )
                        except Exception:
                            log.warning("failed to record MCP response findings", exc_info=True)

    # MCP tools/list response — capture tool descriptions
    if mcp_method == "tools/list" and server.mcp_scanner and resp_text:
        from lumen_argus.mcp.scanner import detect_mcp_tools_list_response

        tools_meta = detect_mcp_tools_list_response(resp_text.encode("utf-8", errors="ignore"))
        if tools_meta and server.extensions:
            _store = server.extensions.get_analytics_store()
            if _store:
                for t in tools_meta:
                    try:
                        _store.record_mcp_tool_seen(
                            t["name"],
                            description=t.get("description", ""),
                            input_schema=json.dumps(t.get("inputSchema", {})),
                        )
                    except Exception:
                        log.debug("failed to record MCP tool '%s'", t.get("name"), exc_info=True)
                log.debug("#%d MCP tools/list: captured %d tool descriptions", request_id, len(tools_meta))
