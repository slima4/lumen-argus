from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
from typing import Any

import aiohttp
from aiohttp import web

from lumen_argus.async_proxy._audit import _log_audit, _request_counter
from lumen_argus.async_proxy._endpoints import _handle_health, _handle_metrics
from lumen_argus.async_proxy._request_scanning import evaluate_block_policy, scan_mcp_request, scan_request_body
from lumen_argus.async_proxy._response import (
    fire_async_response_scan,
    handle_buffered_response,
    handle_response_scan_hook,
    scan_mcp_response,
    stream_sse_response,
)
from lumen_argus.async_proxy._server import _PROXY_KEY, AsyncArgusProxy
from lumen_argus.async_proxy._ssl import _HOP_BY_HOP
from lumen_argus.async_proxy._websocket import _handle_websocket
from lumen_argus.models import ScanResult, SessionContext
from lumen_argus.session import extract_session as _extract_session

log = logging.getLogger("argus.proxy")


async def _handle_request(request: web.Request) -> web.StreamResponse:
    """Main request handler: read -> scan -> forward or block."""
    path = request.path_qs
    method = request.method

    if path == "/health":
        return await _handle_health(request)
    if path == "/metrics":
        return await _handle_metrics(request)

    # WebSocket upgrade — handle on same port
    if request.headers.get("Upgrade", "").lower() == "websocket" or path.startswith("/ws"):
        ws_server: AsyncArgusProxy = request.app[_PROXY_KEY]
        return await _handle_websocket(request, ws_server)

    request_id = next(_request_counter)
    server: AsyncArgusProxy = request.app[_PROXY_KEY]

    # OTel trace span wraps the full request lifecycle
    trace_hook = server.extensions.get_trace_request_hook() if server.extensions else None
    trace_ctx = None
    if trace_hook:
        try:
            trace_ctx = trace_hook(method, path)
        except Exception:
            trace_ctx = None

    with server._active_lock:
        server._active_requests += 1
    try:
        if trace_ctx:
            try:
                with trace_ctx as span:
                    return await _do_forward(request, request_id, server, span)
            except Exception:
                return await _do_forward(request, request_id, server, None)
        else:
            return await _do_forward(request, request_id, server, None)
    finally:
        with server._active_lock:
            server._active_requests -= 1


async def _do_forward(
    request: web.Request, request_id: int, server: "AsyncArgusProxy", span: Any = None
) -> web.StreamResponse:
    """Inner forwarding logic — separated for active request tracking."""
    # Pre-request hook
    pre_hook = server.pipeline._extensions.get_pre_request_hook() if server.pipeline._extensions else None
    if pre_hook:
        try:
            pre_hook(request_id)
        except Exception:
            log.debug("pre-request hook failed for #%d", request_id, exc_info=True)

    path = request.path_qs
    method = request.method
    t0 = time.monotonic()
    body = b""
    resp_size = 0
    resp_text = ""
    model = ""
    host = ""
    provider = "unknown"
    is_streaming = False
    session = SessionContext()
    scan_result = ScanResult()

    try:
        # Read request body
        body = await request.read()
        if not body:
            log.debug("#%d empty body — scan skipped", request_id)

        # Detect provider and determine upstream
        headers_dict = {k.lower(): v for k, v in request.headers.items()}
        host, port, use_ssl, provider = server.router.route(path, headers_dict)
        log.debug(
            "#%d %s %s -> %s:%d (ssl=%s, provider=%s, %d bytes)",
            request_id,
            method,
            path,
            host,
            port,
            use_ssl,
            provider,
            len(body),
        )
        if span and hasattr(span, "set_attribute"):
            span.set_attribute("provider", provider)
            span.set_attribute("body.size", len(body))

        # Parse body once
        req_data = None
        if body:
            try:
                req_data = json.loads(body)
                if isinstance(req_data, dict):
                    model = req_data.get("model", "")
                    is_streaming = req_data.get("stream", False)
                else:
                    is_streaming = False
            except (json.JSONDecodeError, UnicodeDecodeError):
                is_streaming = False
        else:
            is_streaming = False

        # Extract session context
        source_ip = request.remote or ""
        session = _extract_session(req_data, provider, headers_dict, source_ip, hmac_key=server.hmac_key)

        # Scan request body
        scan_result = await scan_request_body(server, request_id, body, provider, model, session, span)

        # MCP-aware scanning
        scan_result, _mcp_info, _mcp_method, mcp_block_resp = await scan_mcp_request(
            server, request_id, body, scan_result, session, provider, model, method, path, t0
        )
        if mcp_block_resp is not None:
            return mcp_block_resp

        # Check if we should block
        scan_result, body, block_resp = evaluate_block_policy(
            server, request_id, scan_result, req_data, body, method, path, provider, model, is_streaming, t0, session
        )
        if block_resp is not None:
            return block_resp

        # Build forwarding headers
        fwd_headers = {}
        for key, val in request.headers.items():
            lk = key.lower()
            if lk in _HOP_BY_HOP:
                continue
            if lk in ("host", "accept-encoding"):
                continue
            if lk == "content-length":
                fwd_headers[key] = str(len(body))
                continue
            fwd_headers[key] = val
        fwd_headers["Host"] = host

        # Build upstream URL
        scheme = "https" if use_ssl else "http"
        upstream_url = "%s://%s:%d%s" % (scheme, host, port, path)

        # Forward to upstream via aiohttp ClientSession
        if server.client_session is None:
            log.error("#%d client session not initialized", request_id)
            return web.Response(status=502, text="Proxy not ready")
        client_session = server.client_session
        response: web.StreamResponse | None = None
        try:
            async with client_session.request(
                method,
                upstream_url,
                data=body,
                headers=fwd_headers,
                timeout=aiohttp.ClientTimeout(total=server.timeout),
            ) as upstream_resp:
                # Determine response scanning strategy
                _should_scan_response = server.response_scanner is not None and server.mode != "passthrough"
                _should_accumulate = (
                    _should_scan_response
                    or (_mcp_info is not None and server.mcp_scanner is not None)
                    or (_mcp_method == "tools/list" and server.mcp_scanner is not None)
                )
                _response_hook = server.extensions.get_response_scan_hook() if server.extensions else None

                content_type = upstream_resp.headers.get("Content-Type", "")
                is_sse = is_streaming or "text/event-stream" in content_type

                # Collect response headers (filter hop-by-hop)
                resp_headers = {}
                for hdr, val in upstream_resp.headers.items():
                    lk = hdr.lower()
                    if lk in _HOP_BY_HOP:
                        continue
                    if lk == "content-length" and is_sse:
                        continue
                    resp_headers[hdr] = val

                # Buffered response scan hook (Pro) — for non-SSE only
                if _response_hook and _should_scan_response and not is_sse:
                    result = await handle_response_scan_hook(
                        server,
                        request_id,
                        upstream_resp,
                        resp_headers,
                        body,
                        method,
                        path,
                        provider,
                        model,
                        t0,
                        scan_result,
                        session,
                        _response_hook,
                    )
                    response, resp_size, resp_text = result
                    if isinstance(response, web.Response) and response.status == 400:
                        return response

                elif is_sse:
                    response, resp_size, resp_text = await stream_sse_response(
                        request,
                        upstream_resp,
                        resp_headers,
                        request_id,
                        _should_accumulate,
                    )

                else:
                    response, resp_size, resp_text = await handle_buffered_response(
                        upstream_resp,
                        resp_headers,
                        _should_accumulate,
                    )

        except asyncio.TimeoutError:
            msg = (
                "Upstream timed out after %ds. "
                "Increase proxy.timeout in ~/.lumen-argus/config.yaml "
                "or the dashboard Settings page." % server.timeout
            )
            log.error("#%d upstream timeout after %ds", request_id, server.timeout)
            server.display.show_error(request_id, msg)
            server.stats.record(provider, len(body), scan_result)
            return web.json_response(
                {"error": {"type": "timeout", "message": msg}},
                status=504,
            )
        except aiohttp.ClientConnectionError as e:
            # Connection-level error — retry if attempts remain
            if server.retries > 0:
                log.debug("#%d connection error (attempt 1/%d): %s", request_id, server.retries + 1, e)
                for _attempt in range(server.retries):
                    try:
                        async with client_session.request(
                            method,
                            upstream_url,
                            data=body,
                            headers=fwd_headers,
                            timeout=aiohttp.ClientTimeout(total=server.timeout),
                        ) as upstream_resp:
                            # On successful retry, read and return full response
                            data = await upstream_resp.read()
                            resp_size = len(data)
                            resp_headers = {
                                hdr: val for hdr, val in upstream_resp.headers.items() if hdr.lower() not in _HOP_BY_HOP
                            }
                            response = web.Response(
                                body=data,
                                status=upstream_resp.status,
                                headers=resp_headers,
                            )
                            log.debug("#%d retry %d succeeded", request_id, _attempt + 1)
                            server.display.show_request(
                                request_id,
                                method,
                                path,
                                model,
                                len(body),
                                resp_size,
                                (time.monotonic() - t0) * 1000,
                                scan_result,
                            )
                            _log_audit(server, request_id, path, provider, model, scan_result, len(body), True, session)
                            server.stats.record(provider, len(body), scan_result)
                            return response
                    except (aiohttp.ClientConnectionError, asyncio.TimeoutError) as retry_err:
                        log.debug("#%d retry %d failed: %s", request_id, _attempt + 1, retry_err)
                        continue
            log.error("#%d upstream connection error: %s", request_id, e)
            server.display.show_error(request_id, str(e))
            server.stats.record(provider, len(body), scan_result)
            return web.json_response(
                {"error": {"type": "proxy_error", "message": str(e)}},
                status=502,
            )
        except aiohttp.ClientError as e:
            log.error("#%d upstream error: %s", request_id, e)
            server.display.show_error(request_id, str(e))
            server.stats.record(provider, len(body), scan_result)
            return web.json_response(
                {"error": {"type": "proxy_error", "message": str(e)}},
                status=502,
            )
        except ssl.SSLCertVerificationError as e:
            msg = (
                "TLS verification failed for %s — %s. "
                "If behind a corporate proxy, set proxy.ca_bundle in "
                "~/.lumen-argus/config.yaml" % (host, e)
            )
            log.error("#%d %s", request_id, msg)
            server.display.show_error(request_id, msg)
            server.stats.record(provider, len(body), scan_result)
            return web.json_response(
                {"error": {"type": "tls_error", "message": msg}},
                status=502,
            )

        # Display request line
        server.display.show_request(
            request_id,
            method,
            path,
            model,
            len(body),
            resp_size,
            (time.monotonic() - t0) * 1000,
            scan_result,
        )

        # Audit log + stats
        _log_audit(server, request_id, path, provider, model, scan_result, len(body), True, session)
        server.stats.record(provider, len(body), scan_result)

        # Async response scanning — scan after forwarding (no latency impact)
        if _should_scan_response and resp_text:
            fire_async_response_scan(server, request_id, resp_text, provider, model, session)

        # MCP response scanning
        scan_mcp_response(server, request_id, resp_text, _mcp_info, _mcp_method, provider, model, session)

        assert response is not None
        return response

    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        log.debug("#%d client disconnected", request_id)
        return web.Response(status=499)
    except Exception as e:
        log.error("#%d request error: %s", request_id, e)
        server.display.show_error(request_id, str(e))
        server.stats.record(provider, len(body), scan_result)
        return web.json_response(
            {"error": {"type": "proxy_error", "message": str(e)}},
            status=502,
        )
