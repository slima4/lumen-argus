from __future__ import annotations

import asyncio
import logging
import time

from aiohttp import web

from lumen_argus.async_proxy._server import _PROXY_KEY

log = logging.getLogger("argus.proxy")


async def _handle_health(request: web.Request) -> web.Response:
    """Respond to /health endpoint.

    Returns 200 when ready, 503 when still starting (pipeline loading).
    The relay uses the HTTP status code to decide engine health.
    """
    server = request.app[_PROXY_KEY]
    ready = server.ready
    data = {
        "status": "ready" if ready else "starting",
        "version": __import__("lumen_argus").__version__,
        "uptime": round(time.monotonic() - server.start_time, 1),
        "requests": server.stats.total_requests,
    }
    health_hook = server.extensions.get_health_hook() if server.extensions else None
    if health_hook:
        try:
            extra = await asyncio.to_thread(health_hook)
            data.update(extra)
        except Exception:
            log.debug("health hook failed", exc_info=True)
    return web.json_response(data, status=200 if ready else 503)


async def _handle_metrics(request: web.Request) -> web.Response:
    """Respond to /metrics with Prometheus exposition format."""
    server = request.app[_PROXY_KEY]
    text = server.stats.prometheus_metrics(
        active_requests=server.active_requests,
        active_ws_connections=server.active_ws_connections,
    )
    metrics_hook = server.extensions.get_metrics_hook() if server.extensions else None
    if metrics_hook:
        try:
            extra = await asyncio.to_thread(metrics_hook)
            if extra:
                text += extra
        except Exception:
            log.debug("metrics hook failed", exc_info=True)
    resp = web.Response(body=text.encode("utf-8"))
    resp.content_type = "text/plain"
    resp.headers["Content-Type"] = "text/plain; version=0.0.4; charset=utf-8"
    return resp
