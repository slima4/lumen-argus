"""Community dashboard HTTP server on configurable port (default 8081).

Async aiohttp server sharing the proxy's event loop. Serves the REST API
and a single-page app dashboard. Supports optional password authentication
with sessions and CSRF protection.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, quote, unquote_plus, urlparse

from aiohttp import web

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore
    from lumen_argus.config import Config
    from lumen_argus.dashboard.sse import SSEBroadcaster
    from lumen_argus.extensions import ExtensionRegistry

from lumen_argus.dashboard.api import handle_community_api

log = logging.getLogger("argus.dashboard")

# Session timeout (8 hours)
_SESSION_TIMEOUT = 8 * 60 * 60

# Max request body for API calls (2 MB)
_MAX_API_BODY = 2 * 1024 * 1024

_LOGIN_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>lumen-argus - login</title>
<style>
:root{--bg:#0a0d12;--surface:#111621;--border:#1e2a3a;--accent:#00d4aa;
  --text:#e2e8f0;--muted:#6b7a8d;--err:#ff5f56;
  --font:'SF Mono','Cascadia Code','JetBrains Mono',monospace}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--font);background:var(--bg);color:var(--text);
  min-height:100vh;display:flex;align-items:center;justify-content:center}
.login{background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:40px;width:100%;max-width:380px}
.login h1{font-size:1.1rem;margin-bottom:6px}
.login h1 span{color:var(--accent);font-weight:400}
.login p{font-size:.78rem;color:var(--muted);margin-bottom:24px}
.login input{width:100%;font-family:var(--font);font-size:.85rem;padding:10px 14px;
  background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);
  outline:none;margin-bottom:16px}
.login input:focus{border-color:var(--accent)}
.login button{width:100%;font-family:var(--font);font-size:.82rem;padding:10px;
  background:var(--accent);color:var(--bg);border:none;border-radius:6px;cursor:pointer;
  font-weight:600;transition:opacity .15s}
.login button:hover{opacity:.9}
.error{color:var(--err);font-size:.78rem;margin-bottom:12px;display:none}
</style>
</head>
<body>
<div class="login">
<h1>lumen<span>-argus</span></h1>
<p>Enter password to access the dashboard</p>
<div class="error" id="err">Invalid password</div>
<form method="POST" action="/login">
<input type="hidden" name="next" id="next-field" value="/">
<input type="password" name="password" placeholder="Password" autofocus>
<button type="submit">Sign in</button>
</form>
</div>
<script>
if(location.search.indexOf('error=1')!==-1)document.getElementById('err').style.display='block';
var params=new URLSearchParams(location.search);
var nextVal=params.get('next');
if(nextVal)document.getElementById('next-field').value=nextVal;
</script>
</body>
</html>
"""

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'unsafe-inline'; "
        "style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
    ),
}


def _parse_cookies(request: web.Request) -> SimpleCookie:
    """Parse cookies from request, silently handling malformed headers."""
    cookie: SimpleCookie = SimpleCookie()
    cookie_header = request.headers.get("Cookie", "")
    try:
        cookie.load(cookie_header)
    except Exception:
        log.debug("malformed cookie header")
    return cookie


def _validate_next_url(url: str) -> str:
    """Validate and sanitize the next URL for login redirects."""
    if (
        not url.startswith("/")
        or url.startswith("//")
        or (len(url) > 1 and url[1] in "/\\")
        or "\r" in url
        or "\n" in url
    ):
        return "/"
    return url


def _nosniff_response(status: int, body: bytes, content_type: str = "application/json") -> web.Response:
    """Create a response with X-Content-Type-Options: nosniff."""
    return web.Response(
        status=status,
        body=body,
        content_type=content_type,
        headers={"X-Content-Type-Options": "nosniff"},
    )


def _json_error(status: int, error: str) -> web.Response:
    """Create a JSON error response with nosniff header."""
    body = json.dumps({"error": error}).encode("utf-8")
    return _nosniff_response(status, body)


# ---------------------------------------------------------------------------
# CSV helpers (static, no state)
# ---------------------------------------------------------------------------


def _findings_to_csv(findings: list[dict[str, Any]]) -> bytes:
    cols = [
        "id",
        "timestamp",
        "detector",
        "finding_type",
        "severity",
        "location",
        "action_taken",
        "provider",
        "model",
    ]
    lines: list[str] = [",".join(cols)]
    for f in findings:
        row: list[str] = []
        for c in cols:
            val = str(f.get(c, ""))
            if "," in val or '"' in val or "\n" in val:
                val = '"' + val.replace('"', '""') + '"'
            row.append(val)
        lines.append(",".join(row))
    return "\n".join(lines).encode("utf-8")


def _audit_to_csv(entries: list[dict[str, Any]]) -> bytes:
    cols = [
        "timestamp",
        "request_id",
        "provider",
        "model",
        "endpoint",
        "action",
        "finding_count",
        "scan_duration_ms",
        "request_size_bytes",
    ]
    lines = [",".join(cols)]
    for e in entries:
        row = []
        for c in cols:
            val = str(e.get(c, ""))
            if "," in val or '"' in val or "\n" in val:
                val = '"' + val.replace('"', '""') + '"'
            row.append(val)
        lines.append(",".join(row))
    return "\n".join(lines).encode("utf-8")


# ---------------------------------------------------------------------------
# AsyncDashboardServer
# ---------------------------------------------------------------------------


class AsyncDashboardServer:
    """Async dashboard server running in the same event loop as the proxy."""

    def __init__(
        self,
        bind: str,
        port: int,
        analytics_store: AnalyticsStore | None,
        extensions: ExtensionRegistry | None,
        password: str = "",
        audit_reader: Any = None,
        sse_broadcaster: SSEBroadcaster | None = None,
        config: Config | None = None,
    ) -> None:
        if bind not in ("127.0.0.1", "localhost"):
            log.warning("binding to %s — dashboard is accessible on the network", bind)
        self.bind = bind
        self.port = port
        self.analytics_store = analytics_store
        self.extensions = extensions
        self.password = password or os.environ.get("LUMEN_ARGUS_DASHBOARD_PASSWORD", "")
        self.audit_reader = audit_reader
        self.sse_broadcaster = sse_broadcaster
        self.config = config
        self._sessions: dict[str, float] = {}
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None

    # --- Session management (single event loop, no lock needed) ---

    def create_session(self) -> str:
        session_id = secrets.token_hex(32)
        now = time.monotonic()
        expired = [k for k, t in self._sessions.items() if now - t > _SESSION_TIMEOUT]
        for k in expired:
            del self._sessions[k]
        self._sessions[session_id] = now
        return session_id

    def validate_session(self, session_id: str) -> bool:
        created = self._sessions.get(session_id)
        if created is None:
            return False
        if time.monotonic() - created > _SESSION_TIMEOUT:
            del self._sessions[session_id]
            return False
        return True

    def invalidate_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    # --- Lifecycle ---

    async def start(self) -> None:
        """Create and start the aiohttp application."""
        app = self._create_app()
        self._runner = web.AppRunner(app)
        await self._runner.setup()

        for attempt in range(2):
            try:
                self._site = web.TCPSite(self._runner, self.bind, self.port)
                await self._site.start()
                if self.password:
                    log.info("dashboard started on http://%s:%d (password protected)", self.bind, self.port)
                else:
                    log.info("dashboard started on http://%s:%d", self.bind, self.port)
                return
            except OSError:
                if attempt == 0:
                    log.info("dashboard port %d in use, retrying in 2s", self.port)
                    await asyncio.sleep(2)
                else:
                    log.warning(
                        "dashboard unavailable — failed to bind to %s:%d",
                        self.bind,
                        self.port,
                    )
                    raise

    async def stop(self) -> None:
        """Shut down the server and clean up."""
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
            self._site = None

    # --- App factory ---

    def _create_app(self) -> web.Application:
        app = web.Application(
            middlewares=[self._nosniff_middleware, self._auth_middleware, self._csrf_middleware],
            client_max_size=_MAX_API_BODY,
        )

        # Routes — order matters: specific paths before catch-all
        app.router.add_get("/api/v1/live", self._handle_live_stream)
        app.router.add_get("/api/v1/findings/export", self._handle_findings_export)
        app.router.add_get("/api/v1/audit/export", self._handle_audit_export)
        app.router.add_get("/api/v1/logs/download", self._handle_logs_download)
        app.router.add_get("/login", self._serve_login)
        app.router.add_post("/login", self._handle_login)
        app.router.add_get("/logout", self._handle_logout)
        app.router.add_route("*", "/api/{tail:.*}", self._handle_api)
        app.router.add_get("/{tail:.*}", self._serve_dashboard)

        return app

    # --- Middleware ---

    @web.middleware
    async def _nosniff_middleware(
        self,
        request: web.Request,
        handler: Any,
    ) -> web.StreamResponse:
        resp: web.StreamResponse = await handler(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        return resp

    @web.middleware
    async def _auth_middleware(
        self,
        request: web.Request,
        handler: Any,
    ) -> web.StreamResponse:
        path = request.path

        # Public paths
        if path in ("/login", "/logout"):
            resp: web.StreamResponse = await handler(request)
            return resp

        # No password = open access
        if not self.password:
            request["user"] = "dashboard"
            resp = await handler(request)
            return resp

        # Check session cookie
        cookie = _parse_cookies(request)
        session_morsel = cookie.get("argus_session")
        if session_morsel and self.validate_session(session_morsel.value):
            request["user"] = "dashboard:admin"
            resp = await handler(request)
            return resp

        # Try extension auth providers
        if self.extensions:
            for provider in self.extensions.get_auth_providers():
                try:
                    user_info = await provider.authenticate(dict(request.headers))
                    if user_info:
                        user_id = user_info.get("user_id", "unknown") if isinstance(user_info, dict) else "unknown"
                        request["user"] = "dashboard:%s" % user_id
                        resp = await handler(request)
                        return resp
                except Exception:
                    log.warning("auth provider %s failed", type(provider).__name__, exc_info=True)

        # API requests → 401 JSON
        if path.startswith("/api/") and "/export" not in path:
            return _json_error(401, "authentication_required")

        # Page requests → redirect to login
        raise web.HTTPFound("/login?next=%s" % quote(path))

    @web.middleware
    async def _csrf_middleware(
        self,
        request: web.Request,
        handler: Any,
    ) -> web.StreamResponse:
        # Only enforce on mutation methods when password auth is active
        if request.method in ("GET", "HEAD") or not self.password:
            resp: web.StreamResponse = await handler(request)
            return resp

        # Login form POST is exempted (no session yet)
        if request.path == "/login":
            resp = await handler(request)
            return resp

        cookie = _parse_cookies(request)
        cookie_token = cookie.get("csrf_token")
        header_token = request.headers.get("X-CSRF-Token", "")

        if not cookie_token or not header_token:
            return _json_error(403, "csrf_validation_failed")

        if not secrets.compare_digest(cookie_token.value, header_token):
            return _json_error(403, "csrf_validation_failed")

        resp = await handler(request)
        return resp

    # --- Handlers ---

    async def _serve_login(self, request: web.Request) -> web.Response:
        query = urlparse(request.path_qs).query
        params = parse_qs(query)
        next_url = _validate_next_url(params.get("next", ["/"])[0])
        html = _LOGIN_HTML.replace(
            'value="/"',
            'value="%s"' % quote(next_url, safe="/"),
        )
        return web.Response(
            text=html,
            content_type="text/html",
            charset="utf-8",
            headers={"X-Content-Type-Options": "nosniff"},
        )

    async def _handle_login(self, request: web.Request) -> web.Response:
        body = await request.text()
        body = body[:4096]

        password = ""
        next_url = "/"
        for pair in body.split("&"):
            if pair.startswith("password="):
                password = unquote_plus(pair[9:])
            elif pair.startswith("next="):
                next_url = unquote_plus(pair[5:])

        next_url = _validate_next_url(next_url)

        if secrets.compare_digest(password, self.password):
            session_id = self.create_session()
            csrf_token = secrets.token_hex(32)
            response = web.HTTPFound(quote(next_url, safe="/"))
            response.set_cookie(
                "argus_session",
                session_id,
                httponly=True,
                samesite="Strict",
                path="/",
            )
            response.set_cookie(
                "csrf_token",
                csrf_token,
                samesite="Strict",
                path="/",
            )
            raise response

        fail_url = "/login?error=1"
        if next_url and next_url != "/":
            fail_url += "&next=%s" % quote(next_url)
        raise web.HTTPFound(fail_url)

    async def _handle_logout(self, request: web.Request) -> web.Response:
        cookie = _parse_cookies(request)
        session_morsel = cookie.get("argus_session")
        if session_morsel:
            self.invalidate_session(session_morsel.value)

        response = web.HTTPFound("/login")
        response.del_cookie("argus_session", path="/")
        response.del_cookie("csrf_token", path="/")
        raise response

    async def _handle_api(self, request: web.Request) -> web.Response:
        method = request.method
        body = await request.read()
        path = request.path_qs
        store = self.analytics_store
        audit_reader = self.audit_reader

        # Try plugin API handler first
        pro_handler = self.extensions.get_dashboard_api_handler() if self.extensions else None
        if pro_handler:
            try:
                result = await pro_handler(path, method, body, store, audit_reader)
                if result is not None:
                    if len(result) == 3:
                        status, content_type, response_body = result
                    else:
                        status, response_body = result
                        content_type = "application/json"
                    return _nosniff_response(status, response_body, content_type)
            except Exception:
                log.warning("plugin API handler failed for %s %s", method, path, exc_info=True)

        # Resolve request user for audit trail
        request_user = request.get("user", "dashboard")

        # Fall through to community handler (sync, runs in thread pool)
        status, response_body = await asyncio.to_thread(
            handle_community_api,
            path,
            method,
            body,
            store,
            audit_reader=audit_reader,
            config=self.config,
            extensions=self.extensions,
            request_user=request_user,
        )
        return _nosniff_response(status, response_body)

    async def _handle_live_stream(self, request: web.Request) -> web.StreamResponse:
        """GET /api/v1/live — SSE endpoint for real-time findings."""
        broadcaster = self.sse_broadcaster
        if broadcaster is None:
            return _json_error(503, "live stream not available")

        response = web.StreamResponse(
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
                "X-Content-Type-Options": "nosniff",
            },
        )
        await response.prepare(request)
        await response.write(b"event: connected\ndata: {}\n\n")

        queue = broadcaster.subscribe()
        try:
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=5)
                    await response.write(payload.encode("utf-8"))
                except asyncio.TimeoutError:
                    await response.write(b": keepalive\n\n")
        except (ConnectionResetError, ConnectionAbortedError, asyncio.CancelledError):
            log.debug("SSE client disconnected")
        finally:
            broadcaster.unsubscribe(queue)

        return response

    async def _handle_findings_export(self, request: web.Request) -> web.Response:
        return await self._handle_export(request, "findings")

    async def _handle_audit_export(self, request: web.Request) -> web.Response:
        return await self._handle_export(request, "audit")

    async def _handle_export(self, request: web.Request, export_type: str) -> web.Response:
        """Handle findings or audit CSV/JSON export."""
        params = dict(request.query.items())
        fmt = params.get("format", "csv")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        if export_type == "findings":
            store = self.analytics_store
            if not store:
                return _json_error(404, "store not available")

            severity = params.get("severity", "") or None
            detector = params.get("detector", "") or None
            provider = params.get("provider", "") or None
            findings, _ = await asyncio.to_thread(
                store.get_findings_page,
                limit=10000,
                offset=0,
                severity=severity,
                detector=detector,
                provider=provider,
            )

            if fmt == "json":
                body = json.dumps(findings, indent=2).encode("utf-8")
                return self._download_response(body, "application/json", "findings-%s.json" % now)
            body = _findings_to_csv(findings)
            return self._download_response(body, "text/csv; charset=utf-8", "findings-%s.csv" % now)

        # audit export
        audit_reader = self.audit_reader
        if not audit_reader:
            return _json_error(404, "audit reader not available")

        action = params.get("action", "") or None
        provider = params.get("provider", "") or None
        search = params.get("search", "") or None
        entries, _ = await asyncio.to_thread(
            audit_reader.read_entries,
            limit=10000,
            offset=0,
            action=action,
            provider=provider,
            search=search,
        )

        if fmt == "json":
            body = json.dumps(entries, indent=2).encode("utf-8")
            return self._download_response(body, "application/json", "audit-%s.json" % now)
        body = _audit_to_csv(entries)
        return self._download_response(body, "text/csv; charset=utf-8", "audit-%s.csv" % now)

    async def _handle_logs_download(self, request: web.Request) -> web.Response:
        """Download the application log file."""
        config = self.config
        if not config:
            return _json_error(404, "config not available")

        log_dir = os.path.expanduser(config.logging_config.log_dir)
        log_file = os.path.join(log_dir, "lumen-argus.log")

        def _read_log() -> str | None:
            if not os.path.exists(log_file):
                return None
            from lumen_argus.log_utils import sanitize_log_line

            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                return "".join(sanitize_log_line(line) for line in f)

        content = await asyncio.to_thread(_read_log)
        if content is None:
            return _json_error(404, "log file not found")

        body = content.encode("utf-8")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return self._download_response(body, "text/plain; charset=utf-8", "lumen-argus-logs-%s.txt" % now)

    async def _serve_dashboard(self, request: web.Request) -> web.Response:
        """Serve the SPA dashboard HTML with plugin injections."""
        from lumen_argus.dashboard.html import COMMUNITY_DASHBOARD_HTML

        html = COMMUNITY_DASHBOARD_HTML

        # Inject plugin CSS before </style>
        extra_css = self.extensions.get_dashboard_css() if self.extensions else []
        if extra_css:
            css_block = "\n".join(extra_css)
            html = html.replace("</style>", css_block + "\n</style>")

        # Inject plugin page JS before </body>
        extra_pages = self.extensions.get_dashboard_pages() if self.extensions else []
        if extra_pages:
            js_blocks = []
            for page in extra_pages:
                parts: list[str] = []
                if page.get("html"):
                    var_name = "_pageHtml_%s" % page["name"]
                    parts.append("<script>var %s=%s;</script>" % (var_name, json.dumps(page["html"])))
                parts.append("<script>\n%s\n</script>" % page["js"])
                js_blocks.append("\n".join(parts))
            html = html.replace("</body>", "\n".join(js_blocks) + "\n</body>")

        return web.Response(
            text=html,
            content_type="text/html",
            charset="utf-8",
            headers=_SECURITY_HEADERS,
        )

    # --- Helpers ---

    @staticmethod
    def _download_response(body: bytes, content_type: str, filename: str) -> web.Response:
        return web.Response(
            body=body,
            content_type=content_type,
            headers={
                "Content-Disposition": 'attachment; filename="%s"' % filename,
                "X-Content-Type-Options": "nosniff",
            },
        )
