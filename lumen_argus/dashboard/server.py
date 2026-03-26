"""Community dashboard HTTP server on configurable port (default 8081).

Serves the REST API and a single-page app dashboard. Runs in a daemon thread
so it doesn't block the proxy. Supports optional password authentication
with sessions and CSRF protection.
"""

import http.server
import json
import logging
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from typing import Optional

from lumen_argus.dashboard.api import handle_community_api

log = logging.getLogger("argus.dashboard")

# Session timeout (8 hours)
_SESSION_TIMEOUT = 8 * 60 * 60

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


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    """Handles dashboard HTTP requests with optional authentication."""

    def log_message(self, format, *args):
        pass  # Suppress default access logging

    def do_GET(self):
        if self.path.startswith("/api/v1/live"):
            if not self._check_auth():
                return
            self._handle_live_stream()
        elif self.path.startswith("/api/v1/findings/export"):
            if not self._check_auth():
                return
            self._handle_export("findings")
        elif self.path.startswith("/api/v1/audit/export"):
            if not self._check_auth():
                return
            self._handle_export("audit")
        elif self.path.startswith("/api/v1/logs/download"):
            if not self._check_auth():
                return
            self._handle_logs_download()
        elif self.path.startswith("/api/"):
            if not self._check_auth():
                return
            self._handle_api("GET")
        elif self.path.startswith("/login"):
            self._serve_login()
        elif self.path.startswith("/logout"):
            self._handle_logout()
        else:
            if not self._check_auth():
                return
            self._serve_dashboard()

    def do_POST(self):
        if self.path.startswith("/login"):
            self._handle_login()
        elif self.path.startswith("/api/"):
            if not self._check_auth():
                return
            if not self._check_csrf():
                return
            self._handle_api("POST")
        else:
            self._send_json(405, {"error": "method_not_allowed"})

    def do_PUT(self):
        if not self._check_auth():
            return
        if not self._check_csrf():
            return
        if self.path.startswith("/api/"):
            self._handle_api("PUT")
        else:
            self._send_json(405, {"error": "method_not_allowed"})

    def do_DELETE(self):
        if not self._check_auth():
            return
        if not self._check_csrf():
            return
        if self.path.startswith("/api/"):
            self._handle_api("DELETE")
        else:
            self._send_json(405, {"error": "method_not_allowed"})

    # --- Auth ---

    def _check_auth(self) -> bool:
        """Check authentication. Returns True if authorized."""
        password = self.server.password
        if not password:
            return True

        cookie_header = self.headers.get("Cookie", "")
        cookie = SimpleCookie()
        try:
            cookie.load(cookie_header)
        except Exception:
            pass

        session_id = cookie.get("argus_session")
        if session_id and self.server.validate_session(session_id.value):
            return True

        # Try plugin auth providers
        for provider in self.server.extensions.get_auth_providers():
            try:
                user_info = provider.authenticate(dict(self.headers))
                if user_info:
                    self._user = user_info
                    return True
            except Exception:
                pass

        # API requests get 401 JSON
        if self.path.startswith("/api/") and "/export" not in self.path:
            self._send_json(401, {"error": "authentication_required"})
            return False

        # Pages redirect to login
        from urllib.parse import quote

        next_url = self.path
        self.send_response(302)
        self.send_header("Location", "/login?next=%s" % quote(next_url))
        self.end_headers()
        return False

    def _check_csrf(self) -> bool:
        """Validate CSRF double-submit cookie."""
        if not self.server.password:
            return True  # No auth = no CSRF needed

        cookie_header = self.headers.get("Cookie", "")
        cookie = SimpleCookie()
        try:
            cookie.load(cookie_header)
        except Exception:
            pass

        cookie_token = cookie.get("csrf_token")
        header_token = self.headers.get("X-CSRF-Token", "")

        if not cookie_token or not header_token:
            self._send_json(403, {"error": "csrf_validation_failed"})
            return False

        if not secrets.compare_digest(cookie_token.value, header_token):
            self._send_json(403, {"error": "csrf_validation_failed"})
            return False

        return True

    def _serve_login(self) -> None:
        from urllib.parse import parse_qs, urlparse, quote

        query = urlparse(self.path).query
        params = parse_qs(query)
        next_url = params.get("next", ["/"])[0]
        if not next_url.startswith("/") or next_url.startswith("//") or (len(next_url) > 1 and next_url[1] in "/\\"):
            next_url = "/"
        html = _LOGIN_HTML.replace(
            'value="/"',
            'value="%s"' % quote(next_url, safe="/"),
        )
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_login(self) -> None:
        content_length = min(int(self.headers.get("Content-Length", 0)), 4096)
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")

        from urllib.parse import unquote_plus

        password = ""
        next_url = "/"
        for pair in body.split("&"):
            if pair.startswith("password="):
                password = unquote_plus(pair[9:])
            elif pair.startswith("next="):
                next_url = unquote_plus(pair[5:])

        if (
            not next_url.startswith("/")
            or next_url.startswith("//")
            or (len(next_url) > 1 and next_url[1] in "/\\")
            or "\r" in next_url
            or "\n" in next_url
        ):
            next_url = "/"

        if secrets.compare_digest(password, self.server.password):
            session_id = self.server.create_session()
            csrf_token = secrets.token_hex(32)
            from urllib.parse import quote

            self.send_response(302)
            self.send_header("Location", quote(next_url, safe="/"))
            self.send_header(
                "Set-Cookie",
                "argus_session=%s; HttpOnly; SameSite=Strict; Path=/" % session_id,
            )
            self.send_header(
                "Set-Cookie",
                "csrf_token=%s; SameSite=Strict; Path=/" % csrf_token,
            )
            self.end_headers()
        else:
            from urllib.parse import quote

            fail_url = "/login?error=1"
            if next_url and next_url != "/":
                fail_url += "&next=%s" % quote(next_url)
            self.send_response(302)
            self.send_header("Location", fail_url)
            self.end_headers()

    def _handle_logout(self) -> None:
        cookie_header = self.headers.get("Cookie", "")
        cookie = SimpleCookie()
        try:
            cookie.load(cookie_header)
        except Exception:
            pass
        session_id = cookie.get("argus_session")
        if session_id:
            self.server.invalidate_session(session_id.value)

        self.send_response(302)
        self.send_header("Location", "/login")
        self.send_header(
            "Set-Cookie",
            "argus_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        )
        self.send_header(
            "Set-Cookie",
            "csrf_token=; SameSite=Strict; Path=/; Max-Age=0",
        )
        self.end_headers()

    # --- API ---

    def _handle_api(self, method: str) -> None:
        content_length = min(int(self.headers.get("Content-Length", 0)), 2 * 1024 * 1024)
        body = self.rfile.read(content_length) if content_length > 0 else b""

        store = self.server.analytics_store
        audit_reader = self.server.audit_reader

        # Try plugin API handler first
        pro_handler = self.server.extensions.get_dashboard_api_handler()
        if pro_handler:
            try:
                result = pro_handler(self.path, method, body, store, audit_reader)
                if result is not None:
                    if len(result) == 3:
                        status, content_type, response_body = result
                    else:
                        status, response_body = result
                        content_type = "application/json"
                    self._send_raw(status, content_type, response_body)
                    return
            except Exception:
                pass

        # Resolve request user for audit trail
        request_user = "dashboard"
        user_info = getattr(self, "_user", None)
        if user_info and isinstance(user_info, dict):
            # Auth provider (Enterprise): "dashboard:<user_id>"
            request_user = "dashboard:%s" % user_info.get("user_id", "unknown")
        elif self.server.password:
            # Password auth active: shared admin user
            request_user = "dashboard:admin"

        # Fall through to community handler
        status, response_body = handle_community_api(
            self.path,
            method,
            body,
            store,
            audit_reader=audit_reader,
            config=self.server.config,
            extensions=self.server.extensions,
            request_user=request_user,
        )
        self._send_raw(status, "application/json", response_body)

    # --- SSE ---

    def _handle_live_stream(self) -> None:
        """GET /api/v1/live — SSE endpoint for real-time findings."""
        broadcaster = self.server.sse_broadcaster
        if broadcaster is None:
            self._send_json(503, {"error": "live stream not available"})
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        try:
            self.wfile.write(b"event: connected\ndata: {}\n\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

        broadcaster.register(self.wfile)
        try:
            while True:
                time.sleep(5)
                try:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    break
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            broadcaster.unregister(self.wfile)

    # --- Export ---

    def _handle_export(self, export_type: str) -> None:
        """Handle findings or audit export."""
        path = self.path
        query = ""
        if "?" in path:
            path, query = path.split("?", 1)

        from urllib.parse import unquote_plus

        params = {}
        for part in query.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                params[unquote_plus(k)] = unquote_plus(v)

        fmt = params.get("format", "csv")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        if export_type == "findings":
            store = self.server.analytics_store
            if not store:
                self._send_json(404, {"error": "store not available"})
                return

            severity = params.get("severity", "") or None
            detector = params.get("detector", "") or None
            provider = params.get("provider", "") or None
            findings, _ = store.get_findings_page(
                limit=10000,
                offset=0,
                severity=severity,
                detector=detector,
                provider=provider,
            )

            if fmt == "json":
                body = json.dumps(findings, indent=2).encode("utf-8")
                self._send_download(body, "application/json", "findings-%s.json" % now)
            else:
                body = self._findings_to_csv(findings)
                self._send_download(body, "text/csv; charset=utf-8", "findings-%s.csv" % now)

        elif export_type == "audit":
            audit_reader = self.server.audit_reader
            if not audit_reader:
                self._send_json(404, {"error": "audit reader not available"})
                return

            action = params.get("action", "") or None
            provider = params.get("provider", "") or None
            search = params.get("search", "") or None
            entries, _ = audit_reader.read_entries(
                limit=10000,
                offset=0,
                action=action,
                provider=provider,
                search=search,
            )

            if fmt == "json":
                body = json.dumps(entries, indent=2).encode("utf-8")
                self._send_download(body, "application/json", "audit-%s.json" % now)
            else:
                body = self._audit_to_csv(entries)
                self._send_download(body, "text/csv; charset=utf-8", "audit-%s.csv" % now)

    @staticmethod
    def _findings_to_csv(findings: list) -> bytes:
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
        lines = [",".join(cols)]
        for f in findings:
            row = []
            for c in cols:
                val = str(f.get(c, ""))
                if "," in val or '"' in val or "\n" in val:
                    val = '"' + val.replace('"', '""') + '"'
                row.append(val)
            lines.append(",".join(row))
        return "\n".join(lines).encode("utf-8")

    @staticmethod
    def _audit_to_csv(entries: list) -> bytes:
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

    # --- Logs download ---

    def _handle_logs_download(self) -> None:
        from lumen_argus.log_utils import sanitize_log_line

        config = self.server.config
        if not config:
            self._send_json(404, {"error": "config not available"})
            return

        log_dir = os.path.expanduser(config.logging_config.log_dir)
        log_file = os.path.join(log_dir, "lumen-argus.log")
        if not os.path.exists(log_file):
            self._send_json(404, {"error": "log file not found"})
            return

        lines = []
        try:
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    lines.append(sanitize_log_line(line))
        except OSError:
            self._send_json(500, {"error": "failed to read log file"})
            return

        content = "".join(lines)
        body = content.encode("utf-8")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        self._send_download(body, "text/plain; charset=utf-8", "lumen-argus-logs-%s.txt" % now)

    # --- Dashboard HTML ---

    def _serve_dashboard(self) -> None:
        from lumen_argus.dashboard.html import COMMUNITY_DASHBOARD_HTML

        html = COMMUNITY_DASHBOARD_HTML

        # Inject plugin CSS before </style>
        extra_css = self.server.extensions.get_dashboard_css()
        if extra_css:
            css_block = "\n".join(extra_css)
            html = html.replace("</style>", css_block + "\n</style>")

        # Inject plugin page JS before </body>
        extra_pages = self.server.extensions.get_dashboard_pages()
        if extra_pages:
            js_blocks = []
            for page in extra_pages:
                parts = []
                if page.get("html"):
                    # Pass HTML template as a JS variable for registerPage() to use
                    import json as _json

                    var_name = "_pageHtml_%s" % page["name"]
                    parts.append("<script>var %s=%s;</script>" % (var_name, _json.dumps(page["html"])))
                parts.append("<script>\n%s\n</script>" % page["js"])
                js_blocks.append("\n".join(parts))
            html = html.replace("</body>", "\n".join(js_blocks) + "\n</body>")

        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'unsafe-inline'; "
            "style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
        )
        self.end_headers()
        self.wfile.write(body)

    # --- Helpers ---

    def _send_json(self, status: int, data: dict) -> None:
        body = json.dumps(data).encode("utf-8")
        self._send_raw(status, "application/json", body)

    def _send_raw(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_download(self, body: bytes, content_type: str, filename: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", 'attachment; filename="%s"' % filename)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class DashboardServer(http.server.ThreadingHTTPServer):
    """Threaded HTTP server for the dashboard with optional auth."""

    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        """Suppress ConnectionResetError from SSE client disconnections."""
        import sys

        exc_type = sys.exc_info()[0]
        if exc_type in (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            return
        super().handle_error(request, client_address)

    def __init__(
        self,
        bind: str,
        port: int,
        analytics_store,
        extensions,
        password: str = "",
        audit_reader=None,
        sse_broadcaster=None,
        config=None,
    ):
        if bind not in ("127.0.0.1", "localhost"):
            log.warning("binding to %s — dashboard is accessible on the network", bind)
        self.analytics_store = analytics_store
        self.extensions = extensions
        self.password = password or os.environ.get("LUMEN_ARGUS_DASHBOARD_PASSWORD", "")
        self.audit_reader = audit_reader
        self.sse_broadcaster = sse_broadcaster
        self.config = config
        self._sessions = {}  # type: dict
        self._session_lock = threading.Lock()
        super().__init__((bind, port), DashboardHandler)

    def create_session(self) -> str:
        session_id = secrets.token_hex(32)
        now = time.monotonic()
        with self._session_lock:
            expired = [k for k, t in self._sessions.items() if now - t > _SESSION_TIMEOUT]
            for k in expired:
                del self._sessions[k]
            self._sessions[session_id] = now
        return session_id

    def validate_session(self, session_id: str) -> bool:
        with self._session_lock:
            created = self._sessions.get(session_id)
            if created is None:
                return False
            if time.monotonic() - created > _SESSION_TIMEOUT:
                del self._sessions[session_id]
                return False
            return True

    def invalidate_session(self, session_id: str) -> None:
        with self._session_lock:
            self._sessions.pop(session_id, None)


def start_dashboard(
    bind: str = "127.0.0.1",
    port: int = 8081,
    analytics_store=None,
    extensions=None,
    password: str = "",
    audit_reader=None,
    sse_broadcaster=None,
    config=None,
) -> Optional[DashboardServer]:
    """Start the dashboard server in a daemon thread.

    Returns the server instance, or None if startup fails.
    """
    for attempt in range(2):
        try:
            server = DashboardServer(
                bind,
                port,
                analytics_store,
                extensions,
                password=password,
                audit_reader=audit_reader,
                sse_broadcaster=sse_broadcaster,
                config=config,
            )
            thread = threading.Thread(
                target=server.serve_forever,
                daemon=True,
                name="dashboard",
            )
            thread.start()
            if server.password:
                log.info("dashboard started on http://%s:%d (password protected)", bind, port)
            else:
                log.info("dashboard started on http://%s:%d", bind, port)
            return server
        except OSError as e:
            if attempt == 0:
                log.info("dashboard port %d in use, retrying in 2s", port)
                time.sleep(2)
            else:
                log.warning(
                    "dashboard unavailable — failed to bind to %s:%d: %s",
                    bind,
                    port,
                    e,
                )
                return None
