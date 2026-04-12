# Extensions

lumen-argus supports plugins via Python entry points. Any pip-installed package can register custom detectors, hooks, and notifiers.

## Plugin Registration

### 1. Declare Entry Point

```toml
# In your plugin's pyproject.toml
[project.entry-points."lumen_argus.extensions"]
my_plugin = "my_package:register"
```

### 2. Implement Register Function

```python
# In my_package/__init__.py
def register(registry):
    """Called by lumen-argus on startup."""
    from my_package.detectors import MyDetector
    registry.add_detector(MyDetector())
```

### 3. Install and Run

```bash
pip install my-plugin
lumen-argus serve  # Plugin auto-discovered and loaded
```

Plugins are logged at startup:

```
INFO  [argus.cli] plugin: my-plugin v1.0.0
```

## Extension Registry API

### Detectors

```python
registry.add_detector(detector, priority=False)
```

- `detector`: Instance implementing `BaseDetector`
- `priority=True`: Run before built-in detectors (prepend)
- `priority=False` (default): Run after built-in detectors (append)

### BaseDetector Interface

```python
from lumen_argus.detectors import BaseDetector
from lumen_argus.models import Finding, ScanField
from lumen_argus.allowlist import AllowlistMatcher

class MyDetector(BaseDetector):
    def scan(self, fields: List[ScanField], allowlist: AllowlistMatcher) -> List[Finding]:
        findings = []
        for field in fields:
            # Your detection logic here
            if "SECRET_PATTERN" in field.text:
                findings.append(Finding(
                    detector="my_detector",
                    type="secret_pattern",
                    severity="high",
                    location=field.path,
                    value_preview="SECR****",
                    matched_value="SECRET_PATTERN_VALUE",  # in-memory only
                ))
        return findings
```

### Hooks

| Hook | Signature | When Called |
|------|-----------|------------|
| `set_pre_request_hook(hook)` | `hook(request_id)` | Start of each request, before any logging |
| `set_post_scan_hook(hook)` | `hook(scan_result, body, provider, session=ctx)` | After scan completes. Accept `**kwargs` for forward compat. |
| `set_evaluate_hook(hook)` | `hook(findings, policy) -> ActionDecision` | Replaces default policy evaluation |
| `set_config_reload_hook(hook)` | `hook(pipeline)` | After SIGHUP config reload |
| `set_redact_hook(hook)` | `hook(body, findings) -> bytes` | When action is "redact" |
| `set_health_hook(hook)` | `hook() -> dict` | Merged into `/health` JSON response (no auth, for container probes) |
| `set_metrics_hook(hook)` | `hook() -> str` | Prometheus text lines appended to `/metrics` response |
| `set_trace_request_hook(hook)` | `hook(method, path) -> context manager` | Wraps full request lifecycle for OTel tracing |

### Observability Hooks

**Health** (`/health` on proxy port 8080):
```python
registry.set_health_hook(lambda: {"license": "valid", "channels_active": 3})
# Response: {"status": "ok", "uptime": 3600, "requests": 42, "license": "valid", ...}
```

**Metrics** (`/metrics` on proxy port 8080):
```python
registry.set_metrics_hook(lambda: "argus_notifications_total 42\nargus_license_days 180\n")
# Appended to community Prometheus metrics
```

**Tracing** (OpenTelemetry):
```python
from opentelemetry import trace
tracer = trace.get_tracer("lumen-argus-pro")
registry.set_trace_request_hook(
    lambda method, path: tracer.start_as_current_span(
        "proxy.request", attributes={"http.method": method, "http.path": path}
    )
)
# Community sets span attributes: provider, body.size, findings.count, action, scan.duration_ms
# Pro detector/redaction/notification spans auto-parent via OTel context propagation
```

All observability hooks are fully guarded — exceptions never break requests.

### Notification Hooks

| Hook | Signature | Description |
|------|-----------|-------------|
| `register_channel_types(types)` | `types: dict` | Register channel type definitions (label + fields) for the dashboard dropdown |
| `set_notifier_builder(builder)` | `builder(channel_dict) -> notifier` | Factory that builds notifier instances from DB channel rows |
| `set_dispatcher(dispatcher)` | `dispatcher.dispatch(findings, provider, model, session_id, session, **kwargs)` | Set the notification dispatcher (Pro adds circuit breakers, async, dedup) |
| `set_channel_limit(limit)` | `limit: int or None` | Set max channels (`None` = unlimited, `1` = freemium default) |

Community provides the DB schema (`notification_channels` table), CRUD API, and dashboard UI. Pro registers channel types, notifier builder, dispatcher, and channel limit. Without Pro, the Notifications page shows YAML-configured channels as read-only with a dispatch warning.

**Notifier signature contract.** Any custom notifier returned by `set_notifier_builder(...)` must accept a forward-compatible `notify()` signature. The pipeline dispatches through `_safe_notify` which calls `notifier.notify(findings, provider=..., model=..., session=...)`. The `session` keyword argument is the full `SessionContext` dataclass and will gain new fields over time (new identity columns, new SDK metadata, etc.). Use either of:

```python
# Option A — accept everything via **kwargs (recommended for third-party notifiers)
def notify(self, findings, provider="", model="", **kwargs):
    session = kwargs.get("session")
    ...

# Option B — declare session explicitly (recommended if you use it)
def notify(self, findings, provider="", model="", session=None, **kwargs):
    ...
```

A notifier whose signature is strict (e.g. `def notify(self, findings, provider, model)` with no `**kwargs`) will raise `TypeError` on every dispatch starting with community `da5ea71`. The error is caught by `BasicDispatcher._safe_notify` and logged; `get_last_status()` reports the failure, but the customer-facing channel goes silent. Always include `**kwargs` or an explicit `session=None` parameter. `session` should be treated as read-only inside the notifier — the same instance is still reachable on the calling thread via the SSE broadcast and post-scan hook, and mutation would race with those readers.

**YAML reconciliation:** Channels defined in `config.yaml` are reconciled to SQLite on startup and SIGHUP (Kubernetes-style). YAML is fully authoritative — all fields including `enabled` overwrite DB values. Dashboard-managed channels are never touched by the reconciler.

**Freemium model:** 1 channel of any type without license, unlimited with Pro. Channel limit is enforced atomically (count + insert under the same lock).

### Server Access

```python
registry.set_proxy_server(server)  # Called by cli.py after server creation
server = registry.get_proxy_server()  # Access from plugin code
```

### Dashboard Hooks

Extend the community dashboard without replacing it:

```python
def register(registry):
    # Add pages (unlock locked placeholders or create new ones)
    registry.register_dashboard_pages([
        {"name": "rules", "label": "Rules",
         "js": "registerPage('rules', 'Rules', {loadFn: loadRules, html: _pageHtml_rules});",
         "html": "<div class='sh'><h2>Detection Rules</h2></div>",
         "order": 25},
    ])

    # Register notification channel types and dispatcher
    registry.register_channel_types({"slack": {"label": "Slack", "fields": {...}}})
    registry.set_notifier_builder(my_builder)
    registry.set_dispatcher(my_dispatcher)
    registry.set_channel_limit(None)  # unlimited with Pro license

    # Add CSS (injected after community CSS)
    registry.register_dashboard_css(".pro-badge { color: gold; }")

    # Add API handler (called before community handler)
    def my_api(path, method, body, store, audit_reader):
        if path == "/api/v1/rules":
            return 200, json.dumps({"rules": []}).encode()
        return None  # fall through to community
    registry.register_dashboard_api(my_api)

    # Override analytics store (Pro extends with more tables)
    registry.set_analytics_store(my_extended_store)

    # Access SSE broadcaster for real-time events
    broadcaster = registry.get_sse_broadcaster()
    if broadcaster:
        broadcaster.broadcast("finding", {"count": 3})
```

!!! warning "Plugin trust model"
    The `js` field is injected as a raw `<script>` block and executes in the dashboard origin — it is **trusted code**. Only register pages from pip-installed entry-point plugins. The `html` field is sanitized client-side via `_safeInjectHTML()` which strips `<script>` tags and `on*` event handlers.

### Clearing Dashboard Extensions (SIGHUP)

Pro calls `clear_dashboard_pages()` during SIGHUP config reload to handle license state changes:

```python
def on_config_reload(pipeline):
    registry.clear_dashboard_pages()  # reset pages, CSS, API handler
    if license_still_valid():
        registry.register_dashboard_pages(get_pro_pages())  # re-register
        registry.register_dashboard_css(get_pro_css())
        registry.register_dashboard_api(handle_pro_api)
    # else: leave empty → community shows locked placeholders
```

### Auth Providers

Register additional authentication methods (Enterprise):

```python
registry.register_auth_provider(my_oauth_provider)
# provider.authenticate(headers) -> {"user_id": "...", "roles": [...]} or None
```

### Multi-Plugin Coordination

When more than one plugin is installed, plugins frequently need to share
state — the late-loading plugin wants the early-loading plugin's store
handle, dispatcher, or metrics collector. The following hooks let plugins
do this without reaching into each other's private module attributes.

#### Plugin Instance Registry

Publish and look up plugin instances by name. Convention: use the package
name without the `lumen_argus_` prefix.

```python
# Plugin A — registers itself during its register() entry point
def register(registry):
    instance = MyPlugin(...)
    registry.set_plugin("my_plugin", instance)

# Plugin B — looks up plugin A by name
def register(registry):
    upstream = registry.get_plugin("my_plugin")  # None if not installed
    if upstream is not None:
        # Use whatever public attributes plugin A exposes
        collector = MyCollector(sink=upstream.public_handle)
```

- `set_plugin(name, instance)` — idempotent, last write wins. No type
  constraint — the caller knows the shape.
- `get_plugin(name)` — returns the instance or `None`.
- Plugin A owns the contract for what attributes it exposes on its own
  instance. Plugin B reads at its own risk if the shape changes.

#### Schema Extension Registration

Plugins that own their own database tables register DDL that runs after the
community schema. Must be idempotent (`CREATE TABLE IF NOT EXISTS`).

```python
def register(registry):
    registry.register_schema_extension("""
        CREATE TABLE IF NOT EXISTS my_plugin_events (
            id {auto_id},
            created_at {ts} NOT NULL,
            payload TEXT NOT NULL
        );
    """)
```

The placeholders `{auto_id}` and `{ts}` resolve to the adapter's dialect
(`INTEGER PRIMARY KEY AUTOINCREMENT` / `TEXT` for SQLite, `SERIAL PRIMARY
KEY` / `TIMESTAMPTZ` for PostgreSQL). Extensions run in registration
order, each applied independently: a failure in one is logged at `ERROR`
and skipped without blocking the others. Broken plugin schemas degrade
that plugin's features — they don't crash the store.

Registration must happen during the plugin's `register()` entry point.
The proxy collects all registered extensions after `load_plugins()` runs
and applies them against the active analytics store, so plugin authors
do not need to worry about startup ordering.

If you need to apply DDL against an already-constructed store (e.g. in
a test), call the public method directly:

```python
store.apply_schema_extensions([
    "CREATE TABLE IF NOT EXISTS my_table (id {auto_id}, name TEXT)",
])
```

#### Public Store Execute API

Plugins with their own tables run queries against the shared database via
three stable methods on `AnalyticsStore`:

```python
# Read — returns list[dict], uses thread-local connection
rows = store.execute(
    "SELECT payload FROM my_plugin_events WHERE id = ?",
    (event_id,),
)

# Single-statement write — acquires adapter write lock, commits
result = store.execute_write(
    "INSERT INTO my_plugin_events (created_at, payload) VALUES (?, ?)",
    (now, payload),
)
print(result.rowcount, result.lastrowid)

# Multi-statement transaction
with store.write_transaction() as conn:
    conn.execute("DELETE FROM my_plugin_events WHERE created_at < ?", (cutoff,))
    conn.execute(
        "INSERT INTO my_plugin_events (created_at, payload) VALUES (?, ?)",
        (now, payload),
    )
# commits on success, rolls back on exception
```

- All methods use `?` placeholders. The adapter translates to `%s` for
  PostgreSQL.
- `execute()` returns `list[dict[str, Any]]` — one dict per row.
- `execute_write()` returns `WriteResult(rowcount, lastrowid)`.
- `write_transaction()` yields a `DBConnection` under the write lock.
- **Never nest**: `execute_write` and `write_transaction` both acquire
  the adapter write lock, which is a plain `threading.Lock` on SQLite
  (non-reentrant). Do not call `execute_write` from inside a
  `write_transaction` block — it will self-deadlock. Put all your
  writes inside a single `write_transaction` block instead.
- **Never log SQL parameters** — they may contain sensitive values
  (the same values the scanner pipeline is looking for).

These are the *only* public SQL entry points for plugins. Do not reach
into `store._adapter` or `store._connect()` — they are internal and may
change without notice.

#### Multi-Package Static File Loading

Plugins can ship their own JS/CSS/HTML files from their own package
directory instead of bundling them inside another plugin. The dashboard
server scans registered directories and injects their contents into the
assembled SPA HTML.

```python
def register(registry):
    static = os.path.join(os.path.dirname(__file__), "dashboard", "static")
    registry.register_static_dir(static)
```

Directory layout:

```
dashboard/static/
├── js/*.js       → concatenated into a <script> block before </body>
├── css/*.css     → concatenated into the <style> block
└── html/*.html   → exposed as var _pageHtml_<basename> inside <script>
```

- Directories are processed in registration order (community first, then
  plugins in entry-point order).
- File name collisions resolve last-write-wins, so a plugin *can* override
  a community file if it really needs to — do this rarely.
- If the registered path doesn't exist at registration time, a warning is
  logged and the directory is skipped.
- Missing subdirectories (`js/`, `css/`, `html/`) are silently ignored,
  so a plugin may provide only JS, only CSS, etc.
- HTML files become `var _pageHtml_<safename>=<json>;` globals. The
  `<safename>` is the basename with non-identifier characters (`-`, `.`,
  etc.) replaced with `_`, so `my-page.v2.html` becomes
  `_pageHtml_my_page_v2`.
- Results are cached on first request and reused across page loads. The
  cache is busted when a plugin calls `registry.clear_dashboard_pages()`
  (which happens on SIGHUP reload), so you never need to clear it
  manually during normal operation.

#### Dashboard Status Data Sharing

The community dashboard calls `/api/v1/status` once per `loadData()`
(initial load + SSE/polling refresh) and exposes the response on two
globals *before* any page `loadFn` runs:

```javascript
window._statusData   // full /api/v1/status JSON response
window._licenseTier  // "community" | "pro" | "team"
```

Plugin JS modules should read these synchronously instead of firing
their own `/api/v1/status` fetch. On direct-hash navigation (e.g.
bookmarking a page hash), the page's `loadFn` is guaranteed to run
*after* `loadData()` completes, so the globals are always set by the
time plugin code needs them.

## Data Structures

### ScanField

```python
@dataclass
class ScanField:
    path: str                # e.g. "messages[3].content"
    text: str                # text to scan
    source_filename: str     # filename if from tool_result
```

### Finding

```python
@dataclass
class Finding:
    detector: str       # "secrets", "pii", "proprietary", "custom", or plugin name
    type: str           # e.g. "aws_access_key", "email"
    severity: str       # "critical", "high", "warning", "info"
    location: str       # path into request body
    value_preview: str  # masked (first 4 chars + "****")
    matched_value: str  # full match — NEVER written to disk
    action: str         # resolved action (set by PolicyEngine)
    count: int          # deduplication count (default 1)
```

!!! warning "Security Invariant"
    `Finding.matched_value` is kept in memory only. It is excluded from audit log serialization, application logs, metrics, and baseline files. Never persist it.
