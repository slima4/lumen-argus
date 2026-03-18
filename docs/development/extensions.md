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
| `set_post_scan_hook(hook)` | `hook(scan_result, body, provider)` | After scan completes |
| `set_evaluate_hook(hook)` | `hook(findings, policy) -> ActionDecision` | Replaces default policy evaluation |
| `set_config_reload_hook(hook)` | `hook(pipeline)` | After SIGHUP config reload |
| `set_redact_hook(hook)` | `hook(body, findings) -> bytes` | When action is "redact" |

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
        {"name": "notifications", "label": "Notifications",
         "js": "registerPage('notifications', 'Notifications', {loadFn: loadNotif, html: _pageHtml_notifications});",
         "html": "<div class='sh'><h2>Notification Channels</h2></div>",
         "order": 55},
    ])

    # Add CSS (injected after community CSS)
    registry.register_dashboard_css(".pro-badge { color: gold; }")

    # Add API handler (called before community handler)
    def my_api(path, method, body, store, audit_reader):
        if path == "/api/v1/notifications":
            return 200, json.dumps({"channels": []}).encode()
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
