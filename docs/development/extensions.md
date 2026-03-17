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
