# Config Schema Reference

lumen-argus loads configuration from YAML files in the following order:

1. **Global config**: `~/.lumen-argus/config.yaml` (created automatically on first run)
2. **Project config**: `.lumen-argus.yaml` in the current working directory (optional, can only be more restrictive)

The config uses PyYAML (`yaml.safe_load`) for full YAML 1.1 spec support including anchors, aliases, block scalars, and flow mappings.

---

## Top-level keys

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `version` | `str` | `"1"` | Config schema version. |
| `default_action` | `str` | `alert` | Default action when a finding has no detector-specific override. One of: `log`, `alert`, `redact`, `block`. |

---

## `proxy`

Network and connection settings for the proxy server.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `proxy.port` | `int` | `8080` | Port to listen on. Range: 1--65535. |
| `proxy.bind` | `str` | `127.0.0.1` | Bind address. Only `127.0.0.1` and `localhost` are allowed (enforced at runtime). |
| `proxy.timeout` | `int` | `120` | Idle-read timeout in seconds for upstream connections. A stream that receives no data for this long is closed. Range: 1--300. |
| `proxy.connect_timeout` | `int` | `10` | TCP connect timeout in seconds for upstream API calls. Range: 1--120. |
| `proxy.retries` | `int` | `1` | Number of retry attempts on upstream connection failure. Range: 0--5. |
| `proxy.max_body_size` | `int` | `52428800` | Maximum request body size in bytes to scan (50 MB). Bodies larger than this are forwarded without scanning. |
| `proxy.max_connections` | `int` | `50` | Maximum concurrent upstream connections. Additional requests queue until a slot opens. Range: 1--100. |
| `proxy.drain_timeout` | `int` | `30` | Seconds to wait for in-flight requests to complete during shutdown. Range: 0--300. |
| `proxy.ca_bundle` | `str` | `""` | Path to a custom CA certificate file or directory. Use this behind corporate proxies. Empty string uses system defaults. |
| `proxy.verify_ssl` | `bool` | `true` | Verify upstream TLS certificates. Set to `false` only for development/testing. |
| `proxy.standalone` | `bool` | `true` | Whether the proxy is running standalone. Set to `false` when managed by tray app. Also settable via `--no-standalone` CLI flag. Exposed in `/api/v1/status`. |

```yaml title="Example"
proxy:
  port: 8080
  bind: "127.0.0.1"
  timeout: 120
  connect_timeout: 10
  retries: 1
  max_body_size: 52428800
  max_connections: 50
  drain_timeout: 30
  ca_bundle: ""
  verify_ssl: true
  standalone: true
```

!!! danger "Do not disable SSL verification in production"
    Setting `proxy.verify_ssl: false` disables all TLS certificate checks. This should only be used in local development or testing environments.

---

## `detectors`

Per-detector configuration. Each detector (`secrets`, `pii`, `proprietary`) accepts the same set of keys.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `detectors.<name>.enabled` | `bool` | `true` | Whether the detector is active. |
| `detectors.<name>.action` | `str` | *(uses `default_action`)* | Action override for this detector. One of: `log`, `alert`, `redact`, `block`. Empty string falls back to `default_action`. |
| `detectors.secrets.entropy_threshold` | `float` | `4.5` | Shannon entropy threshold (bits/char) for the entropy sweep in the secrets detector. Range: 0.0--10.0. |

```yaml title="Example"
detectors:
  secrets:
    enabled: true
    action: alert
    entropy_threshold: 4.5
  pii:
    enabled: true
    action: alert
  proprietary:
    enabled: true
    action: alert
```

!!! note "Redact action in Community Edition"
    In the Community Edition, the `redact` action is automatically downgraded to `alert`. Full redaction requires a Pro license.

---

## `allowlists`

Values and paths that should never be flagged. See the [Allowlists guide](../guide/allowlists.md) for detailed usage.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `allowlists.secrets` | `list[str]` | `[]` | Secret values or glob patterns to skip. Supports exact match and fnmatch globs. |
| `allowlists.pii` | `list[str]` | `[]` | PII values or glob patterns to skip. |
| `allowlists.paths` | `list[str]` | `[]` | File path glob patterns. Matching source files are excluded from scanning entirely. |

```yaml title="Example"
allowlists:
  secrets:
    - "AKIAIOSFODNN7EXAMPLE"
    - "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  pii:
    - "*@example.com"
    - "*@test.local"
  paths:
    - "test/**"
    - "tests/**"
    - "fixtures/**"
```

---

## `custom_rules`

User-defined regex detection rules. Each rule is a list entry with the following keys:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | `str` | *(required)* | Unique identifier for the rule. Used in findings as the `type` field. |
| `pattern` | `str` | *(required)* | Regular expression pattern. Compiled with Python's `re` module. |
| `severity` | `str` | `high` | Finding severity. One of: `critical`, `high`, `warning`, `info`. |
| `action` | `str` | *(uses `default_action`)* | Action override for findings from this rule. One of: `log`, `alert`, `redact`, `block`. |

```yaml title="Example"
custom_rules:
  - name: internal_api_key
    pattern: "INTERNAL-[A-Z0-9]{32}"
    severity: critical
    action: block

  - name: todo_credential
    pattern: "TODO:.*password|TODO:.*secret"
    severity: warning
    action: alert
```

!!! warning "Pattern validation"
    Invalid regex patterns are logged as warnings during config load and the rule is silently skipped. Check proxy startup logs if a custom rule does not appear to be working.

---

## `logging`

Application log file settings (rotated log files written to disk).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `logging.log_dir` | `str` | `~/.lumen-argus/logs` | Directory for application log files. |
| `logging.file_level` | `str` | `info` | Minimum log level written to file. One of: `debug`, `info`, `warning`, `error`. |
| `logging.max_size_mb` | `int` | `10` | Maximum log file size in MB before rotation. |
| `logging.backup_count` | `int` | `5` | Number of rotated log files to keep. |

```yaml title="Example"
logging:
  log_dir: "~/.lumen-argus/logs"
  file_level: info
  max_size_mb: 10
  backup_count: 5
```

---

## `audit`

Audit log settings. Audit logs are JSONL files recording every scanned request.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `audit.log_dir` | `str` | `~/.lumen-argus/audit` | Directory for audit JSONL files. Files are created with `0o600` permissions. |
| `audit.retention_days` | `int` | `90` | Number of days to retain audit log files before automatic cleanup. |

```yaml title="Example"
audit:
  log_dir: "~/.lumen-argus/audit"
  retention_days: 90
```

!!! info "Security note"
    Audit logs never contain the `matched_value` field from findings. Only the masked `value_preview` is written to disk, preventing secondary exfiltration of sensitive data through log files.

---

## `dashboard`

Web dashboard settings. The dashboard runs on a separate port and provides a browser-based UI for viewing findings, stats, and audit logs.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dashboard.enabled` | `bool` | `true` | Whether to start the dashboard server. |
| `dashboard.port` | `int` | `8081` | Port to listen on. Range: 1--65535. |
| `dashboard.bind` | `str` | `127.0.0.1` | Bind address. Non-loopback requires `--host` CLI flag (for Docker). |
| `dashboard.password` | `str` | `""` | Optional password for dashboard access. Can also be set via `LUMEN_ARGUS_DASHBOARD_PASSWORD` env var. Empty = open access. |

```yaml title="Example"
dashboard:
  enabled: true
  port: 8081
  bind: "127.0.0.1"
  password: ""
```

!!! note "Authentication"
    When a password is set, the dashboard uses session-based auth with CSRF double-submit cookies. Sessions expire after 8 hours. Plugin auth providers (OAuth, SAML) can be registered via the extension API for Enterprise use.

---

## `analytics`

SQLite analytics store settings. Powers the dashboard charts and paginated findings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `analytics.enabled` | `bool` | `true` | Whether to create and populate the analytics store. Only active when dashboard is enabled. |
| `analytics.db_path` | `str` | `~/.lumen-argus/analytics.db` | Path to the SQLite database file. Created with `0o600` permissions. |
| `analytics.retention_days` | `int` | `365` | Days to retain findings before automatic cleanup. |

```yaml title="Example"
analytics:
  enabled: true
  db_path: "~/.lumen-argus/analytics.db"
  retention_days: 365
```

!!! info "Pro extension"
    The Pro edition extends the analytics store with additional tables (notification channels, custom rules, allowlist entries, etc.) by subclassing `AnalyticsStore`. Community and Pro share the same SQLite file — data survives license transitions.

---

## `rule_analysis`

Configuration for rule overlap analysis via [crossfire-rules](https://pypi.org/project/crossfire-rules/) (optional dependency).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `rule_analysis.samples` | `int` | `50` | Corpus strings generated per rule. Higher = more stable results, slower analysis. Minimum 10. |
| `rule_analysis.threshold` | `float` | `0.8` | Overlap fraction to classify as duplicate or subset (0.0–1.0). |
| `rule_analysis.seed` | `int` | `42` | Random seed for reproducible corpus generation. |
| `rule_analysis.auto_on_import` | `bool` | `true` | Automatically run analysis after rule import (CLI and auto-import on first startup). |
| `rule_analysis.watchdog_total_s` | `float` | `300.0` | Total wall-clock budget for one analysis run. On timeout the watchdog flips status to `failed` with a `WatchdogTotalTimeout` error; the dashboard stops spinning and renders the error. Set to `0` to disable. |
| `rule_analysis.watchdog_phase_s` | `float` | `120.0` | Per-phase deadline. If any single phase (generating, evaluating, classifying, quality, saving) runs longer than this without a phase-change heartbeat, the watchdog flips to `failed` early with a `WatchdogPhaseTimeout`. Catches single-phase hangs before the total deadline. Set to `0` to disable. |

```yaml
rule_analysis:
  samples: 100
  threshold: 0.8
  seed: 42
  auto_on_import: true
  watchdog_total_s: 300
  watchdog_phase_s: 120
```

Install: `pip install lumen-argus-proxy[rules-analysis]` (or `pip install crossfire-rules[re2]`). The Docker image includes it by default. See [Rule Analysis](../guide/rule-analysis.md) for details.

---

## `notifications`

Notification channels managed via IaC. Reconciled to SQLite on startup and SIGHUP using Kubernetes-style declarative reconciliation — YAML is fully authoritative.

Each entry is a channel definition:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | `str` | *(required)* | Unique channel name. |
| `type` | `str` | *(required)* | Channel type: `webhook`, `email`, `slack`, `teams`, `pagerduty`, `opsgenie`, `jira`. |
| `events` | `list[str]` | `[block, alert]` | Which finding actions trigger this channel. |
| `min_severity` | `str` | `warning` | Minimum severity to dispatch. |
| `enabled` | `bool` | `true` | Whether the channel is active. |

Additional keys are type-specific (e.g., `url`, `smtp_host`, `webhook_url`) and stored in the channel config.

```yaml title="Example"
notifications:
  - name: production-alerts
    type: webhook
    url: "https://hooks.slack.com/services/T00/B00/xxx"
    events: [block, alert]
    min_severity: high

  - name: security-team
    type: email
    smtp_host: "smtp.company.com"
    from_addr: "argus@company.com"
    to_addrs: "security@company.com, sre@company.com"
    events: [block]
    min_severity: critical
```

!!! note "Channel availability"
    Community ships with unlimited channels of any registered type. Channel
    types other than `webhook` require a plugin to register the corresponding
    dispatch implementation; without it, channels of that type appear as
    read-only YAML cards with a dispatch-unavailable warning.

!!! info "YAML reconciliation"
    YAML channels appear as read-only cards in the dashboard with a `YAML` badge. All fields (including `enabled`) are overwritten from YAML on every startup/SIGHUP. Dashboard-managed channels are never touched by the reconciler.

---

## `pipeline`

Pipeline stage configuration. Controls which scanning stages are active and how the encoding decoder behaves. Stages can also be toggled from the Pipeline dashboard page.

### `pipeline.stages.<name>`

Per-stage settings. Each stage accepts:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `pipeline.stages.<name>.enabled` | `bool` | *(varies)* | Whether the stage is active. |
| `pipeline.stages.<name>.action` | `str` | `""` | Stage-level action override (Pro). Empty = use `default_action`. |
| `pipeline.stages.<name>.mode` | `str` | `"async"` | Scanning mode for response stages. `async` (community, zero latency) or `buffered` (Pro, blocks response). |

### Available stages

| Stage | Direction | Default | Available | Description |
|-------|-----------|---------|-----------|-------------|
| `outbound_dlp` | Request | `true` | Yes | Secret/PII/proprietary detection on outbound requests |
| `encoding_decode` | Request | `true` | Yes | Decode base64, hex, URL, Unicode before scanning |
| `response_secrets` | Response | `false` | Yes | Detect secrets in API responses (async, zero latency) |
| `response_injection` | Response | `false` | Yes | Detect prompt injection in responses (async, zero latency) |
| `mcp_arguments` | MCP | `true` | Yes | Scan MCP tool call arguments (via lumen-argus mcp) |
| `mcp_responses` | MCP | `true` | Yes | Scan MCP tool return values (via lumen-argus mcp) |
| `websocket_outbound` | WebSocket | `false` | Yes | Scan outbound WebSocket frames (opt-in, same port) |
| `websocket_inbound` | WebSocket | `false` | Yes | Scan inbound WebSocket frames (opt-in, same port) |

### `pipeline.stages.encoding_decode` (extended)

The encoding decode stage has additional settings:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `base64` | `bool` | `true` | Decode base64-encoded content before scanning. |
| `hex` | `bool` | `true` | Decode hex-encoded content before scanning. |
| `url` | `bool` | `true` | Decode URL-encoded content before scanning. |
| `unicode` | `bool` | `true` | Decode Unicode escape sequences before scanning. |
| `max_depth` | `int` | `2` | Maximum nested encoding layers to decode (e.g., base64 inside URL-encoding). Range: 1--5. |
| `min_decoded_length` | `int` | `8` | Ignore decoded strings shorter than this. Range: 1--100. |
| `max_decoded_length` | `int` | `10000` | Cap decoded output size to prevent memory issues. Range: 100--1000000. |

```yaml title="Example"
pipeline:
  stages:
    outbound_dlp:
      enabled: true
    encoding_decode:
      enabled: true
      base64: true
      hex: true
      url: true
      unicode: true
      max_depth: 2
      min_decoded_length: 8
      max_decoded_length: 10000
    response_secrets:
      enabled: false           # opt-in: detect secrets in API responses
      mode: async              # async (community) | buffered (Pro)
    response_injection:
      enabled: false           # opt-in: detect prompt injection in responses
      mode: async
```

!!! tip "Dashboard Pipeline page"
    All pipeline settings can be configured from the Pipeline page in the dashboard. Changes are saved to the database and applied immediately via hot-reload.

---

## `websocket`

WebSocket proxy settings for the `/ws` endpoint.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `websocket.max_frame_size` | `int` | `1048576` | Maximum text frame size in bytes to scan (1MB). Larger frames are truncated before scanning. |
| `websocket.allowed_origins` | `list[str]` | `[]` | Allowlist of Origin headers. Empty = all origins allowed. |

```yaml title="Example"
websocket:
  max_frame_size: 1048576
  allowed_origins:
    - "https://app.company.com"
```

---

## `mcp`

MCP scanning proxy configuration for `lumen-argus mcp`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mcp.allowed_tools` | `list[str]` | `[]` | Allowlist of tool names. Empty = all tools allowed. |
| `mcp.blocked_tools` | `list[str]` | `[]` | Blocklist of tool names. Takes precedence over allowlist. |
| `mcp.env_filter` | `bool` | `true` | Restrict subprocess environment to safe vars only. |
| `mcp.env_allowlist` | `list[str]` | `[]` | Additional env vars to pass through when env_filter is enabled. |
| `mcp.request_tracking` | `bool` | `true` | Confused deputy protection — track outbound request IDs. |
| `mcp.unsolicited_response_action` | `str` | `"warn"` | Action on unsolicited response: `warn` or `block`. |
| `mcp.scan_tool_descriptions` | `bool` | `true` | Scan tool descriptions for poisoning patterns. |
| `mcp.detect_drift` | `bool` | `true` | Track tool definition changes via SHA-256 baselines. |
| `mcp.drift_action` | `str` | `"alert"` | Action on tool drift: `alert` or `block`. |
| `mcp.session_binding` | `bool` | `false` | Validate tools/call against first tools/list inventory (opt-in). |
| `mcp.unknown_tool_action` | `str` | `"warn"` | Action on unknown tool: `warn` or `block`. |

```yaml title="Example"
mcp:
  allowed_tools: []             # empty = all allowed
  blocked_tools:
    - execute_command
    - run_shell
  env_filter: true
  request_tracking: true
  scan_tool_descriptions: true
  detect_drift: true
  drift_action: alert
  session_binding: false
```

---

## `relay`

Configuration for the relay process in fault-isolated mode.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `relay.port` | `int` | `8080` | Relay listening port. |
| `relay.fail_mode` | `str` | `open` | Action when engine is down. `open` = forward directly to upstream. `closed` = return 503. |
| `relay.engine_url` | `str` | `http://localhost:8090` | Engine process URL. |
| `relay.health_check_interval` | `int` | `2` | Seconds between engine health checks. |
| `relay.health_check_timeout` | `int` | `1` | Seconds before a health check times out. |
| `relay.queue_on_startup` | `int` | `2` | Seconds to buffer requests while engine starts. |

```yaml title="Example"
relay:
  port: 8080
  fail_mode: open
  engine_url: http://localhost:8090
  health_check_interval: 2
  health_check_timeout: 1
  queue_on_startup: 2
```

---

## `engine`

Configuration for the engine process in fault-isolated mode.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `engine.port` | `int` | `8090` | Engine listening port. |

```yaml title="Example"
engine:
  port: 8090
```

---

## `enrollment`

Enterprise agent deployment configuration. Served to agents via `GET /api/v1/enrollment/config` (Pro).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enrollment.organization` | `str` | `""` | Organization name displayed in tray app ("Protected by Acme Corp"). |
| `enrollment.proxy_url` | `str` | `""` | Proxy URL that agents configure AI tools to use. Empty = derived from `proxy.bind:proxy.port`. |
| `enrollment.dashboard_url` | `str` | `""` | Dashboard URL for agent poller/SSE. Empty = derived from `dashboard.bind:dashboard.port`. |
| `enrollment.ca_cert` | `str` | `""` | PEM content or path to CA certificate for TLS inspection proxies. |
| `enrollment.policy.fail_mode` | `str` | `open` | What happens when proxy is unreachable: `open` (direct to upstream) or `closed` (block). |
| `enrollment.policy.auto_configure` | `bool` | `true` | Force-configure all detected AI tools (no per-tool opt-out). |
| `enrollment.policy.allow_disable_protection` | `bool` | `true` | Whether developers can toggle protection off. |
| `enrollment.policy.telemetry_interval_seconds` | `int` | `300` | How often agents send heartbeats (minimum 60). |
| `enrollment.policy.watch_interval_seconds` | `int` | `300` | How often agents scan for new tools (minimum 60). |

```yaml title="Example (K8s ConfigMap)"
enrollment:
  organization: "Acme Corp"
  proxy_url: "https://argus.corp.io:8080"
  dashboard_url: "https://argus.corp.io:8081"
  policy:
    fail_mode: closed
    auto_configure: true
    allow_disable_protection: false
    telemetry_interval_seconds: 300
    watch_interval_seconds: 300
```

---

## Full config example

```yaml
version: "1"

proxy:
  port: 8080
  bind: "127.0.0.1"
  timeout: 120
  connect_timeout: 10
  retries: 1
  max_body_size: 52428800
  max_connections: 50
  drain_timeout: 30
  ca_bundle: ""
  verify_ssl: true
  standalone: true

default_action: alert

detectors:
  secrets:
    enabled: true
    action: alert
    entropy_threshold: 4.5
  pii:
    enabled: true
    action: alert
  proprietary:
    enabled: true
    action: alert

allowlists:
  secrets:
    - "AKIAIOSFODNN7EXAMPLE"
  pii:
    - "*@example.com"
  paths:
    - "test/**"
    - "tests/**"

custom_rules:
  - name: internal_api_key
    pattern: "INTERNAL-[A-Z0-9]{32}"
    severity: critical
    action: block

pipeline:
  stages:
    outbound_dlp:
      enabled: true
    encoding_decode:
      enabled: true
      base64: true
      hex: true
      url: true
      unicode: true
      max_depth: 2
      min_decoded_length: 8
      max_decoded_length: 10000

dashboard:
  enabled: true
  port: 8081
  bind: "127.0.0.1"
  password: ""

# notifications:
#   - name: production-alerts
#     type: webhook
#     url: "https://hooks.slack.com/services/T00/B00/xxx"
#     events: [block, alert]
#     min_severity: high

analytics:
  enabled: true
  db_path: "~/.lumen-argus/analytics.db"
  retention_days: 365

rule_analysis:
  samples: 50
  threshold: 0.8
  seed: 42
  auto_on_import: true

logging:
  log_dir: "~/.lumen-argus/logs"
  file_level: info
  max_size_mb: 10
  backup_count: 5

audit:
  log_dir: "~/.lumen-argus/audit"
  retention_days: 90
```
