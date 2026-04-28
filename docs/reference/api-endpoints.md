# API Endpoints

lumen-argus exposes endpoints on three ports:

- **Proxy port** (default `8080`): `/health` and `/metrics` — handled directly, not forwarded to AI providers
- **Dashboard port** (default `8081`): `/api/v1/*` — dashboard API for findings, stats, notifications, build identity, and more
- **Agent relay port** (default `8070`, `lumen-argus-agent` only): `/health` and `/api/v1/build` — loopback-only, the rest of the surface is transparent forwarding to the proxy

---

## `GET /health`

Returns the proxy's current status as JSON.

### Response

**Status:** `200 OK`
**Content-Type:** `application/json`

```json
{
  "status": "ok",
  "version": "0.1.0",
  "uptime": 3600.1,
  "requests": 142
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `status` | `str` | Always `"ok"` when the proxy is running. |
| `version` | `str` | lumen-argus version string. |
| `uptime` | `float` | Seconds since proxy started. |
| `requests` | `int` | Total number of proxied requests since startup. |

No authentication required — designed for container orchestrator probes (Kubernetes liveness/readiness, ECS, Docker HEALTHCHECK).

Plugins may extend this response via `set_health_hook()`.

### Example

```bash
curl http://localhost:8080/health
```

```json
{"status": "ok", "version": "0.1.0", "uptime": 3600.1, "requests": 42}
```

!!! tip "Use in monitoring"
    Point your uptime monitor, load balancer, or Kubernetes probe at `/health`. A successful `200` response confirms the proxy is accepting connections. The Dockerfile uses this for `HEALTHCHECK`.

---

## `GET /metrics`

Returns session metrics in [Prometheus exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/) (plain text). Designed for scraping by Prometheus, Grafana Agent, or compatible collectors.

### Response

**Status:** `200 OK`
**Content-Type:** `text/plain; version=0.0.4; charset=utf-8`

### Metrics

#### `lumen_argus_active_requests` (gauge)

Number of requests currently in flight.

```
# HELP lumen_argus_active_requests Current in-flight requests
# TYPE lumen_argus_active_requests gauge
lumen_argus_active_requests 3
```

---

#### `lumen_argus_requests_total` (counter)

Total proxied requests, labeled by the resolved action.

| Label | Values |
|-------|--------|
| `action` | `pass`, `log`, `alert`, `redact`, `block` |

```
# HELP lumen_argus_requests_total Total proxied requests by action
# TYPE lumen_argus_requests_total counter
lumen_argus_requests_total{action="pass"} 130
lumen_argus_requests_total{action="log"} 5
lumen_argus_requests_total{action="alert"} 6
lumen_argus_requests_total{action="block"} 1
```

---

#### `lumen_argus_bytes_scanned_total` (counter)

Total bytes of request bodies scanned.

```
# HELP lumen_argus_bytes_scanned_total Total bytes scanned
# TYPE lumen_argus_bytes_scanned_total counter
lumen_argus_bytes_scanned_total 8523614
```

---

#### `lumen_argus_findings_total` (counter)

Total findings by detection type (e.g., `aws_access_key`, `ssn`, `email`).

| Label | Values |
|-------|--------|
| `type` | Any detector finding type string |

```
# HELP lumen_argus_findings_total Total findings by type
# TYPE lumen_argus_findings_total counter
lumen_argus_findings_total{type="aws_access_key"} 3
lumen_argus_findings_total{type="email"} 12
lumen_argus_findings_total{type="github_token"} 1
```

---

#### `lumen_argus_provider_requests_total` (counter)

Total requests by detected upstream provider.

| Label | Values |
|-------|--------|
| `provider` | `anthropic`, `openai`, `gemini`, `unknown` |

```
# HELP lumen_argus_provider_requests_total Requests by provider
# TYPE lumen_argus_provider_requests_total counter
lumen_argus_provider_requests_total{provider="anthropic"} 95
lumen_argus_provider_requests_total{provider="openai"} 47
```

---

#### `lumen_argus_scan_duration_seconds` (summary)

Cumulative scan duration. Exposes `_sum` (total seconds spent scanning) and `_count` (number of scans performed). Divide sum by count to get average scan time.

```
# HELP lumen_argus_scan_duration_seconds Scan duration summary
# TYPE lumen_argus_scan_duration_seconds summary
lumen_argus_scan_duration_seconds_sum 1.234567
lumen_argus_scan_duration_seconds_count 142
```

### Full example

```bash
curl http://localhost:8080/metrics
```

```text
# HELP lumen_argus_active_requests Current in-flight requests
# TYPE lumen_argus_active_requests gauge
lumen_argus_active_requests 1
# HELP lumen_argus_requests_total Total proxied requests by action
# TYPE lumen_argus_requests_total counter
lumen_argus_requests_total{action="pass"} 130
lumen_argus_requests_total{action="alert"} 6
lumen_argus_requests_total{action="block"} 1
# HELP lumen_argus_bytes_scanned_total Total bytes scanned
# TYPE lumen_argus_bytes_scanned_total counter
lumen_argus_bytes_scanned_total 8523614
# HELP lumen_argus_findings_total Total findings by type
# TYPE lumen_argus_findings_total counter
lumen_argus_findings_total{type="aws_access_key"} 3
lumen_argus_findings_total{type="email"} 12
# HELP lumen_argus_provider_requests_total Requests by provider
# TYPE lumen_argus_provider_requests_total counter
lumen_argus_provider_requests_total{provider="anthropic"} 95
lumen_argus_provider_requests_total{provider="openai"} 42
# HELP lumen_argus_scan_duration_seconds Scan duration summary
# TYPE lumen_argus_scan_duration_seconds summary
lumen_argus_scan_duration_seconds_sum 1.234567
lumen_argus_scan_duration_seconds_count 137
```

Plugins may append additional metrics via `set_metrics_hook()`.

!!! note "Prometheus scrape config"
    Add a scrape job to your `prometheus.yml`:

    ```yaml
    scrape_configs:
      - job_name: lumen-argus
        static_configs:
          - targets: ["localhost:8080"]
        metrics_path: /metrics
        scrape_interval: 15s
    ```

---

## Dashboard API

The dashboard runs on a separate port (default `8081`) and provides a REST API for the web UI.

### Read endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/status` | GET | Health, uptime, version, tier, proxy port/bind, standalone |
| `/api/v1/build` | GET | Build identity for sidecar adoption (`build_id` = SHA256 of running binary) + loaded plugins |
| `/api/v1/findings` | GET | Paginated findings with severity/detector/provider/session/account filters |
| `/api/v1/sessions` | GET | Sessions grouped by session_id with finding counts and metadata |
| `/api/v1/findings/:id` | GET | Single finding detail |
| `/api/v1/findings/export` | GET | CSV or JSON export (via `?format=csv` or `?format=json`) |
| `/api/v1/stats` | GET | Aggregated statistics for dashboard charts (`?days=N`, default 30) |
| `/api/v1/stats/advanced` | GET | Action trend, activity matrix, top accounts/projects, detection coverage |
| `/api/v1/config` | GET | Sanitized config (plugin sections appear when registered) |
| `/api/v1/config` | PUT | Save settings to DB. Triggers SIGHUP reload. |
| `/api/v1/pipeline` | GET | Pipeline stage configuration with per-stage stats and encoding settings |
| `/api/v1/pipeline` | PUT | Save stage toggles, detector enables/actions, encoding settings. Triggers SIGHUP reload. |
| `/api/v1/audit` | GET | Paginated audit log entries with action/provider/search filters |
| `/api/v1/audit/export` | GET | Audit log CSV/JSON export |
| `/api/v1/logs/tail` | GET | Last 100 lines of application log |
| `/api/v1/logs/download` | GET | Full sanitized log download |
| `/api/v1/live` | GET | SSE real-time event stream |

### Notification endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/notifications/types` | GET | Registered channel types (label + field schema) |
| `/api/v1/notifications/channels` | GET | List all channels (config masked, enriched with dispatch status) |
| `/api/v1/notifications/channels` | POST | Create channel (type validated, plugin-imposed cap enforced if any, events array) |
| `/api/v1/notifications/channels/:id` | GET | Full channel config (for edit form) |
| `/api/v1/notifications/channels/:id` | PUT | Update channel (partial) |
| `/api/v1/notifications/channels/:id` | DELETE | Delete channel |
| `/api/v1/notifications/channels/:id/test` | POST | Send test notification |
| `/api/v1/notifications/channels/batch` | POST | Bulk enable/disable/delete |

### Rules endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/rules` | GET | Paginated rules list with search/filter by tier, detector, severity, enabled, tag |
| `/api/v1/rules` | POST | Create custom rule (source='dashboard', tier='custom') |
| `/api/v1/rules/stats` | GET | Rule counts by tier, detector, enabled status, and tag aggregation |
| `/api/v1/rules/:name` | GET | Single rule detail |
| `/api/v1/rules/:name` | PUT | Update rule (action, enabled, severity, pattern, tags, etc.) |
| `/api/v1/rules/:name` | DELETE | Delete dashboard-created rules only (source='dashboard') |
| `/api/v1/rules/:name/clone` | POST | Clone rule to custom tier (source='dashboard') |
| `/api/v1/rules/bulk-update` | POST | Batch update rules in a single transaction (max 500) |

`GET /api/v1/rules` supports these query parameters:

| Parameter | Description |
|-----------|-------------|
| `limit` | Page size (default 50, max 200) |
| `offset` | Pagination offset (default 0) |
| `search` / `q` | Search by name or description |
| `detector` | Filter by detector (secrets, pii, injection, custom) |
| `tier` | Filter by tier (community, pro, custom) |
| `severity` | Filter by severity (critical, high, warning, info) |
| `enabled` | Filter by status (`true` or `false`) |
| `tag` | Filter by tag (exact match in JSON tags array) |

`POST /api/v1/rules` and `PUT /api/v1/rules/:name` validate the `action` field against the registered action set. Community ships with `log`, `alert`, `redact`, `block` (plus the empty-string default); plugins can register additional actions via the dashboard JS `registerPipelineAction(name)` hook.

`GET /api/v1/rules` search supports comma-separated terms for OR matching (e.g., `?search=generic_secret,env_file_assignment` returns rules matching either name).

`POST /api/v1/rules/bulk-update` applies the same update to multiple rules in a single transaction. Body: `{"names": ["rule_a", "rule_b"], "update": {"enabled": false}}`. Returns `{"updated": 2, "failed": [], "message": "Updated 2 rules"}`. Failed names include per-name reason. Capped at 500 names per request.

### Rule Analysis endpoints

Rule overlap analysis using [crossfire-rules](https://pypi.org/project/crossfire-rules/) (optional dependency). When `crossfire-rules` is not installed, GET returns `{"available": false}`.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/rules/analysis` | GET | Get cached analysis results (duplicates, subsets, overlaps, clusters) |
| `/api/v1/rules/analysis` | POST | Trigger new analysis (runs in background, returns 202). Returns 409 if already running |
| `/api/v1/rules/analysis/status` | GET | Analysis progress (running, phase, progress text, log lines). Supports `?since=N` for incremental log streaming |
| `/api/v1/rules/analysis/dismiss` | POST | Dismiss a finding pair. Body: `{"rule_a": "...", "rule_b": "..."}` |

Install: `pip install lumen-argus-proxy[rules-analysis]` (or `pip install crossfire-rules[re2]`)

### Allowlist endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/allowlists` | GET | Merged allowlist entries (YAML config + API-managed) |
| `/api/v1/allowlists` | POST | Add allowlist entry |
| `/api/v1/allowlists/test` | POST | Test pattern against value and recent findings |
| `/api/v1/allowlists/:id` | DELETE | Delete API-managed entry (config entries are read-only) |

`GET /api/v1/allowlists` returns entries grouped by type with source attribution:

```json
{
  "secrets": [
    {"pattern": "sk-ant-*", "source": "config"},
    {"pattern": "AKIA_TEST_*", "source": "api", "id": 1}
  ],
  "pii": [{"pattern": "*@example.com", "source": "config"}],
  "paths": [],
  "api_entries": [{"id": 1, "list_type": "secrets", "pattern": "AKIA_TEST_*", "source": "api", "created_at": "..."}]
}
```

`POST /api/v1/allowlists` requires `type` (secrets, pii, or paths) and `pattern`. Config-defined entries (from YAML) are read-only and cannot be deleted via the API.

`POST /api/v1/allowlists/test` accepts `pattern` and optional `value`. Returns `value_match` (boolean) and up to 20 matching recent findings from the database.

### Other mutation endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/license` | POST | Save license key to `~/.lumen-argus/license.key` |

### Authentication

When `dashboard.password` is set (or `LUMEN_ARGUS_DASHBOARD_PASSWORD` env var), all mutation endpoints (POST, PUT, DELETE) require session auth + CSRF token. GET endpoints also require authentication except for `/api/v1/live` (SSE) and export endpoints.

### Session tracking

`GET /api/v1/findings` supports filtering:

| Parameter | Description |
|-----------|-------------|
| `severity` | Filter by severity level (critical, high, warning, info) |
| `detector` | Filter by detector (secrets, pii, proprietary) |
| `action` | Filter by action taken (block, alert, redact, log) |
| `finding_type` | Filter by finding type (e.g., aws_access_key, ssn) |
| `provider` | Filter by API provider (anthropic, openai) |
| `client` | Filter by client name (claude, cursor) |
| `days` | Filter by time range (e.g., 1 = today, 7, 30, 90) |
| `session_id` | Filter by session/conversation ID |
| `account_id` | Filter by account (Anthropic UUID or OpenAI user) |

`GET /api/v1/clients` returns the catalog of supported AI CLI agents with setup instructions:

```json
{
  "clients": [
    {
      "id": "claude_code",
      "display_name": "Claude Code",
      "category": "cli",
      "provider": "anthropic",
      "ua_prefixes": ["claude-code/"],
      "proxy_config": {
        "config_type": "env_var",
        "setup_instructions": "Set ANTHROPIC_BASE_URL to the proxy URL.",
        "env_var": "ANTHROPIC_BASE_URL",
        "setup_cmd": "ANTHROPIC_BASE_URL=http://localhost:8080 claude"
      },
      "website": "https://claude.ai/code"
    }
  ]
}
```

Plugins may extend the list via `extensions.register_clients()`.

`GET /api/v1/sessions` returns sessions grouped by `session_id`:

```json
{
  "sessions": [
    {
      "session_id": "7ef7b337-2fed-492f-9a81-7c9d091eccd6",
      "first_seen": "2026-03-19T15:09:47Z",
      "last_seen": "2026-03-19T15:24:12Z",
      "finding_count": 12,
      "provider": "anthropic",
      "model": "claude-opus-4-6",
      "account_id": "dbd6eafd-726c-4e2c-93ae-9132dae86705",
      "device_id": "dd7554a9...",
      "working_directory": "/Users/dev/myproject",
      "git_branch": "main"
    }
  ]
}
```

Supports `?limit=N` (default 50, max 100).

`GET /api/v1/sessions/dashboard` returns active sessions (last 24 hours) with per-severity breakdown for the dashboard panel. Includes `total` count (uncapped) and `sessions` list (capped at `?limit=N`, default 5, max 10).

### Stats parameters

`GET /api/v1/stats` supports a time range parameter:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `days` | `30` | Number of days for `daily_trend` (1–365). Totals and breakdowns are always all-time. |

Response includes `today_count` (findings from today), `last_finding_time` (most recent finding timestamp), `by_client` (findings grouped by client name), plus existing `by_severity`, `by_detector`, `by_action`, `by_provider`, `by_model`, `top_finding_types`, and `daily_trend`.

The dashboard trend chart includes a 7d / 30d / 90d toggle that sets this parameter.

### Advanced analytics

`GET /api/v1/stats/advanced?days=N` returns data for dashboard analytics charts:

```json
{
  "action_trend": [
    {"date": "2026-03-15", "block": 3, "redact": 1, "alert": 12, "log": 5}
  ],
  "activity_matrix": [
    {"weekday": "Mon", "hours": [0, 0, 5, 2, 0, 0, 0, 0, 3, 8, 12, 7, 4, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]},
    {"weekday": "Tue", "hours": [0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 5, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}
  ],
  "top_accounts": [
    {"account_id": "dbd6eafd-...", "count": 42}
  ],
  "top_projects": [
    {"working_directory": "/Users/dev/myproject", "count": 28}
  ],
  "detection_coverage": {
    "active_rules": 43,
    "total_rules": 45
  }
}
```

Plugins may extend this response with additional fields such as channel dispatch health.

### Pipeline configuration

`GET /api/v1/pipeline` returns the scanning pipeline configuration with per-stage stats:

```json
{
  "default_action": "alert",
  "stages": [
    {
      "name": "outbound_dlp",
      "label": "Outbound DLP",
      "description": "Secret, PII, and proprietary code detection on outbound requests",
      "group": "request",
      "enabled": true,
      "available": true,
      "finding_count": 142,
      "sub_detectors": [
        {"name": "secrets", "enabled": true, "action": "block", "finding_count": 98},
        {"name": "pii", "enabled": true, "action": "default", "finding_count": 31},
        {"name": "proprietary", "enabled": true, "action": "default", "finding_count": 13}
      ]
    },
    {
      "name": "encoding_decode",
      "label": "Encoding Decode",
      "description": "Decode base64, hex, URL, and Unicode before scanning",
      "group": "request",
      "enabled": true,
      "available": true,
      "finding_count": 0,
      "encoding_settings": {
        "base64": true, "hex": true, "url": true, "unicode": true,
        "max_depth": 2, "min_decoded_length": 8, "max_decoded_length": 10000
      }
    },
    {
      "name": "response_secrets",
      "label": "Response Secrets",
      "group": "response",
      "enabled": false,
      "available": false
    }
  ]
}
```

`PUT /api/v1/pipeline` accepts partial updates:

```json
{
  "default_action": "block",
  "stages": {
    "outbound_dlp": {"enabled": true},
    "encoding_decode": {"enabled": false}
  },
  "detectors": {
    "secrets": {"enabled": true, "action": "block"},
    "pii": {"enabled": false}
  },
  "encoding_settings": {
    "base64": true,
    "hex": false,
    "max_depth": 3
  }
}
```

Returns `{"applied": {...}, "errors": [...]}`. Triggers SIGHUP for immediate reload.

Key fields:

- `available`: `false` for stages not yet implemented — dashboard shows "Coming soon"
- `action`: `"default"` means using the global `default_action`, any other value is an explicit override
- `sub_detectors`: only present on `outbound_dlp` stage
- `encoding_settings`: only present on `encoding_decode` stage

### Channel limit enforcement

Community ships with no channel cap; plugins may impose one by calling
`extensions.set_channel_limit(N)`. When that limit is reached,
`POST /api/v1/notifications/channels` returns `409`:

```json
{
  "error": "channel_limit_reached",
  "message": "Channel limit reached.",
  "limit": 1,
  "count": 1
}
```

---

## `GET /api/v1/build`

Returns the running sidecar's build identity. Designed for sidecar-adoption callers that want to decide whether a still-running process is safe to reuse, or whether the binary on disk has changed since it was spawned and the process should be respawned.

Exposed on both the **proxy dashboard** (`:8081`) and the **agent relay** (`:8070`) — see [Agent Relay API](#agent-relay-api) for the agent's version, which emits the same shape.

### Response

**Status:** `200 OK`
**Content-Type:** `application/json`

```json
{
  "service": "lumen-argus",
  "version": "0.1.0",
  "git_commit": "2e3947b670cad8fe7fb0262bf73ac1e9a8fb5087",
  "build_id": "sha256:def4567890abcdef...",
  "built_at": "2026-04-18T06:51:03Z",
  "plugins": [
    {
      "name": "lumen-argus-pro",
      "version": "0.3.0",
      "git_commit": "789ab12cafef00d...",
      "build_id": "sha256:abcdef01..."
    }
  ]
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `service` | `str` | `"lumen-argus"` (proxy) or `"lumen-argus-agent"` (relay). |
| `version` | `str` | Semantic version from the package's `pyproject.toml` at build time. Falls back to the package's `__version__` in dev runs. |
| `git_commit` | `str` | `git rev-parse HEAD` at build time (40-char SHA). `"unknown"` in dev runs or outside a git checkout. |
| `build_id` | `str` | `sha256:<hex>` of the running binary (`sys.executable`). Cached once per process. **This is the authoritative comparator** — two processes with the same `build_id` are running identical binary bytes. `sha256:unknown` if the executable is unreadable. |
| `built_at` | `str` | RFC3339 UTC timestamp of the PyInstaller build. `"unknown"` in dev runs. |
| `plugins` | `list[object]` | Loaded plugins' build identities. Empty on the agent (the agent never loads plugins). On the proxy, each entry has the same four fields as the top-level shape (`name`, `version`, `git_commit`, `build_id`) — read from the plugin module's `__build_info__` attribute. Plugins that haven't shipped `__build_info__` still appear, with `git_commit` / `build_id` defaulted to the `"unknown"` sentinels. |

### Authentication

- **Proxy** (`:8081`): same auth as every other `/api/v1/*` route — session cookie or Bearer token (via plugin-registered agent auth provider). Unauthenticated requests return `401`.
- **Agent relay** (`:8070`): no inbound auth. The relay binds loopback-only; this endpoint mirrors `/health` in that respect. The rest of the relay's surface is transparent forwarding, so a dedicated bearer scheme for one endpoint would be inconsistent.

### Stability

The response shape is a **stable contract within a major version** of `lumen-argus-core` (which defines the shared helper both services use to build the response). Downstream callers that parse specific fields — e.g. `jq '.plugins[].build_id'` in a release-verification script — can rely on these guarantees:

- Top-level fields (`service`, `version`, `git_commit`, `build_id`, `built_at`, `plugins`) will remain present with the types documented above.
- Each `plugins[]` entry will retain the four fields documented (`name`, `version`, `git_commit`, `build_id`).
- **Additive changes** — new top-level fields, or new fields inside `plugins[]` entries — are **not** considered breaking. Parsers should ignore unknown fields gracefully.
- **Breaking changes** (field removal, type change, rename, semantic repurpose) require a major version bump on `lumen-argus-core`, with a one-minor-version deprecation window: the new shape ships as additive in version `N.(M+1).0`, and the old shape is removed no earlier than `(N+1).0.0`.
- Sentinel values (`"unknown"`, `"sha256:unknown"`) are part of the contract — callers should treat them as valid values rather than parse errors.

The stability guarantee covers the response **shape**, not the values. `build_id` and `git_commit` are expected to change on every rebuild — that's the point.

### Why `build_id` is computed at runtime

A PyInstaller onefile binary extracts to `/tmp/_MEIxxxxx` at spawn and lazy-loads modules from there. If the on-disk binary is replaced between spawn and the next request (auto-update, manual rebuild), lazy imports can fail (`zlib.error: Error -3`) — `/api/v1/status` will still return `200` because its code path is already loaded, but the dashboard HTML route will `500`. Hashing `sys.executable` at request time reflects exactly the bytes the current process is running from; a caller comparing it against a bundled manifest catches the drift before relying on the process.

### Example

```bash
curl -s http://localhost:8081/api/v1/build | jq
```

---

## Agent Relay API

The agent relay (`lumen-argus-agent relay`, default port `8070`) is primarily a **forwarding proxy** — it wraps AI API traffic with OS-level identity headers and sends it to the upstream proxy. Two loopback-only diagnostic endpoints are served out of that same port.

### `GET /health`

Returns the relay's status and upstream health.

```json
{
  "status": "ok",
  "upstream": "healthy",
  "upstream_url": "http://localhost:8080",
  "fail_mode": "open",
  "agent_id": "agent_abc123",
  "enrolled": true,
  "uptime": 143.2
}
```

No authentication required — designed for sidecar-adoption callers and local health checks.

### `GET /api/v1/build`

Same shape as the proxy's `/api/v1/build` (see [above](#get-apiv1build)), with `service = "lumen-argus-agent"` and `plugins = []` (the agent never loads plugins). No authentication — loopback-only.
