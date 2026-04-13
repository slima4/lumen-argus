# API Endpoints

lumen-argus exposes endpoints on two ports:

- **Proxy port** (default `8080`): `/health` and `/metrics` — handled directly, not forwarded to AI providers
- **Dashboard port** (default `8081`): `/api/v1/*` — dashboard API for findings, stats, notifications, and more

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

Pro extends this response via `set_health_hook()` with license status, notification channel health, and analytics metrics.

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
| `action` | `pass`, `log`, `alert`, `block` |

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

Pro extends `/metrics` via `set_metrics_hook()` with notification dispatch stats, license metrics, and more.

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
| `/api/v1/findings` | GET | Paginated findings with severity/detector/provider/session/account filters |
| `/api/v1/sessions` | GET | Sessions grouped by session_id with finding counts and metadata |
| `/api/v1/findings/:id` | GET | Single finding detail |
| `/api/v1/findings/export` | GET | CSV or JSON export (via `?format=csv` or `?format=json`) |
| `/api/v1/stats` | GET | Aggregated statistics for dashboard charts (`?days=N`, default 30) |
| `/api/v1/stats/advanced` | GET | Pro analytics: action trend, activity matrix, top accounts/projects, coverage (402 without Pro) |
| `/api/v1/config` | GET | Sanitized config (community + Pro sections) |
| `/api/v1/config` | PUT | Save settings to DB (community: proxy; Pro: all). Triggers SIGHUP reload. |
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

`POST /api/v1/rules` and `PUT /api/v1/rules/:name` validate the `action` field. Community allows: empty string (default), `log`, `alert`, `block`. Pro overrides to also allow `redact`.

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

### Pro-only endpoints

These return `402 pro_required` when Pro is not active:

| Endpoint | Description |
|----------|-------------|
| `/api/v1/stats/advanced` | Advanced analytics (action trend, activity matrix, top accounts, top projects, detection coverage) |

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

Pro extends the list with enterprise clients via `extensions.register_clients()`.

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

### Advanced analytics (Pro)

`GET /api/v1/stats/advanced?days=N` returns data for Pro dashboard charts. Returns `402 pro_required` without a valid Pro license.

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
    "total_rules": 45,
    "pro_imported": 1800
  }
}
```

Pro extends this response with `notification_health` (per-channel dispatch status).

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
