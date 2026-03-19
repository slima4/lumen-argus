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
| `/api/v1/status` | GET | Health, uptime, version, tier (community/pro) |
| `/api/v1/findings` | GET | Paginated findings with severity/detector/provider filters |
| `/api/v1/findings/:id` | GET | Single finding detail |
| `/api/v1/findings/export` | GET | CSV or JSON export (via `?format=csv` or `?format=json`) |
| `/api/v1/stats` | GET | Aggregated statistics for dashboard charts |
| `/api/v1/config` | GET | Sanitized read-only config |
| `/api/v1/audit` | GET | Paginated audit log entries with action/provider/search filters |
| `/api/v1/audit/export` | GET | Audit log CSV/JSON export |
| `/api/v1/logs/tail` | GET | Last 100 lines of application log |
| `/api/v1/logs/download` | GET | Full sanitized log download |
| `/api/v1/live` | GET | SSE real-time event stream |

### Notification endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/notifications/types` | GET | Available channel types + channel limit + count |
| `/api/v1/notifications/channels` | GET | List all channels (config masked) |
| `/api/v1/notifications/channels` | POST | Create channel (type validated, limit enforced) |
| `/api/v1/notifications/channels/:id` | GET | Full channel config (for edit form) |
| `/api/v1/notifications/channels/:id` | PUT | Update channel (partial) |
| `/api/v1/notifications/channels/:id` | DELETE | Delete channel |
| `/api/v1/notifications/channels/:id/test` | POST | Send test notification |
| `/api/v1/notifications/channels/batch` | POST | Bulk enable/disable/delete |

### Other mutation endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/license` | POST | Save license key to `~/.lumen-argus/license.key` |

### Pro-only endpoints

These return `402 pro_required` when Pro is not active:

| Endpoint | Description |
|----------|-------------|
| `/api/v1/rules/*` | Custom rules management |
| `/api/v1/patterns/*` | Pattern browser and toggle |
| `/api/v1/allowlist/*` | Allowlist management |

### Authentication

When `dashboard.password` is set (or `LUMEN_ARGUS_DASHBOARD_PASSWORD` env var), all mutation endpoints (POST, PUT, DELETE) require session auth + CSRF token. GET endpoints also require authentication except for `/api/v1/live` (SSE) and export endpoints.

### Channel limit enforcement

`POST /api/v1/notifications/channels` returns `409` when the channel limit is reached:

```json
{
  "error": "channel_limit_reached",
  "message": "Free tier allows 1 channel(s). Upgrade to Pro for unlimited.",
  "limit": 1,
  "count": 1
}
```
