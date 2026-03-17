# API Endpoints

lumen-argus exposes two local HTTP endpoints for health checks and monitoring. These endpoints are handled directly by the proxy and are **not forwarded** to upstream AI providers.

Both endpoints are available at `http://127.0.0.1:<port>/` where `<port>` is the configured proxy port (default `8080`).

---

## `GET /health`

Returns the proxy's current status as JSON.

### Response

**Status:** `200 OK`
**Content-Type:** `application/json`

```json
{
  "status": "ok",
  "version": "0.5.0",
  "requests": 142
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `status` | `str` | Always `"ok"` when the proxy is running. |
| `version` | `str` | lumen-argus version string. |
| `requests` | `int` | Total number of proxied requests since startup. |

### Example

```bash
curl http://localhost:8080/health
```

```json
{"status": "ok", "version": "0.5.0", "requests": 42}
```

!!! tip "Use in monitoring"
    Point your uptime monitor or load balancer health check at `/health`. A successful `200` response confirms the proxy is accepting connections.

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
