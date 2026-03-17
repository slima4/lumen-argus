# Monitoring

## Health Check

```bash
curl http://localhost:8080/health
```

```json
{
  "status": "ok",
  "version": "0.1.0",
  "requests": 42
}
```

Use for load balancer health checks or uptime monitoring.

## Prometheus Metrics

```bash
curl http://localhost:8080/metrics
```

Returns metrics in [Prometheus exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/):

```
# HELP lumen_argus_active_requests Current in-flight requests
# TYPE lumen_argus_active_requests gauge
lumen_argus_active_requests 3

# HELP lumen_argus_requests_total Total proxied requests by action
# TYPE lumen_argus_requests_total counter
lumen_argus_requests_total{action="pass"} 42
lumen_argus_requests_total{action="alert"} 7
lumen_argus_requests_total{action="block"} 2

# HELP lumen_argus_bytes_scanned_total Total bytes scanned
# TYPE lumen_argus_bytes_scanned_total counter
lumen_argus_bytes_scanned_total 45000000

# HELP lumen_argus_findings_total Total findings by type
# TYPE lumen_argus_findings_total counter
lumen_argus_findings_total{type="aws_access_key"} 15
lumen_argus_findings_total{type="email"} 8

# HELP lumen_argus_provider_requests_total Requests by provider
# TYPE lumen_argus_provider_requests_total counter
lumen_argus_provider_requests_total{provider="anthropic"} 40
lumen_argus_provider_requests_total{provider="openai"} 11

# HELP lumen_argus_scan_duration_seconds Scan duration summary
# TYPE lumen_argus_scan_duration_seconds summary
lumen_argus_scan_duration_seconds_sum 1.234000
lumen_argus_scan_duration_seconds_count 51
```

### Available Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `lumen_argus_active_requests` | gauge | — | Currently in-flight requests |
| `lumen_argus_requests_total` | counter | `action` | Total requests by action (pass/alert/block) |
| `lumen_argus_bytes_scanned_total` | counter | — | Total bytes scanned |
| `lumen_argus_findings_total` | counter | `type` | Total findings by detection type |
| `lumen_argus_provider_requests_total` | counter | `provider` | Requests by AI provider |
| `lumen_argus_scan_duration_seconds` | summary | — | Scan duration (sum + count) |

### Prometheus Scrape Config

```yaml
# prometheus.yml
scrape_configs:
  - job_name: lumen-argus
    static_configs:
      - targets: ["localhost:8080"]
    metrics_path: /metrics
    scrape_interval: 15s
```

### Grafana Dashboard

Useful queries:

```promql
# Request rate by action
rate(lumen_argus_requests_total[5m])

# Block rate
rate(lumen_argus_requests_total{action="block"}[5m])

# Average scan duration
rate(lumen_argus_scan_duration_seconds_sum[5m]) / rate(lumen_argus_scan_duration_seconds_count[5m])

# Active requests
lumen_argus_active_requests
```

## Session Stats

On shutdown, lumen-argus logs a summary:

```
shutdown: 51 requests, uptime 3600s
```

The terminal display shows a detailed breakdown:

```
  shutdown — 51 requests | 2 blocked | 7 alerts | avg scan 12.3ms
  findings: aws_access_key x15, email x8, private_key x3
```
