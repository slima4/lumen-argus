# Configuration

A default config is created at `~/.lumen-argus/config.yaml` on first run. Edit it to customize behavior.

## Full Config Example

```yaml
version: "1"

proxy:
  port: 8080
  bind: "127.0.0.1"
  timeout: 120            # idle-read timeout (seconds)
  connect_timeout: 10     # TCP connect timeout (seconds)
  retries: 1              # retry count on connection failure
  max_connections: 50     # max concurrent upstream connections
  drain_timeout: 30       # seconds to wait for in-flight requests on shutdown
  # ca_bundle: "/path/to/ca-certs.pem"  # custom CA for corporate proxies
  # verify_ssl: false     # disable TLS verification (dev only)

# Global default action: log | alert | block
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

# Never flag these
allowlists:
  secrets:
    - "sk-ant-api03-example-key-not-real"
  pii:
    - "*@example.com"
    - "*@test.local"
  paths:
    - "test/**"
    - "tests/**"
    - "fixtures/**"

# Custom detection patterns
custom_rules:
  - name: internal_api_token
    pattern: "itk_[a-zA-Z0-9]{32}"
    severity: critical
    action: block
  - name: staging_db_url
    pattern: "postgres://staging[^\\s]+"
    severity: high

# Web dashboard
dashboard:
  enabled: true
  port: 8081
  bind: "127.0.0.1"
  # password: ""  # or LUMEN_ARGUS_DASHBOARD_PASSWORD env var

# Analytics store (SQLite, powers dashboard charts)
analytics:
  enabled: true
  db_path: "~/.lumen-argus/analytics.db"
  retention_days: 365

# Application logging (file rotation)
logging:
  log_dir: "~/.lumen-argus/logs"
  file_level: info          # debug | info | warning | error
  max_size_mb: 10           # max size before rotation
  backup_count: 5           # rotated files to keep

# Audit log
audit:
  log_dir: "~/.lumen-argus/audit"
  retention_days: 90
```

## Config Locations

| Location | Purpose |
|----------|---------|
| `~/.lumen-argus/config.yaml` | Global config (created on first run) |
| `.lumen-argus.yaml` | Project-level overrides (committed to repo) |
| `--config PATH` | CLI flag to specify config path |

## Project-Level Overrides

Commit `.lumen-argus.yaml` to your repo root to enforce project-specific rules. Project config merges with global config and can only be **more restrictive** (cannot downgrade `block` to `alert`).

```yaml
# .lumen-argus.yaml — project-level (more restrictive only)
detectors:
  pii:
    action: block  # upgrade from alert to block for this project
allowlists:
  paths:
    - "docs/**"    # additional paths to ignore
```

## Hot-Reload

Send `SIGHUP` to reload config without restarting:

```bash
kill -HUP $(pgrep -f "lumen_argus")
```

Updates allowlists, action overrides, timeout, connect timeout, retries, file log level, SSL context, and custom rules. Changed settings are logged. No proxy downtime.

!!! note
    `proxy.max_connections`, `dashboard.*`, and `analytics.*` require a restart to take effect.

See the [Config Schema Reference](../reference/config.md) for every config key.
