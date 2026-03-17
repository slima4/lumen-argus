# Config Schema Reference

lumen-argus loads configuration from YAML files in the following order:

1. **Global config**: `~/.lumen-argus/config.yaml` (created automatically on first run)
2. **Project config**: `.lumen-argus.yaml` in the current working directory (optional, can only be more restrictive)

The config uses a bundled YAML-subset parser (no PyYAML dependency). Supported syntax: mappings, sequences, scalars, quoted strings, inline comments. Not supported: anchors, aliases, multi-line block scalars (`|`, `>`), flow mappings (`{}`).

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
| `proxy.timeout` | `int` | `120` | Socket timeout in seconds for upstream connections. Range: 1--300. |
| `proxy.retries` | `int` | `1` | Number of retry attempts on upstream connection failure. Range: 0--5. |
| `proxy.max_body_size` | `int` | `52428800` | Maximum request body size in bytes to scan (50 MB). Bodies larger than this are forwarded without scanning. |
| `proxy.max_connections` | `int` | `10` | Maximum concurrent upstream connections. Additional requests queue until a slot opens. Range: 1--100. |
| `proxy.drain_timeout` | `int` | `30` | Seconds to wait for in-flight requests to complete during shutdown. Range: 0--300. |
| `proxy.ca_bundle` | `str` | `""` | Path to a custom CA certificate file or directory. Use this behind corporate proxies. Empty string uses system defaults. |
| `proxy.verify_ssl` | `bool` | `true` | Verify upstream TLS certificates. Set to `false` only for development/testing. |

```yaml title="Example"
proxy:
  port: 8080
  bind: "127.0.0.1"
  timeout: 120
  retries: 1
  max_body_size: 52428800
  max_connections: 10
  drain_timeout: 30
  ca_bundle: ""
  verify_ssl: true
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
    action: block
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

## Full config example

```yaml
version: "1"

proxy:
  port: 8080
  bind: "127.0.0.1"
  timeout: 120
  retries: 1
  max_body_size: 52428800
  max_connections: 10
  drain_timeout: 30
  ca_bundle: ""
  verify_ssl: true

default_action: alert

detectors:
  secrets:
    enabled: true
    action: block
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

logging:
  log_dir: "~/.lumen-argus/logs"
  file_level: info
  max_size_mb: 10
  backup_count: 5

audit:
  log_dir: "~/.lumen-argus/audit"
  retention_days: 90
```
