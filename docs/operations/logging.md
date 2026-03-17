# Logging

lumen-argus has two separate log systems: an **application log** for diagnostics and a **audit log** for compliance.

## Application Log

Written to `~/.lumen-argus/logs/lumen-argus.log` with automatic rotation.

### Configuration

```yaml
logging:
  log_dir: "~/.lumen-argus/logs"
  file_level: info          # debug | info | warning | error
  max_size_mb: 10           # max size before rotation
  backup_count: 5           # rotated files to keep (60MB total max)
```

The `--log-level` CLI flag controls **console** output only. The file always logs at `file_level` (default: `info`), which is typically more verbose than console.

### Log Levels

| Level | What's Logged |
|-------|---------------|
| **ERROR** | Upstream connection failures, config parse failures, plugin load failures, audit write failures |
| **WARNING** | Oversized body skipped, slow scan >50ms, config validation issues |
| **INFO** | Startup summary, block/redact actions, config reload, shutdown stats, audit rotation |
| **DEBUG** | Every request routing, scan results, field extraction, connection pool ops |

### Log Format

```
2026-03-16 14:30:00.123 INFO  [argus.proxy] #42 BLOCK aws_access_key, private_key_pem (2 findings)
2026-03-16 14:30:00.135 WARN  [argus.pipeline] slow scan: 87.3ms (12 fields, 198KB, budget 200KB)
2026-03-16 14:30:12.456 ERROR [argus.proxy] #43 upstream timeout after 120s
```

### File Permissions

Log files are created with `0o600` permissions (owner read/write only). The log directory is `0o700`. Permissions are enforced atomically on creation and after rotation — no race window.

### SIGHUP Reload

Send SIGHUP to update the file log level without restarting:

```bash
# In config.yaml, change: file_level: debug
kill -HUP $(pgrep -f "lumen_argus")
# Log shows: file log level: info -> debug
```

## Audit Log

Every proxied request produces a JSONL entry at `~/.lumen-argus/audit/guard-{timestamp}.jsonl`.

### What's Recorded

- Timestamp, request ID, provider, model, endpoint
- Action taken (pass/alert/block)
- Finding metadata (detector, type, severity, location)
- Scan duration, request size

### What's Never Recorded

- `Finding.matched_value` — the actual secret/PII value
- Request/response bodies
- API keys or authorization headers

This is a security invariant. Audit logs may be shared with support or stored in ticket systems.

### Retention

Old audit files are automatically deleted after `retention_days` (default: 90). Deletion is logged at INFO level.

## Export for Support

```bash
# Export with IPs, hostnames, and file paths stripped
lumen-argus logs export --sanitize > support-logs.txt

# Export full logs
lumen-argus logs export > full-logs.txt
```

The `--sanitize` flag strips:

- IP addresses → `[IP]`
- Hostnames (except AI provider domains) → `[HOST]`
- File paths → basename only

Keeps: timestamps, log levels, request IDs, finding types, actions, durations.
