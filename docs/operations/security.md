# Security

## Network Security

### Localhost-Only Binding

lumen-argus **always** binds to `127.0.0.1` — never `0.0.0.0`. This is enforced by a runtime assertion in `ArgusProxyServer.__init__`:

```python
if bind != "127.0.0.1" and bind != "localhost":
    raise ValueError("lumen-argus must bind to 127.0.0.1 or localhost")
```

Setting `proxy.bind` to anything else in config produces a validation warning and the proxy refuses to start.

### Plain HTTP In, HTTPS Out

The proxy accepts plain HTTP on localhost (no TLS interception needed) and forwards to upstream AI providers over HTTPS. This means:

- No need to install custom CA certificates on the client
- No MITM — the proxy reads the request body, not the TLS stream
- Upstream TLS is validated against system CA bundles

### Corporate Proxy / Custom CA

If behind a corporate proxy with custom certificate authority:

```yaml
proxy:
  ca_bundle: "/path/to/corporate-ca.pem"  # or directory of CA certs
```

For development/testing only:

```yaml
proxy:
  verify_ssl: false  # WARNING: disables TLS verification
```

!!! warning
    `verify_ssl: false` logs a warning on startup and should never be used in production.

## Data Security

### Matched Values Never Persisted

The actual secret/PII value (`Finding.matched_value`) is kept in memory only:

- **Audit log**: excluded from `AuditEntry.to_dict()` serialization
- **Application log**: only finding type and count are logged, never values
- **Metrics**: only aggregated counters by type
- **Baseline files**: SHA-256 hash of the value, not the value itself

This prevents the proxy from becoming a secondary exfiltration vector. If logs are shared with support, no secrets leak.

### File Permissions

| Resource | Permissions | Method |
|----------|-------------|--------|
| Application log | `0o600` | Atomic via `os.open()` with `O_CREAT` |
| Rotated log files | `0o600` | Secured on rotation via `doRollover()` |
| Log directory | `0o700` | Created with `os.makedirs(mode=0o700)` |
| Audit log | `0o600` | Atomic via `os.open()` with `O_CREAT` |

### Connection Isolation

Connection pooling is scoped per-host — connections to `api.anthropic.com` are never reused for `api.openai.com`. Authorization headers are forwarded only to the intended provider.

## Backpressure

The `proxy.max_connections` setting (default: 10) limits concurrent upstream connections using a semaphore. This prevents:

- File descriptor exhaustion under heavy parallel sub-agent usage
- Overwhelming upstream providers with too many connections
- Thread contention on shared resources

When the limit is reached, requests are queued and a WARNING is logged.

## Graceful Shutdown

On SIGINT/SIGTERM, lumen-argus:

1. Stops accepting new connections
2. Waits up to `proxy.drain_timeout` seconds for in-flight requests
3. Force-closes remaining connections if timeout reached
4. Logs shutdown summary

```yaml
proxy:
  drain_timeout: 30  # seconds, 0 = immediate shutdown
```
