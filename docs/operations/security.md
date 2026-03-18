# Security

## Network Security

### Bind Address

lumen-argus binds to `127.0.0.1` by default — both the proxy (port 8080) and dashboard (port 8081). Non-loopback binds log a warning.

For Docker containers, use the `--host` CLI flag:

```bash
lumen-argus serve --host 0.0.0.0
```

This overrides the bind address for both proxy and dashboard. Docker's port mapping (`-p`) then controls what's exposed to the host network.

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

## Dashboard Security

### Authentication

When `dashboard.password` is set (or `LUMEN_ARGUS_DASHBOARD_PASSWORD` env var), the dashboard requires authentication:

- **Sessions**: 8-hour timeout, stored server-side with `secrets.token_hex(32)`
- **Cookies**: `argus_session` (HttpOnly, SameSite=Strict), `csrf_token` (SameSite=Strict)
- **CSRF**: Double-submit cookie pattern with `secrets.compare_digest()` on all mutations (POST/PUT/DELETE). GET requests are exempt.
- **Login redirect**: Validates `next` parameter against open redirect (rejects `//`, `\/`) and CRLF header injection (strips `\r`, `\n`). Output URL-encoded via `urllib.parse.quote`.

### License Key Storage

License keys submitted via `POST /api/v1/license` are validated before writing:

- Maximum 4KB, no newline characters
- Saved to `~/.lumen-argus/license.key` with `0o600` permissions
- Read by Pro plugin on startup and SIGHUP reload

### Plugin Trust Model

Dashboard extensions are loaded from pip-installed entry points only:

- **`js` field**: Injected as raw `<script>` blocks server-side. Treated as **trusted code** — same trust level as any pip-installed package.
- **`html` field**: Sanitized client-side via `_safeInjectHTML()` which strips `<script>` tags and all `on*` event handlers before DOM insertion.
- **API handler**: Plugin API handler runs server-side with full access to the analytics store and audit reader.

Only install plugins from trusted sources.

### Thread Safety

- **AnalyticsStore**: Thread-local SQLite connections, WAL mode, write serialization via `threading.Lock`
- **AuditReader**: Cache protected by `threading.Lock` for concurrent dashboard requests
- **SSEBroadcaster**: Client list protected by lock; broadcast snapshots list before I/O
- **DashboardServer**: `ThreadingHTTPServer` with daemon threads; session storage lock-protected

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
| Analytics DB | `0o600` | `os.chmod()` on every startup |
| License key | `0o600` | `os.chmod()` after write |

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
