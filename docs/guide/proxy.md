# Proxy Server

The `lumen-argus serve` command starts a transparent HTTP proxy on localhost
that intercepts requests from AI coding tools, scans them for sensitive data,
and forwards clean requests to the upstream API provider over HTTPS.

## Starting the Proxy

```bash
# Default: port 8080, all detectors enabled
lumen-argus serve

# Custom port
lumen-argus serve --port 9090

# With explicit config
lumen-argus serve --config /path/to/config.yaml

# JSON output (for log aggregation)
lumen-argus serve --format json

# Debug logging
lumen-argus serve --log-level debug
```

### CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--port`, `-p` | `8080` | Port to listen on (overrides config) |
| `--config`, `-c` | `~/.lumen-argus/config.yaml` | Path to config file |
| `--log-dir` | `~/.lumen-argus/audit` | Audit log directory |
| `--format`, `-f` | `text` | Output format: `text` or `json` |
| `--no-color` | off | Disable ANSI color output |
| `--log-level` | `warning` | Console log verbosity: `debug`, `info`, `warning`, `error` |

---

## Provider Auto-Detection

lumen-argus automatically routes requests to the correct upstream API based on
the request path and headers. No manual provider configuration is needed.

=== "Anthropic"

    **Detected by:**

    - Path starts with `/v1/messages` or `/v1/complete`
    - Header `x-api-key` is present
    - Header `anthropic-version` is present
    - Authorization header contains `Bearer sk-ant-`

    **Upstream:** `https://api.anthropic.com`

=== "OpenAI"

    **Detected by:**

    - Path starts with `/v1/chat/completions`
    - Path starts with `/v1/completions`
    - Path starts with `/v1/embeddings`
    - Authorization header contains `Bearer sk-`

    **Upstream:** `https://api.openai.com`

=== "Gemini"

    **Detected by:**

    - Path contains `/generateContent`
    - Path starts with `/v1beta/`

    **Upstream:** `https://generativelanguage.googleapis.com`

### Connecting AI Tools

Point each tool's base URL environment variable at the proxy:

```bash
# Claude Code
export ANTHROPIC_BASE_URL=http://localhost:8080

# GitHub Copilot / OpenAI-compatible tools
export OPENAI_BASE_URL=http://localhost:8080

# Gemini
export GEMINI_BASE_URL=http://localhost:8080
```

---

## Connection Pooling

lumen-argus maintains a per-host connection pool for upstream HTTPS connections.
Non-streaming responses return their connection to the pool for reuse. SSE
streaming connections are consumed fully and closed (they cannot be reused
mid-stream).

```yaml title="~/.lumen-argus/config.yaml"
proxy:
  timeout: 120        # Socket timeout in seconds (1-300)
  retries: 1          # Retry count on connection failure (0-5)
```

!!! info "Idle connection eviction"
    Pooled connections are evicted after sitting idle for `timeout * 2` seconds.
    When a retry occurs after a stale-connection failure, the retry bypasses
    the pool and creates a fresh connection.

---

## Backpressure

The proxy limits concurrent upstream connections with a semaphore to prevent
overwhelming the upstream provider during bursts.

```yaml title="~/.lumen-argus/config.yaml"
proxy:
  max_connections: 10   # Max concurrent upstream connections (1-100)
```

When all connection slots are in use, new requests queue on the semaphore. A
warning is logged when a request has to wait:

```
WARNING: #42 queued — max concurrent connections reached
```

!!! warning "Changing `max_connections` requires restart"
    Unlike most config values, `max_connections` cannot be updated via SIGHUP
    reload. The semaphore is initialized at startup and changing it requires
    restarting the proxy.

---

## Graceful Shutdown

On `SIGINT` or `SIGTERM`, lumen-argus stops accepting new connections and waits
for in-flight requests to complete before exiting.

```yaml title="~/.lumen-argus/config.yaml"
proxy:
  drain_timeout: 30   # Seconds to wait for in-flight requests (0-300)
```

The shutdown sequence:

1. Signal received -- stop accepting new connections
2. Wait up to `drain_timeout` seconds for active requests to finish
3. Force-close any requests still active after the timeout (logged as a warning)
4. Close the connection pool
5. Flush and close audit logs
6. Print session summary

A second signal during the drain period forces an immediate exit.

---

## TLS Configuration

### Corporate Proxy / Custom CA

If your organization uses a TLS-intercepting proxy, provide the CA certificate
bundle:

```yaml title="~/.lumen-argus/config.yaml"
proxy:
  ca_bundle: /etc/ssl/certs/corporate-ca.pem
```

The `ca_bundle` value can be a path to a single PEM file or a directory of
certificates. The path is validated at config load time.

### Disable Verification (Development Only)

```yaml title="~/.lumen-argus/config.yaml"
proxy:
  verify_ssl: false
```

!!! danger "Never disable TLS verification in production"
    Setting `verify_ssl: false` disables all certificate checks, making the
    connection vulnerable to man-in-the-middle attacks. A warning is logged on
    every startup when this is set.

TLS settings reload on `SIGHUP` -- the SSL context is rebuilt and all pooled
connections are closed so new ones pick up the updated certificates.

---

## SSE Streaming Passthrough

For streaming API responses (used by Claude, ChatGPT, and other LLM providers),
lumen-argus uses `read1()` for low-latency chunk forwarding. Each chunk is
written to the client and flushed immediately, preserving the real-time
streaming experience.

```
Client <-- HTTP (SSE chunks) <-- lumen-argus <-- HTTPS (SSE chunks) <-- Provider
```

!!! note "Scanning happens on the request, not the response"
    lumen-argus scans the outbound request body (your prompts and context).
    Response streams are forwarded without inspection -- the goal is to prevent
    sensitive data from leaving your machine, not to filter what comes back.

---

## Performance

The proxy is designed to add minimal overhead to each request:

| Metric | Target |
|---|---|
| Scan latency | < 50ms per request |
| Scan budget | First 200KB of request body |
| Pattern compilation | At import time (zero per-request cost) |
| Connection reuse | Pooled HTTPS connections for non-streaming requests |

Bodies larger than `max_body_size` (default 50MB) skip scanning entirely with a
warning logged. This prevents memory issues with unusually large payloads.

```yaml title="~/.lumen-argus/config.yaml"
proxy:
  max_body_size: 52428800   # 50MB in bytes
```

---

## Local Endpoints

The proxy exposes two local endpoints that are handled directly (not forwarded
upstream):

### Health Check

```bash
curl http://localhost:8080/health
```

```json
{"status": "ok", "version": "0.1.0", "requests": 42}
```

### Metrics

```bash
curl http://localhost:8080/metrics
```

Returns Prometheus exposition format metrics including total requests,
active requests, and per-provider statistics.

---

## Configuration Reload

Send `SIGHUP` to reload the config file without restarting:

```bash
kill -HUP $(pgrep -f lumen-argus)
```

Reloadable settings include:

- Default action and per-detector action overrides
- Allowlists (secrets, PII, paths)
- Custom rules (recompiled on reload)
- Timeout and retry counts
- TLS settings (`ca_bundle`, `verify_ssl`)
- File log level

Settings that require a restart:

- `port` and `bind`
- `max_connections`

---

## Security Model

!!! info "Localhost only"
    The proxy binds exclusively to `127.0.0.1`. Attempting to set `bind` to
    `0.0.0.0` or any non-loopback address raises a `ValueError` at startup.
    This is enforced by a runtime assertion in the server constructor.

The proxy receives plain HTTP on localhost and upgrades to HTTPS for upstream
connections. Since the proxy only listens on loopback, the unencrypted local
hop never leaves the machine.
