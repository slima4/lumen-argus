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
- `port` and `bind` (graceful rebind — in-flight requests complete on the old address)
- `max_body_size` (scan limit and aiohttp rejection limit)
- File log level

Settings that require a restart:

- `max_connections` (aiohttp connector is initialized at startup)
- `ca_bundle` and `verify_ssl` (SSL context is baked into the connector)

Settings that take effect on next shutdown:

- `drain_timeout`

---

## Passthrough Mode

The proxy supports an `active`/`passthrough` mode toggle for disabling inspection without stopping the proxy:

```bash
# Disable inspection (forward everything without scanning)
curl -X PUT localhost:8081/api/v1/config \
  -H "Content-Type: application/json" \
  -d '{"proxy.mode": "passthrough"}'

# Re-enable inspection
curl -X PUT localhost:8081/api/v1/config \
  -H "Content-Type: application/json" \
  -d '{"proxy.mode": "active"}'
```

In passthrough mode:

- All requests are forwarded without scanning (no findings, no blocking)
- Audit trail still logs requests with `action=pass`
- MCP scanning, response scanning, and WebSocket frame scanning are all skipped
- `GET /api/v1/status` includes `"mode": "active"` or `"mode": "passthrough"`
- SSE emits a `mode-changed` event on transition
- A `mode_changed` finding (severity=warning) is recorded when switching to passthrough

The mode is persisted in the SQLite config overrides — it survives proxy restarts.

!!! warning "No auth required"
    Any process that can reach the dashboard API can change the mode. This will be gated on auth/RBAC when available.

---

## Internal Fail-Open

The proxy never returns 5xx to an AI tool because of an internal scanning bug. All scanning paths are wrapped in try/except:

- **Pipeline scan failure** → request forwarded unscanned, `scan_error` finding logged (severity=critical)
- **MCP detection failure** → MCP scanning skipped, request forwarded normally
- **MCP argument scan failure** → arguments not scanned, request forwarded
- **WebSocket frame scan failure** → frame relayed without scanning
- **Response scan failure** → response returned unmodified (already had try/except)

A spike in `scan_error` findings is a clear signal that a detector or rule has a bug.

---

## Relay + Engine Architecture

For fault isolation, the proxy can run as two separate processes:

```
AI Tool → Relay (:8080) → Engine (:8090) → Upstream LLM Provider
                ↓ (engine down, fail-open)
                └──────────────────────────→ Upstream LLM Provider
```

- **Relay** (port 8080): lightweight HTTP forwarder, ~400 lines, no scanning imports, near-zero crash risk
- **Engine** (port 8090): full inspection pipeline, rules, findings, dashboard — this is where bugs happen

### Three runtime modes

```bash
# Separate processes (tray app spawns both)
lumen-argus engine --port 8090
lumen-argus relay --port 8080 --engine http://localhost:8090 --fail-mode open

# Combined in one process
lumen-argus serve --engine-port 8090 --fail-mode open

# Standard (no relay, backwards compatible)
lumen-argus serve
```

### How the relay works

The relay has a 3-state machine:

| State | Behavior |
|-------|----------|
| **STARTING** | Queue requests for `queue_on_startup` seconds, then apply fail_mode |
| **HEALTHY** | Forward all traffic to engine |
| **UNHEALTHY** | Apply fail_mode policy |

A background task health-checks the engine every `health_check_interval` seconds via `GET /health`. The engine returns 503 while its pipeline is loading ("starting"), then 200 when ready ("ready"). The relay only marks the engine as healthy on 200.

### Fail modes

| Engine state | `fail_mode` | Relay behavior | Tool experience |
|---|---|---|---|
| Healthy | any | Forward via engine | Normal (inspected) |
| Unhealthy | `open` | Forward directly to upstream provider | Normal (uninspected) |
| Unhealthy | `closed` | Return 503 | Request fails |
| Starting | any | Queue briefly, then apply fail_mode | Brief delay |

Default: `open` (developer tools keep working even if the engine crashes).

### Relay health endpoint

```
GET http://localhost:8080/health
```

```json
{"status": "ok", "engine": "healthy", "fail_mode": "open", "uptime": 42.1}
```

### Configuration

```yaml
relay:
  port: 8080
  fail_mode: open
  engine_url: http://localhost:8090
  health_check_interval: 2
  health_check_timeout: 1
  queue_on_startup: 2
  timeout: 150

engine:
  port: 8090
```

The relay timeout (150s) is intentionally higher than the engine timeout (120s) to account for scanning overhead.

### SIGHUP reload

Both relay and engine support `kill -HUP <pid>` for config reload:

- **Engine**: reloads rules, allowlists, detectors, timeouts, port/bind, mode
- **Relay**: reloads fail_mode, engine_url, health check intervals, timeout

### Request tracing

The relay adds `X-Request-ID: relay-N` and `X-Forwarded-For` headers when forwarding to the engine. This enables correlating logs across the two processes.

---

## Forward Proxy Mode

Some AI tools hardcode their API endpoints and don't support custom base URLs.
For these tools, the agent provides a **forward proxy** mode that uses TLS
interception (via mitmproxy) to scan traffic transparently.

### How it works

```
AI Tool  →  HTTPS_PROXY=:9090  →  Agent (mitmproxy TLS intercept)
                                       ↓ (decrypt + add identity headers)
                                  Proxy (:8080) via /_forward
                                       ↓ (scan + forward to original host)
                                  api.individual.githubcopilot.com
```

The tool thinks it's talking directly to the API. The agent terminates TLS
with a local CA certificate, inspects the request, enriches it with identity
headers, and re-routes AI traffic to the proxy's `/_forward` endpoint. Non-AI
hosts pass through without TLS interception.

### Supported tools

| Tool | Why forward proxy is needed |
|------|---------------------------|
| Copilot CLI (GitHub auth) | `COPILOT_PROVIDER_BASE_URL` activates BYOK mode and breaks GitHub authentication |

### Setup

```bash
# Start agent with both reverse relay and forward proxy
lumen-argus-agent relay --port 8070 --upstream http://proxy:8080 --forward-proxy-port 9090

# View CA certificate path
lumen-argus-agent forward-proxy ca-path

# Install CA to system trust store (requires admin)
sudo lumen-argus-agent forward-proxy install-ca

# Generate tool aliases
lumen-argus-agent forward-proxy aliases
```

### Tool-specific aliases

Forward proxy uses shell aliases instead of global `HTTPS_PROXY` to avoid
routing all terminal HTTPS traffic through the proxy:

```bash
# Added to ~/.zshrc (or via lumen-argus-agent forward-proxy aliases)
source ~/.lumen-argus/forward-proxy-aliases.sh
```

The aliases file contains entries like:

```bash
alias copilot='HTTPS_PROXY=http://localhost:9090 NODE_EXTRA_CA_CERTS=~/.lumen-argus/ca/ca-cert.pem copilot'
```

Only the aliased tools route through the forward proxy. Other terminal tools
(`curl`, `pip`, `brew`, `git`) are unaffected.

### CA certificate

The agent generates a CA certificate on first forward proxy start. The
certificate is stored at `~/.lumen-argus/ca/ca-cert.pem` and must be trusted
by the tool's runtime:

- **Node.js tools** (Copilot CLI): `NODE_EXTRA_CA_CERTS` env var (set by alias)
- **System-wide**: `sudo lumen-argus-agent forward-proxy install-ca`

### Findings

Forward proxy findings appear in the same findings table with
`intercept_mode: forward` and `original_host` populated from the
`X-Lumen-Forward-Host` header (e.g., `api.individual.githubcopilot.com`)
so you can distinguish traffic by its pre-interception destination. All
identity fields (hostname, username, working directory) are populated
via PID resolution, same as reverse proxy.

---

## Security Model

!!! info "Localhost only"
    The proxy binds exclusively to `127.0.0.1`. Attempting to set `bind` to
    `0.0.0.0` or any non-loopback address raises a `ValueError` at startup.
    This is enforced by a runtime assertion in the server constructor.

The proxy receives plain HTTP on localhost and upgrades to HTTPS for upstream
connections. Since the proxy only listens on loopback, the unencrypted local
hop never leaves the machine.
