# lumen-argus

**AI coding tool DLP proxy** — scan outbound requests for secrets, PII, and proprietary data before they reach AI providers.

```
Developer's AI Tool  ──HTTP──▶  lumen-argus (localhost)  ──HTTPS──▶  AI Provider API
                                       │
                              ┌────────┴────────┐
                              │ Detection Engine │
                              │  • Secrets       │
                              │  • PII           │
                              │  • Proprietary   │
                              └────────┬────────┘
                              Actions: block │ alert │ log
```

## Why

AI coding assistants send your code to external APIs on every request. This creates data leak risks:

- **Secrets** — API keys, database credentials, private keys embedded in code or config
- **PII** — Customer data, SSNs, credit card numbers in source code, test fixtures, or logs
- **Proprietary code** — Trade secrets, unreleased features sent to third-party AI providers

lumen-argus sits between your AI tool and the provider, scanning every outbound request and taking action.

## Quick Start

**Requirements:** Python 3.9+ (zero external dependencies)

```bash
# Clone and install
git clone https://github.com/slima4/lumen-argus.git
cd lumen-argus
pip install -e .

# Start the proxy — creates default config on first launch
lumen-argus serve --port 8080
```

Then point your AI tool at the proxy:

```bash
# Claude Code
ANTHROPIC_BASE_URL=http://localhost:8080 claude

# OpenAI / Copilot
OPENAI_BASE_URL=http://localhost:8080 your-tool

# Gemini
GEMINI_BASE_URL=http://localhost:8080 your-tool
```

Multiple sessions (including mixed providers) can share the same proxy instance.

## What It Detects

### Secrets (34 patterns + entropy analysis)

AWS keys, GitHub tokens, Anthropic/OpenAI/Google API keys, Stripe keys, Slack tokens, JWTs, database URLs, PEM private keys, generic passwords, and more. High-entropy strings near secret-related keywords are also flagged via Shannon entropy analysis. Duplicate findings are automatically collapsed (e.g. `aws_access_key×47` instead of 47 separate lines).

### PII (8 patterns with validation)

| Type | Validation |
|---|---|
| Email | Domain format check |
| SSN (US) | Range validation (rejects 000, 666, 900+) |
| Credit Card | Luhn algorithm |
| Phone (US/Intl) | Format check |
| IP Address | Excludes private/loopback ranges |
| IBAN | MOD-97 checksum |
| Passport (US) | Context-required |

### Proprietary Code

- **File pattern blocklist** — `.pem`, `.key`, `.env`, `credentials.json`, etc.
- **Keyword detection** — `CONFIDENTIAL`, `TRADE SECRET`, `INTERNAL ONLY`, etc.

## Performance

Scanning overhead stays under 50ms for typical payloads (up to 100KB). Larger payloads are handled via a scan budget that prioritizes the most recent messages — where fresh file reads with potential secrets live. Connection pooling eliminates redundant TLS handshakes for consecutive requests.

| Payload Size | Median Scan Time | P95 |
|---|---|---|
| 1 KB | 0.2ms | 0.2ms |
| 10 KB | 2.6ms | 2.7ms |
| 100 KB | 25.3ms | 26.3ms |
| 500 KB | 51.5ms | 53.7ms |
| 1 MB | 52.3ms | 54.0ms |

Run `python3 benchmark.py` to measure on your machine.

## CLI Output

```
  lumen-argus — listening on http://127.0.0.1:8080

  #1   POST /v1/messages  opus-4-6  88.3k->1.5k  2312ms  PASS
  #2   POST /v1/messages  opus-4-6  90.1k->0.8k  1134ms  ALERT  aws_access_key (messages[4])
  #3   POST /v1/messages  opus-4-6  91.2k->2.1k  3412ms  BLOCK  private_key×3

  shutdown — 3 requests | 1 blocked | 1 alerts | avg scan 12.3ms
  findings: aws_access_key, private_key×3
```

## Commands

### serve — Run the proxy

```bash
lumen-argus serve [--port PORT] [--host HOST] [--config PATH] [--log-dir DIR] [--format text|json] [--log-level LEVEL] [--no-color]
```

| Flag | Default | Description |
|---|---|---|
| `--port`, `-p` | 8080 | Proxy port |
| `--host`, `-H` | 127.0.0.1 | Bind address for proxy and dashboard (use `0.0.0.0` for Docker) |
| `--config`, `-c` | `~/.lumen-argus/config.yaml` | Config file path |
| `--log-dir` | `~/.lumen-argus/audit/` | Audit log directory |
| `--format`, `-f` | text | Output format: `text` (human) or `json` (machine-readable) |
| `--log-level` | warning | Logging verbosity: debug, info, warning, error |
| `--no-color` | false | Disable ANSI colors |

JSON format outputs one JSON line per request — useful for piping to `jq`, scripts, or log aggregation.

### scan — Catch secrets before they reach AI tools

The proxy catches secrets at request time — but by then the AI tool already read the file and the secret is stuck in conversation history. `scan` catches them earlier, at commit time:

```bash
$ lumen-argus scan .env config/database.yml
lumen-argus: .env — 3 finding(s)
  [CRITICAL] secrets: aws_secret_key
  [CRITICAL] secrets: database_url
  [HIGH] secrets: generic_password
lumen-argus: config/database.yml — 1 finding(s)
  [CRITICAL] secrets: database_url

$ echo $?
1
```

```bash
# Scan stdin (e.g. from a pipe)
cat deployment.yaml | lumen-argus scan

# JSON output for CI pipelines
lumen-argus scan --format json .env
{"file":".env","count":3,"findings":[{"detector":"secrets","type":"aws_secret_key","severity":"critical","count":1},...]}

# Scan only staged changes (fast pre-commit hook)
lumen-argus scan --diff

# Scan diff against a branch (PR check)
lumen-argus scan --diff main

# Ignore known findings from a baseline
lumen-argus scan --baseline .lumen-argus-baseline.json src/

# Generate a baseline from current state
lumen-argus scan --create-baseline .lumen-argus-baseline.json src/

# As a git pre-commit hook — blocks commits with secrets
echo 'lumen-argus scan --diff' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Same detection engine as the proxy, same config, same allowlists.

**Exit codes:**

| Code | Meaning | CI action |
|------|---------|-----------|
| 0 | No findings | Pass |
| 1 | Findings with action `block` | Fail build |
| 2 | Findings with action `alert`/`redact` | Warn (optional fail) |
| 3 | Findings with action `log` | Informational |

### logs export — Share logs safely with support

```bash
lumen-argus logs export [--sanitize] [--config PATH]
```

| Flag | Description |
|---|---|
| `--sanitize` | Strip IP addresses, hostnames (except AI provider domains), and file paths |
| `--config`, `-c` | Config file path |

Reads all rotated log files in chronological order and writes to stdout. Pipe to a file for sharing.

## Configuration

A default config is created at `~/.lumen-argus/config.yaml` on first run. Edit it to customize:

```yaml
proxy:
  port: 8080
  bind: "127.0.0.1"
  timeout: 120          # upstream connection timeout (seconds)
  retries: 1            # retry count on connection failure
  max_connections: 10   # max concurrent upstream connections
  drain_timeout: 30     # seconds to wait for in-flight requests on shutdown
  # ca_bundle: "/path/to/ca-certs.pem"  # custom CA for corporate proxies
  # verify_ssl: false   # disable TLS verification (dev only)

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
    - "[REDACTED:aws_access_key_id_value]IOSFODNN7EXAMPLE"
  pii:
    - "*@example.com"
    - "*@test.local"
  paths:
    - "test/**"
    - "fixtures/**"

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

# Custom detection patterns (unlimited)
custom_rules:
  - name: internal_api_token
    pattern: "itk_[a-zA-Z0-9]{32}"
    severity: critical
    action: block
  - name: staging_db_url
    pattern: "postgres://staging[^\\s]+"
    severity: high
```

### Custom Rules

Define custom regex patterns without writing a plugin. Each rule has `name` (required), `pattern` (regex, required), `severity` (default: high), and `action` (optional per-rule override). Rules reload on SIGHUP. Findings appear as `detector=custom, type={name}`.

### Hot-Reload

Send `SIGHUP` to reload config without restarting:

```bash
kill -HUP $(pgrep -f "lumen_argus")
```

Updates allowlists, action overrides, timeout, retries, and file log level. Changed settings are logged. No proxy downtime.

### Project-Level Overrides

Commit `.lumen-argus.yaml` to your repo root to enforce project-specific rules. Project config merges with global config and can only be **more restrictive** (cannot downgrade `block` to `log`).

## Actions

| Action | Behavior |
|---|---|
| **log** | Record finding in audit log, allow request |
| **alert** | Log + print to terminal, allow request |
| **block** | Reject request with HTTP 403 (or SSE error event for streaming) |

When multiple detectors flag the same request, the highest-severity action wins: `block > alert > log`.

## Logging

### Application Log

lumen-argus writes a rotating application log for diagnostics and support:

```
~/.lumen-argus/logs/lumen-argus.log
```

The log captures startup info, blocked/redacted requests, slow scans, errors, and config reloads. Sensitive values are never written to the log — safe to share with support.

Configure in `config.yaml`:

```yaml
logging:
  log_dir: "~/.lumen-argus/logs"
  file_level: info          # debug | info | warning | error
  max_size_mb: 10           # max size before rotation
  backup_count: 5           # rotated files to keep
```

The `--log-level` CLI flag controls **console** output only. The file always logs at `file_level` (default: `info`). SIGHUP reload updates the file level if changed in config.

Log files are created with `0600` permissions.

### Export Logs for Support

```bash
# Export with IPs, hostnames, and file paths stripped
lumen-argus logs export --sanitize > support-logs.txt
```

### Audit Log

Every request produces a JSONL audit entry at `~/.lumen-argus/audit/guard-{timestamp}.jsonl` with `0600` permissions. Matched secret values are never written to disk — only masked previews (e.g., `[REDACTED:aws_access_key_id_value]****`). Old logs are automatically cleaned up based on `retention_days` (default: 90).

## Monitoring

- **`/health`** — returns JSON with proxy status, version, and request count
- **`/metrics`** — Prometheus exposition format (requests by action, findings by type, scan duration, active requests, bytes scanned)
- **`--format json`** — structured JSON output for log aggregation
- **Session stats** — on shutdown, shows request counts, action breakdown, finding types, avg scan time

## Extensions

lumen-argus supports plugins via Python entry points. Any pip package can register custom detectors:

```toml
# In your plugin's pyproject.toml
[project.entry-points."lumen_argus.extensions"]
my_plugin = "my_package:register"
```

```python
# In my_package/__init__.py
def register(registry):
    from my_package.detectors import MyDetector
    registry.add_detector(MyDetector())
```

Plugins are automatically discovered and loaded at startup.

## Dashboard

lumen-argus includes a built-in web dashboard on port 8081:

```
http://localhost:8081
```

Enable it in config:

```yaml
dashboard:
  enabled: true
  port: 8081
  # password: "optional-password"  # or set LUMEN_ARGUS_DASHBOARD_PASSWORD env var
```

**Community pages:** Dashboard (stats, trend charts, recent findings), Findings (paginated table with filters, detail panel, CSV/JSON export), Audit (log viewer with search), Settings (config display, license activation, log download).

**Pro pages (locked):** Rules, Patterns, Allowlists, Notifications — shown with upgrade prompts. Unlocked automatically when a Pro license is active.

The dashboard uses an SQLite analytics store (`~/.lumen-argus/analytics.db`) to persist findings across restarts. Data survives upgrades and license transitions.

### Dashboard API

All community API endpoints are read-only:

| Endpoint | Description |
|---|---|
| `GET /api/v1/status` | Health, uptime, version |
| `GET /api/v1/findings` | Paginated findings (filterable) |
| `GET /api/v1/findings/:id` | Finding detail |
| `GET /api/v1/findings/export` | CSV/JSON export |
| `GET /api/v1/stats` | Aggregated statistics |
| `GET /api/v1/config` | Sanitized config |
| `GET /api/v1/audit` | Audit log entries |
| `GET /api/v1/audit/export` | Audit log export |
| `GET /api/v1/logs/tail` | Tail log lines |
| `GET /api/v1/logs/download` | Sanitized log download |
| `GET /api/v1/live` | SSE real-time feed |
| `POST /api/v1/license` | Activate license key |

## Docker

```bash
# Quick start
docker compose up -d

# Point Claude Code at the proxy
ANTHROPIC_BASE_URL=http://localhost:8080 claude

# Dashboard
open http://localhost:8081
```

The `--host 0.0.0.0` flag (set in the Dockerfile) allows Docker to expose the proxy and dashboard ports. Data (audit logs, analytics DB) persists in a named volume across container rebuilds.

To use a custom config, create `config.yaml` in the project directory and uncomment the volume mount in `docker-compose.yml`.

## Security

- Proxy and dashboard bind to `127.0.0.1` by default. `--host 0.0.0.0` binds both (for Docker only)
- Plain HTTP on localhost, HTTPS to upstream — no TLS interception needed
- Audit logs and analytics DB created with `0600` permissions
- Matched values kept in memory only, never written to disk or analytics DB
- Connection pooling scoped per-host — no auth header leakage across providers
- Dashboard auth: session cookies (HttpOnly, SameSite=Strict), CSRF double-submit, CRLF-safe login redirects
- License keys validated for length and format before writing to disk
- Plugin `html` templates sanitized client-side (scripts and event handlers stripped); plugin `js` is trusted code from pip entry points only

## License

MIT — Community Edition.
