<p align="center">
  <img src="https://img.shields.io/badge/python-3.9+-blue?logo=python&logoColor=white" alt="Python 3.9+">
  <a href="https://github.com/slima4/lumen-argus/actions/workflows/test.yml"><img src="https://github.com/slima4/lumen-argus/actions/workflows/test.yml/badge.svg" alt="tests"></a>
  <img src="https://img.shields.io/badge/dependencies-minimal-brightgreen" alt="Minimal dependencies">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <a href="https://slima4.github.io/lumen-argus/docs/"><img src="https://img.shields.io/badge/docs-mkdocs-blue" alt="Documentation"></a>
</p>

# lumen-argus

**AI coding tool DLP proxy** — scan outbound requests for secrets, PII, and proprietary data before they reach AI providers.

```
Developer's AI Tool  ──HTTP──>  lumen-argus (localhost)  ──HTTPS──>  AI Provider API
                                       |
                              +--------+--------+
                              | Detection Engine |
                              |  * Secrets       |
                              |  * PII           |
                              |  * Proprietary   |
                              +--------+--------+
                              Actions: block | alert | log
```

## The Problem

AI coding assistants send your code to external APIs on every request. This creates data leak risks:

- **Secrets** — API keys, database credentials, private keys embedded in code or config
- **PII** — Customer data, SSNs, credit card numbers in source code, test fixtures, or logs
- **Proprietary code** — Trade secrets, unreleased features sent to third-party AI providers

lumen-argus sits between your AI tool and the provider, scanning every outbound request and taking action — **before anything leaves your machine**.

## Key Features

- **34+ secret patterns** with Shannon entropy analysis
- **Encoding-aware scanning** — catches base64, hex, URL, Unicode encoded secrets
- **Response scanning** — detect secrets and prompt injection in API responses (async, zero latency)
- **MCP proxy** — scan MCP traffic across stdio, HTTP, and WebSocket transports (`lumen-argus mcp`)
- **WebSocket proxy** — bidirectional frame scanning on same port (opt-in, `ws://localhost:8080/ws?url=ws://target`)
- **8 PII detectors** with validation (Luhn, SSN ranges, IBAN checksums)
- **Proprietary code** detection (file patterns + keyword matching)
- **< 50ms scanning overhead** for typical payloads
- **Minimal dependencies** — PyYAML + aiohttp, everything else is stdlib
- **Session tracking** — identify WHO, WHICH project, WHICH conversation per finding
- **Cross-request dedup** — 3-layer dedup eliminates redundant scanning of conversation history
- **Web dashboard** with real-time findings, charts, session filtering, and audit log
- **Notification channels** — webhook, email, Slack, Teams, PagerDuty, OpsGenie, Jira
- **DB-backed rules engine** — import, export, toggle, and manage detection rules via CLI and dashboard. Aho-Corasick pre-filter scans 1,700+ rules in <50ms
- **Pre-commit scanner** — catch secrets before they enter conversation history
- **Hot-reload** — update config via SIGHUP, no downtime
- **Docker ready** — single command, data persists across upgrades

## Quick Start

**Requirements:** Python 3.9+

```bash
pip install lumen-argus
lumen-argus serve
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

**Docker:**

```bash
docker compose up -d
ANTHROPIC_BASE_URL=http://localhost:8080 claude
open http://localhost:8081   # dashboard
```

Multiple sessions (including mixed providers) can share the same proxy instance. Each session is automatically tracked — the proxy extracts account, device, project, and conversation identifiers from every request.

The proxy uses an async architecture (aiohttp) for high concurrency and low memory usage. Thread-safe for Python 3.13+ free-threaded mode (no-GIL).

## CLI Output

```
  lumen-argus — listening on http://127.0.0.1:8080

  #1   POST /v1/messages  opus-4-6  88.3k->1.5k  2312ms  PASS
  #2   POST /v1/messages  opus-4-6  90.1k->0.8k  1134ms  ALERT  aws_access_key (messages[4])
  #3   POST /v1/messages  opus-4-6  91.2k->2.1k  3412ms  BLOCK  private_key*3

  shutdown — 3 requests | 1 blocked | 1 alerts | avg scan 12.3ms
  findings: aws_access_key, private_key*3
```

## What It Detects

### Secrets (34 patterns + entropy analysis)

AWS keys, GitHub tokens, Anthropic/OpenAI/Google API keys, Stripe keys, Slack tokens, JWTs, database URLs, PEM private keys, generic passwords, and more. High-entropy strings near secret-related keywords are also flagged via Shannon entropy analysis. Duplicate findings are automatically collapsed.

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

### Encoding-Aware Scanning

Secrets hidden behind encoding are decoded before scanning:

| Encoding | Example |
|---|---|
| Base64 | `c2tfbGl2ZV8xMjM0...` → `sk_live_1234...` |
| Hex | `736b5f6c6976655f...` → `sk_live_...` |
| URL | `sk%5Flive%5F1234...` → `sk_live_1234...` |
| Unicode | `\u0073\u006b\u005f...` → `sk_...` |

Nested encoding supported (e.g., base64 inside URL-encoding, configurable depth). Each encoding type toggleable from the Pipeline dashboard page. Finding locations annotated: `messages[0].content[base64]`.

### Response Scanning

API responses are scanned asynchronously for secrets and prompt injection — zero latency impact on the request/response cycle.

| Detection | Patterns | Description |
|---|---|---|
| **Secrets** | Reuses all request detectors | Catches secrets leaked from context in model output |
| **Injection** | 10 community + Pro extended | Detects prompt injection (e.g., "ignore previous instructions", `<system>` tags, exfiltration attempts) |

Injection patterns are stored as rules in the DB (detector=`injection`) — visible and configurable from the Rules dashboard page. Enable via Pipeline page: toggle `Response Secrets` and/or `Response Injection` stages.

### MCP Server Scanning

Wrap any MCP server with DLP scanning — tool call arguments and responses are scanned bidirectionally across 4 transport modes:

```bash
# Stdio subprocess — wrap a local MCP server
lumen-argus mcp -- npx @modelcontextprotocol/server-filesystem /path

# HTTP bridge — stdio client, HTTP upstream
lumen-argus mcp --upstream http://localhost:3000/mcp

# HTTP reverse proxy — scan MCP traffic centrally
lumen-argus mcp --listen :8089 --upstream http://mcp-server:3000

# WebSocket bridge — stdio client, WS upstream
lumen-argus mcp --upstream ws://localhost:9000/mcp
```

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "lumen-argus",
      "args": ["mcp", "--", "npx", "@modelcontextprotocol/server-filesystem", "/path"]
    }
  }
}
```

**Security layers** (all enabled by default):
- **Tool description poisoning detection** — 7 pattern categories (injection tags, file exfiltration, cross-tool manipulation, dangerous exec, download+exec, script injection, command injection)
- **Tool drift detection** — SHA-256 baselines detect definition changes between sessions (rug-pull prevention)
- **Confused deputy protection** — tracks outbound request IDs, rejects unsolicited responses
- **Session binding** — validates `tools/call` against tool inventory from first `tools/list` (opt-in)
- **Environment restriction** — subprocess mode strips secrets from child process environment

Configurable tool allow/block lists via `mcp:` config section or dashboard API. MCP over HTTP is automatically detected and scanned by the main proxy — no config needed. `lumen-argus mcp` covers all other transports: stdio subprocess for local MCP servers, HTTP bridge for remote servers, HTTP reverse proxy for centralized enterprise scanning, and WebSocket bridge for WS-based MCP servers.

## Rules Engine

Detection rules are stored in SQLite — manage via CLI or dashboard (Pro). Community rules auto-imported on first run.

```bash
lumen-argus rules import              # import 53 community rules
lumen-argus rules import --pro        # import 1,800+ Pro rules (license required)
lumen-argus rules list                # show loaded rules
lumen-argus rules export > backup.json  # backup for migration
```

Rules support three sources: **import** (CLI, pattern read-only), **dashboard** (full CRUD, Pro), **yaml** (config-managed, Kubernetes-style reconciliation). Each rule has tier (`community`/`pro`/`custom`), action override, enable/disable toggle, and validators.

## Session Tracking

Every proxied request is enriched with session context — no configuration needed. Security teams can filter findings by:

| Field | Source | Answers |
|---|---|---|
| `account_id` | Provider metadata | WHO leaked? |
| `session_id` | Provider metadata or derived fingerprint | WHICH conversation? |
| `device_id` | Claude Code metadata | WHICH machine? |
| `working_directory` | System prompt | WHICH project? |
| `git_branch` | System prompt | WHICH branch? |
| `client_name` | User-Agent header | WHICH tool? |

Claude Code, Cursor, and OpenAI-compatible clients are auto-detected. Dashboard findings are filterable by session and account.

## Cross-Request Dedup

LLM API requests contain the full conversation history — every previous message is re-sent. Without dedup, the same secret generates duplicate findings on every request. A 50-message conversation with 5 secrets would produce ~250 duplicate rows; with dedup, it produces 5.

| Layer | What it does | Impact |
|---|---|---|
| **Content fingerprinting** | Skips already-scanned fields (SHA-256 hash set per session) | 80-95% less scan CPU |
| **Finding TTL cache** | Suppresses duplicate DB writes within 30-min window | ~0 duplicate INSERTs |
| **Store unique constraint** | `INSERT OR IGNORE` on `(content_hash, session_id)` | Defense in depth |

No configuration needed — works automatically when session tracking is active. Tunable via `dedup:` config section.

Each finding tracks `seen_count` — how many requests included that secret. Dashboard shows a `×N` badge on findings seen multiple times.

**Value hashing:** HMAC-SHA-256 hash of each matched secret stored as `value_hash` in the findings DB. Enables cross-session tracking ("this exact key appeared in 5 sessions") without persisting the raw secret. Enabled by default, disable via `analytics.hash_secrets: false`.

## Performance

Scanning overhead stays under 50ms for typical payloads. Connection pooling eliminates redundant TLS handshakes.

| Payload Size | Median Scan Time | P95 |
|---|---|---|
| 1 KB | 0.2ms | 0.2ms |
| 10 KB | 2.6ms | 2.7ms |
| 100 KB | 25.3ms | 26.3ms |
| 500 KB | 51.5ms | 53.7ms |
| 1 MB | 52.3ms | 54.0ms |

## Dashboard

Built-in web dashboard at `http://localhost:8081`:

**Community pages:** Dashboard (severity cards, trend chart with 7d/30d/90d toggle, top detectors, top providers, recent findings), Findings (paginated table with filters, CSV/JSON export), Audit (log viewer with search), Pipeline (scanning stage config — toggle stages, detectors, encoding settings, default action), Settings (proxy config, license activation), Notifications (channel management).

**Pro pages:** Rules, Allowlists — unlocked with a Pro license. Pro also adds 6 analytics charts to the Dashboard: actions trend (stacked area), activity heatmap (hour × weekday), top accounts, top projects, detection coverage gauge, and notification health.

### Dashboard API

| Endpoint | Description |
|---|---|
| `GET /api/v1/status` | Health, uptime, version |
| `GET /api/v1/findings` | Paginated findings (filter by session, account, severity) |
| `GET /api/v1/sessions` | Sessions with finding counts and metadata |
| `GET /api/v1/stats` | Aggregated statistics (`?days=N` for trend range) |
| `GET /api/v1/stats/advanced` | Pro analytics (action trend, heatmap, top accounts/projects) |
| `GET /api/v1/config` | Current configuration |
| `PUT /api/v1/config` | Save settings (community: proxy; Pro: all) |
| `GET /api/v1/pipeline` | Pipeline stage configuration with stats |
| `PUT /api/v1/pipeline` | Save stage toggles, detector actions, encoding settings |
| `GET /api/v1/audit` | Audit log entries |
| `GET /api/v1/live` | SSE real-time feed |
| `GET /api/v1/notifications/channels` | List notification channels |
| `POST /api/v1/notifications/channels` | Create channel (limit enforced) |

[Full API reference](https://slima4.github.io/lumen-argus/docs/reference/api-endpoints/)

## Notification Channels

Configure alerting via YAML (IaC-managed) or the dashboard. 7 channel types available:

| Channel | Config |
|---------|--------|
| **Webhook** | Any URL — covers Slack webhooks, Discord, custom endpoints |
| **Email** | SMTP with TLS, authentication |
| **Slack** | Native integration (Pro) |
| **Teams** | Adaptive cards (Pro) |
| **PagerDuty** | Incident routing (Pro) |
| **OpsGenie** | Team routing (Pro) |
| **Jira** | Auto-create tickets (Pro) |

**Freemium:** 1 channel of any type for free, unlimited with Pro.

```yaml
notifications:
  - name: production-alerts
    type: webhook
    url: "https://hooks.slack.com/services/T00/B00/xxx"
    events: [block, alert]
    min_severity: high
```

YAML channels are reconciled to SQLite on startup/SIGHUP (Kubernetes-style declarative).

## Pre-Commit Scanner

Catch secrets before they enter AI conversation history:

```bash
$ lumen-argus scan .env config/database.yml
lumen-argus: .env — 3 finding(s)
  [CRITICAL] secrets: aws_secret_key
  [CRITICAL] secrets: database_url
  [HIGH] secrets: generic_password

$ echo $?
1
```

```bash
# Git pre-commit hook
echo 'lumen-argus scan --diff' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# Scan diff against a branch (CI/PR check)
lumen-argus scan --diff main

# Baseline management
lumen-argus scan --create-baseline .lumen-argus-baseline.json src/
lumen-argus scan --baseline .lumen-argus-baseline.json src/
```

| Exit Code | Meaning | CI Action |
|-----------|---------|-----------|
| 0 | No findings | Pass |
| 1 | `block` findings | Fail build |
| 2 | `alert`/`redact` findings | Warn |
| 3 | `log` findings | Informational |

## Configuration

Default config created at `~/.lumen-argus/config.yaml` on first run:

```yaml
proxy:
  port: 8080
  bind: "127.0.0.1"
  timeout: 120
  max_connections: 10

default_action: alert     # log | alert | block

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

allowlists:
  secrets:
    - "AKIAIOSFODNN7EXAMPLE"
  pii:
    - "*@example.com"
  paths:
    - "test/**"

pipeline:
  stages:
    outbound_dlp:
      enabled: true
    encoding_decode:
      enabled: true
      base64: true
      hex: true
      url: true
      unicode: true
      max_depth: 2

custom_rules:
  - name: internal_api_token
    pattern: "itk_[a-zA-Z0-9]{32}"
    severity: critical
    action: block
```

**Pipeline page:** Configure scanning stages from the dashboard — toggle stages on/off, enable/disable individual detectors, set per-detector actions, configure encoding decode settings. All saved to DB and applied via hot-reload.

**Hot-reload:** `kill -HUP $(pgrep -f lumen_argus)` — updates allowlists, actions, timeouts. No downtime.

**Project overrides:** Commit `.lumen-argus.yaml` to your repo root. Project config can only be **more restrictive** than global.

## Actions

| Action | Behavior |
|---|---|
| **log** | Record in audit log, allow request |
| **alert** | Log + print to terminal, allow request |
| **block** | Reject with HTTP 400 (`invalid_request_error`). If findings are only in conversation history, strips those messages and forwards the cleaned request (logged as `strip`). |
| **redact** | Replace sensitive values in request body (Pro) |

Highest-severity action wins: `block > redact > alert > log`.

## Monitoring

| Endpoint | Format | Description |
|----------|--------|-------------|
| `/health` | JSON | Proxy status, uptime, request count (Pro extends with license/analytics) |
| `/metrics` | Prometheus | Requests by action, findings by type, scan duration (Pro extends with notification stats) |
| `--format json` | JSONL | Structured output for log aggregation |

Pro adds OpenTelemetry tracing across the full request lifecycle — detector, redaction, and notification spans nest under a root `proxy.request` span.

## Docker

```bash
docker compose up -d                                    # start
ANTHROPIC_BASE_URL=http://localhost:8080 claude          # connect
open http://localhost:8081                               # dashboard
```

Data persists in a named volume across container rebuilds. Custom config via volume mount.

## Extensions

Plugin system via Python entry points:

```toml
[project.entry-points."lumen_argus.extensions"]
my_plugin = "my_package:register"
```

```python
def register(registry):
    from my_package.detectors import MyDetector
    registry.add_detector(MyDetector())
```

## Security

- Binds to `127.0.0.1` by default (use `--host 0.0.0.0` for Docker only)
- Plain HTTP on localhost, HTTPS to upstream — no TLS interception
- All sensitive files created with `0600` permissions
- Matched values kept in memory only — never written to disk, logs, or DB
- Value hashing uses HMAC-SHA-256 with auto-generated key (`~/.lumen-argus/hmac.key`, 0600) — DB compromise without key is useless
- Connection pooling scoped per-host — no auth header leakage across providers
- Dashboard: session auth (HttpOnly, SameSite=Strict), CSRF double-submit, CRLF-safe redirects
- Plugin HTML sanitized client-side; plugin JS is trusted (entry-point only)

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Pro

Upgrade to Pro for advanced features:

- **Redaction** — replace secrets in request bodies instead of blocking
- **1,800+ detection patterns** — AI-generated, curated, and validated
- **NLP-based PII detection** — beyond regex
- **Advanced notifications** — circuit breakers, retry, deduplication, dispatch history
- **Unlimited channels** — free tier allows 1 channel of any type
- **Dashboard CRUD** — Rules, Allowlists pages
- **Compliance reporting** — audit exports, analytics
- **OpenTelemetry tracing** — full request lifecycle spans with provider, findings, action attributes

```bash
# Activate Pro — same package, just add a license key
export LUMEN_ARGUS_LICENSE_KEY=eyJ...
lumen-argus serve
```

## License

MIT — [Artem Senenko](https://github.com/slima4)
