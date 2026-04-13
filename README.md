<p align="center">
  <img src="https://img.shields.io/badge/python-3.12+-blue?logo=python&logoColor=white" alt="Python 3.12+">
  <a href="https://github.com/lumen-argus/lumen-argus/actions/workflows/test.yml"><img src="https://github.com/lumen-argus/lumen-argus/actions/workflows/test.yml/badge.svg" alt="tests"></a>
  <img src="https://img.shields.io/badge/dependencies-minimal-brightgreen" alt="Minimal dependencies">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <a href="https://lumen-argus.github.io/lumen-argus/docs/"><img src="https://img.shields.io/badge/docs-mkdocs-blue" alt="Documentation"></a>
</p>

# lumen-argus

**AI coding tool DLP proxy** — scan outbound requests for secrets, PII, and proprietary data before they reach AI providers.

```
                        Reverse Proxy (tools with base URL support)
AI Tool  ──BASE_URL──>  Agent Relay (:8070)  ──>  lumen-argus (:8080)  ──HTTPS──>  AI Provider API
                              |                          |
                        OS identity              +-------+-------+
                        enrichment               | Detection     |
                                                 |  * Secrets    |
                        Forward Proxy            |  * PII        |
AI Tool  ──HTTPS_PROXY──>  Agent (:9090)  ──────>|  * Proprietary|
  (Copilot CLI,             TLS intercept        +-------+-------+
   Warp, etc.)              via mitmproxy        Actions: block | alert | log
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
- **MCP detection** — discover MCP servers from 8 AI tools + Claude Code plugins (user-configured and plugin-provided)
- **WebSocket proxy** — bidirectional frame scanning on same port (opt-in, `ws://localhost:8080/ws?url=ws://target`)
- **8 PII detectors** with validation (Luhn, SSN ranges, IBAN checksums)
- **Proprietary code** detection (file patterns + keyword matching)
- **< 50ms scanning overhead** for typical payloads
- **Minimal dependencies** — PyYAML + aiohttp, everything else is stdlib
- **Forward proxy** — TLS-intercepting proxy (mitmproxy) for tools that don't support custom base URLs (Copilot CLI with GitHub auth). Tool-specific shell aliases, CA cert management, combined relay+forward mode
- **Session tracking** — identify WHO, WHICH project, WHICH conversation per finding. Agent relay enriches with OS-level identity (hostname, username, working directory via PID correlation)
- **Cross-request dedup** — 3-layer dedup eliminates redundant scanning of conversation history
- **Web dashboard** with real-time findings, charts, session filtering, and audit log
- **Notification channels** — webhook, email, Slack, Teams, PagerDuty, OpsGenie, Jira
- **DB-backed rules engine** — import, export, toggle, and manage detection rules via CLI and dashboard. Aho-Corasick pre-filter scans 1,700+ rules in <50ms
- **Pre-commit scanner** — catch secrets before they enter conversation history
- **Relay + engine split** — fault-isolated two-process architecture; relay forwards when engine crashes (fail-open/closed)
- **Protection toggle** — `lumen-argus protection enable/disable/status` for tray app integration
- **Hot-reload** — update config via SIGHUP, no downtime
- **Docker ready** — single command, data persists across upgrades

## Quick Start

**Requirements:** Python 3.12+

```bash
pip install lumen-argus-proxy
lumen-argus serve
```

Then point your AI tool at the proxy. **27 agents supported** — auto-detect and configure them all:

| Proxied (env var) | Proxied (config/IDE) | Proxied (manual) | Detected only |
|---|---|---|---|
| Claude Code | GitHub Copilot (IDE) | GitHub Copilot CLI | Windsurf |
| Aider | Cody | Cursor | Amazon Q |
| Codex CLI | Continue | Cline | Tabnine |
| OpenCode | | Roo Code | Augment Code |
| Gemini CLI | | Aide | Gemini Code Assist |
| | | Droid | Antigravity |
| | | CodeBuddy | Kiro |
| | | Kilo Code | Kiro CLI |
| | | | Trae |
| | | | Qoder |
| | | | Warp |

```bash
# Auto-detect installed AI tools
lumen-argus detect

# Detect MCP servers from AI tool configs
lumen-argus detect --mcp

# Auto-configure all detected tools (env vars, IDE settings, forward proxy)
lumen-argus setup

# Wrap MCP servers through scanning proxy (stdio + HTTP/WS)
lumen-argus setup --mcp

# Setup includes forward proxy for tools like Copilot CLI (step-by-step):
lumen-argus setup copilot_cli

# Or configure manually:
ANTHROPIC_BASE_URL=http://localhost:8080 claude
OPENAI_BASE_URL=http://localhost:8080 aider
GEMINI_BASE_URL=http://localhost:8080 gemini
```

**Background monitoring** — detect and configure new tools automatically:

```bash
# Run as a foreground watch daemon
lumen-argus watch --auto-configure

# Or install as a system service (launchd/systemd)
lumen-argus watch --install --auto-configure
```

**Shell hook** — warn about unconfigured tools on every new shell:

```bash
# Add to your .zshrc / .bashrc (runs in <100ms)
eval "$(lumen-argus detect --check-quiet 2>/dev/null)"
# Or install automatically:
lumen-argus setup  # offers to install the hook
```

**Agent relay** — local identity enrichment proxy (recommended for multi-agent setups):

```bash
# Start local relay — enriches requests with working directory, hostname, user
lumen-argus-agent relay --upstream http://proxy:8080

# AI tools connect to relay, not proxy directly
ANTHROPIC_BASE_URL=http://localhost:8070 claude
```

**Forward proxy** — TLS interception for tools that don't support custom base URLs (e.g., Copilot CLI with GitHub auth):

```bash
# Start relay with forward proxy (combined mode)
lumen-argus-agent relay --upstream http://proxy:8080 --forward-proxy-port 9090

# Generate and view CA certificate
lumen-argus-agent forward-proxy ca-path
sudo lumen-argus-agent forward-proxy install-ca  # trust system-wide

# Tool-specific alias (only Copilot CLI routes through forward proxy)
alias copilot='HTTPS_PROXY=http://localhost:9090 NODE_EXTRA_CA_CERTS=~/.lumen-argus/ca/ca-cert.pem copilot'
```

**Fault-isolated mode** (relay + engine):

```bash
# Two separate processes — relay survives engine crashes
lumen-argus engine --port 8090 &
lumen-argus relay --port 8080 --engine http://localhost:8090 --fail-mode open

# Or combined in one process
lumen-argus serve --engine-port 8090 --fail-mode open

# Toggle protection on/off (for tray app integration)
lumen-argus protection enable
lumen-argus protection disable
lumen-argus protection status
```

**Docker:**

```bash
docker compose up -d
ANTHROPIC_BASE_URL=http://localhost:8080 claude
open http://localhost:8081   # dashboard
```

If `8080`/`8081` are already in use on your machine, copy `.env.example` to `.env` and edit `LUMEN_ARGUS_PROXY_PORT` / `LUMEN_ARGUS_DASH_PORT` before running `docker compose up -d`.

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

Configurable tool allow/block lists via `mcp:` config section or dashboard API. Pro adds ABAC tool policies (glob matching on tool name, server, arguments, context), human-in-the-loop approval gate, and risk classification. MCP over HTTP is automatically detected and scanned by the main proxy — no config needed. `lumen-argus mcp` covers all other transports: stdio subprocess for local MCP servers, HTTP bridge for remote servers, HTTP reverse proxy for centralized enterprise scanning, and WebSocket bridge for WS-based MCP servers.

**MCP server detection** (`lumen-argus detect --mcp`) discovers servers from 8 AI tools plus Claude Code plugins:

| Source | Config Location | JSON Key |
|--------|----------------|----------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | `mcpServers` |
| Claude Code (user) | `~/.claude.json` | `mcpServers` |
| Claude Code (settings) | `~/.claude/settings.json` | `mcpServers` |
| Claude Code (project) | `<cwd>/.mcp.json` | `mcpServers` |
| Claude Code (plugins) | `~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/.mcp.json` | `mcpServers` or top-level |
| Cursor | `~/.cursor/mcp.json` | `mcpServers` |
| Windsurf | `~/.windsurf/mcp.json` | `mcpServers` |
| Cline | `~/.cline/mcp_servers.json` | `mcpServers` |
| Roo Code | `~/.roo-code/mcp.json` | `mcpServers` |
| VS Code (global) | `~/Library/Application Support/Code/User/mcp.json` | `servers` |
| VS Code (workspace) | `<cwd>/.vscode/mcp.json` | `servers` |

Plugin detection reads `~/.claude/plugins/installed_plugins.json` for install paths and `~/.claude/settings.json` for enabled status. Only enabled plugins are scanned. Both `.mcp.json` formats are supported: top-level server names (serena, greptile) and `mcpServers` wrapper key (playwright).

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
| `client_name` | Client registry (User-Agent matching) | WHICH tool? (normalized ID, e.g., "cursor") |
| `client_version` | User-Agent header | WHICH version? (e.g., "0.45.1") |
| `sdk_name` | Parsed from User-Agent | WHICH SDK? (e.g., "ai-sdk/anthropic") |
| `sdk_version` | Parsed from User-Agent | WHICH SDK version? |
| `runtime` | Parsed from User-Agent | WHICH runtime? (e.g., "bun/1.3.11") |
| `api_format` | Auto-detected from body | WHICH wire format? (anthropic/openai/gemini) |

27 AI CLI agents auto-detected via client registry (`lumen-argus clients` to list). Dashboard findings filterable by client, session, and account.

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

**Community pages:** Dashboard (quick stats cards, severity breakdown, trend chart with 7d/30d/90d toggle, top detectors, top providers, activity feed, recent sessions with severity breakdown, pipeline health), Findings (paginated table with 8 filters: severity, detector, action, type, provider, client, time range, session; CSV/JSON export), Rules (paginated rule list with search/filter, stat chips, tag chips, rule cards with enable toggle, action select, add/edit/clone/delete; URL hash deep-links from findings; overlap badges linking to Rule Analysis), Rule Analysis (Crossfire-powered overlap detection — duplicate/subset/overlap cards with Disable/Review/Dismiss actions, live progress with log streaming; `pip install lumen-argus[rules-analysis]`), Allowlists (secrets/PII/paths allowlists — merged YAML config + API entries, inline add/delete, pattern test panel against recent findings), Audit (log viewer with search), Pipeline (scanning stage config — toggle stages, detectors, encoding settings, default action), Settings (proxy config, license activation), Notifications (channel management).

**Pro pages:** MCP, Performance — unlocked with a Pro license. Pro extends the Rules page with "Import Pro Rules" button and `redact` action. Pro also adds 6 analytics charts to the Dashboard: actions trend (stacked area), activity heatmap (hour × weekday), top accounts, top projects, detection coverage gauge, and notification health.

### Dashboard API

| Endpoint | Description |
|---|---|
| `GET /api/v1/status` | Health, uptime, version |
| `GET /api/v1/findings` | Paginated findings (filter by severity, detector, action, type, provider, client, days, session, account) |
| `GET /api/v1/sessions` | Sessions with finding counts and metadata |
| `GET /api/v1/sessions/dashboard` | Active sessions (last 24h) with severity breakdown |
| `GET /api/v1/stats` | Aggregated statistics incl. `today_count`, `last_finding_time`, `by_client` (`?days=N` for trend) |
| `GET /api/v1/stats/advanced` | Pro analytics (action trend, heatmap, top accounts/projects) |
| `GET /api/v1/config` | Current configuration |
| `PUT /api/v1/config` | Save settings (community: proxy; Pro: all) |
| `GET /api/v1/pipeline` | Pipeline stage configuration with stats |
| `PUT /api/v1/pipeline` | Save stage toggles, detector actions, encoding settings |
| `GET /api/v1/rules` | Paginated rules (filter by tier, detector, severity, enabled, tag, search) |
| `POST /api/v1/rules` | Create custom rule (action: log/alert/block; Pro adds redact) |
| `GET /api/v1/rules/stats` | Rule counts by tier, detector, enabled, tags |
| `GET /api/v1/rules/:name` | Single rule detail |
| `PUT /api/v1/rules/:name` | Update rule (action, enabled, severity, etc.) |
| `DELETE /api/v1/rules/:name` | Delete dashboard-created rules |
| `POST /api/v1/rules/:name/clone` | Clone rule to custom tier |
| `POST /api/v1/rules/bulk-update` | Batch update rules (max 500 per request) |
| `GET /api/v1/rules/analysis` | Cached overlap analysis results (requires crossfire) |
| `POST /api/v1/rules/analysis` | Trigger new overlap analysis (background, 202) |
| `GET /api/v1/rules/analysis/status` | Analysis progress with incremental log streaming |
| `POST /api/v1/rules/analysis/dismiss` | Dismiss an overlap finding pair |
| `GET /api/v1/allowlists` | Merged allowlist entries (YAML config + API-managed) |
| `POST /api/v1/allowlists` | Add allowlist entry (type: secrets/pii/paths) |
| `POST /api/v1/allowlists/test` | Test pattern against value and recent findings |
| `DELETE /api/v1/allowlists/:id` | Delete API-managed entry |
| `GET /api/v1/audit` | Audit log entries |
| `GET /api/v1/live` | SSE real-time feed |
| `GET /api/v1/notifications/channels` | List notification channels |
| `POST /api/v1/notifications/channels` | Create channel (limit enforced) |

[Full API reference](https://lumen-argus.github.io/lumen-argus/docs/reference/api-endpoints/)

## Notification Channels

Configure alerting via YAML (IaC-managed) or the dashboard. Community includes Webhook with fire-and-forget dispatch. Pro adds 6 more channel types:

| Channel | Config |
|---------|--------|
| **Webhook** | Any URL — covers Slack webhooks, Discord, custom endpoints |
| **Email** | SMTP with TLS, authentication |
| **Slack** | Native integration (Pro) |
| **Teams** | Adaptive cards (Pro) |
| **PagerDuty** | Incident routing (Pro) |
| **OpsGenie** | Team routing (Pro) |
| **Jira** | Auto-create tickets (Pro) |

**Community:** unlimited webhook channels with fire-and-forget dispatch and configurable event triggers (block/alert/log).

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

**Pipeline page:** Configure scanning stages from the dashboard — toggle stages on/off, enable/disable individual detectors, set per-detector actions, configure encoding decode settings. Only changed settings are saved to DB and applied via hot-reload. Dispatches `pipeline-rendered` event for Pro extensions.

**Hot-reload:** `kill -HUP $(pgrep -f lumen_argus)` — updates allowlists, actions, timeouts, port/bind, and max body size. No downtime.

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

## Packages

Three PyPI packages from one monorepo:

| Package | What | Size | Dependencies |
|---------|------|------|-------------|
| `lumen-argus-core` | Client registry, detection engine, setup wizard | 27KB | Zero (stdlib only) |
| `lumen-argus-agent` | Lightweight workstation agent CLI | 5KB | `lumen-argus-core` |
| `lumen-argus-proxy` | Full proxy server with dashboard | 245KB | `lumen-argus-core` + aiohttp + pyyaml |

```bash
# Individual developer — full proxy
pip install lumen-argus-proxy

# Enterprise workstation — lightweight agent only
pip install lumen-argus-agent
lumen-argus-agent detect --audit --proxy-url https://argus.corp.io
lumen-argus-agent setup --proxy-url https://argus.corp.io --non-interactive
```

### Enterprise Deployment

Central proxy on K8s, lightweight agent on developer machines:

```bash
# Developer machines (via Ansible/MDM)
pip install lumen-argus-agent
lumen-argus-agent enroll --server https://argus.corp.io --non-interactive
# → auto-configures all AI tools, enables protection, installs watch daemon

# Or use the desktop tray app (macOS) — bundles both sidecars
# Local mode: full proxy | Dedicated mode: agent only (8MB vs 12MB binary)
```

Agent commands: `detect`, `setup`, `watch`, `protection`, `clients`, `enroll`, `heartbeat`.

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

## License

MIT — [Artem Senenko](https://github.com/lumen-argus)
