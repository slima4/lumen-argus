# Changelog

All notable changes to lumen-argus are documented here.

## Unreleased

### Agent Uninstall — Single-Command Workstation Cleanup

- New subcommand `lumen-argus-agent uninstall [--keep-data]
  [--non-interactive]` reverses every system change the agent made
  during `setup` / `protection enable` / `enroll` / MCP wrapping, and
  removes agent-owned state files from `~/.lumen-argus/`.  Also
  available as a standalone `lumen-argus-uninstall` binary (same
  flags, same JSON output) for callers that want discovery by
  binary name rather than subcommand.
- Step ordering is load-bearing:
  `disable_protection` → `undo_mcp_setup` → `undo_setup` → data files.
  Running `disable_protection` first lets it snapshot the managed env
  vars *before* anything truncates the env file, so `launchctl
  unsetenv` on macOS sees the right names.
- `disable_protection()` now clears the matching launchctl env vars
  on macOS (read-then-truncate-then-launchctl order, so a crash
  mid-way fails safe) and returns a new `launchctl_vars_cleared`
  field in the status dict.  GUI-launched AI tools (Claude Desktop,
  Cursor) stop hitting the proxy immediately instead of only on new
  terminals.
- New module `lumen_argus_core.platform_env.clear_launchctl_env_vars`
  owns the macOS launchctl seam — strict `[A-Za-z_][A-Za-z0-9_]*`
  whitelist on var names (shell-injection defence), no-op on Linux /
  Windows, per-name failure tolerated and excluded from the returned
  list.  Zero new runtime dependencies (stdlib `subprocess`).
- Orchestrator (`lumen_argus_agent.uninstall.uninstall_agent`) is
  best-effort per step — a failing step is logged with `exc_info`
  and the next step still runs.  The CLI always prints structured
  JSON (`steps`, `launchctl_vars_cleared`, `data_files_removed`,
  `errors`) so tray-app / shell-script callers do not parse stderr.
  Exit code `0` iff `errors` is empty, `1` otherwise.
- **Out of scope** (tray app / desktop installer's job, deliberately
  untouched): `.app-path`, `license.key`, `trial.json`, `bin/`,
  LaunchAgent plists, `/Applications/*.app`, macOS App Support /
  Logs directories.  The ownership boundary from the uninstall spec
  is preserved.
- Tests: `test_platform_env.py` (8 launchctl scenarios — empty input,
  non-Darwin no-op, happy path, non-zero exit, `OSError`,
  `TimeoutExpired`, non-identifier name rejection, missing
  `launchctl` binary), `test_uninstall.py` (happy path, best-effort
  failure — one step / two steps, `--keep-data`, clean-machine
  idempotency, JSON serialisation), plus new pins in
  `test_setup_wizard.py` for the read-before-truncate ordering and
  the idempotent empty-file path.

### Protection Env File — Dual-Mode Body with Sticky Mode

- New module `lumen_argus_core.env_template` owns the
  `~/.lumen-argus/env` body format end-to-end: `render_body(...)` for
  writes, `parse_header_managed_by(...)` for reads, and the
  `ManagedBy` StrEnum (`CLI` / `TRAY`) both sides agree on.
  `setup_wizard.write_env_file()` only handles atomic I/O.
- The env file has two body shapes.  `ManagedBy.CLI` *(default)*
  emits unconditional `export` lines with a
  `# lumen-argus:managed-env (cli)` header — the right shape for
  users running the proxy from a terminal (source, `pip`, `brew`).
  `ManagedBy.TRAY` wraps the exports in a pure-shell liveness guard
  (`.app-path` marker or `enrollment.json` + live relay PID) with a
  `(tray)` header — the shape the desktop tray app and the
  enrollment flow need so a dragged-to-Trash bundle does not leave
  AI tools pointed at a dead proxy.
- CLI surface: `--managed-by {cli,tray}` on `protection enable` in
  both `lumen-argus` and `lumen-argus-agent`.  The tray app sidecar
  and `lumen-argus-agent enroll` pass `--managed-by tray`.  No
  heuristic inference of deployment context — the invoker states
  the mode.  The `choices` list is derived from the enum so a third
  mode propagates to both parsers automatically.
- **Sticky mode:** `write_env_file(..., managed_by=None)` (the
  default for low-level mutators like `add_env_to_env_file` and
  `setup`) reads the existing file header and preserves the mode.
  Running `setup` on an enrolled machine no longer silently strips
  the liveness guard.
- `enable_protection()` and `protection_status()` now return
  `managed_by` in their status dicts.  Tray-app / dashboard
  consumers can verify ownership by comparing the value against
  what they themselves last wrote.
- Zero subprocesses in the tray guard — `relay.json` PID is parsed
  with `while read` + `case '"pid":'` + `${line##*: }` / `${pid%,}`.
  Two or three `stat()` syscalls plus one small file read on every
  shell startup; well under 1 ms in either mode.
- `render_body` uses `match`/`case` + `case _: raise ValueError`,
  so adding a future `ManagedBy` value hard-fails at render time
  rather than silently falling into the CLI shape.
- Tests: 17 pure-function tests (format + parser), 3 CLI-mode
  real-`bash` tests, 5 TRAY-mode real-`bash` tests covering every
  activation-matrix row, plus `test_setup_wizard.py` pins for the
  sticky-mode invariant and the `protection_status` contract.

### Dashboard Layering Cleanup

- Removed all hardcoded tier branches, locked placeholders, and upsell
  copy from the community dashboard. Plugins now own their dashboard
  surface end-to-end, including any tier-aware rendering.
- `pipeline.js` exposes a new `registerPipelineAction(name)` registry
  hook so plugins can append action options to the dropdowns. The
  community base set is `['log','alert','block']`.
- Settings page reads `status.tier` directly and applies a `tier-<name>`
  CSS class instead of branching on hardcoded tier values.
- Removed the artificial 1-channel webhook cap. `ExtensionRegistry`
  ships with `_channel_limit = None`. Plugins may impose a cap via
  `set_channel_limit(N)`.
- `GET /api/v1/notifications/types` and `GET /api/v1/notifications/channels`
  no longer carry `channel_limit` / `channel_count` keys. The 409 response
  on POST still surfaces a plugin-imposed cap when one is set.
- New regression suite `tests/test_dashboard_layering.py` pins the
  contract — fails the build if tier-aware marketing or gating leaks
  back into community dashboard JS, HTML, or extension defaults.

## 0.6.0 (2026-03-23)

### MCP Security Hardening (Phase 2)

- Confused deputy protection: `RequestTracker` tracks outbound request IDs, rejects unsolicited
  responses from MCP servers (FIFO eviction at 10K, seeding gate, configurable warn/block)
- Tool description poisoning detection: 7 pattern categories (instruction tags, file exfiltration,
  cross-tool manipulation, dangerous exec, download+exec, script injection, command injection)
- Tool drift/rug-pull detection: SHA-256 baselines in `mcp_tool_baselines` DB table, human-readable
  diff summary on change (description length, added text, parameter changes)
- Session binding: validates `tools/call` against tool inventory from first `tools/list` response
  (opt-in via `mcp.session_binding`, 10K tool cap, configurable warn/block)
- All 4 proxy modes (stdio, HTTP bridge, HTTP listener, WS bridge) wired with all security features
- Config: `mcp.request_tracking`, `mcp.unsolicited_response_action`, `mcp.scan_tool_descriptions`,
  `mcp.detect_drift`, `mcp.drift_action`, `mcp.session_binding`, `mcp.unknown_tool_action`
- 31 new tests (935 total)

### MCP Proxy Unification (Phase 1)

- Unified `lumen-argus mcp` subcommand replaces `mcp-wrap` with flag-based transport modes
- Stdio subprocess mode: `lumen-argus mcp -- <command>` (replaces `mcp-wrap`)
- HTTP bridge mode: `lumen-argus mcp --upstream http://...` (stdio client, HTTP upstream)
- HTTP reverse proxy mode: `lumen-argus mcp --listen :8089 --upstream http://...`
- WebSocket bridge mode: `lumen-argus mcp --upstream ws://...`
- New `lumen_argus/mcp/` package with transport abstraction (scanner, transport, proxy, env_filter)
- Environment variable restriction for subprocess mode — safe vars only by default,
  `--env KEY=VALUE` to add more, `--no-env-filter` to disable
- Config: `mcp.env_filter`, `mcp.env_allowlist` in YAML
- `--action` flag to override default action per invocation
- Removed `mcp_scanner.py` and `mcp_wrap.py` (replaced by `lumen_argus/mcp/` package)

### Rules Performance Optimization (Phase 1)

- Aho-Corasick pre-filter: single O(n) pass narrows 1,700+ rules to ~15 candidates per field
- Literal extraction from regex patterns via `sre_parse` (handles alternation, (?i), escapes)
- Early termination: stop after first match when action is `block`
- Hot-first ordering: rules sorted by `hit_count DESC` on reload
- In-memory hit count accumulation with 60s periodic batch flush to DB
- Graceful fallback: if `pyahocorasick` unavailable, sequential scan (current behavior)
- Pro metrics hook: `extensions.set_rule_metrics_collector(collector)`
- `pyahocorasick>=2.0` added as dependency (pre-built wheels for all major platforms)
- Benchmark: 184KB/53 rules: 236ms → 36ms (under 50ms target)
- Parallel rule batching: when enabled (Pro toggle) and candidates > 50, groups rules
  by detector category and evaluates concurrently via ThreadPoolExecutor
- `RulesDetector.set_parallel(bool)` for runtime toggle from Pipeline page
- Pipeline page: "Parallel rule evaluation" toggle in Advanced section
- Config: `pipeline.parallel_batching` in YAML + DB overrides, applied at startup and SIGHUP
- Accelerator factory hook: `extensions.set_accelerator_factory(factory)` — Pro/Enterprise
  can swap Aho-Corasick with a custom pre-filter engine (e.g., Hyperscan/Vectorscan);
  graceful fallback if factory raises

## 0.5.0 (2026-03-22)

### Async Proxy (Phase 1)

- New `async_proxy.py` — `aiohttp.web`-based proxy server replacing `ThreadingHTTPServer`
- Non-blocking I/O with coroutine per request instead of thread per request
- CPU-bound scanning runs in thread pool via `asyncio.to_thread()`
- SSE streaming via `StreamResponse` + async iteration
- Built-in connection pooling via `aiohttp.ClientSession` with `TCPConnector`
- Retry on connection errors (`aiohttp.ClientConnectionError`)
- SIGHUP reload via `loop.add_signal_handler()`
- All existing functionality preserved: MCP detection, history stripping, session extraction, response scanning
- `aiohttp>=3.9` added as dependency
- 18 new integration tests, 867 total tests passing

### WebSocket Unification (Phase 2)

- WebSocket relay moved from standalone port 8083 into the main proxy on port 8080
- Client connects via `ws://localhost:8080/ws?url=ws://target`
- Uses `aiohttp.web.WebSocketResponse` + `ClientSession.ws_connect()` — no separate `websockets` package needed
- `websockets` dependency removed — `aiohttp` handles both HTTP and WebSocket
- SSRF protection: only `ws://` and `wss://` schemes allowed
- Origin validation configurable via `websocket.allowed_origins`
- SIGHUP reloads scanner config without server restart (same port)
- Dependencies reduced from 3 (`pyyaml`, `aiohttp`, `websockets`) to 2 (`pyyaml`, `aiohttp`)

### WebSocket Connection Lifecycle Hooks

- Each WebSocket connection assigned a unique `connection_id` (UUID)
- Extension hook fires on `open`, `finding_detected`, and `close` events
- `ws_connections` SQLite table tracks connection history (target URL, origin, duration, frame counts, findings, close code)
- Default community hook records to analytics store; Pro can override for richer analytics
- Hook calls run in thread pool via `asyncio.to_thread()` — no event loop blocking
- Connection data included in daily retention cleanup
- WebSocket findings now enforced by policy (block closes connection, alert logs + continues)
- REST API: `GET /api/v1/ws/connections`, `GET /api/v1/ws/stats`

### Cleanup

- Removed dead `proxy.py` (old ThreadingHTTPServer) and `pool.py` (old connection pool)
- Removed legacy test files (`test_proxy_integration.py`, `test_pool.py`)
- Session tracking tests updated to use `async_proxy` module

### Thread Safety (Python 3.13+ free-threaded / no-GIL)

- `ScannerPipeline.scan()` snapshots shared references (`_allowlist`, `_policy`, `_decoder`, `_detectors`) under `_reload_lock` before scanning — prevents torn reads during `reload()`
- `ScannerPipeline.reload()` swaps references under the same `_reload_lock`
- `AsyncArgusProxy._active_requests` uses `threading.Lock` for atomic increment/decrement
- Safe for `PYTHON_GIL=0` (PEP 703) — all shared mutable state is properly synchronized

## 0.4.0 (2026-03-20)

### Rules Engine

- DB-backed detection rules replace hardcoded Python pattern files
- `rules` table in SQLite: name, pattern, detector, severity, action, enabled, tier, source, description, tags, validator
- CLI: `lumen-argus rules import/export/list/validate` subcommands
- Auto-import 43 community rules on first `serve` (opt out: `--no-default-rules`)
- `RulesDetector`: loads compiled patterns from DB, license-gated for Pro rules
- Validator registry: `luhn`, `ssn_range`, `iban_mod97`, `exclude_private_ips`
- Capture-group-aware matching: `group(1)` preferred over `group(0)`
- Pipeline uses `RulesDetector` when DB has rules, falls back to hardcoded detectors
- YAML `custom_rules:` reconciled to DB on startup/SIGHUP (Kubernetes-style)
- SIGHUP reloads rules from DB via `RulesDetector.reload()`
- Configurable: `rules.auto_import: false` to skip auto-import

### Cross-Request Deduplication

- 3-layer dedup architecture eliminates redundant scanning of conversation history
- Layer 1: Content fingerprinting — per-session SHA-256 hash set skips already-scanned fields before detectors run
- Layer 2: Finding-level TTL cache — session-scoped `(detector, type, matched_value_hash, session_id)` suppresses duplicate DB writes
- Layer 3: Store-level unique constraint — `content_hash` column with `UNIQUE(content_hash, session_id)` index, `INSERT OR IGNORE`
- Configurable via `dedup:` config section (`conversation_ttl_minutes`, `finding_ttl_minutes`, `max_conversations`, `max_hashes_per_conversation`)
- Background cleanup schedulers for both content fingerprint and finding caches
- All findings remain in `ScanResult` for policy enforcement — dedup only affects DB recording
- Notification dispatcher still receives all findings (has its own cooldown)
- `seen_count` column tracks how many requests included each finding (dashboard shows ×N badge)
- `content_hash` uses `hash(matched_value)` — no collisions between different secrets with same masked preview
- `bump_seen_counts()` increments existing findings when conversation history is re-sent

### Value Hashing

- HMAC-SHA-256 hash of matched secret values stored as `value_hash` in findings DB
- Enables cross-session secret tracking without persisting raw secrets
- Auto-generated 32-byte key at `~/.lumen-argus/hmac.key` (0600 permissions)
- Full 64 hex chars output (256 bits, no truncation)
- Configurable: `analytics.hash_secrets` (default: true)
- Dashboard detail panel shows "Value Hash" field when populated

---

## 0.3.0 (2026-03-19)

### Session Tracking

- Per-request session context extraction: account_id, session_id, device_id, source_ip, working_directory, git_branch, os_platform, client_name, api_key_hash
- Claude Code metadata.user_id JSON string parsing (account_uuid, device_id, session_id)
- System prompt field extraction for working directory, git branch, and OS platform
- User-Agent parsing for client tool identification
- Derived fingerprint (`fp:<hash>`) fallback when no provider session ID
- 9 session columns in findings DB (no migration — direct schema update)
- `GET /api/v1/sessions` endpoint with grouped finding counts
- `GET /api/v1/findings` supports `session_id` and `account_id` filters
- Dashboard: Session, Account, Device, Branch, Client columns in findings table
- Session filter dropdown with clickable session IDs
- `api_key_hash` excluded from JSONL audit log (stored in analytics DB only)
- `post_scan` hook signature updated with `session=` kwarg (backward-compatible)

---

## 0.2.0 (2026-03-19)

### Notification Channels

- Notifications page unlocked in community dashboard (freemium: 1 channel any type, unlimited with Pro)
- 7 channel types available: webhook, email, Slack, Teams, PagerDuty, OpsGenie, Jira
- Kubernetes-style YAML reconciliation — YAML is fully authoritative
- Dashboard: CRUD for dashboard-managed channels, read-only for YAML channels with badge
- Source-aware buttons: YAML channels get Toggle + Test, dashboard channels get full CRUD
- Audit trail: `created_by` / `updated_by` fields on all channel operations
- Channel limit enforcement with atomic count + insert under same lock
- Sensitive field masking in API responses (webhook URLs, passwords, API keys)

### Observability

- `/health` endpoint: added `uptime` field, extension hook for Pro enrichment
- `/metrics` endpoint: extension hook for Pro to append Prometheus metrics
- OpenTelemetry tracing hook: `set_trace_request_hook()` wraps full request lifecycle
- Span attributes: `provider`, `body.size`, `findings.count`, `action`, `scan.duration_ms`
- All hooks fully guarded — exceptions never break requests

### CI/CD

- Docker smoke test in GitHub Actions (build image, verify `/health`)
- Workflow permissions hardened (`contents: read`)
- Concurrency: cancel in-progress runs on new push
- README: CI status badge

### Documentation

- MkDocs Material site at lumen-argus.github.io/lumen-argus/docs/
- Landing page at lumen-argus.github.io/lumen-argus/ with comparison table
- GitHub Pages auto-deploy via Actions

### Open Source

- LICENSE (MIT, Artem Senenko)
- SECURITY.md (responsible disclosure policy)
- CONTRIBUTING.md (setup, constraints, commit format)
- Issue templates (bug report, feature request, security link)
- PR template (stdlib-only, security checklist)
- Repo topics, description, homepage

---

## 0.1.0 (2026-03-17)

Initial release of the lumen-argus Community Edition.

### Detection

- 34+ secret detection patterns (AWS, GitHub, Anthropic, OpenAI, Google, Stripe, Slack, JWT, database URLs, PEM keys, generic passwords)
- Shannon entropy analysis (>4.5 bits/char near secret keywords)
- PII detection with validation: email, SSN (range validation), credit card (Luhn), phone, IP (excludes private), IBAN (MOD-97), passport
- Proprietary code detection: file pattern blocklist, keyword detection
- Custom regex rules in config (unlimited, SIGHUP reloadable)
- Duplicate finding deduplication

### Proxy

- Transparent HTTP proxy for AI coding tools (Claude Code, Copilot, Cursor)
- Provider auto-detection: Anthropic, OpenAI, Gemini
- SSE streaming passthrough via `read1()`
- Connection pooling with idle-read timeout (`proxy.timeout`) and separate TCP connect timeout (`proxy.connect_timeout`)
- Backpressure via `max_connections` semaphore (default: 50)
- Graceful drain on shutdown (`drain_timeout`)
- Custom CA bundle support for corporate proxies
- `/health` JSON endpoint
- `/metrics` Prometheus endpoint

### Scanning

- `lumen-argus scan` for file and stdin scanning
- `--diff` mode for git pre-commit hooks (staged changes or ref diff)
- `--baseline` / `--create-baseline` for known finding suppression
- Differentiated exit codes (0=clean, 1=block, 2=alert, 3=log)
- JSON output format for CI pipelines

### Configuration

- Bundled YAML parser (no PyYAML dependency)
- Global + project-level config with merge semantics
- Hot-reload via SIGHUP with config diff logging
- Allowlists for secrets, PII, and paths (exact + glob)
- Per-detector action overrides

### Logging

- Rotating application log (`~/.lumen-argus/logs/lumen-argus.log`)
- Secure file permissions (0o600, atomic creation)
- Startup summary at INFO (version, Python, OS, config, detectors)
- Block/redact actions at INFO, slow scans at WARNING
- `lumen-argus logs export --sanitize` for safe log sharing
- Thread-safe JSONL audit log with retention policy

### Extensions

- Plugin system via Python entry points
- Hooks: pre_request, post_scan, evaluate, config_reload, redact
- Public API: `pipeline.reload()`, `registry.set_proxy_server()`

### Security

- Localhost-only binding (127.0.0.1, enforced at runtime)
- `matched_value` never written to disk
- Async-signal-safe shutdown handlers
- TLS certificate verification with custom CA support
