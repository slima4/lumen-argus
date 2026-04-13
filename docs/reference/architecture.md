# Architecture

lumen-argus is a transparent HTTP proxy that intercepts requests from AI coding tools (Claude Code, Copilot, Cursor) before they reach provider APIs. It scans outbound request bodies for secrets, PII, and proprietary data, then takes a configurable action: log, alert, redact, or block.

## Pipeline overview

The system processes each request through a four-stage pipeline:

```
Client Request
     |
     v
+-----------------+     +-----------------+     +-----------------+     +-----------------+
| 1. Proxy Server | --> | 2. Scanner      | --> | 3. Policy       | --> | 4. Audit        |
|                 |     |    Pipeline      |     |    Engine       |     |    Logger        |
+-----------------+     +-----------------+     +-----------------+     +-----------------+
     |                        |                       |
     v                        v                       v
  Forward or Block      Extract -> Detect        Resolve action
                                                  (block > redact
                                                   > alert > log)
```

---

## Stage 1: Proxy Server

**Module:** `lumen_argus/async_proxy.py`

The proxy uses `aiohttp.web` with non-blocking I/O. Each request is handled by a coroutine, and CPU-bound scanning runs in a thread pool via `asyncio.to_thread()`.

| Property | Detail |
|----------|--------|
| **Bind address** | `127.0.0.1` by default. Use `--host 0.0.0.0` for Docker (logs a warning for non-loopback). |
| **Protocol** | Plain HTTP in, HTTPS out |
| **Concurrency** | Coroutine per request (non-blocking I/O) |
| **SSE streaming** | Async iteration via `StreamResponse` |
| **Connection pooling** | `aiohttp.ClientSession` with `TCPConnector(limit=max_connections)` |
| **Scanning** | Thread pool via `asyncio.to_thread()` (~30ms, doesn't block event loop) |
| **Signal handling** | `loop.add_signal_handler()` for SIGINT, SIGTERM, SIGHUP |
| **Retry** | Connection errors retried up to `proxy.retries` times |
| **WebSocket** | Native upgrade on same port (`/ws?url=ws://target`) — no separate port needed |
| **Thread safety** | Free-threaded Python 3.13+ safe — `ScannerPipeline.scan()` snapshots shared references under `_reload_lock`, `_active_requests` uses lock |

### Provider routing

**Module:** `lumen_argus/provider.py`

The `ProviderRouter` determines which upstream API to forward to:

| Mode | Detection | Example |
|------|-----------|---------|
| **Auto-detect** | Path + header heuristics | `/v1/messages` + `x-api-key` → Anthropic |
| **Named upstream** | `/_upstream/<name>/` path prefix | `/_upstream/opencode_zen/chat/completions` → configured URL |

Auto-detect covers Anthropic, OpenAI, and Gemini. Named upstream routing handles gateway providers (OpenCode Zen/Go, Groq, OpenRouter, etc.) whose API endpoints are not one of the three built-in targets.

Well-known gateway upstreams are built-in from `opencode_providers.py` — no manual `config.yaml` needed. The setup wizard / `enable_protection()` auto-configures `opencode.json` with per-provider `baseURL` overrides pointing to the proxy. Standard providers point directly to the proxy; gateway providers use the `/_upstream/<name>` prefix. Supports `managed=True` for enterprise MDM — writes to `/Library/Application Support/opencode/` (macOS) or `/etc/opencode/` (Linux), which has the highest priority in OpenCode's config merge chain and cannot be overridden by user or project configs.

Custom upstreams can also be added via `config.yaml`:

```yaml
proxy:
  upstream:
    my_provider: https://api.myprovider.com/v1
```

Then point the tool's `baseURL` at `http://proxy:8080/_upstream/my_provider`. The proxy strips the prefix and forwards to the configured upstream with the remaining path appended.

!!! info "Backpressure"
    The proxy limits concurrent upstream connections via `aiohttp.TCPConnector(limit=max_connections)`.

---

## Stage 2: Scanner Pipeline

**Module:** `lumen_argus/pipeline.py`

The pipeline orchestrates extraction, encoding decode, content fingerprinting, detection, finding dedup, and policy evaluation. Per-stage timing is recorded in `ScanResult.stage_timings` for observability.

### Extraction

**Module:** `lumen_argus/extractor.py`

The `RequestExtractor` parses JSON request bodies from three provider formats and produces `ScanField` objects:

| Provider | Detection method |
|----------|-----------------|
| **Anthropic** | Path prefix `/v1/messages`, header `x-api-key` or `anthropic-version` |
| **OpenAI** | Path prefix `/v1/chat/completions` |
| **Gemini** | Path prefix containing `generateContent` |

Each `ScanField` contains:

- `path` -- location in the request body (e.g., `messages[4].content`)
- `text` -- the extracted string to scan
- `source_filename` -- filename if from a tool-result file read (used for path allowlisting)

!!! note "Scan budget"
    To keep scan time under 50ms, the pipeline caps total scanned text at 200 KB per request. Fields are scanned in reverse order (newest messages first), since older messages were already scanned in previous requests.

### Encoding Decode

**Module:** `lumen_argus/decoders.py`

The `ContentDecoder` expands extracted fields by decoding encoded content before detection. Each field produces the original text plus any decoded variants:

| Encoding | Detection pattern | Example |
|----------|------------------|---------|
| **Base64** | 20+ chars of `[A-Za-z0-9+/]` | `c2tfbGl2ZV8...` → `sk_live_...` |
| **Hex** | 16+ hex chars (even length) | `736b5f6c69...` → `sk_live_...` |
| **URL** | `%XX` sequences | `sk%5Flive%5F...` → `sk_live_...` |
| **Unicode** | `\uXXXX` sequences | `\u0073\u006b...` → `sk_...` |

Decoded variants get annotated paths: `messages[0].content[base64]`. A quality filter (`_is_meaningful`) rejects non-printable binary output (images, protobuf).

Configurable via `pipeline.stages.encoding_decode` in YAML or the Pipeline dashboard page:

- Per-encoding toggles (base64, hex, URL, Unicode)
- `max_depth` (default 2) — nested encoding layers
- `min_decoded_length` / `max_decoded_length` — filter noise

Gated by the `encoding_decode` pipeline stage toggle. When disabled, fields pass through unchanged.

### Detection

**Module:** `lumen_argus/detectors/`

Detectors run **sequentially** on extracted fields. Each detector implements the `BaseDetector` ABC defined in `lumen_argus/detectors/__init__.py`.

When the `rules` DB table has rules (auto-imported on first run), the pipeline uses `RulesDetector` which replaces `SecretsDetector`, `PIIDetector`, and `CustomDetector`. `ProprietaryDetector` always runs (file-pattern based, not regex rules).

| Detector | Module | Description |
|----------|--------|-------------|
| **RulesDetector** | `detectors/rules.py` | DB-backed rules with validator registry and license gating. Used when DB has rules. |
| **SecretsDetector** | `detectors/secrets.py` | Fallback: 30+ compiled regex patterns plus Shannon entropy sweep. Used when DB has no rules. |
| **PIIDetector** | `detectors/pii.py` | Fallback: regex patterns with validators (Luhn, SSN, IBAN). Used when DB has no rules. |
| **ProprietaryDetector** | `detectors/proprietary.py` | File pattern blocklist and keyword detection. Always active. |
| **CustomDetector** | `detectors/custom.py` | Fallback: user-defined regex rules from config. Used when DB has no rules. |

All regex patterns are compiled at load time (startup or SIGHUP reload) to avoid runtime compilation overhead. The `RulesDetector` supports named validators (`luhn`, `ssn_range`, `iban_mod97`, `exclude_private_ips`) and is license-aware — Pro rules (`tier='pro'`) are skipped when no valid license is present.

### Rule Overlap Analysis

Optional integration with [crossfire-rules](https://pypi.org/project/crossfire-rules/) (`pip install lumen-argus-proxy[rules-analysis]`). Detects duplicate, subset, and overlapping rules using corpus-based analysis. The `rule_analysis.py` module generates test strings per rule via `CorpusGenerator`, cross-evaluates all rules against all corpora via `Evaluator`, then classifies pairs via `Classifier` into duplicates, subsets, and overlaps.

Results cached in the `rule_analysis` SQLite table. Dashboard "Rule Analysis" page shows findings with Disable/Review/Dismiss actions. Auto-analysis runs in a background thread after rule import. Configurable via `rule_analysis:` config section (samples, threshold, seed, auto_on_import). Rules page shows `[N ovr]` overlap badges linking to the analysis page.

### Response Scanning

**Module:** `lumen_argus/response_scanner.py`

The `ResponseScanner` scans API response text (model output) after it has been forwarded to the client. Runs asynchronously in a background thread — zero latency impact on the request/response cycle.

Two detection types:

| Type | Detector | Patterns | Description |
|------|----------|----------|-------------|
| **Secrets** | Reuses existing detectors (SecretsDetector, PIIDetector, etc.) | All request patterns | Catches secrets leaked from context in model output |
| **Injection** | Built-in regex patterns | 10 patterns | Detects prompt injection attempts (e.g., "ignore previous instructions") |

Response findings are recorded to the analytics store and audit log with `response.` location prefix (e.g., `response.content`). Controlled by `response_secrets` and `response_injection` pipeline stages — both disabled by default (opt-in).

Async mode (community): response is forwarded immediately, scanned in background thread, findings recorded post-hoc. Pro adds buffered/blocking mode and custom injection patterns via rules engine.

### MCP Scanning

**Package:** `lumen_argus/mcp/` — unified scanning proxy with 4 transport modes.

**Modules:** `scanner.py` (MCPScanner), `proxy.py` (transport loops), `transport.py` (StdioTransport, HTTPClientTransport, WebSocketClientTransport), `request_tracker.py`, `tool_scanner.py`, `session_binding.py`, `env_filter.py`.

The `MCPScanner` is shared between two MCP scanning paths:

**1. HTTP proxy MCP scanning (enterprise/k8s):**
The proxy automatically detects MCP `tools/call` JSON-RPC in HTTP request bodies via `detect_mcp_request()`. When detected:
- Checks tool against allow/block lists → blocks with JSON-RPC error if denied
- Scans tool arguments with existing detectors
- Tracks tool usage in `mcp_detected_tools` table (name, call count, first/last seen)
- Scans response `result.content` text via `detect_mcp_response()`
- No developer-side config needed — works automatically for MCP over HTTP

**2. `lumen-argus mcp` — 4 transport modes:**
- **Stdio subprocess** (`-- cmd`): spawns MCP server as child process, relays stdin/stdout with scanning. Restricted environment (safe vars only).
- **HTTP bridge** (`--upstream http://...`): stdio client → HTTP upstream.
- **HTTP reverse proxy** (`--listen :PORT --upstream http://...`): accepts HTTP POST, forwards to upstream.
- **WebSocket bridge** (`--upstream ws://...`): stdio client → WebSocket upstream.

**Security layers** (all modes):
- **Confused deputy protection**: tracks outbound request IDs, rejects unsolicited responses (FIFO eviction at 10K)
- **Tool description poisoning detection**: 7 pattern categories scanned on `tools/list` response
- **Tool drift detection**: SHA-256 baselines in `mcp_tool_baselines` DB table, detects definition changes
- **Session binding** (opt-in): validates `tools/call` against tool inventory from first `tools/list`
- **Environment restriction** (stdio only): strips sensitive vars from child process environment

Both paths share:
- **Request scanning**: serializes tool arguments to text, runs existing detectors
- **Response scanning**: extracts text from `content[]` array, runs detectors + injection patterns
- **Tool allow/block lists**: `mcp.allowed_tools` / `mcp.blocked_tools` in config + DB (`mcp_tool_lists` table)
- **Block action**: returns JSON-RPC error (`-32600`)
- Findings have `mcp.` location prefix (e.g., `mcp.tools/call.write_file.arguments`)

**Tool call validation pipeline** (`_check_tools_call` in `mcp/proxy/_scanning.py`):

1. **Session binding** — validates tool name against `tools/list` baseline
2. **ABAC tool policy evaluation** (Pro) — `get_tool_policy_evaluator()` hook. Evaluates tool against YAML/DB/fleet policies with glob matching on tool name, server ID, arguments, and context. Returns allow/block/alert/approval.
3. **Approval gate** (Pro) — `get_approval_gate()` hook. If policy action is `approval`, suspends the tool call and waits for admin decision via dashboard. Fail-open: gate failure allows the call with error-level logging.
4. **Legacy policy engine** (Pro) — `get_mcp_policy_engine()` hook. Pattern-based rule matching.
5. **DLP argument scanning** — runs configured detectors (secrets, PII) on serialized arguments.

`server_id` is populated from the command (stdio) or upstream URL (bridges) and passed to the evaluator and gate for server-scoped policy matching.

Controlled by `mcp_arguments` and `mcp_responses` pipeline stages (enabled by default).

**MCP server detection** (`detect_mcp_servers()` in `packages/core/lumen_argus_core/detect.py`):

Discovers MCP servers from AI tool config files. Three source types:

1. **Global config sources** — Claude Desktop, Claude Code (`~/.claude.json` + `~/.claude/settings.json`), Cursor, Windsurf, Cline, Roo Code, VS Code (`mcp.json`). Each has platform-specific paths (macOS, Linux, Windows). Registered in `mcp_configs.py`.
2. **Project-scoped sources** — Claude Code `.mcp.json` and VS Code `.vscode/mcp.json`. Checked in CWD + explicit `project_dirs`.
3. **Claude Code plugins** — Reads `~/.claude/plugins/installed_plugins.json` for install paths, cross-references `~/.claude/settings.json` `enabledPlugins` for active status, then reads `.mcp.json` at each plugin's install path. Handles both `.mcp.json` formats: top-level server names (e.g., `{"serena": {"command": "uvx", ...}}`) and `mcpServers` wrapper key (e.g., `{"mcpServers": {"pw-testrail": {...}}}`).

Wrapped detection: servers using `lumen-argus mcp --` or `--upstream` are detected as `scanning_enabled=True`. Env values redacted in serialized output.

### WebSocket Proxy

**Modules:** `lumen_argus/ws_proxy.py` (scanner), `lumen_argus/async_proxy.py` (relay)

The `WebSocketScanner` scans WebSocket text frames bidirectionally. The relay runs on the same port as the proxy — clients connect with `ws://localhost:8080/ws?url=ws://target`.

- **Outbound scanning**: client → server text frames scanned for secrets/PII
- **Inbound scanning**: server → client text frames scanned for secrets + injection patterns
- **Binary frames**: passed through without scanning
- **Origin check**: configurable `websocket.allowed_origins` list
- **Frame size cap**: `websocket.max_frame_size` (default 1MB)
- **SSRF protection**: target URL must use `ws://` or `wss://` scheme
- Findings have `ws.outbound` or `ws.inbound` location prefix

Controlled by `websocket_outbound` and `websocket_inbound` pipeline stages (disabled by default, opt-in). Runs on the same port as the proxy (`ws://localhost:8080/ws?url=ws://target`). SIGHUP reloads the scanner configuration without server restart.

**Connection lifecycle hooks**: Each WebSocket connection gets a unique `connection_id` (UUID). Extension hooks fire on `open`, `finding_detected` (text frames with findings), and `close` events. Community records connection data to `ws_connections` SQLite table (target URL, origin, duration, frame counts, findings count, close code). Pro can override via `extensions.set_ws_connection_hook()` for richer per-connection analytics. Hook calls run in thread pool via `asyncio.to_thread()` to avoid blocking the event loop.

**Policy enforcement**: WebSocket findings are evaluated against the same policy as HTTP requests. Block action closes the connection immediately (frame not forwarded). Alert/log actions record findings and continue forwarding.

### Within-Request Deduplication

After detection, findings with the same `(detector, type, matched_value)` tuple are collapsed into a single finding with an incremented `count`. This reduces noise from secrets repeated across conversation history.

### Cross-Request Deduplication

LLM API requests contain the full conversation history — every previous message is re-sent. Without cross-request dedup, the same secret generates new findings on every subsequent request, causing quadratic growth in finding rows.

A 3-layer architecture eliminates this redundancy:

| Layer | Location | What it does | Failure mode if missing |
|-------|----------|-------------|------------------------|
| **Content fingerprinting** | Before detectors | Per-session SHA-256[:16] hash set skips already-scanned fields | 80-95% wasted scan CPU |
| **Finding TTL cache** | After policy eval, before `record_findings()` | Session-scoped `(detector, type, hash(matched_value), session_id)` cache suppresses duplicate DB writes | Same finding written N times per conversation |
| **Store unique constraint** | `ON CONFLICT DO UPDATE` | `UNIQUE(content_hash, session_id)` index, increments `seen_count` | Duplicates after process restart or cache eviction |

**Content fingerprinting** (`ContentFingerprint` class) uses `session.session_id` as the conversation key. Each conversation tracks a set of SHA-256[:16] hashes of field text. On each request, only fields with unseen hashes are passed to detectors. Sharded (16 locks) for low contention, with TTL eviction (default 30 minutes) and a per-conversation hash cap (5,000). Two-phase commit: `filter_new_fields()` returns pending hashes, `commit_hashes()` stores them only if the request is not blocked. After successful history stripping, `commit_pending()` commits the hashes so subsequent requests skip the stripped content — avoiding repeated strip overhead for the rest of the session.

**Finding TTL cache** (`_FindingDedup` class) filters findings before `record_findings()` but keeps all findings in `ScanResult` for policy evaluation — the action (block/alert) still fires even if the finding isn't new. The notification dispatcher also receives all findings (it has its own independent cooldown). Both cleanup schedulers run on background daemon threads.

**Store unique constraint** uses a `content_hash` column computed as SHA-256[:16] of `detector|type|hash(matched_value)`. The partial unique index `WHERE content_hash != ''` excludes legacy rows. `ON CONFLICT DO UPDATE SET seen_count = seen_count + 1` tracks how many times each finding was detected. When Layer 1 skips fields (conversation history re-sent), `bump_seen_counts()` increments all existing findings in the session.

**Value hashing:** Each finding optionally stores `value_hash` — an HMAC-SHA-256 hash of `matched_value` using a server-side key (`~/.lumen-argus/hmac.key`, auto-generated, 0600 permissions). Full 64 hex chars (256 bits). Enables cross-session secret tracking without persisting raw secrets. Configurable via `analytics.hash_secrets` (default: true).

Configurable via `dedup:` in config.yaml:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `conversation_ttl_minutes` | 30 | Content fingerprint TTL per conversation |
| `finding_ttl_minutes` | 30 | Finding-level cache TTL |
| `max_conversations` | 10,000 | Max tracked conversations (TTL eviction) |
| `max_hashes_per_conversation` | 5,000 | Cap hashes per conversation (~80KB each) |

---

## Stage 3: Policy Engine

**Module:** `lumen_argus/policy.py`

The policy engine evaluates all findings and determines the highest-priority action.

### Action priority

Actions are resolved using a strict priority order:

| Priority | Action | Description |
|----------|--------|-------------|
| 4 | `block` | Reject with HTTP 400 (`invalid_request_error`) regardless of streaming mode. If findings are only in conversation history, strips affected messages and forwards the cleaned request (logged as `strip`). |
| 3 | `redact` | Replace matched values in the request body before forwarding. **(Pro only)** |
| 2 | `alert` | Forward the request but log and display a warning. |
| 1 | `log` | Forward the request and record the finding silently. |
| 0 | `pass` | No findings -- forward without action. |

The winning action is the **highest priority** across all findings in a request. For example, if one finding triggers `alert` and another triggers `block`, the request is blocked.

### Per-detector overrides

Each detector can have its own action via `detectors.<name>.action` in the config. If not set, the `default_action` applies.

!!! warning "Community Edition limitation"
    In the Community Edition, the `redact` action is automatically downgraded to `alert` by the policy engine. Full redaction support requires the Pro edition, which registers an `evaluate` hook to bypass this downgrade.

### History stripping

When block fires but findings are only in conversation history (not the latest user message), the proxy strips those messages/content blocks from the request body and forwards the cleaned request. This prevents a blocked message from tainting the entire session.

- **Message-level**: In multi-message conversations, entire messages containing findings are removed.
- **Content-block-level**: Claude Code packs everything into `messages[0]` with multiple content blocks — only the offending blocks are removed, preserving the rest.
- **Audit**: Strip events are logged with `action="strip"`, preserving findings for forensic review.
- **Dedup**: After successful strip, `commit_pending()` commits fingerprint hashes so subsequent requests skip the stripped content (no repeated strip overhead).

---

## Stage 4: Audit Logger

**Module:** `lumen_argus/audit.py`

The audit logger writes JSONL records for every scanned request to `~/.lumen-argus/audit/guard-{timestamp}.jsonl`.

| Property | Detail |
|----------|--------|
| **Format** | JSONL (one JSON object per line) |
| **File permissions** | `0o600` (owner read/write only) |
| **Thread safety** | Thread-safe writes via locking |
| **Retention** | Configurable via `audit.retention_days` (default: 90 days) |

!!! danger "Security: matched_value is never written to disk"
    The `Finding.matched_value` field (the actual secret/PII value) is kept in memory only. Audit log entries contain only the masked `value_preview` (e.g., `AKIA****EXAMPLE`). This prevents secondary exfiltration of sensitive data through log files.

History strip events are recorded with `action="strip"` — the findings are preserved in the audit log for forensic review, even though the cleaned request was forwarded.

---

## Key data structures

**Module:** `lumen_argus/models.py`

All shared data structures are defined in a single module with no internal imports, preventing circular dependencies.

### `Finding`

A single detection result.

| Field | Type | Description |
|-------|------|-------------|
| `detector` | `str` | Detector name: `secrets`, `pii`, `proprietary`, or custom rule name |
| `type` | `str` | Finding type (e.g., `aws_access_key`, `ssn`, `email`) |
| `severity` | `str` | `critical`, `high`, `warning`, or `info` |
| `location` | `str` | Path into request body (e.g., `messages[4].content`) |
| `value_preview` | `str` | Masked preview (e.g., `AKIA****EXAMPLE`) |
| `matched_value` | `str` | Full matched text (memory only, never serialized) |
| `action` | `str` | Resolved action for this finding |
| `count` | `int` | Number of occurrences after deduplication |

### `ScanField`

An extracted text field from a request body.

| Field | Type | Description |
|-------|------|-------------|
| `path` | `str` | Location descriptor (e.g., `messages[3].content`) |
| `text` | `str` | The extracted string to scan |
| `source_filename` | `str` | Filename if from a tool-result file read |

### `ScanResult`

Aggregated result of scanning a request.

| Field | Type | Description |
|-------|------|-------------|
| `findings` | `list[Finding]` | All findings from the scan |
| `scan_duration_ms` | `float` | Total time spent scanning in milliseconds |
| `action` | `str` | Highest-priority resolved action: `pass`, `log`, `alert`, or `block` |
| `stage_timings` | `dict[str, float]` | Per-stage timing breakdown in ms: `extraction`, `encoding_decode`, `fingerprint`, `outbound_dlp` |

### `SessionContext`

Session/conversation identity extracted from each request. Populated by the proxy before scanning, passed through the pipeline to audit log and analytics store. Each field is a separate DB column for direct filtering.

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `account_id` | `str` | Anthropic `metadata.user_id.account_uuid`, OpenAI `user` | Account identifier (WHO) |
| `api_key_hash` | `str` | SHA-256[:16] of `x-api-key` or `Authorization` header | Truncated key hash (not in audit JSONL) |
| `session_id` | `str` | Provider metadata or derived `fp:<hash>` | Conversation identifier (WHICH CHAT) |
| `device_id` | `str` | Anthropic `metadata.user_id.device_id` | Machine identifier (WHICH MACHINE) |
| `source_ip` | `str` | `X-Forwarded-For` or `client_address` | Client IP (WHERE) |
| `working_directory` | `str` | Agent relay `X-Lumen-Argus-Working-Dir` or system prompt | Project path (WHAT PROJECT) |
| `git_branch` | `str` | Agent relay `X-Lumen-Argus-Git-Branch` or system prompt | Git branch |
| `os_platform` | `str` | Agent relay `X-Lumen-Argus-OS-Platform` or system prompt | OS (darwin, linux, win32) |
| `hostname` | `str` | Agent relay `X-Lumen-Argus-Hostname` | Machine hostname (WHICH MACHINE) |
| `username` | `str` | Agent relay `X-Lumen-Argus-Username` | OS username (WHO) |
| `client_name` | `str` | Client registry (`identify_client()`) | Normalized client ID (e.g., "cursor", "aider", "opencode") |
| `client_version` | `str` | Parsed from `User-Agent` token | Client version (e.g., "0.45.1") |
| `raw_user_agent` | `str` | `User-Agent` header (max 512 chars) | Full UA string for forensics |
| `api_format` | `str` | Auto-detected from body structure | Wire format: `anthropic`, `openai`, `gemini` |
| `sdk_name` | `str` | Parsed from UA (`parse_user_agent_metadata()`) | SDK identifier (e.g., `ai-sdk/anthropic`, `claude-code`) |
| `sdk_version` | `str` | Parsed from UA | SDK version (e.g., `3.0.64`) |
| `runtime` | `str` | Parsed from UA | Runtime and version (e.g., `bun/1.3.11`) |
| `intercept_mode` | `str` | Set by `/_forward` handler | `reverse` (default) or `forward` (TLS interception). Always emitted in audit JSONL. |
| `original_host` | `str` | Forward proxy only; read from `X-Lumen-Forward-Host` header on `/_forward` requests | Original destination host before TLS interception (e.g., `api.individual.githubcopilot.com`). Empty in reverse mode. |

!!! tip "Identity priority chain"
    Session fields are populated using a priority chain: (1) **Agent relay headers** (`X-Lumen-Argus-*`) from authenticated agents — OS-level, most reliable. (2) **System prompt extraction** via regex — works for Claude Code, OpenCode, Cursor. (3) **Derived session fingerprint** — hash of first messages (fallback). The proxy only trusts `X-Lumen-Argus-*` headers from authenticated agent relays; unauthenticated requests have these headers stripped.

!!! note "OpenCode client detection"
    OpenCode's Vercel AI SDK overwrites the `User-Agent` with `ai-sdk/openai` or `ai-sdk/anthropic`, hiding the `opencode/` token. The proxy uses secondary detection: the `x-session-affinity` header (always set by OpenCode for non-hosted providers) identifies the client as OpenCode when UA-based matching fails.

!!! note "Claude Code metadata parsing"
    Claude Code sends `metadata.user_id` as a JSON-encoded string: `'{"device_id":"...","account_uuid":"...","session_id":"..."}'`. The proxy detects strings starting with `{`, parses with `json.loads()`, and extracts individual fields.

### `AuditEntry`

A single audit log record. Serialized to JSONL via `to_dict()`, which explicitly excludes `matched_value` from all findings and `api_key_hash` from session context.

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | `str` | ISO 8601 UTC timestamp |
| `request_id` | `int` | Monotonically increasing request counter |
| `provider` | `str` | Detected provider (`anthropic`, `openai`, `gemini`, `unknown`) |
| `model` | `str` | Model name from request body |
| `endpoint` | `str` | Request path |
| `action` | `str` | Resolved action |
| `findings` | `list[Finding]` | Findings (serialized without `matched_value`) |
| `scan_duration_ms` | `float` | Scan time |
| `request_size_bytes` | `int` | Request body size |
| `passed` | `bool` | Whether the request was forwarded to upstream |
| Session fields | `str` | All `SessionContext` fields except `api_key_hash`. Omitted when empty, with one exception: `intercept_mode` is always emitted (defaults to `reverse`) to match the REST `/api/v1/findings` shape so downstream consumers see a consistent field across audit JSONL and API responses. `original_host` is emitted only when populated (forward mode only). |

---

## Extensions

**Module:** `lumen_argus/extensions.py`

The extension system provides the open-core boundary between Community and Pro/Enterprise editions. Extensions are discovered via Python entry points in the `lumen_argus.extensions` group.

### Entry point registration

```toml title="pyproject.toml (extension package)"
[project.entry-points."lumen_argus.extensions"]
my_plugin = "my_package:register"
```

```python title="my_package/__init__.py"
def register(registry):
    from my_package.detectors import MyDetector
    registry.add_detector(MyDetector())
```

### Available hooks

| Hook | Signature | Description |
|------|-----------|-------------|
| `pre_request` | `(request_id: int) -> None` | Called at the start of each request. Use for correlation ID setup. |
| `post_scan` | `(result: ScanResult, body: bytes, provider: str, session=ctx) -> None` | Called after each scan completes. Use for notifications or SSE push. Accept `**kwargs` for forward compat. |
| `evaluate` | `(findings: list[Finding], policy: PolicyEngine) -> ActionDecision` | Replaces the default policy evaluation. Used by Pro to support the `redact` action. Falls back to default on exception. |
| `redact` | `(body: bytes, findings: list[Finding]) -> bytes` | Transforms the request body to redact matched values before forwarding. Pro only. |
| `config_reload` | `(pipeline: ScannerPipeline) -> None` | Called after SIGHUP config reload. Use for plugin re-initialization. |
| `response_scan` | `(text: str, provider: str, model: str, session) -> (action, findings)` | Buffered response scanning. Runs INSTEAD of async scan when set. Return `("block", findings)` to reject response with 400. Pro only. |

### Dashboard extension hooks

| Hook | Signature | Description |
|------|-----------|-------------|
| `register_dashboard_pages(pages)` | `pages: list[dict]` | Register additional dashboard pages. Each page dict has `name`, `label`, `js`, `order`. Plugins own their pages end-to-end — community no longer pre-registers locked placeholders. |
| `register_dashboard_css(css)` | `css: str` | Register additional CSS injected after community CSS. |
| `register_dashboard_api(handler)` | `async handler(path, method, body, store, audit_reader, agent_identity) -> (status, body) or None` | Register a plugin API handler. Called before community handler; return `None` to fall through. `agent_identity` is `AgentIdentity | None`. |
| `set_analytics_store(store)` | `store: AnalyticsStore` | Override the analytics store (Pro passes its extended store). |
| `set_sse_broadcaster(broadcaster)` | `broadcaster: SSEBroadcaster` | Store the SSE broadcaster for plugin access. |
| `register_auth_provider(provider)` | `provider.authenticate(headers) -> dict or None` | Register an auth provider (Enterprise: OAuth, SAML). |

### Notification hooks

| Hook | Signature | Description |
|------|-----------|-------------|
| `register_channel_types(types)` | `types: dict` | Register channel type definitions for the dashboard dropdown. |
| `set_notifier_builder(builder)` | `builder(channel_dict) -> notifier or None` | Factory that builds notifier instances from DB channel rows. |
| `set_dispatcher(dispatcher)` | `dispatcher.dispatch(findings, provider)` | Set the notification dispatcher. Community calls this from pipeline. |
| `set_channel_limit(limit)` | `limit: int or None` | Cap the number of dashboard-managed channels (`None` = unlimited, the community default). |

### Observability hooks

| Hook | Signature | Description |
|------|-----------|-------------|
| `set_health_hook(hook)` | `hook() -> dict` | Merged into `/health` JSON response. |
| `set_metrics_hook(hook)` | `hook() -> str` | Prometheus text lines appended to `/metrics`. |
| `set_trace_request_hook(hook)` | `hook(method, path) -> context manager` | Wraps full request lifecycle for OpenTelemetry tracing. |

All observability hooks are fully guarded — exceptions never break requests.

### MCP tool policy hooks

| Hook | Signature | Description |
|------|-----------|-------------|
| `set_tool_policy_evaluator(evaluator)` | `evaluator.evaluate(tool_name, arguments, server_id, context) -> PolicyDecision` | ABAC tool policy evaluation. Returns decision with action (allow/block/alert/approval), policy name, reason. |
| `get_tool_policy_evaluator()` | `-> evaluator or None` | Retrieve registered evaluator. Called in `_check_tools_call()` pipeline. |
| `set_approval_gate(gate)` | `gate.request_approval(tool_name, arguments, server_id, session_id, identity, client_name, policy) -> ApprovalDecision` | Human-in-the-loop approval. Suspends tool call until admin decides. |
| `get_approval_gate()` | `-> gate or None` | Retrieve registered gate. Called when policy action is `approval`. |

Both hooks are fail-open: evaluator/gate exceptions allow the tool call with error-level logging.

### Registry methods

Extensions interact with the proxy through the `ExtensionRegistry`:

- `add_detector(detector, priority=False)` -- Register an additional detector (prepend with `priority=True`)
- `add_notifier(notifier)` -- Register a notification handler
- `set_proxy_server(server)` / `get_proxy_server()` -- Access the proxy server instance for runtime config updates
- `get_analytics_store()` / `get_sse_broadcaster()` -- Access shared infrastructure
- `get_dashboard_pages()` / `get_dashboard_css()` / `get_dashboard_api_handler()` -- Read registered extensions
- `get_auth_providers()` -- List registered auth providers
- `get_channel_types()` / `get_notifier_builder()` / `get_dispatcher()` / `get_channel_limit()` -- Notification infrastructure
- `get_health_hook()` / `get_metrics_hook()` / `get_trace_request_hook()` -- Observability hooks

---

## Agent Relay

**Package:** `lumen_argus_agent` — **Modules:** `relay.py`, `context.py`

The agent relay is a local forwarding proxy that runs on each workstation (`:8070`). It sits between AI coding tools and the lumen-argus proxy, enriching every request with OS-level identity headers before forwarding.

### Architecture (CASB agent model)

```
AI Tool → Agent Relay (:8070) → Proxy (:8080) → API Provider
              |
              +-- Enriches with X-Lumen-Argus-* headers:
                  Working-Dir, Git-Branch, OS-Platform,
                  Hostname, Username, Client-PID,
                  Agent-Id, Device-Id
```

### Context resolution

The relay resolves caller context from OS-level APIs, not from system prompt regex:

| Method | macOS | Linux |
|--------|-------|-------|
| **PID lookup** | `lsof -i TCP:{port} -FpPn` — match source port from connection name | `/proc/net/tcp` inode → `/proc/{pid}/fd/` symlink scan |
| **Working directory** | `lsof -p {pid} -Fn -d cwd` | `/proc/{pid}/cwd` readlink |
| **Executable** | `ps -p {pid} -o comm=` | `/proc/{pid}/exe` readlink |
| **Git branch** | `git -C {cwd} rev-parse --abbrev-ref HEAD` | Same |

Falls back to static machine context (hostname, username, OS) when PID resolution fails.

!!! note "Working directory on first request"
    Some AI tools (e.g., Claude Code) don't include the full system prompt in the first 1–2 requests of a new conversation. Since the relay resolves `working_directory` from the OS process cwd — which may be `/` for Node.js-based tools — findings captured on early requests may have an empty `working_directory`. Fields populated from the relay (hostname, username, device_id) are always present. The `working_directory` populates on subsequent requests once the AI tool sends its full system prompt. Findings in the same `session_id` can be correlated to fill in the gap.

### Fail modes

| Mode | Behavior when proxy unreachable |
|------|--------------------------------|
| `open` (default) | Forward directly to API provider — no scanning, warning logged |
| `closed` | Return HTTP 503 — request blocked |

### Forward proxy mode

**Modules:** `forward.py`, `mitm_addon.py`, `ca.py`

For AI tools that don't support custom base URLs (e.g., Copilot CLI with GitHub auth), the agent provides a forward proxy mode using mitmproxy for TLS interception.

```
AI Tool → HTTPS_PROXY=:9090 → Agent (mitmproxy :9090)
                                    ↓ (TLS terminate + add identity headers)
                               Proxy (:8080) via /_forward
                                    ↓ (scan + forward to original host)
                               api.individual.githubcopilot.com
```

The addon (`mitm_addon.py`) intercepts HTTPS CONNECT requests, terminates TLS with a local CA, and re-routes AI traffic to the proxy's `/_forward` endpoint with `X-Lumen-Forward-Host` headers. Non-AI hosts pass through without interception. The proxy reads the forward headers, runs the standard scan pipeline, and forwards to the original destination.

Combined mode starts both relay (:8070) and forward proxy (:9090) in one process via `--forward-proxy-port`. Tool-specific shell aliases ensure only targeted tools route through the forward proxy.

CA certificates are generated by mitmproxy into `~/.lumen-argus/ca/` on first start. The public cert (`ca-cert.pem`) is extracted for user trust. Node.js tools use `NODE_EXTRA_CA_CERTS` env var.

### Trust model

The proxy only reads `X-Lumen-Argus-*` headers from authenticated agents (via `AgentAuthProvider`). Unauthenticated requests have these headers stripped before session extraction and before forwarding to upstream API providers.

The `/_forward` endpoint has a three-state authentication gate:

- **Pro mode — `AgentAuthProvider` registered.** Only authenticated agents may use `/_forward`. Unauthenticated callers are rejected with HTTP 403; providers that raise `AuthenticationError` surface as HTTP 401. This protects multi-tenant Pro deployments where the proxy may hold agent-scoped credentials or enforce per-agent egress policy.
- **Community mode — no provider, non-loopback bind.** Rejected with HTTP 403. The loopback-trust argument below depends on the proxy being unreachable from the network. Docker deployments (`--host 0.0.0.0`) and any other non-loopback bind do not satisfy that assumption, so the relaxed gate is withheld and forward proxy cannot be used in community mode. Such deployments must either register a Pro auth provider or switch to reverse-proxy mode (`ANTHROPIC_BASE_URL=http://proxy:8080`).
- **Community mode — no provider, loopback bind.** The gate is skipped. Loopback callers are already local processes that could reach upstream hosts directly; the proxy builds forwarding headers purely from the incoming request (with `X-Lumen-*` stripped) and does not inject credentials on the caller's behalf, so `/_forward` grants no SSRF escalation beyond what the caller already has. The first community-mode pass-through emits a one-shot `INFO` log line for operator visibility.

The gate transitions automatically when Pro registers a provider via `extensions.set_agent_auth_provider()` or the operator rebinds the proxy — no config flag, no restart. The loopback check uses the same address set (`127.0.0.1`, `localhost`) as the startup warning in `async_proxy/_server.py`.

---

## Module structure

### CLI and startup

The proxy entry point (`cli.py`) is a thin argparse dispatcher. Server lifecycle is decomposed into focused modules:

| Module | Responsibility |
|--------|---------------|
| `cli.py` | Argument parsing, command dispatch, thin `_run_*` handlers |
| `startup.py` | Server construction, component wiring, async run loop |
| `config_loader.py` | HMAC key, rules bundle loading, analytics init, DB config overrides |
| `reload.py` | SIGHUP hot-reload (config, pipeline, scanners, channels) |
| `mcp_cmd.py` | Standalone `lumen-argus mcp` CLI with own detector stack |

### Dashboard API

The dashboard REST API is split by domain. All handlers import shared utilities from `api_helpers.py`:

| Module | Endpoints |
|--------|-----------|
| `dashboard/api.py` | Dispatcher + small inline handlers (ws, audit) |
| `dashboard/api_helpers.py` | `json_response`, `parse_pagination`, `parse_json_body`, `require_store`, `broadcast_sse`, `send_sighup`, `mask_channel` |
| `dashboard/api_findings.py` | Findings list/detail, sessions, stats |
| `dashboard/api_rules.py` | Rules CRUD, bulk update, clone, analysis |
| `dashboard/api_channels.py` | Notification channel CRUD, types, test, batch |
| `dashboard/api_config.py` | Config/pipeline CRUD, status, license, logs, clients |
| `dashboard/api_allowlists.py` | Allowlist CRUD and pattern testing |
| `dashboard/api_mcp.py` | MCP tool list management |

Pro extensions should import shared helpers from `lumen_argus.dashboard.api_helpers` (not from `api.py`). The public entry point `handle_community_api()` remains in `api.py`.
