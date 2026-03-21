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

**Module:** `lumen_argus/proxy.py`

The proxy is built on Python's `http.server.ThreadingHTTPServer` with daemon threads. It accepts plain HTTP on `127.0.0.1` and forwards requests over HTTPS to upstream AI providers.

| Property | Detail |
|----------|--------|
| **Bind address** | `127.0.0.1` by default. Use `--host 0.0.0.0` for Docker (logs a warning for non-loopback). |
| **Protocol** | Plain HTTP in, HTTPS out |
| **Threading** | One thread per request (daemon threads) |
| **SSE streaming** | Passthrough via `read1()` for low-latency chunk forwarding |
| **Body buffering** | Full request body buffered in memory before scanning |
| **Session extraction** | `SessionContext` populated from headers, body metadata, and system prompt before each scan |
| **Local endpoints** | `/health` and `/metrics` handled directly, not forwarded |

!!! info "Backpressure"
    The proxy limits concurrent upstream connections via a semaphore (`proxy.max_connections`). When the limit is reached, new requests queue until a slot opens.

### Connection pool

**Module:** `lumen_argus/pool.py`

Upstream connections are managed by a thread-safe per-host connection pool:

- Non-streaming responses return their connection to the pool for reuse
- SSE streaming connections are **not** pooled (the stream must be fully consumed first)
- Idle connections are evicted after `timeout * 2` seconds
- Pool size is configurable per host (default: 4 idle connections)
- On retry after a stale-connection failure, a fresh connection is created bypassing the pool
- SSL context is shared across all connections and rebuilt on config reload

---

## Stage 2: Scanner Pipeline

**Module:** `lumen_argus/pipeline.py`

The pipeline orchestrates extraction, content fingerprinting, detection, finding dedup, and policy evaluation.

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
| `scan_duration_ms` | `float` | Time spent scanning in milliseconds |
| `action` | `str` | Highest-priority resolved action: `pass`, `log`, `alert`, or `block` |

### `SessionContext`

Session/conversation identity extracted from each request. Populated by the proxy before scanning, passed through the pipeline to audit log and analytics store. Each field is a separate DB column for direct filtering.

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `account_id` | `str` | Anthropic `metadata.user_id.account_uuid`, OpenAI `user` | Account identifier (WHO) |
| `api_key_hash` | `str` | SHA-256[:16] of `x-api-key` or `Authorization` header | Truncated key hash (not in audit JSONL) |
| `session_id` | `str` | Provider metadata or derived `fp:<hash>` | Conversation identifier (WHICH CHAT) |
| `device_id` | `str` | Anthropic `metadata.user_id.device_id` | Machine identifier (WHICH MACHINE) |
| `source_ip` | `str` | `X-Forwarded-For` or `client_address` | Client IP (WHERE) |
| `working_directory` | `str` | System prompt: `Primary working directory:` | Project path (WHAT PROJECT) |
| `git_branch` | `str` | System prompt: `Current branch:` | Git branch |
| `os_platform` | `str` | System prompt: `Platform:` | OS (darwin, linux, win32) |
| `client_name` | `str` | `User-Agent` header first token | Client tool (HOW) |

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
| Session fields | `str` | All `SessionContext` fields except `api_key_hash` (omitted when empty) |

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

### Dashboard extension hooks

| Hook | Signature | Description |
|------|-----------|-------------|
| `register_dashboard_pages(pages)` | `pages: list[dict]` | Register additional dashboard pages. Each page dict has `name`, `label`, `js`, `order`. Pages matching locked placeholders unlock them. |
| `register_dashboard_css(css)` | `css: str` | Register additional CSS injected after community CSS. |
| `register_dashboard_api(handler)` | `handler(path, method, body, store, audit_reader) -> (status, body) or None` | Register a plugin API handler. Called before community handler; return `None` to fall through. |
| `set_analytics_store(store)` | `store: AnalyticsStore` | Override the analytics store (Pro passes its extended store). |
| `set_sse_broadcaster(broadcaster)` | `broadcaster: SSEBroadcaster` | Store the SSE broadcaster for plugin access. |
| `register_auth_provider(provider)` | `provider.authenticate(headers) -> dict or None` | Register an auth provider (Enterprise: OAuth, SAML). |

### Notification hooks

| Hook | Signature | Description |
|------|-----------|-------------|
| `register_channel_types(types)` | `types: dict` | Register channel type definitions for the dashboard dropdown. |
| `set_notifier_builder(builder)` | `builder(channel_dict) -> notifier or None` | Factory that builds notifier instances from DB channel rows. |
| `set_dispatcher(dispatcher)` | `dispatcher.dispatch(findings, provider)` | Set the notification dispatcher. Community calls this from pipeline. |
| `set_channel_limit(limit)` | `limit: int or None` | Set max channels (`None` = unlimited, `1` = freemium default). |

### Observability hooks

| Hook | Signature | Description |
|------|-----------|-------------|
| `set_health_hook(hook)` | `hook() -> dict` | Merged into `/health` JSON response. |
| `set_metrics_hook(hook)` | `hook() -> str` | Prometheus text lines appended to `/metrics`. |
| `set_trace_request_hook(hook)` | `hook(method, path) -> context manager` | Wraps full request lifecycle for OpenTelemetry tracing. |

All observability hooks are fully guarded — exceptions never break requests.

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
