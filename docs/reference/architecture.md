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
| **Bind address** | `127.0.0.1` only (enforced by runtime assertion; `0.0.0.0` raises `ValueError`) |
| **Protocol** | Plain HTTP in, HTTPS out |
| **Threading** | One thread per request (daemon threads) |
| **SSE streaming** | Passthrough via `read1()` for low-latency chunk forwarding |
| **Body buffering** | Full request body buffered in memory before scanning |
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

The pipeline orchestrates three steps: extraction, detection, and deduplication.

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

| Detector | Module | Description |
|----------|--------|-------------|
| **SecretsDetector** | `detectors/secrets.py` | 30+ compiled regex patterns (AWS, GitHub, Anthropic, OpenAI, Google, Stripe, Slack, JWT, database URLs, PEM keys, etc.) plus Shannon entropy sweep (threshold default: 4.5 bits/char). |
| **PIIDetector** | `detectors/pii.py` | Regex patterns with validators: email, SSN (range validation), credit cards (Luhn check), phone numbers, IP addresses (excluding private ranges), IBAN, passport numbers. |
| **ProprietaryDetector** | `detectors/proprietary.py` | File pattern blocklist (`.pem`, `.key`, `.env`, etc.) and keyword detection (`CONFIDENTIAL`, `TRADE SECRET`, etc.). |
| **CustomDetector** | `detectors/custom.py` | User-defined regex rules from `custom_rules` config. Reloaded on SIGHUP. |

All regex patterns are compiled at import time to avoid runtime compilation overhead.

### Deduplication

After detection, findings with the same `(detector, type, matched_value)` tuple are collapsed into a single finding with an incremented `count`. This reduces noise from secrets repeated across conversation history.

---

## Stage 3: Policy Engine

**Module:** `lumen_argus/policy.py`

The policy engine evaluates all findings and determines the highest-priority action.

### Action priority

Actions are resolved using a strict priority order:

| Priority | Action | Description |
|----------|--------|-------------|
| 4 | `block` | Reject the request with a 403 response (or SSE-compatible block for streaming). |
| 3 | `redact` | Replace matched values in the request body before forwarding. **(Pro only)** |
| 2 | `alert` | Forward the request but log and display a warning. |
| 1 | `log` | Forward the request and record the finding silently. |
| 0 | `pass` | No findings -- forward without action. |

The winning action is the **highest priority** across all findings in a request. For example, if one finding triggers `alert` and another triggers `block`, the request is blocked.

### Per-detector overrides

Each detector can have its own action via `detectors.<name>.action` in the config. If not set, the `default_action` applies.

!!! warning "Community Edition limitation"
    In the Community Edition, the `redact` action is automatically downgraded to `alert` by the policy engine. Full redaction support requires the Pro edition, which registers an `evaluate` hook to bypass this downgrade.

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

### `AuditEntry`

A single audit log record. Serialized to JSONL via `to_dict()`, which explicitly excludes `matched_value` from all findings.

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
| `post_scan` | `(result: ScanResult, body: bytes, provider: str) -> None` | Called after each scan completes. Use for analytics, notifications, or SSE push. |
| `evaluate` | `(findings: list[Finding], policy: PolicyEngine) -> ActionDecision` | Replaces the default policy evaluation. Used by Pro to support the `redact` action. Falls back to default on exception. |
| `redact` | `(body: bytes, findings: list[Finding]) -> bytes` | Transforms the request body to redact matched values before forwarding. Pro only. |
| `config_reload` | `(pipeline: ScannerPipeline) -> None` | Called after SIGHUP config reload. Use for plugin re-initialization. |

### Registry methods

Extensions interact with the proxy through the `ExtensionRegistry`:

- `add_detector(detector, priority=False)` -- Register an additional detector (prepend with `priority=True`)
- `add_notifier(notifier)` -- Register a notification handler
- `set_proxy_server(server)` / `get_proxy_server()` -- Access the proxy server instance for runtime config updates (e.g., `server.update_timeout()`)
