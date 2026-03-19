# Changelog

All notable changes to lumen-argus are documented here.

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

- MkDocs Material site at slima4.github.io/lumen-argus/docs/
- Landing page at slima4.github.io/lumen-argus/ with comparison table
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
- Connection pooling with idle timeout
- Backpressure via `max_connections` semaphore
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
