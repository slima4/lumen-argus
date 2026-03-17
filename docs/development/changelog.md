# Changelog

All notable changes to lumen-argus are documented here.

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
