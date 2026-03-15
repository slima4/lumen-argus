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

**Requirements:** Python 3.8+ (zero external dependencies)

```bash
# Clone and run
git clone https://github.com/slima4/lumen-argus.git
cd lumen-argus
python3 -m lumen_argus

# Or install as a CLI tool
pip install -e .
lumen-argus
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

## What It Detects

### Secrets (34 patterns + entropy analysis)

AWS keys, GitHub tokens, Anthropic/OpenAI/Google API keys, Stripe keys, Slack tokens, JWTs, database URLs, PEM private keys, generic passwords, and more. High-entropy strings near secret-related keywords are also flagged via Shannon entropy analysis.

### PII (8 patterns with validation)

| Type | Validation |
|---|---|
| Email | Domain format check |
| SSN (US) | Range validation (rejects 000, 666, 900+) |
| Credit Card | Luhn algorithm |
| Phone (US/Intl) | Format check |
| IP Address | Excludes private/loopback ranges |
| IBAN | Country format |
| Passport (US) | Context-required |

### Proprietary Code

- **File pattern blocklist** — `.pem`, `.key`, `.env`, `credentials.json`, etc.
- **Keyword detection** — `CONFIDENTIAL`, `TRADE SECRET`, `INTERNAL ONLY`, etc.

## Performance

Scanning overhead stays under 50ms for typical payloads (up to 100KB). Larger payloads are handled via a scan budget that prioritizes the most recent messages — where fresh file reads with potential secrets live.

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
  #3   POST /v1/messages  opus-4-6  91.2k->2.1k  3412ms  BLOCK  private_key (tool_result[2])
```

## Configuration

Create `~/.lumen-argus/config.yaml` (or copy `config-example.yaml`):

```yaml
proxy:
  port: 8080
  bind: "127.0.0.1"

# Global default action: log | alert | block
default_action: alert

detectors:
  secrets:
    enabled: true
    action: block
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
    - "AKIAIOSFODNN7EXAMPLE"
  pii:
    - "*@example.com"
    - "*@test.local"
  paths:
    - "test/**"
    - "fixtures/**"
```

### Project-Level Overrides

Commit `.lumen-argus.yaml` to your repo root to enforce project-specific rules. Project config merges with global config and can only be **more restrictive** (cannot downgrade `block` to `log`).

## Actions

| Action | Behavior |
|---|---|
| **log** | Record finding in audit log, allow request |
| **alert** | Log + print to terminal, allow request |
| **block** | Reject request with HTTP 403, return error to AI tool |

When multiple detectors flag the same request, the highest-severity action wins: `block > alert > log`.

## Audit Log

Every request produces a JSONL audit entry at `~/.lumen-argus/audit/guard-{timestamp}.jsonl` with `0600` permissions. Matched secret values are never written to disk — only masked previews (e.g., `AKIA****`).

## CLI Options

```
lumen-argus [--port PORT] [--config PATH] [--log-dir DIR] [--no-color] [--version]
```

| Flag | Default | Description |
|---|---|---|
| `--port`, `-p` | 8080 | Proxy port |
| `--config`, `-c` | `~/.lumen-argus/config.yaml` | Config file path |
| `--log-dir` | `~/.lumen-argus/audit/` | Audit log directory |
| `--no-color` | false | Disable ANSI colors |

## Security

- Proxy binds to `127.0.0.1` only — never `0.0.0.0` (enforced at runtime)
- Plain HTTP on localhost, HTTPS to upstream — no TLS interception needed
- Audit logs created with `0600` permissions
- Matched values kept in memory only, never written to disk

## License

MIT — Community Edition.
