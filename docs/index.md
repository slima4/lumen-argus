# lumen-argus

**AI coding tool DLP proxy** — scan outbound requests for secrets, PII, and proprietary data before they reach AI providers.

```
Developer's AI Tool  --HTTP-->  lumen-argus (localhost)  --HTTPS-->  AI Provider API
                                       |
                              +--------+--------+
                              | Detection Engine |
                              |  - Secrets       |
                              |  - PII           |
                              |  - Proprietary   |
                              |  - Custom Rules  |
                              +--------+--------+
                              Actions: block | alert | log
```

## Why

AI coding assistants send your code to external APIs on every request. This creates data leak risks:

- **Secrets** — API keys, database credentials, private keys embedded in code or config
- **PII** — Customer data, SSNs, credit card numbers in source code, test fixtures, or logs
- **Proprietary code** — Trade secrets, unreleased features sent to third-party AI providers

lumen-argus sits between your AI tool and the provider, scanning every outbound request and taking action.

## Key Features

- **34+ secret patterns** with Shannon entropy analysis
- **PII detection** with validation (Luhn, SSN ranges, IP exclusion)
- **Custom regex rules** in config — no plugin needed
- **Zero dependencies** — Python stdlib only
- **Pre-commit scanning** with `--diff` and `--baseline` support
- **Hot-reload** via SIGHUP — no proxy downtime
- **Prometheus metrics** at `/metrics`
- **Graceful shutdown** with configurable drain timeout

## Quick Install

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

See the [Getting Started](getting-started/installation.md) guide for detailed setup instructions.
