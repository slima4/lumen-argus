# Quick Start

## Connect Your AI Tool

Start the proxy and point your AI tool at it:

=== "Claude Code"

    ```bash
    lumen-argus serve &
    ANTHROPIC_BASE_URL=http://localhost:8080 claude
    ```

=== "OpenAI / Copilot"

    ```bash
    lumen-argus serve &
    OPENAI_BASE_URL=http://localhost:8080 your-tool
    ```

=== "Gemini"

    ```bash
    lumen-argus serve &
    GEMINI_BASE_URL=http://localhost:8080 your-tool
    ```

Multiple sessions (including mixed providers) can share the same proxy instance. Provider auto-detection uses path prefixes and headers.

## What You'll See

```
  lumen-argus — listening on http://127.0.0.1:8080

  #1   POST /v1/messages  opus-4-6  88.3k->1.5k  2312ms  PASS
  #2   POST /v1/messages  opus-4-6  90.1k->0.8k  1134ms  ALERT  aws_access_key (messages[4])
  #3   POST /v1/messages  opus-4-6  91.2k->2.1k  3412ms  BLOCK  private_key x3
```

- **PASS** — No findings, request forwarded
- **ALERT** — Findings detected, request forwarded (logged)
- **BLOCK** — Findings detected, request rejected (HTTP 403)

## Scan Files Before Committing

```bash
# Scan specific files
lumen-argus scan .env config/database.yml

# Scan only staged changes (pre-commit hook)
lumen-argus scan --diff

# Use as a git pre-commit hook
echo 'lumen-argus scan --diff' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Customize Detection

Edit `~/.lumen-argus/config.yaml`:

```yaml
# Change PII from alert to block
detectors:
  pii:
    action: block

# Add custom patterns for your org
custom_rules:
  - name: internal_token
    pattern: "itk_[a-zA-Z0-9]{32}"
    severity: critical
    action: block
```

Changes take effect on restart, or send `SIGHUP` for hot-reload:

```bash
kill -HUP $(pgrep -f "lumen_argus")
```

## Web Dashboard

The built-in dashboard starts automatically on port 8081:

```
http://localhost:8081
```

View real-time stats, browse findings, search audit logs, and manage your license. Additional pages (Rules, Allowlists, Notifications) are available with a Pro license.

## Next Steps

- [Configuration](configuration.md) — Full config reference
- [Detection](../guide/detection.md) — What patterns are detected
- [Custom Rules](../guide/custom-rules.md) — Add your own patterns
- [Scanning Files](../guide/scan-cli.md) — CI/CD integration
