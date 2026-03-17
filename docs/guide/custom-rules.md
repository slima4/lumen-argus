# Custom Rules

Custom rules let you add organization-specific detection patterns without
modifying the built-in detectors. Define them in your `config.yaml` and they
run alongside the standard secrets, PII, and proprietary detectors.

## Configuration Format

Add custom rules under the `custom_rules` key in your config file:

```yaml title="~/.lumen-argus/config.yaml"
custom_rules:
  - name: internal_service_token
    pattern: "svc_tok_[A-Za-z0-9]{32,}"
    severity: critical
    action: block

  - name: staging_db_url
    pattern: "staging-db\\.[a-z]+\\.internal\\.example\\.com"
    severity: high
    action: alert

  - name: corp_api_key
    pattern: "(?i)x-corp-api-key:\\s*[A-Fa-f0-9]{40}"
    severity: high
```

### Rule Fields

| Field | Required | Default | Description |
|---|---|---|---|
| `name` | yes | -- | Unique identifier for the rule. Appears in findings as the `type` field. |
| `pattern` | yes | -- | Regular expression to match. Compiled at config load time. |
| `severity` | no | `high` | One of `critical`, `high`, `warning`, `info`. |
| `action` | no | *(uses `default_action`)* | Per-rule action override: `block`, `alert`, `redact`, `log`. |

!!! note "Regex syntax"
    Patterns use Python `re` syntax. Backslashes in YAML must be doubled
    (e.g., `\\b` for a word boundary, `\\d` for a digit). Alternatively, wrap
    the pattern in single quotes to reduce escaping.

---

## How Findings Are Reported

Custom rule findings use `detector=custom` and `type={name}`:

=== "Text Output"

    ```
    lumen-argus: 2 finding(s) detected
      [CRITICAL] custom: internal_service_token
      [HIGH]     custom: staging_db_url (x3)
    ```

=== "JSON Output"

    ```json
    {
      "status": "findings",
      "count": 2,
      "findings": [
        {
          "detector": "custom",
          "type": "internal_service_token",
          "severity": "critical",
          "location": "messages[0].content",
          "count": 1
        },
        {
          "detector": "custom",
          "type": "staging_db_url",
          "severity": "high",
          "location": "messages[1].content",
          "count": 3
        }
      ]
    }
    ```

---

## Compilation and Validation

Patterns are compiled into `re.Pattern` objects when the config file is loaded.
This happens at startup and on every SIGHUP reload.

**If a pattern contains invalid regex**, lumen-argus:

1. Logs a config warning with the rule index and the `re.error` message
2. Skips that rule entirely (other rules are unaffected)
3. Continues startup normally

```
  [argus.config] WARNING: config.yaml: custom_rules[2].pattern is invalid regex:
  unterminated subpattern at position 4
```

!!! tip "Test your patterns"
    Validate regex before deploying by piping test data through `lumen-argus scan`:

    ```bash
    echo 'svc_tok_ABCDEFabcdef1234567890abcdef12' | lumen-argus scan --format json
    ```

---

## Live Reload

Custom rules reload on `SIGHUP` without restarting the proxy:

```bash
kill -HUP $(pgrep -f lumen-argus)
```

The reload process:

1. Re-reads the config file from disk
2. Re-compiles all custom rule patterns
3. Replaces the active rule set in the scanner pipeline
4. Logs the number of configuration changes detected

!!! warning "Validation on reload"
    The same validation runs on reload as on startup. Invalid patterns are
    skipped with a warning, and the remaining valid rules take effect
    immediately.

---

## Unlimited Rules

There is no hard limit on the number of custom rules. However, because every
rule's compiled regex runs against every scanned field, adding many complex
patterns will increase scan latency. Keep patterns focused and test with
representative request bodies to stay within the <50ms scan budget.

---

## Example Patterns

### Internal Authentication Tokens

```yaml
custom_rules:
  - name: internal_bearer_token
    pattern: "Bearer itk_[A-Za-z0-9_\\-]{36,}"
    severity: critical
    action: block
```

### Staging and Internal URLs

```yaml
custom_rules:
  - name: staging_url
    pattern: "https?://[a-z0-9\\-]+\\.staging\\.example\\.com"
    severity: high
    action: alert

  - name: internal_api_endpoint
    pattern: "https?://api\\.internal\\.example\\.com/v[0-9]+"
    severity: warning
    action: log
```

### Service Account Identifiers

```yaml
custom_rules:
  - name: service_key_header
    pattern: "(?i)x-service-key:\\s*[A-Fa-f0-9]{64}"
    severity: critical
    action: block
```

### Project-Specific Code Markers

```yaml
custom_rules:
  - name: launch_codename
    pattern: "(?i)\\bproject[\\-_]phoenix\\b"
    severity: warning
    action: alert

  - name: unreleased_feature_flag
    pattern: "(?i)feature_flag[\\._](?:alpha|beta)_[a-z_]+"
    severity: info
    action: log
```
