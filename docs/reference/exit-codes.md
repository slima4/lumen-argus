# Exit Codes

The `lumen-argus scan` command returns differentiated exit codes based on the severity of findings. This enables CI pipelines to distinguish between critical issues (block the build) and informational warnings.

## Exit Code Table

| Code | Meaning | Action | CI Recommendation |
|------|---------|--------|--------------------|
| **0** | No findings | Clean | Pass |
| **1** | Findings with action `block` | Critical secrets detected | **Fail build** |
| **2** | Findings with action `alert` or `redact` | Warnings detected | Warn (optional fail) |
| **3** | Findings with action `log` | Informational only | Pass with note |

The highest-severity finding across all scanned files determines the exit code. `block` (exit 1) always wins over `alert` (exit 2) which wins over `log` (exit 3).

## CI Pipeline Examples

### GitHub Actions

```yaml
- name: Security scan
  run: lumen-argus scan --diff ${{ github.event.pull_request.base.ref }}
  # Exit 1 = block findings → step fails
  # Exit 2 = alert findings → step fails (default)

- name: Security scan (warn only on alerts)
  run: |
    lumen-argus scan --diff main
    exit_code=$?
    if [ $exit_code -eq 1 ]; then
      echo "::error::Critical secrets detected"
      exit 1
    elif [ $exit_code -eq 2 ]; then
      echo "::warning::Security warnings detected"
    fi
```

### GitLab CI

```yaml
security-scan:
  script:
    - lumen-argus scan --diff $CI_MERGE_REQUEST_TARGET_BRANCH_NAME
  allow_failure:
    exit_codes:
      - 2  # Allow alerts, block on secrets
      - 3  # Allow log-level findings
```

### Pre-commit Hook

```bash
#!/bin/sh
# .git/hooks/pre-commit
lumen-argus scan --diff
exit $?  # 0=clean, 1=blocked (abort commit), 2+=warnings (commit proceeds)
```

## JSON Output

When using `--format json`, the exit code is included in the output:

```json
{
  "file": "config.py",
  "count": 2,
  "exit_code": 1,
  "findings": [...]
}
```
