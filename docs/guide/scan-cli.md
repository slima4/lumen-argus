# Scanning Files

The `lumen-argus scan` subcommand runs the full detection pipeline against
local files, stdin, or git diffs -- without starting the proxy server. Use it
in pre-commit hooks, CI pipelines, and ad-hoc audits.

## Basic Usage

### Scan Files

```bash
lumen-argus scan src/config.py deploy/secrets.env
```

### Scan from Stdin

```bash
cat suspicious_file.txt | lumen-argus scan
```

### Scan Staged Changes (Pre-Commit)

```bash
lumen-argus scan --diff
```

### Scan Diff Against a Ref

```bash
lumen-argus scan --diff main
lumen-argus scan --diff HEAD~3
```

---

## Exit Codes

The exit code reflects the highest-severity action across all findings:

| Exit Code | Meaning | CI Recommendation |
|---|---|---|
| `0` | Clean -- no findings | Pass |
| `1` | Findings with action `block` | Fail the build |
| `2` | Findings with action `alert` or `redact` | Warn or fail (your choice) |
| `3` | Findings with action `log` only | Informational, pass |

!!! tip "Lower exit code = higher severity"
    Exit code `1` (block) takes priority over `2` (alert) which takes priority
    over `3` (log). If a scan produces both block and alert findings, the exit
    code is `1`.

---

## Output Formats

=== "Text (default)"

    Findings print to stderr with severity, detector, and type:

    ```
    lumen-argus: src/config.py — 3 finding(s)
      [CRITICAL] secrets: aws_access_key (x2)
      [WARNING]  pii: email
    ```

=== "JSON"

    Machine-readable output for CI integration:

    ```bash
    lumen-argus scan --format json src/config.py
    ```

    ```json
    {
      "file": "src/config.py",
      "count": 3,
      "exit_code": 1,
      "findings": [
        {
          "detector": "secrets",
          "type": "aws_access_key",
          "severity": "critical",
          "location": "src/config.py",
          "count": 2
        },
        {
          "detector": "pii",
          "type": "email",
          "severity": "warning",
          "location": "src/config.py",
          "count": 1
        }
      ]
    }
    ```

    A clean scan returns:

    ```json
    {"status": "clean", "findings": []}
    ```

---

## Diff Mode

The `--diff` flag scans only added lines from a git diff, ignoring deletions
(removed secrets are no longer a risk).

```bash
# Staged changes (git diff --cached)
lumen-argus scan --diff

# Changes relative to a branch or commit
lumen-argus scan --diff main
lumen-argus scan --diff HEAD~5
lumen-argus scan --diff v2.1.0
```

!!! info "How diff parsing works"
    lumen-argus runs `git diff --cached -U0` (or `git diff <ref> -U0`) and
    extracts only lines prefixed with `+` from the unified diff output. Each
    file's added lines are scanned independently. Binary files are skipped
    with a warning.

---

## Baselines

Baselines let you acknowledge existing findings so they do not fail future
scans. This is useful when adopting lumen-argus in a project that has
pre-existing secrets in test fixtures or configuration samples.

### Create a Baseline

```bash
lumen-argus scan --create-baseline .argus-baseline.json src/ tests/
```

### Scan with Baseline

```bash
lumen-argus scan --baseline .argus-baseline.json src/ tests/
```

Only new findings (not in the baseline) produce non-zero exit codes.

!!! note "Baseline security"
    The baseline file stores a SHA-256 hash of each finding's composite key
    (`detector + type + file path`). **Matched secret values are never stored
    in the baseline file.**

!!! warning "Baselines and `--diff`"
    `--create-baseline` is not supported with `--diff`. Use file-based scans
    to create baselines. You can use `--baseline` with `--diff` to filter
    findings during diff scans.

---

## Pre-Commit Hook

### Using a `.pre-commit-config.yaml`

```yaml title=".pre-commit-config.yaml"
repos:
  - repo: local
    hooks:
      - id: lumen-argus
        name: lumen-argus secret scan
        entry: lumen-argus scan --diff
        language: system
        always_run: true
        pass_filenames: false
```

### Manual Git Hook

```bash title=".git/hooks/pre-commit"
#!/bin/sh
lumen-argus scan --diff
```

```bash
chmod +x .git/hooks/pre-commit
```

The hook runs `--diff` with no ref, which scans staged changes
(`git diff --cached`). Exit code `1` blocks the commit; exit codes `2` and `3`
print warnings but allow it.

---

## CI Pipeline Examples

### GitHub Actions

```yaml title=".github/workflows/secrets-scan.yml"
name: Secret Scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install lumen-argus
        run: pip install lumen-argus

      - name: Scan diff against main
        run: lumen-argus scan --diff origin/main --format json
```

### GitLab CI

```yaml title=".gitlab-ci.yml"
secret-scan:
  stage: test
  script:
    - pip install lumen-argus
    - lumen-argus scan --diff origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME --format json
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  allow_failure:
    exit_codes:
      - 2  # Allow alert-only findings
      - 3  # Allow log-only findings
```

!!! tip "Fail only on block findings"
    Both examples use `--diff` against the target branch to scan only new
    changes. Exit code `1` (block) fails the pipeline. In GitLab, use
    `allow_failure.exit_codes` to let alert and log findings pass. In GitHub
    Actions, add a `continue-on-error` step or check `$?` manually for
    finer control.

---

## CLI Reference

```
usage: lumen-argus scan [-h] [--diff [REF]] [--baseline FILE]
                        [--create-baseline FILE] [--config CONFIG]
                        [--format {text,json}]
                        [files ...]

positional arguments:
  files                     Files to scan (reads stdin if none)

options:
  --diff [REF]              Scan git diff (staged changes by default, or
                            diff against REF)
  --baseline FILE           Ignore findings present in baseline file
  --create-baseline FILE    Save current findings as baseline
  --config, -c CONFIG       Path to config YAML
  --format, -f {text,json}  Output format (default: text)
```
