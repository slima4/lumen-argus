# Allowlists

Allowlists let you suppress known-safe values so they are never flagged as findings. lumen-argus supports three allowlist types, each configured under the `allowlists` key in your config file.

## Allowlist types

### Secrets allowlist

Entries in `allowlists.secrets` are matched against the raw matched value produced by the secrets detector. Matching uses **exact string comparison first**, then falls back to **glob pattern matching** via Python's `fnmatch` module.

Use this for well-known example keys, test tokens, and placeholder credentials that appear in documentation or fixtures.

```yaml
allowlists:
  secrets:
    # Exact match — the full AWS example key
    - "AKIAIOSFODNN7EXAMPLE"
    # Exact match — a known test token
    - "sk-ant-api03-test-key-not-real"
```

### PII allowlist

Entries in `allowlists.pii` are matched against detected PII values (email addresses, phone numbers, etc.) using **glob patterns**.

```yaml
allowlists:
  pii:
    # Any email at example.com or test.local
    - "*@example.com"
    - "*@test.local"
    # A specific test phone number
    - "555-0100"
```

### Paths allowlist

Entries in `allowlists.paths` are matched against the `source_filename` field extracted from tool-result file reads in the request body. Any `ScanField` whose source filename matches a path pattern is **skipped entirely** -- none of its content is scanned.

```yaml
allowlists:
  paths:
    # Skip test directories
    - "test/**"
    - "tests/**"
    - "fixtures/**"
    # Skip a specific file
    - "docs/example-credentials.md"
```

## Glob pattern syntax

All allowlist types use Python's [`fnmatch`](https://docs.python.org/3/library/fnmatch.html) for pattern matching:

| Pattern | Matches |
|---------|---------|
| `*`     | Any sequence of characters (within a single path segment for paths) |
| `?`     | Any single character |
| `[seq]` | Any character in *seq* |
| `[!seq]`| Any character NOT in *seq* |

!!! note "Secrets use exact match first"
    For the `secrets` allowlist, the value is compared with `==` before falling back to `fnmatch`. This means an entry like `AKIAIOSFODNN7EXAMPLE` matches that exact string without needing glob syntax.

## Global vs. project-level config

Allowlists can be defined in both the global config (`~/.lumen-argus/config.yaml`) and a project-level config (`.lumen-argus.yaml` in the project root).

!!! warning "Project configs can only add entries"
    A project-level `.lumen-argus.yaml` can **add** allowlist entries on top of the global config, but it cannot remove entries from the global allowlist. Project-level configs can only make policy **more restrictive** (e.g., upgrading an action from `alert` to `block`), never less restrictive.

```yaml title=".lumen-argus.yaml (project-level)"
allowlists:
  secrets:
    # These are ADDED to the global allowlist
    - "test-api-key-12345"
  paths:
    - "e2e/**"
```

## Reload on SIGHUP

Allowlist changes take effect without restarting the proxy. Send `SIGHUP` to the running process to reload the config:

```bash
# Reload config (including allowlists)
kill -HUP $(pgrep -f lumen-argus)
```

The reload is atomic: a new `AllowlistMatcher` is built from the updated config and swapped in via a single reference assignment, so in-flight requests are not affected.

## Full example

```yaml title="~/.lumen-argus/config.yaml"
allowlists:
  secrets:
    # AWS example keys from documentation
    - "AKIAIOSFODNN7EXAMPLE"
    - "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    # Anthropic placeholder key
    - "sk-ant-api03-placeholder*"

  pii:
    # Test email domains
    - "*@example.com"
    - "*@example.org"
    - "*@test.local"
    # RFC 5737 documentation IPs are already excluded by the PII detector,
    # but you can allowlist additional known-safe values here
    - "10.0.0.1"

  paths:
    # Test and fixture directories
    - "test/**"
    - "tests/**"
    - "fixtures/**"
    - "testdata/**"
    # Generated or vendored code
    - "vendor/**"
    - "node_modules/**"
```

!!! tip "Debugging allowlists"
    Run the proxy with `--log-level debug` to see which values are being checked against the allowlist and whether they match. The allowlist check happens after extraction but before detection for paths, and during detection for secrets and PII values.
