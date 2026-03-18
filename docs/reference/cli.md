# CLI Reference

lumen-argus provides three subcommands: `serve`, `scan`, and `logs`.

```
lumen-argus [--version] [--help] <command> [<args>]
```

## Global flags

| Flag | Short | Description |
|------|-------|-------------|
| `--version` | `-V` | Print version and exit |
| `--help` | `-h` | Show help message and exit |

---

## `serve`

Start the proxy server. This is the primary command for production use.

```bash
lumen-argus serve [OPTIONS]
```

### Flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--port` | `-p` | `int` | `8080` | Port to listen on. Overrides `proxy.port` in config. |
| `--host` | `-H` | `str` | `127.0.0.1` | Bind address for proxy and dashboard. Use `0.0.0.0` for Docker containers. |
| `--config` | `-c` | `str` | `~/.lumen-argus/config.yaml` | Path to config YAML file. |
| `--log-dir` | | `str` | `~/.lumen-argus/audit` | Directory for audit log files. Overrides `audit.log_dir` in config. |
| `--format` | `-f` | `str` | `text` | Output format for terminal display. Choices: `text`, `json`. |
| `--log-level` | | `str` | `warning` | Console logging verbosity. Choices: `debug`, `info`, `warning`, `error`. |
| `--no-color` | | `bool` | `false` | Disable ANSI color codes in terminal output. |

### Examples

```bash
# Start with defaults
lumen-argus serve

# Custom port and config
lumen-argus serve --port 9090 --config /path/to/config.yaml

# JSON output for log aggregation
lumen-argus serve --format json --log-level info

# Debug mode with no colors (for CI/log files)
lumen-argus serve --log-level debug --no-color
```

!!! note "Bind address"
    The proxy binds to `127.0.0.1` by default. Use `--host 0.0.0.0` for Docker containers. Non-loopback binds log a warning. The `--host` flag overrides `proxy.bind` and `dashboard.bind` simultaneously.

---

## `scan`

Scan files, stdin, or git diffs for secrets, PII, and proprietary data. Useful as a pre-commit hook or in CI pipelines.

```bash
lumen-argus scan [FILES...] [OPTIONS]
```

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `files` | `str...` | One or more file paths to scan. If omitted and `--diff` is not used, reads from stdin. |

### Flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--diff` | | `str` (optional) | *(none)* | Scan git diff instead of files. With no argument, scans staged changes. With a ref argument (e.g., `--diff HEAD~3`), scans diff against that ref. |
| `--baseline` | | `str` | *(none)* | Path to a baseline file. Findings present in the baseline are ignored (suppressed). |
| `--create-baseline` | | `str` | *(none)* | Save current findings to the specified file as a new baseline. Cannot be used with `--diff`. |
| `--config` | `-c` | `str` | `~/.lumen-argus/config.yaml` | Path to config YAML file. |
| `--format` | `-f` | `str` | `text` | Output format. Choices: `text`, `json`. |

### Examples

=== "Scan files"

    ```bash
    # Scan specific files
    lumen-argus scan src/config.py .env.example

    # Scan with JSON output
    lumen-argus scan --format json src/**/*.py
    ```

=== "Scan git diff"

    ```bash
    # Scan staged changes (pre-commit hook)
    lumen-argus scan --diff

    # Scan changes since a specific commit
    lumen-argus scan --diff HEAD~5

    # Scan diff against main branch
    lumen-argus scan --diff main
    ```

=== "Baselines"

    ```bash
    # Create a baseline of existing findings
    lumen-argus scan src/ --create-baseline .argus-baseline.json

    # Scan and ignore baseline findings
    lumen-argus scan src/ --baseline .argus-baseline.json
    ```

=== "Stdin"

    ```bash
    # Pipe content to scan
    echo "AKIA1234567890ABCDEF" | lumen-argus scan

    # Scan clipboard contents (macOS)
    pbpaste | lumen-argus scan
    ```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings |
| `1` | One or more findings detected |

---

## `logs`

Log file utilities.

### `logs export`

Export audit and application logs for sharing with support or compliance review.

```bash
lumen-argus logs export [OPTIONS]
```

#### Flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--sanitize` | | `bool` | `false` | Strip IP addresses, hostnames, and file paths from exported logs. |
| `--config` | `-c` | `str` | `~/.lumen-argus/config.yaml` | Path to config YAML file (used to locate log directories). |

#### Examples

```bash
# Export logs as-is
lumen-argus logs export

# Export with sanitized paths and IPs
lumen-argus logs export --sanitize

# Export using a specific config
lumen-argus logs export --config /path/to/config.yaml
```

---

## Configuration precedence

CLI flags override values from the config file. The full precedence order (highest to lowest):

1. CLI flags (`--port`, `--log-dir`, etc.)
2. Project-level config (`.lumen-argus.yaml` in working directory)
3. Global config (`~/.lumen-argus/config.yaml`)
4. Built-in defaults

## Signal handling

| Signal | Behavior |
|--------|----------|
| `SIGINT` / `SIGTERM` | Graceful shutdown: stop accepting connections, drain in-flight requests (up to `proxy.drain_timeout` seconds), then exit. |
| `SIGHUP` | Reload config from disk without restarting. Updates allowlists, detector actions, custom rules, SSL context, and log levels. |

!!! tip "Second SIGINT forces exit"
    If the proxy is stuck during graceful shutdown, sending a second `SIGINT` (Ctrl+C) forces an immediate exit.
