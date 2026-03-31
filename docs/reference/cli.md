# CLI Reference

lumen-argus provides subcommands for proxy operation, scanning, tool detection, and setup.

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
| `--no-default-rules` | | `bool` | `false` | Skip auto-import of community rules on first run. |
| `--engine-port` | | `int` | | Enable relay+engine combined mode. Engine binds to this port, relay on `--port`. |
| `--fail-mode` | | `str` | `open` | Relay fail mode when engine is down. Choices: `open`, `closed`. |

### Examples

```bash
# Start with defaults
lumen-argus serve

# Custom port and config
lumen-argus serve --port 9090 --config /path/to/config.yaml

# Combined relay+engine mode
lumen-argus serve --port 8080 --engine-port 8090 --fail-mode open

# JSON output for log aggregation
lumen-argus serve --format json --log-level info

# Debug mode with no colors (for CI/log files)
lumen-argus serve --log-level debug --no-color
```

!!! note "Bind address"
    The proxy binds to `127.0.0.1` by default. Use `--host 0.0.0.0` for Docker containers. Non-loopback binds log a warning. The `--host` flag overrides `proxy.bind` and `dashboard.bind` simultaneously.

---

## `relay`

Run the lightweight relay process for fault-isolated deployments. The relay forwards all traffic to the engine and applies fail-mode policy when the engine is down.

```bash
lumen-argus relay [OPTIONS]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--port` | `-p` | `int` | `8080` | Relay listening port. |
| `--host` | `-H` | `str` | `127.0.0.1` | Bind address. |
| `--engine` | | `str` | `http://localhost:8090` | Engine URL. |
| `--fail-mode` | | `str` | `open` | `open` = forward direct to upstream when engine down. `closed` = return 503. |
| `--config` | `-c` | `str` | | Config YAML path. |
| `--log-level` | | `str` | `info` | Logging verbosity. |

```bash
lumen-argus relay --port 8080 --engine http://localhost:8090 --fail-mode open
```

---

## `engine`

Run the full inspection engine on an internal port. Equivalent to `serve` with a different default port.

```bash
lumen-argus engine [OPTIONS]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--port` | `-p` | `int` | `8090` | Engine listening port. |
| `--host` | `-H` | `str` | `127.0.0.1` | Bind address. |
| `--config` | `-c` | `str` | | Config YAML path. |
| `--log-dir` | | `str` | | Audit log directory. |
| `--log-level` | | `str` | `warning` | Logging verbosity. |
| `--no-default-rules` | | `bool` | `false` | Skip auto-import of community rules. |

```bash
lumen-argus engine --port 8090
```

---

## `protection`

Toggle proxy routing on/off. Used by the tray app for the "Enable/Disable Protection" toggle.

```bash
lumen-argus protection <enable|disable|status> [OPTIONS]
```

| Arg/Flag | Type | Description |
|----------|------|-------------|
| `action` | `str` | `enable`, `disable`, or `status`. |
| `--proxy-url` | `str` | Proxy URL for `enable` (default: `http://localhost:8080`). |

`enable` writes all ENV_VAR client env vars to `~/.lumen-argus/env`. `disable` truncates the file. `status` returns JSON with `enabled`, `env_file`, and `env_vars_set`.

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

## `detect`

Scan the system for installed AI CLI agents and check proxy configuration status.

```bash
lumen-argus detect [OPTIONS]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--versions` | `bool` | `false` | Detect versions by running `--version` subprocesses (slower). |
| `--json` | `bool` | `false` | Output as JSON for CI/automation. |
| `--audit` | `bool` | `false` | Audit proxy compliance — shows [OK]/[FAIL] per tool. |
| `--check-quiet` | `bool` | `false` | Shell hook mode: prints warning to stderr if unconfigured tools found, silent otherwise. Designed for `eval` in shell profiles (<100ms). |
| `--proxy-url` | `str` | `http://localhost:8080` | Expected proxy URL to check against. |

### Examples

```bash
# Detect installed tools
lumen-argus detect

# Include version info
lumen-argus detect --versions

# JSON output for CI
lumen-argus detect --json

# Compliance audit
lumen-argus detect --audit

# Shell hook (add to .zshrc)
eval "$(lumen-argus detect --check-quiet 2>/dev/null)"
```

### CI/CD Environment Detection

When running in CI/CD or container environments, `detect` automatically identifies the platform via environment variables:

- **GitHub Actions** (`GITHUB_ACTIONS`)
- **GitLab CI** (`GITLAB_CI`)
- **CircleCI**, **Jenkins**, **Travis CI**, **Buildkite**, **AWS CodeBuild**, **Azure Pipelines**, **Bitbucket Pipelines**, **TeamCity**
- **Kubernetes** (`KUBERNETES_SERVICE_HOST`)
- **Docker** (`/.dockerenv` file)
- **Generic CI** (`CI=true`)

---

## `setup`

Configure detected AI tools to route through the proxy.

```bash
lumen-argus setup [CLIENT] [OPTIONS]
```

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `client` | `str` (optional) | Configure only this specific client (e.g., `aider`). |

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--proxy-url` | `str` | `http://localhost:8080` | Proxy URL to configure. |
| `--undo` | `bool` | `false` | Remove all proxy configuration and restore backups. |
| `--dry-run` | `bool` | `false` | Show what would change without modifying files. |
| `--non-interactive` | `bool` | `false` | Auto-configure without prompting. |

### Examples

```bash
# Interactive setup wizard
lumen-argus setup

# Configure specific tool
lumen-argus setup aider

# Preview changes
lumen-argus setup --dry-run

# Auto-configure without prompts
lumen-argus setup --non-interactive

# Undo all changes
lumen-argus setup --undo
```

### What setup modifies

- **Shell profiles**: Adds `export VAR=URL` lines tagged with `# lumen-argus:managed` to `~/.zshrc`, `~/.bashrc`, `~/.config/fish/config.fish`, or PowerShell profiles.
- **IDE settings**: Updates `settings.json` for VS Code, Cursor, Windsurf, and other IDE variants.
- **Backups**: Every modification is backed up to `~/.lumen-argus/setup/backups/` with a manifest for undo.

---

## `watch`

Background daemon that periodically scans for newly installed AI tools. Optionally auto-configures them.

```bash
lumen-argus watch [OPTIONS]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--proxy-url` | `str` | `http://localhost:8080` | Proxy URL to configure. |
| `--interval` | `int` | `300` | Scan interval in seconds. |
| `--auto-configure` | `bool` | `false` | Auto-configure new tools without prompting. |
| `--install` | `bool` | `false` | Install as system service (launchd on macOS, systemd on Linux). |
| `--uninstall` | `bool` | `false` | Remove the system service. |
| `--status` | `bool` | `false` | Show watch daemon status. |

### Examples

```bash
# Run foreground watch loop
lumen-argus watch

# Install as system service with auto-configure
lumen-argus watch --install --auto-configure

# Check status
lumen-argus watch --status

# Remove service
lumen-argus watch --uninstall
```

---

## `clients`

List all 17 supported AI CLI agents with setup instructions.

```bash
lumen-argus clients [--json]
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
| `SIGHUP` | Reload config from disk without restarting. Updates allowlists, detector actions, custom rules, timeouts, log levels, port/bind (graceful rebind), and max body size. |

!!! tip "Second SIGINT forces exit"
    If the proxy is stuck during graceful shutdown, sending a second `SIGINT` (Ctrl+C) forces an immediate exit.
