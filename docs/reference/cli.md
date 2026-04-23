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
| `--dashboard-port` | | `int` | `8081` | Dashboard listening port. Overrides `dashboard.port` in config. |
| `--no-standalone` | | `bool` | `false` | Mark as managed by tray app. Exposed in `/api/v1/status` as `standalone: false`. |
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
| `--dashboard-port` | | `int` | `8081` | Dashboard listening port. |
| `--no-standalone` | | `bool` | `false` | Mark as managed by tray app. |

```bash
lumen-argus engine --port 8090 --dashboard-port 8082
```

---

## `protection`

Toggle proxy routing on/off. Used by the tray app for the "Enable/Disable Protection" toggle.

```bash
lumen-argus-agent protection <enable|disable|status> [OPTIONS]
```

| Arg/Flag | Type | Description |
|----------|------|-------------|
| `action` | `str` | `enable`, `disable`, or `status`. |
| `--proxy-url` | `str` | Proxy URL for `enable` (default: `http://localhost:8080`). |
| `--managed-by` | `str` | Lifecycle owner — `cli` (default) or `tray`. Pass `tray` when invoked by the desktop app or enrollment flow to emit the self-healing liveness guard around the exports. |

`enable` writes all ENV_VAR client env vars to `~/.lumen-argus/env`.
By default (`--managed-by cli`) the exports are unconditional — right
for users running the binary from a terminal.  `--managed-by tray`
wraps the exports in a liveness guard so they skip when the tray app
is gone and no relay is running.  `disable` truncates the file **and**
clears the matching launchctl env vars on macOS so GUI-launched AI
tools (Claude Desktop, Cursor) stop pointing at the proxy immediately
— not just new terminals.  `status` returns JSON with `enabled`,
`env_file`, `env_vars_set`, and (when enabled) the recorded
`managed_by`.  `disable` additionally returns
`launchctl_vars_cleared` (macOS only — empty list elsewhere).  See
the [Protection Env File reference](protection-env-file.md) for the
full format and guard semantics.

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
| `--mcp` | `bool` | `false` | Include MCP servers discovered from AI tool config files (Claude Desktop, Claude Code, Cursor, Windsurf, Cline, Roo Code). |
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

# Detect MCP servers configured in AI tools
lumen-argus detect --mcp

# MCP detection with JSON output
lumen-argus detect --mcp --json

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
lumen-argus-agent setup [CLIENT] [OPTIONS]
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
| `--mcp` | `bool` | `false` | Wrap MCP servers through `lumen-argus mcp` scanning proxy instead of configuring AI client proxy vars. |
| `--server` | `str` | `""` | MCP server name to wrap/unwrap (with `--mcp`). Empty = all detected. |
| `--source` | `str` | `""` | Source tool ID filter (with `--mcp`, e.g. `claude_desktop`). |

### Examples

```bash
# Interactive setup wizard
lumen-argus-agent setup

# Configure specific tool
lumen-argus-agent setup aider

# Forward proxy setup for Copilot CLI (step-by-step: CA, alias, shell profile).
# CA generation requires mitmproxy, which lives in the agent package — run
# this command via the agent CLI, not the proxy CLI. Invoking it via
# `lumen-argus-agent setup copilot_cli` from a proxy-only install emits a clean
# pointer to `lumen-argus-agent setup copilot_cli`.
lumen-argus-agent setup copilot_cli

# Preview changes
lumen-argus-agent setup --dry-run

# Auto-configure without prompts
lumen-argus-agent setup --non-interactive

# Undo all changes
lumen-argus-agent setup --undo

# Wrap MCP servers through scanning proxy (interactive)
lumen-argus-agent setup --mcp

# Wrap all MCP servers without prompting
lumen-argus-agent setup --mcp --non-interactive

# Wrap a specific MCP server
lumen-argus-agent setup --mcp --server filesystem --source claude_desktop

# Preview MCP wrapping
lumen-argus-agent setup --mcp --dry-run

# Unwrap all MCP servers
lumen-argus-agent setup --mcp --undo

# Unwrap a specific MCP server
lumen-argus-agent setup --mcp --undo --server filesystem
```

### What setup modifies

- **Shell profiles**: Adds `export VAR=URL` lines tagged with `# lumen-argus:managed` to `~/.zshrc`, `~/.bashrc`, `~/.config/fish/config.fish`, or PowerShell profiles.
- **IDE settings**: Updates `settings.json` for VS Code, Cursor, Windsurf, and other IDE variants.
- **MCP configs** (with `--mcp`): Rewrites `mcpServers` entries in AI tool config files (Claude Desktop, Claude Code, Cursor, Windsurf, Cline, Roo Code) to route through `lumen-argus mcp -- <original-command>`. Only stdio servers are supported; HTTP/SSE servers are detected but not wrapped yet.
- **Backups**: Every modification is backed up to `~/.lumen-argus/setup/backups/` with a manifest for undo.

---

## `watch`

Background daemon that periodically scans for newly installed AI tools. Optionally auto-configures them.

```bash
lumen-argus-agent watch [OPTIONS]
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
lumen-argus-agent watch

# Install as system service with auto-configure
lumen-argus-agent watch --install --auto-configure

# Check status
lumen-argus-agent watch --status

# Remove service
lumen-argus-agent watch --uninstall
```

---

## `clients`

List all 27 supported AI CLI agents with setup instructions.

```bash
lumen-argus clients [--json]
```

---

## `lumen-argus-agent`

Lightweight workstation agent — available as a separate package (`pip install lumen-argus-agent`).

Supports a subset of commands: `detect`, `setup`, `watch`, `protection`, `clients`, `enroll`, `heartbeat`, `refresh-policy`, `relay`, `forward-proxy`, `uninstall`.

```bash
lumen-argus-agent [--version] [--help] <command> [<args>]
```

### `enroll`

Enroll this machine with a central lumen-argus proxy (enterprise deployment).

```bash
lumen-argus-agent enroll [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--server` | `str` | | Central proxy server URL |
| `--token` | `str` | | Enrollment token |
| `--non-interactive` | `bool` | `false` | No prompts |
| `--undo` | `bool` | `false` | Unenroll and remove all configuration |

```bash
# Interactive enrollment
lumen-argus-agent enroll --server https://argus.corp.io

# Non-interactive (Ansible/MDM)
lumen-argus-agent enroll --server https://argus.corp.io --token enroll_abc123 --non-interactive

# Unenroll
lumen-argus-agent enroll --undo
```

Enrollment fetches configuration from the proxy, registers the agent, configures all detected AI tools, enables protection, and installs the watch daemon. State saved to `~/.lumen-argus/enrollment.json`.

### `heartbeat`

Send a single heartbeat to the central proxy with current tool status.

```bash
lumen-argus-agent heartbeat
```

Reports: agent version, installed tools, proxy configuration status, protection state, watch daemon status. Used by the tray app and cron jobs for fleet monitoring.

Every successful heartbeat also refreshes the enrollment policy from `GET /api/v1/enrollment/config` so admin-side changes (fail-mode, auto-configure, tray-allowed-disable, telemetry interval) propagate to enrolled devices within one heartbeat cycle. Refresh failures never flip the heartbeat return value — the next heartbeat retries. Devices without an agent bearer token (community-only mode) skip the refresh silently.

### `refresh-policy`

Out-of-cycle policy pull. Re-fetches the enrollment policy from the central proxy and atomically rewrites the `.policy` slice of `~/.lumen-argus/enrollment.json`. Identity fields (`agent_id`, `agent_token`, `enrolled_at`, ...) are never touched.

```bash
lumen-argus-agent refresh-policy [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--json` | `bool` | `false` | Emit `{"changed": bool, "policy_version": iso8601}` on stdout for machine parsing |
| `--non-interactive` | `bool` | `false` | Accepted for script compatibility — refresh has no interactive prompts |

Exit codes:

| Code | Meaning |
|------|---------|
| **0** | Refresh completed (policy changed or already current) |
| **1** | Network, auth, or malformed-response error |
| **2** | Not enrolled |

```bash
# Invoke out-of-cycle (e.g. right after re-enroll)
lumen-argus-agent refresh-policy

# Machine-readable — exit 0 regardless of whether policy changed
lumen-argus-agent refresh-policy --json
# {"changed": true, "policy_version": "2026-04-02T10:30:00Z"}
```

Policy refresh also runs automatically inside every `heartbeat` call; `refresh-policy` is the standalone entry point for callers that want a pull without a heartbeat round-trip. Bearer token is sent over HTTPS or loopback only; cleartext HTTP to a non-loopback host is refused.

### `relay`

Start the local forwarding proxy with OS-level identity enrichment. AI tools connect to the relay, which enriches requests with `X-Lumen-Argus-*` headers and forwards to the upstream proxy.

```bash
lumen-argus-agent relay [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--port` | `int` | `8070` | Listen port |
| `--host` | `str` | `127.0.0.1` | Bind address |
| `--upstream` | `str` | from enrollment or `http://localhost:8080` | Upstream proxy URL |
| `--fail-mode` | `str` | `open` | Behavior when proxy unreachable: `open` (pass-through) or `closed` (block) |
| `--timeout` | `int` | `150` | Idle-read timeout in seconds for upstream connections |
| `--connect-timeout` | `int` | `10` | TCP connect timeout in seconds |
| `--log-level` | `str` | `info` | Log level |

```bash
# Start relay with defaults (localhost:8070 → proxy:8080)
lumen-argus-agent relay

# Custom upstream and fail-closed
lumen-argus-agent relay --upstream http://proxy-server:8080 --fail-mode closed

# Configure AI tools to use relay
ANTHROPIC_BASE_URL=http://localhost:8070 claude
OPENAI_BASE_URL=http://localhost:8070 opencode
```

The relay resolves caller identity from OS-level APIs (process working directory, git branch, hostname, username) and injects `X-Lumen-Argus-*` headers into every forwarded request. The proxy reads these headers from authenticated agents to attribute findings to specific agent instances.

### `uninstall`

Reverse every system change the agent made: tool configurations, MCP
wrappers, shell profile source blocks, shell env file, launchctl env
vars (macOS), and agent-owned state files.  Idempotent — running on a
clean machine is a no-op.

Two equivalent entry points ship with the agent package:

```bash
lumen-argus-agent uninstall [OPTIONS]

# Standalone alias — same flags, same output.  Useful when the
# subcommand form is awkward (e.g. a Homebrew post-uninstall hook
# that gets invoked by binary name).
lumen-argus-uninstall [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--keep-data` | `bool` | `false` | Skip removal of agent-owned state files (`~/.lumen-argus/env`, `enrollment.json`, `relay.json`, `.env.lock`).  Use when the caller plans to `rm -rf ~/.lumen-argus/` itself (desktop tray app uninstall path). |
| `--non-interactive` | `bool` | `false` | Accepted for script compatibility.  `uninstall` has no interactive prompts. |

Step ordering is load-bearing — the command runs:

1. `protection_disable` — snapshots the managed env vars, truncates
   `~/.lumen-argus/env`, removes OpenCode per-provider overrides, and
   clears the snapshotted names via `launchctl unsetenv` (macOS).
2. `mcp_undo` — unwraps every MCP server back to its original command
   or URL.
3. `setup_undo` — removes shell profile source blocks, restores IDE
   settings from backups, clears forward-proxy aliases, truncates the
   env file again (idempotent).
4. `data_files_removed` — deletes agent-owned state files unless
   `--keep-data` was passed.

Each step is best-effort — a failure in one is logged and the
orchestrator continues so a partially-broken machine still gets
maximal cleanup.  Exit code is `0` when every step succeeded, `1`
when at least one failed.

Always emits JSON on stdout so callers (desktop tray app, shell
scripts) do not have to parse free text:

```json
{
  "steps": {
    "protection_disable": "ok",
    "mcp_undo": "ok",
    "setup_undo": "ok",
    "data_files_removed": "ok"
  },
  "launchctl_vars_cleared": ["ANTHROPIC_BASE_URL", "OPENAI_BASE_URL"],
  "data_files_removed": [
    "/Users/alice/.lumen-argus/env",
    "/Users/alice/.lumen-argus/enrollment.json"
  ],
  "errors": []
}
```

```bash
# CLI user — clean up before pip uninstall
lumen-argus-agent uninstall

# Tray app sidecar — reverse config, but keep data files so the
# tray app can rm -rf the directory itself
lumen-argus-agent uninstall --keep-data --non-interactive
```

What the command does **not** touch — these belong to the desktop
installer:

-   `~/.lumen-argus/.app-path`, `license.key`, `trial.json`, `bin/`
-   LaunchAgent plists (tray watchdog, relay service)
-   The application bundle in `/Applications`
-   macOS App Support / Logs directories

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
| `SIGHUP` | Reload config from disk without restarting. Updates allowlists, detector actions, custom rules, timeouts (including connect timeout), log levels, port/bind (graceful rebind), and max body size. |

!!! tip "Second SIGINT forces exit"
    If the proxy is stuck during graceful shutdown, sending a second `SIGINT` (Ctrl+C) forces an immediate exit.
