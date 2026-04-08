# Client Detection & Setup

lumen-argus can automatically detect which AI coding tools are installed on your
machine, check whether they're configured to route through the proxy, and set
them up in one command.

## Overview

The detection and setup workflow has three layers:

1. **Detect** — read-only scan that finds installed tools and checks proxy status
2. **Setup** — interactive (or non-interactive) wizard that configures tools
3. **Watch** — background daemon that detects newly installed tools over time

All three share the same detection engine and client registry of 27 supported agents.

---

## Detecting Installed Tools

```bash
lumen-argus detect
```

This scans your system using 8 detection layers (in priority order):

| Layer | What it checks | Example |
|-------|---------------|---------|
| Binary | `shutil.which()` for CLI tools | `claude`, `aider`, `codex` |
| pip | `importlib.metadata` (no subprocess) | `aider-chat` |
| npm | Global `node_modules/package.json` | `@anthropic-ai/claude-code` |
| Homebrew | Cellar directory (macOS) | `aider` formula |
| VS Code extensions | 8 IDE variants (VS Code, Insiders, VSCodium, Cursor, Windsurf, Kiro, Trae, Antigravity) | `github.copilot` |
| macOS app bundles | `/Applications/*.app` with Info.plist version | `Cursor.app` |
| JetBrains plugins | Product plugin directories | `github-copilot-intellij` |
| Neovim plugins | lazy.nvim, vim-plug, native pack directories | `copilot.vim` |

First match wins — if a tool is found as a binary, later layers are skipped for
that tool.

### Output modes

=== "Standard"

    ```bash
    lumen-argus detect
    ```
    ```
    Detected AI tools (3):

      [+] Claude Code                 binary     proxied
      [-] Aider           0.50.1      pip        not configured
      [+] GitHub Copilot  1.200.0     vscode_ext proxied

    2/3 configured for proxy (http://localhost:8080)
    Run 'lumen-argus setup' to configure remaining tools.
    ```

=== "Audit"

    ```bash
    lumen-argus detect --audit
    ```
    ```
    AI Tool Proxy Compliance Audit:

      [OK]   Claude Code           Proxied (~/.zshrc:42)
      [FAIL] Aider          0.50.1 NOT PROXIED — OPENAI_BASE_URL not configured
      [OK]   GitHub Copilot 1.200.0 Proxied (settings.json)

    Summary: 2/3 tools routed through proxy
    Action required: run 'lumen-argus setup' to configure uncovered tools.
    ```

=== "JSON"

    ```bash
    lumen-argus detect --json
    ```
    Full JSON output suitable for CI pipelines and automation scripts.

=== "Versions"

    ```bash
    lumen-argus detect --versions
    ```
    Runs `--version` subprocesses for CLI tools and reads `Info.plist` for app
    bundles. Slower but gives exact version numbers.

=== "MCP Servers"

    ```bash
    lumen-argus detect --mcp
    ```
    Discovers MCP servers from 8 AI tools plus Claude Code plugins:

    - **Claude Desktop** — `~/Library/Application Support/Claude/claude_desktop_config.json`
    - **Claude Code** — `~/.claude.json` (user-configured servers), `~/.claude/settings.json`, `.mcp.json` (project)
    - **Claude Code plugins** — reads `~/.claude/plugins/installed_plugins.json`, only enabled plugins
    - **Cursor** — `~/.cursor/mcp.json`
    - **Windsurf** — `~/.windsurf/mcp.json`
    - **VS Code** — `~/Library/Application Support/Code/User/mcp.json` (global), `.vscode/mcp.json` (workspace)
    - **Cline** — `~/.cline/mcp_servers.json`
    - **Roo Code** — `~/.roo-code/mcp.json`

    Shows transport type (stdio/http/ws), source tool, and whether the server
    is already wrapped through `lumen-argus mcp` for scanning. Combine with
    `--json` for machine-readable output.

    Cloud MCP servers (e.g., `claude.ai Gmail`) are Anthropic-hosted and have
    no local config — they are not detectable.

### MCP server wrapping

Once you've detected MCP servers with `--mcp`, you can wrap them through
`lumen-argus mcp` for scanning:

```bash
# Interactive — prompts for each server
lumen-argus setup --mcp

# Wrap all detected stdio servers without prompting
lumen-argus setup --mcp --non-interactive

# Wrap a specific server
lumen-argus setup --mcp --server filesystem --source claude_desktop

# Undo — restore original config
lumen-argus setup --mcp --undo
```

Wrapping rewrites the config file so `{"command": "npx", "args": [...]}` becomes
`{"command": "lumen-argus", "args": ["mcp", "--", "npx", ...]}`. The original
config is backed up to `~/.lumen-argus/setup/backups/`.

Both stdio and HTTP/WS MCP servers can be wrapped:

- **Stdio servers**: config rewrites `command` to `lumen-argus mcp -- <original-command>`
- **HTTP/WS servers**: config converts URL to stdio bridge: `lumen-argus mcp --upstream <original-url>` — the AI tool manages the bridge process lifecycle

When enrolled with a Pro proxy, fleet policies from `~/.lumen-argus/mcp_policies.json`
are enforced during wrapping:

- **`blocked`** servers are skipped with a warning
- **`must_scan`** servers are auto-wrapped without prompting
- **`allowed`** and **`review`** servers follow normal interactive/non-interactive flow

### Proxy configuration check

Detection checks two sources to determine if a tool is routed through the proxy:

1. **Shell profiles** — scans `~/.zshrc`, `~/.bashrc`, `~/.config/fish/config.fish`,
   and PowerShell profiles for `export OPENAI_BASE_URL=...` (or the tool's
   specific env var)
2. **IDE settings** — loads `settings.json` for each VS Code variant and checks
   tool-specific proxy keys (`http.proxy`, `cody.proxy`, `continue.proxy`, etc.)

### CI/CD environment detection

When running in CI or containers, detection automatically identifies the platform:

| Environment | Detected via |
|-------------|-------------|
| GitHub Actions | `GITHUB_ACTIONS` env var |
| GitLab CI | `GITLAB_CI` env var |
| CircleCI | `CIRCLECI` env var |
| Jenkins | `JENKINS_URL` env var |
| Travis CI | `TRAVIS` env var |
| Buildkite | `BUILDKITE` env var |
| AWS CodeBuild | `CODEBUILD_BUILD_ID` env var |
| Azure Pipelines | `TF_BUILD` env var |
| Bitbucket Pipelines | `BITBUCKET_BUILD_NUMBER` env var |
| TeamCity | `TEAMCITY_VERSION` env var |
| Kubernetes | `KUBERNETES_SERVICE_HOST` env var |
| Docker | `/.dockerenv` file |
| Generic CI | `CI=true` env var |

In CI environments, you typically don't need detection — just set the proxy env
vars directly in your CI config:

```yaml
# GitHub Actions example
env:
  OPENAI_BASE_URL: https://proxy.corp.io:8080
  ANTHROPIC_BASE_URL: https://proxy.corp.io:8080
```

---

## Setting Up Tools

```bash
lumen-argus setup
```

The setup wizard:

1. Detects installed tools (calls `detect` internally)
2. Filters to tools that are installed but **not yet** routed through the proxy
3. For each unconfigured tool, asks whether to configure it
4. Applies the configuration (shell profile or IDE settings)
5. Creates timestamped backups before every modification

### What gets modified

The setup wizard uses a **two-layer approach** for toggleable protection:

**1. Shell profile** — a source block is written once and never touched again:

```bash
# In your .zshrc / .bashrc (written by lumen-argus setup):
# lumen-argus:begin
[ -f "$HOME/.lumen-argus/env" ] && source "$HOME/.lumen-argus/env"
# lumen-argus:end
```

**2. Env file** — the actual env vars are written to `~/.lumen-argus/env`:

```bash
export OPENAI_BASE_URL=http://localhost:8080  # lumen-argus:managed client=aider
export ANTHROPIC_BASE_URL=http://localhost:8080  # lumen-argus:managed client=claude_code
```

This separation lets the tray app toggle protection by writing or truncating the env file, without ever touching your shell profile.

**IDE extensions** (VS Code, JetBrains) get their proxy setting updated in
`settings.json`:

```json
{
    "http.proxy": "http://localhost:8080"
}
```

Every managed line is tagged with `# lumen-argus:managed` for clean identification and
removal. The env file is secured with `0o600` permissions (owner-only) because it is sourced by the shell.

### Modes

```bash
# Interactive (default) — prompts for each tool
lumen-argus setup

# Configure a specific tool only
lumen-argus setup aider

# Non-interactive — auto-configure everything
lumen-argus setup --non-interactive

# Dry run — show what would change, don't touch files
lumen-argus setup --dry-run

# Custom proxy URL
lumen-argus setup --proxy-url http://localhost:9090
```

### Backups and undo

Every file modification creates a timestamped backup in
`~/.lumen-argus/setup/backups/`. A manifest tracks all changes.

To revert everything:

```bash
lumen-argus setup --undo
```

This removes source blocks and managed lines from shell profiles, truncates the env file, and restores IDE settings from backups.

---

## Shell Hook

For ongoing monitoring, you can install a shell hook that warns about
unconfigured tools every time you open a new terminal:

```bash
# Add to your .zshrc / .bashrc
eval "$(lumen-argus detect --check-quiet 2>/dev/null)"
```

This runs in under 100ms and only prints a warning to stderr if unconfigured
tools are found:

```
[lumen-argus] 1 unconfigured tool(s): Aider — run 'lumen-argus setup'
```

If all tools are configured, it produces no output.

The setup wizard can install this hook for you via `install_shell_hook()`, and
`setup --undo` removes it along with everything else (it uses the same
`# lumen-argus:managed` tag).

---

## Watch Daemon

For hands-free monitoring, the watch daemon periodically rescans the system and
optionally auto-configures new tools:

```bash
# Run in the foreground (Ctrl+C to stop)
lumen-argus watch

# Auto-configure new tools without prompting
lumen-argus watch --auto-configure

# Custom scan interval (default: 300 seconds)
lumen-argus watch --interval 600
```

### How it works

1. On startup, runs a detection scan and saves the list of known tools
2. Every interval (default 5 minutes), rescans and compares against the known list
3. If a new tool appears, logs it (and auto-configures if `--auto-configure` is set)
4. State is persisted in `~/.lumen-argus/watch/state.json` across restarts

### Installing as a system service

Instead of running in the foreground, you can install the watch daemon as a
system service that starts on login:

=== "macOS (launchd)"

    ```bash
    # Install
    lumen-argus watch --install --auto-configure

    # Start
    launchctl load ~/Library/LaunchAgents/io.lumen-argus.watch.plist

    # Check status
    lumen-argus watch --status

    # Stop and remove
    launchctl unload ~/Library/LaunchAgents/io.lumen-argus.watch.plist
    lumen-argus watch --uninstall
    ```

=== "Linux (systemd)"

    ```bash
    # Install
    lumen-argus watch --install --auto-configure

    # Enable and start
    systemctl --user daemon-reload
    systemctl --user enable --now lumen-argus-watch

    # Check status
    lumen-argus watch --status

    # Stop and remove
    systemctl --user stop lumen-argus-watch
    lumen-argus watch --uninstall
    ```

Logs go to `~/.lumen-argus/logs/watch.log` (launchd) or the journal (systemd).

---

## Protection Toggle

The `protection` command provides a VPN-like toggle for the tray app (or CLI):

```bash
# Enable — write all tool env vars to ~/.lumen-argus/env
lumen-argus protection enable

# Disable — truncate the env file (tools connect directly to providers)
lumen-argus protection disable

# Check status (JSON output for tray app consumption)
lumen-argus protection status
```

Output:

```json
{
  "enabled": true,
  "env_file": "/Users/you/.lumen-argus/env",
  "env_vars_set": 7
}
```

**How it works:**

- `enable` writes env vars for ALL CLI tools (not just installed ones) to `~/.lumen-argus/env`
- `disable` truncates the file to empty — new terminal sessions connect directly
- Existing terminal sessions are not affected until restarted (inherent OS limitation)
- For instant effect on running sessions, combine with passthrough mode (see [Proxy Guide](proxy.md#passthrough-mode))

The env file uses atomic writes (temp file + rename) and file locking (`fcntl.flock`) to prevent corruption from concurrent access.

---

## Supported Agents

All 27 agents in the built-in registry, with their proxy configuration and detection methods:

| Agent | Proxy Config | Setup Mechanism | Detection |
|-------|-------------|-----------------|-----------|
| Claude Code | `ANTHROPIC_BASE_URL` | env var | binary, npm |
| GitHub Copilot CLI | `COPILOT_PROVIDER_BASE_URL` | env var | binary, brew |
| Aider | `OPENAI_BASE_URL` | env var | binary, pip, brew |
| Codex CLI | `OPENAI_BASE_URL` | env var | binary, npm |
| OpenCode | env vars + `opencode.json` per-provider `baseURL` | env var + config file | binary, npm |
| Gemini CLI | `GEMINI_BASE_URL` | env var | binary, npm, brew |
| Cursor | Manual (IDE settings UI) | manual | binary, app bundle |
| GitHub Copilot | `http.proxy` (forward proxy) | IDE settings | VS Code, JetBrains, Neovim |
| Continue | `~/.continue/config.json` | config file | VS Code, Neovim |
| Cody | `cody.serverEndpoint` | IDE settings | VS Code, JetBrains, Neovim |
| Cline | Manual (extension UI) | manual | VS Code |
| Roo Code | Manual (extension UI) | manual | VS Code |
| Aide | Manual (IDE settings UI) | manual | binary, app bundle |
| Droid | Manual (BYOK settings) | manual | binary, npm, VS Code |
| CodeBuddy | Manual (models.json) | manual | binary, npm, VS Code, JetBrains |
| Kilo Code | Manual (extension UI) | manual | npm, VS Code |
| Windsurf | Not supported | — | binary, app bundle |
| Amazon Q | Not supported | — | binary, VS Code, JetBrains |
| Tabnine | Not supported | — | VS Code, JetBrains |
| Augment Code | Not supported | — | VS Code |
| Gemini Code Assist | Not supported | — | VS Code |
| Antigravity | Not supported | — | binary, app bundle |
| Kiro | Not supported | — | binary, app bundle |
| Kiro CLI | Not supported | — | binary |
| Trae | Not supported | — | app bundle |
| Qoder | Not supported | — | app bundle |
| Warp | Not supported | — | binary, app bundle |

Run `lumen-argus clients` to see the full list with setup instructions.

---

## Platform Support

### macOS and Linux

Full support for all detection layers, shell profiles (zsh, bash, fish), IDE
settings, and service installation.

### Windows

Detection and setup support includes:

- **PowerShell profiles** — both PowerShell 7 (`Documents/PowerShell/`) and
  Windows PowerShell 5.1 (`Documents/WindowsPowerShell/`)
- **PowerShell syntax** — uses `$env:VAR = "value"` instead of `export`
- **VS Code settings** — checks `%APPDATA%/Code/User/settings.json` (and
  variants for Cursor, Windsurf, Kiro, Trae, Insiders, VSCodium)
- **JetBrains plugins** — checks `%APPDATA%/JetBrains/`
- **npm global packages** — checks `%APPDATA%/npm/node_modules/`

### Node Version Managers

The npm scanner checks paths managed by popular Node version managers:

- **nvm** — `NVM_DIR/current/lib/node_modules`
- **fnm** — `FNM_DIR` (or default platform path), `FNM_MULTISHELL_PATH`, aliases/default
- **volta** — `VOLTA_HOME/tools/image/packages`, `VOLTA_HOME/tools/image/node/<version>/lib/node_modules`
