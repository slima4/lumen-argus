"""Client auto-detection engine — scans for installed AI CLI agents.

Discovers installed AI coding tools via binary lookup, package managers,
IDE extensions, and app bundles. Checks proxy configuration status in
shell profiles and IDE settings.

All detection is read-only — never modifies files. Setup is in setup_wizard.py.
"""

import json
import logging
import os
import platform
import re
from typing import Any

from lumen_argus_core.clients import CLIENT_REGISTRY, PROXY_ENV_VARS, ClientDef, ProxyConfigType
from lumen_argus_core.detect_models import (
    CIEnvironment,
    DetectedClient,
    DetectionReport,
    MCPConfigSource,
    MCPDetectionReport,
    MCPServerEntry,
    get_vscode_variants,
)
from lumen_argus_core.forward_proxy import ALIASES_PATH as _FORWARD_PROXY_ALIASES_PATH
from lumen_argus_core.scanners import (
    detect_version as _detect_version,
)
from lumen_argus_core.scanners import (
    scan_app_bundle as _scan_app_bundle,
)
from lumen_argus_core.scanners import (
    scan_binary as _scan_binary,
)
from lumen_argus_core.scanners import (
    scan_brew_package as _scan_brew_package,
)
from lumen_argus_core.scanners import (
    scan_jetbrains_plugin as _scan_jetbrains_plugin,
)
from lumen_argus_core.scanners import (
    scan_neovim_plugin as _scan_neovim_plugin,
)
from lumen_argus_core.scanners import (
    scan_npm_package as _scan_npm_package,
)
from lumen_argus_core.scanners import (
    scan_pip_package as _scan_pip_package,
)
from lumen_argus_core.scanners import (
    scan_vscode_extension as _scan_vscode_extension,
)

log = logging.getLogger("argus.detect")

# Shell profile files to scan (in priority order per shell)
_SHELL_PROFILES = {
    "zsh": ("~/.zshrc", "~/.zshenv", "~/.zprofile"),
    "bash": ("~/.bashrc", "~/.bash_profile", "~/.profile"),
    "fish": ("~/.config/fish/config.fish",),
    "powershell": (),  # dynamically resolved via _get_powershell_profiles()
}


def _get_powershell_profiles() -> tuple[str, ...]:
    """Get PowerShell profile paths on Windows."""
    if platform.system() != "Windows":
        return ()
    # PowerShell 7 (pwsh) and Windows PowerShell 5.1
    docs = os.environ.get("USERPROFILE", os.path.expanduser("~"))
    return (
        os.path.join(docs, "Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1"),
        os.path.join(docs, "Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
    )


def _strip_jsonc_comments(text: str) -> str:
    """Strip // comments from JSONC text, preserving // inside strings."""
    result: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            # String literal — copy until closing quote, respecting escapes
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                elif text[j] == '"':
                    j += 1
                    break
                else:
                    j += 1
            result.append(text[i:j])
            i = j
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            # Line comment — skip to end of line
            while i < n and text[i] != "\n":
                i += 1
        else:
            result.append(c)
            i += 1
    return "".join(result)


def load_jsonc(path: str) -> dict[str, Any]:
    """Load a JSONC file (JSON with // comments). Returns parsed dict or empty dict on error."""
    expanded = os.path.expanduser(path)
    if not os.path.isfile(expanded):
        return {}
    try:
        with open(expanded, "r", encoding="utf-8") as f:
            raw = f.read()
        result: dict[str, Any] = json.loads(_strip_jsonc_comments(raw))
        return result
    except json.JSONDecodeError as e:
        log.warning("invalid JSON in %s: %s", path, e)
        return {}
    except OSError as e:
        log.warning("could not read %s: %s", path, e)
        return {}


# Pre-compiled env var extraction patterns (one set per var)
_ENV_VAR_PATTERNS = {
    var: [
        re.compile(r"export\s+%s=[\"']?([^\s\"'#]+)" % re.escape(var)),
        re.compile(r"%s=[\"']?([^\s\"'#]+)" % re.escape(var)),
        re.compile(r"set\s+-x\s+%s\s+[\"']?([^\s\"'#]+)" % re.escape(var)),  # fish
        # PowerShell: $env:VAR = "value"
        re.compile(r"\$env:%s\s*=\s*[\"']?([^\s\"'#]+)" % re.escape(var)),
    ]
    for var in PROXY_ENV_VARS
}


# ---------------------------------------------------------------------------
# CI/CD environment detection
# ---------------------------------------------------------------------------

# Known CI/CD environments detected via env vars
_CI_ENVIRONMENTS = (
    ("GITHUB_ACTIONS", "github_actions", "GitHub Actions"),
    ("GITLAB_CI", "gitlab_ci", "GitLab CI"),
    ("CIRCLECI", "circleci", "CircleCI"),
    ("JENKINS_URL", "jenkins", "Jenkins"),
    ("TRAVIS", "travis_ci", "Travis CI"),
    ("BUILDKITE", "buildkite", "Buildkite"),
    ("CODEBUILD_BUILD_ID", "aws_codebuild", "AWS CodeBuild"),
    ("TF_BUILD", "azure_pipelines", "Azure Pipelines"),
    ("BITBUCKET_BUILD_NUMBER", "bitbucket_pipelines", "Bitbucket Pipelines"),
    ("TEAMCITY_VERSION", "teamcity", "TeamCity"),
)

# Container environments
_CONTAINER_ENVIRONMENTS = (
    ("KUBERNETES_SERVICE_HOST", "kubernetes", "Kubernetes"),
    # /.dockerenv file check handled in code
)


def detect_ci_environment() -> CIEnvironment | None:
    """Detect if running in a CI/CD or container environment.

    Returns CIEnvironment if detected, None otherwise.
    """
    # Check CI/CD platforms
    for env_var, env_id, display_name in _CI_ENVIRONMENTS:
        if os.environ.get(env_var):
            details: dict[str, str] = {}
            if env_id == "github_actions":
                details["repository"] = os.environ.get("GITHUB_REPOSITORY", "")
                details["workflow"] = os.environ.get("GITHUB_WORKFLOW", "")
                details["runner_os"] = os.environ.get("RUNNER_OS", "")
            elif env_id == "gitlab_ci":
                details["project"] = os.environ.get("CI_PROJECT_NAME", "")
                details["pipeline_id"] = os.environ.get("CI_PIPELINE_ID", "")
            log.debug("CI environment detected: %s", display_name)
            return CIEnvironment(env_id=env_id, display_name=display_name, detected=True, details=details)

    # Check container environments
    for env_var, env_id, display_name in _CONTAINER_ENVIRONMENTS:
        if os.environ.get(env_var):
            details = {}
            if env_id == "kubernetes":
                details["namespace"] = os.environ.get("KUBERNETES_NAMESPACE", "")
            log.debug("container environment detected: %s", display_name)
            return CIEnvironment(env_id=env_id, display_name=display_name, detected=True, details=details)

    # Check Docker (file-based)
    if os.path.exists("/.dockerenv"):
        log.debug("container environment detected: Docker")
        return CIEnvironment(env_id="docker", display_name="Docker", detected=True)

    # Generic CI flag (many CI systems set CI=true)
    if os.environ.get("CI", "").lower() in ("true", "1", "yes"):
        log.debug("generic CI environment detected via CI env var")
        return CIEnvironment(env_id="ci_generic", display_name="CI (generic)", detected=True)

    return None


# ---------------------------------------------------------------------------
# Env file reading (for routing_active)
# ---------------------------------------------------------------------------


_ENV_FILE_PATH = "~/.lumen-argus/env"


def _read_env_file_vars() -> set[str]:
    """Read ~/.lumen-argus/env and return the set of env var names present."""
    env_file = os.path.expanduser(_ENV_FILE_PATH)
    if not os.path.isfile(env_file):
        return set()
    result: set[str] = set()
    try:
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"export\s+(\w+)=\S+", line)
                if m:
                    result.add(m.group(1))
    except OSError:
        log.debug("could not read env file for routing_active check")
    return result


# ---------------------------------------------------------------------------
# Shell profile scanning
# ---------------------------------------------------------------------------


def _scan_shell_profiles(_proxy_url: str = "") -> dict[str, list[tuple[str, str, int, str]]]:
    """Scan shell profile files for proxy env vars.

    Returns {var_name: [(value, file_path, line_number, client_tag), ...]}
    for each found var.  ``client_tag`` is the ``client=<id>`` value from
    a ``# lumen-argus:managed client=<id>`` comment, or ``""`` for
    manually-set lines.
    """
    found: dict[str, list[tuple[str, str, int, str]]] = {}
    current_shell = os.path.basename(os.environ.get("SHELL", ""))

    # Determine which profiles to scan (current shell first, then others)
    profiles_to_scan: list[str] = []
    if current_shell in _SHELL_PROFILES:
        profiles_to_scan.extend(_SHELL_PROFILES[current_shell])
    for shell, profiles in _SHELL_PROFILES.items():
        if shell != current_shell:
            profiles_to_scan.extend(profiles)
    # Add PowerShell profiles on Windows
    if platform.system() == "Windows":
        profiles_to_scan.extend(_get_powershell_profiles())

    # Also scan the lumen-argus env file (appended last so entries win
    # in last-applicable-line matching via _match_shell_entry)
    profiles_to_scan.append(_ENV_FILE_PATH)

    for profile_path in profiles_to_scan:
        expanded = os.path.expanduser(profile_path)
        if not os.path.isfile(expanded):
            continue
        try:
            with open(expanded, "r", encoding="utf-8", errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    for var in PROXY_ENV_VARS:
                        # Match: export VAR=value, VAR=value, set -x VAR value (fish)
                        if var in stripped:
                            value = _extract_env_value(stripped, var)
                            if value:
                                client_tag = _extract_client_tag(stripped)
                                found.setdefault(var, []).append((value, profile_path, line_num, client_tag))
                                log.debug(
                                    "shell env found: %s=%s in %s:%d (client=%s)",
                                    var,
                                    value,
                                    profile_path,
                                    line_num,
                                    client_tag or "<untagged>",
                                )
        except OSError as e:
            log.warning("could not read shell profile %s: %s", profile_path, e)
    return found


_CLIENT_TAG_RE = re.compile(r"#\s*lumen-argus:managed\b.*?\bclient=(\S+)")


def _extract_client_tag(line: str) -> str:
    """Extract the client=<id> value from a lumen-argus:managed comment."""
    m = _CLIENT_TAG_RE.search(line)
    return m.group(1) if m else ""


def _match_shell_entry(entries: list[tuple[str, str, int, str]], client_id: str) -> tuple[str, str, int, str] | None:
    """Pick the shell env entry that applies to *client_id*.

    Shells evaluate top-to-bottom, so the *last* assignment wins at
    runtime.  We honour that: the last entry that is either tagged for
    this client or untagged is the effective one.  Lines tagged for a
    *different* client are skipped entirely.
    """
    best: tuple[str, str, int, str] | None = None
    for entry in entries:
        tag = entry[3]
        if tag == client_id or not tag:
            best = entry  # keep updating — last applicable line wins
    return best


def _extract_env_value(line: str, var_name: str) -> str:
    """Extract env var value from a shell profile line."""
    compiled = _ENV_VAR_PATTERNS.get(var_name)
    if not compiled:
        return ""
    for pattern in compiled:
        match = pattern.search(line)
        if match:
            return match.group(1)
    return ""


# ---------------------------------------------------------------------------
# IDE settings scanning
# ---------------------------------------------------------------------------


def _build_settings_cache() -> dict[str, tuple[dict[str, Any], str]]:
    """Load and parse all existing IDE settings files once. Returns {expanded_path: (settings, path)}."""
    cache: dict[str, tuple[dict[str, Any], str]] = {}
    for variant in get_vscode_variants():
        for settings_path in variant.settings:
            expanded = os.path.expanduser(settings_path)
            if expanded in cache:
                continue
            settings = load_jsonc(expanded)
            if settings:
                cache[expanded] = (settings, settings_path)
                log.debug("cached IDE settings: %s (%d keys)", settings_path, len(settings))
    return cache


def _check_ide_proxy_settings(
    settings_key: str, proxy_url: str = "", settings_cache: dict[str, tuple[dict[str, Any], str]] | None = None
) -> tuple[bool, str, str] | None:
    """Check if IDE settings have proxy configured for the given key.

    Returns (is_configured, proxy_value, settings_file) or None if no settings found.
    """
    if not settings_key:
        return None

    if settings_cache is None:
        settings_cache = _build_settings_cache()

    for settings, settings_path in settings_cache.values():
        value: str = str(settings.get(settings_key, ""))
        if value:
            is_match = bool(proxy_url and proxy_url in value)
            log.debug(
                "IDE setting found: %s=%s in %s (match=%s)",
                settings_key,
                value,
                settings_path,
                is_match,
            )
            return is_match, value, settings_path
    return None


# ---------------------------------------------------------------------------
# Main detection API
# ---------------------------------------------------------------------------


def detect_installed_clients(
    proxy_url: str = "http://localhost:8080",
    include_versions: bool = False,
    extra_clients: list[ClientDef] | None = None,
) -> DetectionReport:
    """Scan the system for installed AI CLI agents and their proxy configuration status.

    Args:
        proxy_url: Expected proxy URL to check against configured values.
        include_versions: If True, run --version commands (slower).
        extra_clients: Additional ClientDef entries from Pro extensions.

    Returns:
        DetectionReport with all detection results.
    """
    log.info("starting client detection (versions=%s, proxy_url=%s)", include_versions, proxy_url)

    clients_to_scan = list(CLIENT_REGISTRY)
    if extra_clients:
        clients_to_scan.extend(extra_clients)

    # Scan shell profiles and IDE settings once (shared across all clients)
    shell_env = _scan_shell_profiles(proxy_url)
    settings_cache = _build_settings_cache()

    # Read env file once for routing_active check
    env_file_vars = _read_env_file_vars()

    results = []
    for client in clients_to_scan:
        detected = _detect_single_client(client, shell_env, proxy_url, include_versions, settings_cache)
        # Check routing_active: env var present in ~/.lumen-argus/env
        if detected.installed and client.proxy_config.config_type == ProxyConfigType.ENV_VAR:
            pc = client.proxy_config
            if pc.env_var and pc.env_var in env_file_vars:
                detected.routing_active = True
            elif pc.alt_config and pc.alt_config.env_var and pc.alt_config.env_var in env_file_vars:
                detected.routing_active = True
        results.append(detected)

    total_detected = sum(1 for r in results if r.installed)
    total_configured = sum(1 for r in results if r.installed and r.proxy_configured)

    # Detect CI/CD environment
    ci_env = detect_ci_environment()

    report = DetectionReport(
        clients=results,
        shell_env_vars=shell_env,
        platform="%s %s" % (platform.system(), platform.machine()),
        total_detected=total_detected,
        total_configured=total_configured,
        ci_environment=ci_env,
    )

    log.info(
        "detection complete: %d/%d tools detected, %d/%d configured for proxy",
        total_detected,
        len(clients_to_scan),
        total_configured,
        total_detected,
    )
    return report


def _detect_single_client(
    client: ClientDef,
    shell_env: dict[str, list[tuple[str, str, int, str]]],
    proxy_url: str,
    include_versions: bool,
    settings_cache: dict[str, tuple[dict[str, Any], str]] | None = None,
) -> DetectedClient:
    """Run all scanners for a single client, merge results."""
    # Try each scanner in order — first match wins for install detection
    detected = None
    scanners = [
        _scan_binary,
        _scan_pip_package,
        _scan_npm_package,
        _scan_brew_package,
        _scan_vscode_extension,
        _scan_app_bundle,
        _scan_jetbrains_plugin,
        _scan_neovim_plugin,
    ]
    for scanner in scanners:
        try:
            result = scanner(client)
            if result:
                detected = result
                break
        except Exception as e:
            log.error("scanner failed for %s: %s", client.id, e, exc_info=True)

    if detected is None:
        return DetectedClient(
            client_id=client.id,
            display_name=client.display_name,
            proxy_config_type=client.proxy_config.config_type.value,
            setup_instructions=client.proxy_config.setup_instructions,
            forward_proxy=client.proxy_config.forward_proxy,
            website=client.website,
        )

    # Version detection (optional, runs subprocess)
    if include_versions:
        detected.version = _detect_version(client, detected)

    # Check proxy configuration based on proxy_config type
    pc = client.proxy_config

    if pc.config_type == ProxyConfigType.ENV_VAR:
        # Check shell env for this specific env var (with client tag filtering)
        _check_env_var_config(pc.env_var, client.id, shell_env, proxy_url, detected)
        # Also check alt_config env var (e.g., Aider's ANTHROPIC_BASE_URL)
        if not detected.proxy_configured and pc.alt_config and pc.alt_config.config_type == ProxyConfigType.ENV_VAR:
            _check_env_var_config(pc.alt_config.env_var, client.id, shell_env, proxy_url, detected)
        # OpenCode: also check per-provider baseURL in opencode.json
        if not detected.proxy_configured and client.id == "opencode":
            _check_opencode_config(proxy_url, detected)

    elif pc.config_type == ProxyConfigType.IDE_SETTINGS:
        ide_result = _check_ide_proxy_settings(pc.ide_settings_key, proxy_url, settings_cache)
        if ide_result:
            is_configured, value, settings_file = ide_result
            detected.proxy_url = value
            detected.proxy_config_location = settings_file
            detected.proxy_configured = is_configured

    elif pc.config_type == ProxyConfigType.CONFIG_FILE:
        cfg_result = _check_config_file(pc.config_file_path, pc.config_key, proxy_url)
        if cfg_result:
            is_configured, value, file_path = cfg_result
            detected.proxy_url = value
            detected.proxy_config_location = file_path
            detected.proxy_configured = is_configured

    # MANUAL and UNSUPPORTED: proxy_configured stays False

    if pc.forward_proxy and not detected.proxy_configured:
        _check_forward_proxy_aliases(client, detected)

    # Forward proxy flag — propagate from client registry
    detected.forward_proxy = pc.forward_proxy

    return detected


def _check_env_var_config(
    env_var: str,
    client_id: str,
    shell_env: dict[str, list[tuple[str, str, int, str]]],
    proxy_url: str,
    detected: DetectedClient,
) -> None:
    """Check shell env for a specific env var, respecting client tags."""
    if env_var in shell_env:
        entry = _match_shell_entry(shell_env[env_var], client_id)
        if entry:
            value, file_path, line_num, _tag = entry
            detected.proxy_url = value
            detected.proxy_config_location = "%s:%d" % (file_path, line_num)
            detected.proxy_configured = bool(proxy_url and proxy_url in value)


def _check_config_file(config_path: str, config_key: str, proxy_url: str) -> tuple[bool, str, str] | None:
    """Check a tool-specific config file for proxy URL configuration.

    Supports dot-path keys for nested JSON (e.g. ``provider.openai.options.baseURL``).
    """
    expanded = os.path.expanduser(config_path)
    if not os.path.isfile(expanded):
        return None
    try:
        with open(expanded, "r", encoding="utf-8") as f:
            data = json.load(f)
        value = _navigate_json_path(data, config_key)
        if isinstance(value, str) and value:
            is_configured = bool(proxy_url and proxy_url in value)
            return is_configured, value, expanded
    except (json.JSONDecodeError, OSError) as e:
        log.debug("could not read config file %s: %s", expanded, e)
    return None


def _navigate_json_path(data: Any, key: str) -> Any:
    """Navigate a dot-separated key path in a JSON object.

    Returns the value at the path, or ``""`` if any segment is missing.
    Single-segment keys fall back to a simple ``dict.get()`` for backward
    compatibility.
    """
    obj: Any = data
    for segment in key.split("."):
        if isinstance(obj, dict):
            obj = obj.get(segment)
        else:
            return ""
    return obj if obj is not None else ""


def _check_opencode_config(proxy_url: str, detected: DetectedClient) -> None:
    """Check opencode.json for per-provider baseURL overrides pointing to our proxy.

    Considers any provider whose ``options.baseURL`` contains the proxy URL,
    regardless of whether the ``_lumen_argus`` marker is present.  This
    recognises both wizard-managed and manually configured setups.
    """
    from lumen_argus_core.opencode_providers import OPENCODE_CONFIG_PATH

    expanded = os.path.expanduser(OPENCODE_CONFIG_PATH)
    if not os.path.isfile(expanded):
        return
    try:
        with open(expanded, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return

    providers = data.get("provider", {})
    if not isinstance(providers, dict):
        return

    for entry in providers.values():
        if not isinstance(entry, dict):
            continue
        base_url = _navigate_json_path(entry, "options.baseURL")
        if isinstance(base_url, str) and proxy_url and proxy_url in base_url:
            detected.proxy_url = base_url
            detected.proxy_config_location = expanded
            detected.proxy_configured = True
            return


# ---------------------------------------------------------------------------
# Forward-proxy alias detection
# ---------------------------------------------------------------------------

# Matches an active `alias <binary>=` line written by setup_wizard; the
# "(disabled)" comment marker left by undo_setup does not match.
_FORWARD_PROXY_ALIAS_RE = re.compile(r"^alias\s+([A-Za-z0-9_-]+)\s*=", re.MULTILINE)


def _check_forward_proxy_aliases(client: ClientDef, detected: DetectedClient) -> None:
    """Mark a forward-proxy tool as configured when its alias line is present."""
    if not os.path.isfile(_FORWARD_PROXY_ALIASES_PATH):
        return
    try:
        with open(_FORWARD_PROXY_ALIASES_PATH, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError as e:
        log.debug("could not read %s: %s", _FORWARD_PROXY_ALIASES_PATH, e)
        return

    tool_binary = client.id.replace("_cli", "")
    for match in _FORWARD_PROXY_ALIAS_RE.finditer(content):
        if match.group(1) == tool_binary:
            detected.proxy_configured = True
            detected.proxy_config_location = _FORWARD_PROXY_ALIASES_PATH
            log.debug("forward-proxy alias detected for %s", client.id)
            return


# ---------------------------------------------------------------------------
# MCP server detection
# ---------------------------------------------------------------------------

# Commands that indicate the MCP server is wrapped through lumen-argus
_WRAPPER_COMMANDS = {"lumen-argus", "lumen-argus-agent"}


def detect_mcp_servers(
    project_dirs: list[str] | None = None,
) -> MCPDetectionReport:
    """Detect MCP servers configured in AI tool config files.

    Reads mcpServers entries from Claude Desktop, Claude Code, Cursor,
    Windsurf, Cline, Roo Code, and VS Code config files.

    Args:
        project_dirs: Additional directories to scan for project-level
            .mcp.json files.  CWD is always included.

    Returns:
        MCPDetectionReport with all discovered MCP servers.
    """
    from lumen_argus_core.mcp_configs import GLOBAL_MCP_SOURCES, PROJECT_MCP_SOURCES

    servers: list[MCPServerEntry] = []
    checked: list[str] = []

    # Global sources
    for source in GLOBAL_MCP_SOURCES:
        for cfg_path in source.config_paths:
            expanded = os.path.expanduser(cfg_path)
            checked.append(expanded)
            entries = _read_mcp_config(expanded, source)
            servers.extend(entries)

    # Project sources
    dirs = [os.getcwd()]
    if project_dirs:
        dirs.extend(project_dirs)
    seen_dirs: set[str] = set()
    for d in dirs:
        real = os.path.realpath(d)
        if real in seen_dirs:
            continue
        seen_dirs.add(real)
        for source in PROJECT_MCP_SOURCES:
            for cfg_path in source.config_paths:
                expanded = os.path.join(real, cfg_path)
                checked.append(expanded)
                entries = _read_mcp_config(expanded, source)
                servers.extend(entries)

    # Claude Code plugin-provided MCP servers
    plugin_servers, plugin_checked = _detect_claude_code_plugins()
    servers.extend(plugin_servers)
    checked.extend(plugin_checked)

    # Deduplicate: same (name, source_tool) → last wins (project overrides global)
    seen: dict[tuple[str, str], int] = {}
    for i, s in enumerate(servers):
        seen[(s.name, s.source_tool)] = i
    servers = [servers[i] for i in sorted(seen.values())]

    total_scanning = sum(1 for s in servers if s.scanning_enabled)

    report = MCPDetectionReport(
        servers=servers,
        platform="%s %s" % (platform.system(), platform.machine()),
        total_detected=len(servers),
        total_scanning=total_scanning,
        config_files_checked=checked,
    )

    log.info(
        "MCP detection: %d server(s) found, %d scanning-enabled",
        len(servers),
        total_scanning,
    )
    return report


def _detect_claude_code_plugins() -> tuple[list[MCPServerEntry], list[str]]:
    """Detect MCP servers provided by Claude Code plugins.

    Reads ~/.claude/plugins/installed_plugins.json for install paths,
    then checks each plugin's .mcp.json for MCP server definitions.
    Only returns servers from plugins enabled in ~/.claude/settings.json.

    Returns:
        Tuple of (servers, checked_paths).
    """
    plugins_json = os.path.expanduser(os.path.join("~", ".claude", "plugins", "installed_plugins.json"))
    settings_json = os.path.expanduser(os.path.join("~", ".claude", "settings.json"))

    checked: list[str] = [plugins_json, settings_json]
    if not os.path.isfile(plugins_json):
        return [], checked

    # Load enabled plugins from settings
    enabled_plugins: dict[str, bool] = {}
    settings = load_jsonc(settings_json)
    if settings:
        enabled_plugins = settings.get("enabledPlugins", {})

    # Load installed plugins
    installed = load_jsonc(plugins_json)
    if not installed:
        return [], checked

    plugins = installed.get("plugins", {})
    if not isinstance(plugins, dict):
        return [], checked

    servers: list[MCPServerEntry] = []

    for plugin_id, entries in plugins.items():
        if not enabled_plugins.get(plugin_id, False):
            continue
        if not isinstance(entries, list) or not entries:
            continue

        # Use first (most recent) entry
        first = entries[0]
        if not isinstance(first, dict):
            continue
        install_path = first.get("installPath", "")
        if not install_path:
            continue

        mcp_path = os.path.join(install_path, ".mcp.json")
        checked.append(mcp_path)
        if not os.path.isfile(mcp_path):
            continue

        data = load_jsonc(mcp_path)
        if not data:
            continue

        # Plugin .mcp.json has two formats:
        # 1. {"mcpServers": {"name": {...}}}  — wrapper key
        # 2. {"name": {...}}                  — top-level server names
        server_defs = data.get("mcpServers", data)
        if not isinstance(server_defs, dict):
            continue

        plugin_name = plugin_id.split("@")[0]
        plugin_source = MCPConfigSource(
            tool_id="claude_code_plugin",
            display_name="Claude Code Plugin (%s)" % plugin_name,
            config_paths=(),
            json_key="mcpServers",
            scope="global",
        )

        for name, server_def in server_defs.items():
            if not isinstance(server_def, dict):
                continue
            entry = _parse_mcp_server(name, server_def, plugin_source, mcp_path)
            if entry:
                servers.append(entry)

    if servers:
        log.debug("MCP: %d server(s) from Claude Code plugins", len(servers))
    return servers, checked


def _read_mcp_config(
    config_path: str,
    source: MCPConfigSource,
) -> list[MCPServerEntry]:
    """Read MCP servers from a single config file."""
    if not os.path.isfile(config_path):
        return []

    data = load_jsonc(config_path)
    if not data:
        return []

    # Navigate dot-path keys (e.g. "mcp.servers")
    obj: Any = data
    for key in source.json_key.split("."):
        if isinstance(obj, dict):
            obj = obj.get(key)
        else:
            obj = None
            break

    if not isinstance(obj, dict):
        return []

    entries: list[MCPServerEntry] = []
    for name, server_def in obj.items():
        if not isinstance(server_def, dict):
            continue
        entry = _parse_mcp_server(name, server_def, source, config_path)
        if entry:
            entries.append(entry)

    if entries:
        log.debug(
            "MCP: %d server(s) from %s (%s)",
            len(entries),
            source.display_name,
            config_path,
        )
    return entries


def _parse_mcp_server(
    name: str,
    server_def: dict[str, Any],
    source: MCPConfigSource,
    config_path: str,
) -> MCPServerEntry | None:
    """Parse a single MCP server definition into an MCPServerEntry."""
    command = server_def.get("command", "")
    url = server_def.get("url", "")
    args = server_def.get("args", [])
    env = server_def.get("env", {})

    if not isinstance(args, list):
        args = []
    if not isinstance(env, dict):
        env = {}

    # Determine transport
    if command:
        transport = "stdio"
    elif url:
        if url.startswith(("http://", "https://")):
            transport = "http"
        elif url.startswith(("ws://", "wss://")):
            transport = "ws"
        else:
            transport = "http"
    else:
        return None  # no command or url — skip

    # Check if already wrapped through lumen-argus mcp
    scanning_enabled = False
    original_command = ""
    original_args: list[str] = []
    original_url = ""

    if transport == "stdio" and command in _WRAPPER_COMMANDS and args and args[0] == "mcp":
        if "--" in args:
            # stdio mode: lumen-argus mcp -- <original-command> <original-args>
            scanning_enabled = True
            separator_idx = args.index("--")
            remaining = args[separator_idx + 1 :]
            if remaining:
                original_command = remaining[0]
                original_args = remaining[1:]
        elif "--upstream" in args:
            # HTTP/WS bridge mode: lumen-argus mcp --upstream <url>
            scanning_enabled = True
            upstream_idx = args.index("--upstream")
            if upstream_idx + 1 < len(args):
                original_url = args[upstream_idx + 1]
                # Restore transport to match the original server type
                if original_url.startswith(("ws://", "wss://")):
                    transport = "ws"
                else:
                    transport = "http"

    return MCPServerEntry(
        name=name,
        transport=transport,
        command=command if not scanning_enabled else "",
        args=args if not scanning_enabled else [],
        url=url,
        env=env,
        source_tool=source.tool_id,
        source_display_name=source.display_name,
        config_path=config_path,
        scope=source.scope,
        scanning_enabled=scanning_enabled,
        original_command=original_command,
        original_args=original_args,
        original_url=original_url,
    )
