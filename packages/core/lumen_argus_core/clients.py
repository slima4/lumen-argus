"""Client registry — catalog of supported AI CLI agents.

Data-driven registry mapping User-Agent patterns to structured client
metadata. Used by session.py for client identification, dashboard API
for setup guides, and CLI for listing supported tools.

Pro extends via extensions.register_clients() to add enterprise clients.
"""

from __future__ import annotations

import enum
import logging
import re
from dataclasses import asdict, dataclass
from typing import Any

log = logging.getLogger("argus.clients")


# ---------------------------------------------------------------------------
# Proxy configuration types
# ---------------------------------------------------------------------------


class ProxyConfigType(str, enum.Enum):
    """How a client can be configured to route through a reverse proxy."""

    ENV_VAR = "env_var"  # CLI tools: set a shell environment variable
    CONFIG_FILE = "config_file"  # Tool-specific config file (e.g., ~/.continue/config.json)
    IDE_SETTINGS = "ide_settings"  # VS Code / JetBrains settings.json key
    MANUAL = "manual"  # Requires manual UI interaction (no full automation)
    UNSUPPORTED = "unsupported"  # Tool has NO reverse proxy support


@dataclass(frozen=True)
class ProxyConfig:
    """Describes how a client is configured to route through the proxy.

    Fields are type-specific — only the fields relevant to ``config_type``
    are populated.  Consumers branch on ``config_type`` and read the
    appropriate fields.
    """

    config_type: ProxyConfigType
    # Human-readable setup instructions (always present for all types)
    setup_instructions: str
    # ENV_VAR: the environment variable name (e.g., "ANTHROPIC_BASE_URL")
    env_var: str = ""
    # ENV_VAR: one-liner shell command example
    setup_cmd: str = ""
    # CONFIG_FILE: path to config file (with ~ expansion)
    config_file_path: str = ""
    # CONFIG_FILE: JSON key to set
    config_key: str = ""
    # IDE_SETTINGS: VS Code/JetBrains settings key
    ide_settings_key: str = ""
    # Secondary configuration method (e.g., Aider also supports ANTHROPIC_BASE_URL)
    alt_config: ProxyConfig | None = None


# ---------------------------------------------------------------------------
# Client definition
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClientDef:
    """Definition of a supported AI CLI agent."""

    # Identity
    id: str  # stable key stored in DB (e.g., "claude_code")
    display_name: str  # human-readable (e.g., "Claude Code")
    category: str  # "cli" | "ide"
    provider: str  # "anthropic" | "openai" | "gemini" | "multi"
    ua_prefixes: tuple[str, ...]  # lowercase prefixes for User-Agent matching
    proxy_config: ProxyConfig  # how to configure proxy routing
    website: str  # project URL
    # Detection hints (used by lumen_argus/detect.py)
    detect_binary: tuple[str, ...] = ()  # binary names to check via shutil.which()
    detect_pip: str = ""  # pip package name (importlib.metadata)
    detect_npm: str = ""  # npm global package name
    detect_brew: str = ""  # homebrew formula name
    detect_vscode_ext: str = ""  # VS Code extension ID
    detect_jetbrains_plugin: str = ""  # JetBrains plugin dir name
    detect_neovim_plugin: str = ""  # Neovim plugin dir name (lazy.nvim/vim-plug/native)
    detect_app_name: str = ""  # macOS /Applications/*.app
    version_command: tuple[str, ...] = ()  # command to get version


# ---------------------------------------------------------------------------
# Built-in registry — 27 supported AI CLI agents
# Ordered by specificity (longer/more-specific prefixes first)
# ---------------------------------------------------------------------------

CLIENT_REGISTRY: list[ClientDef] = [
    # -- CLI tools (env var works) ------------------------------------------
    ClientDef(
        id="claude_code",
        display_name="Claude Code",
        category="cli",
        provider="anthropic",
        ua_prefixes=("claude-code/",),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.ENV_VAR,
            env_var="ANTHROPIC_BASE_URL",
            setup_cmd="ANTHROPIC_BASE_URL=http://localhost:8080 claude",
            setup_instructions="Set ANTHROPIC_BASE_URL to the proxy URL.",
        ),
        website="https://claude.ai/code",
        detect_binary=("claude",),
        detect_npm="@anthropic-ai/claude-code",
        version_command=("claude", "--version"),
    ),
    ClientDef(
        id="copilot_cli",
        display_name="GitHub Copilot CLI",
        category="cli",
        provider="multi",
        ua_prefixes=("copilot/",),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.ENV_VAR,
            env_var="COPILOT_PROVIDER_BASE_URL",
            setup_cmd="COPILOT_PROVIDER_BASE_URL=http://localhost:8080 copilot",
            setup_instructions="Set COPILOT_PROVIDER_BASE_URL to the proxy URL.",
        ),
        website="https://github.com/features/copilot/cli",
        detect_binary=("copilot",),
        detect_brew="copilot",
        version_command=("copilot", "--version"),
    ),
    ClientDef(
        id="aider",
        display_name="Aider",
        category="cli",
        provider="multi",
        ua_prefixes=("aider/",),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.ENV_VAR,
            env_var="OPENAI_BASE_URL",
            setup_cmd="OPENAI_BASE_URL=http://localhost:8080 aider",
            setup_instructions=(
                "Set OPENAI_BASE_URL to the proxy URL. For Anthropic models, also set ANTHROPIC_BASE_URL."
            ),
            alt_config=ProxyConfig(
                config_type=ProxyConfigType.ENV_VAR,
                env_var="ANTHROPIC_BASE_URL",
                setup_cmd="ANTHROPIC_BASE_URL=http://localhost:8080 aider --model claude-sonnet-4-20250514",
                setup_instructions="Set ANTHROPIC_BASE_URL for Anthropic model routing.",
            ),
        ),
        website="https://aider.chat",
        detect_binary=("aider",),
        detect_pip="aider-chat",
        detect_brew="aider",
        version_command=("aider", "--version"),
    ),
    ClientDef(
        id="codex_cli",
        display_name="OpenAI Codex CLI",
        category="cli",
        provider="openai",
        ua_prefixes=("codex/", "openai-codex/"),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.ENV_VAR,
            env_var="OPENAI_BASE_URL",
            setup_cmd="OPENAI_BASE_URL=http://localhost:8080 codex",
            setup_instructions="Set OPENAI_BASE_URL to the proxy URL.",
        ),
        website="https://github.com/openai/codex",
        detect_binary=("codex",),
        detect_npm="@openai/codex",
        version_command=("codex", "--version"),
    ),
    ClientDef(
        id="opencode",
        display_name="OpenCode",
        category="cli",
        provider="multi",
        ua_prefixes=("opencode/",),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.ENV_VAR,
            env_var="OPENAI_BASE_URL",
            setup_cmd="OPENAI_BASE_URL=http://localhost:8080 opencode",
            setup_instructions="Set OPENAI_BASE_URL to the proxy URL, or set baseURL in opencode.json.",
            alt_config=ProxyConfig(
                config_type=ProxyConfigType.CONFIG_FILE,
                config_file_path="~/.config/opencode/config.json",
                config_key="baseURL",
                setup_instructions='Set "baseURL" in ~/.config/opencode/config.json per provider.',
            ),
        ),
        website="https://opencode.ai",
        detect_binary=("opencode",),
        detect_npm="opencode",
        version_command=("opencode", "--version"),
    ),
    ClientDef(
        id="gemini_cli",
        display_name="Gemini CLI",
        category="cli",
        provider="gemini",
        ua_prefixes=("geminicli/", "gemini-cli/"),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.ENV_VAR,
            env_var="GEMINI_BASE_URL",
            setup_cmd="GEMINI_BASE_URL=http://localhost:8080 gemini",
            setup_instructions="Set GEMINI_BASE_URL to the proxy URL.",
        ),
        website="https://github.com/google-gemini/gemini-cli",
        detect_binary=("gemini",),
        detect_npm="@google/gemini-cli",
        detect_brew="gemini-cli",
        version_command=("gemini", "--version"),
    ),
    # -- IDE tools (various mechanisms) -------------------------------------
    ClientDef(
        id="cursor",
        display_name="Cursor",
        category="ide",
        provider="multi",
        ua_prefixes=("cursor/",),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.MANUAL,
            setup_instructions="Open Cursor Settings > Models > enable 'Override OpenAI Base URL' > enter proxy URL.",
        ),
        website="https://cursor.com",
        detect_binary=("cursor",),
        detect_app_name="Cursor.app",
    ),
    ClientDef(
        id="copilot",
        display_name="GitHub Copilot",
        category="ide",
        provider="openai",
        ua_prefixes=("github-copilot/", "copilot-"),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.IDE_SETTINGS,
            ide_settings_key="http.proxy",
            setup_instructions=(
                'Set "http.proxy" in VS Code settings.json. Note: this is a forward proxy, not a base URL override.'
            ),
        ),
        website="https://github.com/features/copilot",
        detect_vscode_ext="github.copilot",
        detect_jetbrains_plugin="github-copilot-intellij",
        detect_neovim_plugin="copilot.vim",
    ),
    ClientDef(
        id="continue",
        display_name="Continue",
        category="ide",
        provider="multi",
        ua_prefixes=("continue/",),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.CONFIG_FILE,
            config_file_path="~/.continue/config.json",
            config_key="apiBase",
            setup_instructions='Set "apiBase" per model in ~/.continue/config.json.',
        ),
        website="https://continue.dev",
        detect_vscode_ext="continue.continue",
        detect_neovim_plugin="continue.nvim",
    ),
    ClientDef(
        id="cody",
        display_name="Cody",
        category="ide",
        provider="multi",
        ua_prefixes=("cody/", "sourcegraph-"),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.IDE_SETTINGS,
            ide_settings_key="cody.serverEndpoint",
            setup_instructions=(
                'Set "cody.serverEndpoint" in VS Code settings.'
                " Note: Cody uses Sourcegraph protocol, not standard LLM APIs."
            ),
        ),
        website="https://sourcegraph.com/cody",
        detect_vscode_ext="sourcegraph.cody-ai",
        detect_jetbrains_plugin="sourcegraph",
        detect_neovim_plugin="sg.nvim",
    ),
    ClientDef(
        id="cline",
        display_name="Cline",
        category="ide",
        provider="multi",
        ua_prefixes=("cline/",),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.MANUAL,
            setup_instructions="Open Cline sidebar > select provider > enable 'Use custom base URL' > enter proxy URL.",
        ),
        website="https://cline.bot",
        detect_vscode_ext="saoudrizwan.claude-dev",
    ),
    ClientDef(
        id="roo_code",
        display_name="Roo Code",
        category="ide",
        provider="multi",
        ua_prefixes=("roo-code/", "roo/"),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.MANUAL,
            setup_instructions=(
                "Open Roo Code sidebar > select provider > enable 'Use custom base URL' > enter proxy URL."
            ),
        ),
        website="https://roocode.com",
        detect_vscode_ext="rooveterinaryinc.roo-cline",
    ),
    ClientDef(
        id="aide",
        display_name="Aide",
        category="ide",
        provider="multi",
        ua_prefixes=("aide/", "codestory/"),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.MANUAL,
            setup_instructions="Open Aide > Preferences > Model Selection > set OpenAI-compatible endpoint URL.",
        ),
        website="https://aide.dev",
        detect_binary=("aide",),
        detect_app_name="Aide.app",
    ),
    ClientDef(
        id="droid",
        display_name="Droid",
        category="cli",
        provider="multi",
        ua_prefixes=("droid/", "factory/"),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.MANUAL,
            setup_instructions=('Set "base_url" in ~/.factory/settings.json under the provider config (BYOK mode).'),
        ),
        website="https://factory.ai",
        detect_binary=("droid",),
        detect_npm="@factory/cli",
        detect_vscode_ext="Factory.factory-vscode-extension",
    ),
    ClientDef(
        id="codebuddy",
        display_name="CodeBuddy",
        category="cli",
        provider="multi",
        ua_prefixes=("codebuddy/",),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.MANUAL,
            setup_instructions=("Add a custom model in models.json with base_url pointing to the proxy URL."),
        ),
        website="https://www.codebuddy.ai",
        detect_binary=("codebuddy",),
        detect_npm="@tencent-ai/codebuddy-code",
        detect_vscode_ext="Tencent-Cloud.coding-copilot",
        detect_jetbrains_plugin="tencent-cloud-codebuddy",
    ),
    ClientDef(
        id="kilo_code",
        display_name="Kilo Code",
        category="ide",
        provider="multi",
        ua_prefixes=("kilo-code/", "kilo/"),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.MANUAL,
            setup_instructions=(
                "Open Kilo Code settings > add OpenAI-compatible provider > set Base URL to the proxy URL."
            ),
        ),
        website="https://kilo.ai",
        detect_npm="@kilocode/cli",
        detect_vscode_ext="kilocode.Kilo-Code",
    ),
    # -- IDE tools (unsupported — proprietary backends) ---------------------
    ClientDef(
        id="windsurf",
        display_name="Windsurf",
        category="ide",
        provider="multi",
        ua_prefixes=("windsurf/", "codeium/"),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.UNSUPPORTED,
            setup_instructions="Windsurf routes through Codeium's proprietary backend. No reverse proxy support.",
        ),
        website="https://codeium.com/windsurf",
        detect_binary=("windsurf",),
        detect_app_name="Windsurf.app",
    ),
    ClientDef(
        id="amazon_q",
        display_name="Amazon Q Developer",
        category="ide",
        provider="multi",
        ua_prefixes=("amazon-q/", "aws-toolkit/"),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.UNSUPPORTED,
            setup_instructions="Amazon Q uses proprietary AWS authentication. No custom base URL support.",
        ),
        website="https://aws.amazon.com/q/developer/",
        detect_binary=("q",),
        detect_vscode_ext="amazonwebservices.aws-toolkit-vscode",
        detect_jetbrains_plugin="aws-toolkit-jetbrains",
    ),
    ClientDef(
        id="tabnine",
        display_name="Tabnine",
        category="ide",
        provider="multi",
        ua_prefixes=("tabnine/",),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.UNSUPPORTED,
            setup_instructions="Tabnine uses a proprietary protocol. Enterprise: set server URL in Tabnine settings.",
        ),
        website="https://www.tabnine.com",
        detect_vscode_ext="tabnine.tabnine-vscode",
        detect_jetbrains_plugin="tabnine-intellij",
    ),
    ClientDef(
        id="augment",
        display_name="Augment Code",
        category="ide",
        provider="multi",
        ua_prefixes=("augment/",),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.UNSUPPORTED,
            setup_instructions="Augment Code uses a proprietary backend. No custom endpoint support.",
        ),
        website="https://www.augmentcode.com",
        detect_vscode_ext="augment.augment-vscode",
    ),
    ClientDef(
        id="gemini_assist",
        display_name="Gemini Code Assist",
        category="ide",
        provider="gemini",
        ua_prefixes=("gemini-code-assist/",),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.UNSUPPORTED,
            setup_instructions=(
                "Gemini Code Assist VS Code extension has no base URL override. Use Gemini CLI with GEMINI_BASE_URL."
            ),
        ),
        website="https://cloud.google.com/gemini/docs/codeassist",
        detect_vscode_ext="google.gemini-code-assist",
    ),
    ClientDef(
        id="antigravity",
        display_name="Antigravity",
        category="ide",
        provider="multi",
        ua_prefixes=("antigravity/",),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.UNSUPPORTED,
            setup_instructions="Antigravity routes through Google's proprietary backend. No reverse proxy support.",
        ),
        website="https://antigravity.google",
        detect_binary=("antigravity",),
        detect_app_name="Antigravity.app",
    ),
    ClientDef(
        id="kiro",
        display_name="Kiro",
        category="ide",
        provider="multi",
        ua_prefixes=("kiro/",),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.UNSUPPORTED,
            setup_instructions="Kiro IDE uses AWS proprietary backend. No custom base URL support.",
        ),
        website="https://kiro.dev",
        detect_binary=("kiro",),
        detect_app_name="Kiro.app",
    ),
    ClientDef(
        id="kiro_cli",
        display_name="Kiro CLI",
        category="cli",
        provider="multi",
        ua_prefixes=("kiro-cli/",),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.UNSUPPORTED,
            setup_instructions="Kiro CLI uses AWS proprietary backend. No custom base URL support.",
        ),
        website="https://kiro.dev/cli/",
        detect_binary=("kiro-cli",),
    ),
    ClientDef(
        id="trae",
        display_name="Trae",
        category="ide",
        provider="multi",
        ua_prefixes=("trae/",),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.UNSUPPORTED,
            setup_instructions="Trae IDE routes through ByteDance's proprietary backend. No base URL override.",
        ),
        website="https://www.trae.ai",
        detect_app_name="Trae.app",
    ),
    ClientDef(
        id="qoder",
        display_name="Qoder",
        category="ide",
        provider="multi",
        ua_prefixes=("qoder/",),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.UNSUPPORTED,
            setup_instructions="Qoder routes through Alibaba's proprietary backend. No reverse proxy support.",
        ),
        website="https://qoder.com",
        detect_app_name="Qoder.app",
    ),
    ClientDef(
        id="warp",
        display_name="Warp",
        category="cli",
        provider="multi",
        ua_prefixes=("warp/",),
        proxy_config=ProxyConfig(
            config_type=ProxyConfigType.UNSUPPORTED,
            setup_instructions=(
                "Warp routes AI through its proprietary backend. Enterprise BYOLLM supports AWS Bedrock only."
            ),
        ),
        website="https://www.warp.dev",
        detect_app_name="Warp.app",
        detect_binary=("warp",),
    ),
]

# Build prefix→client lookup for fast matching
_PREFIX_INDEX: list[tuple[str, ClientDef]] = [
    (_prefix, _client) for _client in CLIENT_REGISTRY for _prefix in _client.ua_prefixes
]


# ---------------------------------------------------------------------------
# Derived constants
# ---------------------------------------------------------------------------


def _collect_env_vars() -> tuple[str, ...]:
    """Derive the set of proxy env vars from the registry."""
    seen: set[str] = set()
    for c in CLIENT_REGISTRY:
        pc = c.proxy_config
        if pc.config_type == ProxyConfigType.ENV_VAR and pc.env_var:
            seen.add(pc.env_var)
        if pc.alt_config and pc.alt_config.config_type == ProxyConfigType.ENV_VAR and pc.alt_config.env_var:
            seen.add(pc.alt_config.env_var)
    return tuple(sorted(seen))


PROXY_ENV_VARS: tuple[str, ...] = _collect_env_vars()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?(?:[.-]\w+)?")


def _parse_version(raw_token: str) -> str:
    """Extract version from a UA token like 'aider/0.50.1' → '0.50.1'.

    Handles multi-segment tokens like 'GeminiCLI/0.34.0/gemini-pro' → '0.34.0'.
    """
    if "/" not in raw_token:
        return ""
    after_slash = raw_token.split("/", 1)[1]
    m = _VERSION_RE.match(after_slash)
    return m.group(0) if m else after_slash


def identify_client(user_agent: str, headers: dict[str, str] | None = None) -> tuple[str, str, str, str]:
    """Identify the AI CLI agent from request headers.

    Returns (client_id, display_name, version, raw_ua_token):
        - client_id: registry ID or raw token if no match
        - display_name: human-readable name or raw token
        - version: parsed version string (e.g., "0.50.1")
        - raw_ua_token: first User-Agent token (for logging)
    """
    if not user_agent or user_agent.startswith("Mozilla/"):
        return "", "", "", ""

    raw_token = user_agent.split()[0][:128]
    lower_token = raw_token.lower()

    for prefix, client in _PREFIX_INDEX:
        if lower_token.startswith(prefix):
            return client.id, client.display_name, _parse_version(raw_token), raw_token

    # No registry match — return raw token as ID/name
    return raw_token, raw_token, _parse_version(raw_token), raw_token


def get_client_by_id(client_id: str) -> ClientDef | None:
    """Look up a client definition by ID."""
    for client in CLIENT_REGISTRY:
        if client.id == client_id:
            return client
    return None


def get_all_clients(extra_clients: list[Any] | None = None) -> list[dict[str, Any]]:
    """Return all clients as dicts for API responses.

    Merges built-in registry with Pro-registered extra clients.
    """
    result = [asdict(c) for c in CLIENT_REGISTRY]
    if extra_clients:
        for ec in extra_clients:
            if isinstance(ec, ClientDef):
                result.append(asdict(ec))
            elif isinstance(ec, dict):
                result.append(ec)
    return result
