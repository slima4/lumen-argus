"""Client registry — catalog of supported AI CLI agents.

Data-driven registry mapping User-Agent patterns to structured client
metadata. Used by session.py for client identification, dashboard API
for setup guides, and CLI for listing supported tools.

Pro extends via extensions.register_clients() to add enterprise clients.
"""

import logging
from dataclasses import asdict, dataclass
from typing import List, Optional, Tuple

log = logging.getLogger("argus.clients")


@dataclass(frozen=True)
class ClientDef:
    """Definition of a supported AI CLI agent."""

    id: str  # stable key stored in DB (e.g., "claude_code")
    display_name: str  # human-readable (e.g., "Claude Code")
    category: str  # "cli" | "ide"
    provider: str  # "anthropic" | "openai" | "gemini" | "multi"
    ua_prefixes: tuple  # lowercase prefixes for User-Agent matching
    env_var: str  # primary env var for setup
    setup_cmd: str  # one-liner setup example
    website: str  # project URL


# ---------------------------------------------------------------------------
# Built-in registry — 15 popular AI CLI agents
# Ordered by specificity (longer/more-specific prefixes first)
# ---------------------------------------------------------------------------

CLIENT_REGISTRY: List[ClientDef] = [
    ClientDef(
        id="claude_code",
        display_name="Claude Code",
        category="cli",
        provider="anthropic",
        ua_prefixes=("claude-code/",),
        env_var="ANTHROPIC_BASE_URL",
        setup_cmd="ANTHROPIC_BASE_URL=http://localhost:8080 claude",
        website="https://claude.ai/code",
    ),
    ClientDef(
        id="cursor",
        display_name="Cursor",
        category="ide",
        provider="multi",
        ua_prefixes=("cursor/",),
        env_var="OPENAI_BASE_URL",
        setup_cmd="OPENAI_BASE_URL=http://localhost:8080 cursor",
        website="https://cursor.com",
    ),
    ClientDef(
        id="copilot",
        display_name="GitHub Copilot",
        category="ide",
        provider="openai",
        ua_prefixes=("github-copilot/", "copilot-"),
        env_var="OPENAI_BASE_URL",
        setup_cmd="OPENAI_BASE_URL=http://localhost:8080",
        website="https://github.com/features/copilot",
    ),
    ClientDef(
        id="aider",
        display_name="Aider",
        category="cli",
        provider="multi",
        ua_prefixes=("aider/",),
        env_var="OPENAI_BASE_URL",
        setup_cmd="OPENAI_BASE_URL=http://localhost:8080 aider",
        website="https://aider.chat",
    ),
    ClientDef(
        id="continue",
        display_name="Continue",
        category="ide",
        provider="multi",
        ua_prefixes=("continue/",),
        env_var="OPENAI_BASE_URL",
        setup_cmd="OPENAI_BASE_URL=http://localhost:8080",
        website="https://continue.dev",
    ),
    ClientDef(
        id="cody",
        display_name="Cody",
        category="ide",
        provider="multi",
        ua_prefixes=("cody/", "sourcegraph-"),
        env_var="OPENAI_BASE_URL",
        setup_cmd="OPENAI_BASE_URL=http://localhost:8080",
        website="https://sourcegraph.com/cody",
    ),
    ClientDef(
        id="windsurf",
        display_name="Windsurf",
        category="ide",
        provider="multi",
        ua_prefixes=("windsurf/", "codeium/"),
        env_var="OPENAI_BASE_URL",
        setup_cmd="OPENAI_BASE_URL=http://localhost:8080",
        website="https://codeium.com/windsurf",
    ),
    ClientDef(
        id="amazon_q",
        display_name="Amazon Q Developer",
        category="ide",
        provider="openai",
        ua_prefixes=("amazon-q/", "aws-toolkit/"),
        env_var="OPENAI_BASE_URL",
        setup_cmd="OPENAI_BASE_URL=http://localhost:8080",
        website="https://aws.amazon.com/q/developer/",
    ),
    ClientDef(
        id="tabnine",
        display_name="Tabnine",
        category="ide",
        provider="openai",
        ua_prefixes=("tabnine/",),
        env_var="OPENAI_BASE_URL",
        setup_cmd="OPENAI_BASE_URL=http://localhost:8080",
        website="https://www.tabnine.com",
    ),
    ClientDef(
        id="cline",
        display_name="Cline",
        category="ide",
        provider="multi",
        ua_prefixes=("cline/",),
        env_var="OPENAI_BASE_URL",
        setup_cmd="OPENAI_BASE_URL=http://localhost:8080",
        website="https://cline.bot",
    ),
    ClientDef(
        id="roo_code",
        display_name="Roo Code",
        category="ide",
        provider="multi",
        ua_prefixes=("roo-code/", "roo/"),
        env_var="ANTHROPIC_BASE_URL",
        setup_cmd="ANTHROPIC_BASE_URL=http://localhost:8080",
        website="https://roocode.com",
    ),
    ClientDef(
        id="augment",
        display_name="Augment Code",
        category="ide",
        provider="multi",
        ua_prefixes=("augment/",),
        env_var="OPENAI_BASE_URL",
        setup_cmd="OPENAI_BASE_URL=http://localhost:8080",
        website="https://www.augmentcode.com",
    ),
    ClientDef(
        id="gemini_assist",
        display_name="Gemini Code Assist",
        category="ide",
        provider="gemini",
        ua_prefixes=("gemini-code-assist/",),
        env_var="GEMINI_BASE_URL",
        setup_cmd="GEMINI_BASE_URL=http://localhost:8080",
        website="https://cloud.google.com/gemini/docs/codeassist",
    ),
    ClientDef(
        id="codex_cli",
        display_name="OpenAI Codex CLI",
        category="cli",
        provider="openai",
        ua_prefixes=("codex/", "openai-codex/"),
        env_var="OPENAI_BASE_URL",
        setup_cmd="OPENAI_BASE_URL=http://localhost:8080 codex",
        website="https://github.com/openai/codex",
    ),
    ClientDef(
        id="aide",
        display_name="Aide",
        category="ide",
        provider="multi",
        ua_prefixes=("aide/", "codestory/"),
        env_var="OPENAI_BASE_URL",
        setup_cmd="OPENAI_BASE_URL=http://localhost:8080",
        website="https://aide.dev",
    ),
]

# Build prefix→client lookup for fast matching
_PREFIX_INDEX: List[Tuple[str, ClientDef]] = []
for _client in CLIENT_REGISTRY:
    for _prefix in _client.ua_prefixes:
        _PREFIX_INDEX.append((_prefix, _client))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _parse_version(raw_token: str) -> str:
    """Extract version from a UA token like 'aider/0.50.1' → '0.50.1'."""
    if "/" in raw_token:
        return raw_token.split("/", 1)[1]
    return ""


def identify_client(user_agent: str, headers: dict = None) -> Tuple[str, str, str, str]:
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


def get_client_by_id(client_id: str) -> Optional[ClientDef]:
    """Look up a client definition by ID."""
    for client in CLIENT_REGISTRY:
        if client.id == client_id:
            return client
    return None


def get_all_clients(extra_clients: list = None) -> List[dict]:
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
