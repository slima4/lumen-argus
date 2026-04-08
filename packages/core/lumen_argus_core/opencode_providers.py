"""OpenCode built-in provider registry.

OpenCode (opencode.ai) ships 22 bundled SDK providers and auto-discovers
110+ providers from models.dev.  Providers appear in the TUI without any
user configuration — ``opencode.json`` is only for overrides.

This module maintains a registry of the most common built-in providers,
their default upstream API URLs, and whether the lumen-argus proxy can
auto-detect them from request path/headers.

Two categories:

* **Standard** — Anthropic, OpenAI, Google.  The proxy auto-detects the
  provider from the request path and headers.  ``baseURL`` points directly
  to the proxy (or relay).

* **Gateway** — All other providers (Zen, Groq, Mistral, etc.).  The proxy
  cannot distinguish them from OpenAI because they share the same
  ``/v1/chat/completions`` path.  ``baseURL`` must include the
  ``/_upstream/<name>`` prefix so the proxy knows where to forward.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Standard providers — proxy auto-detects from path + headers
# ---------------------------------------------------------------------------

STANDARD_PROVIDERS: dict[str, str] = {
    "anthropic": "https://api.anthropic.com",
    "openai": "https://api.openai.com",
    "google": "https://generativelanguage.googleapis.com",
}

# ---------------------------------------------------------------------------
# Gateway providers — need /_upstream/<name> routing
#
# Only providers with simple bearer-token auth are included.  Providers
# that require platform-specific auth (AWS SigV4, Azure AD, Google Cloud
# ADC) cannot be transparently proxied via baseURL override.
# ---------------------------------------------------------------------------

# Default gateway providers — always configured.
# OpenCode Zen is free and active by default in every OpenCode install.
GATEWAY_PROVIDERS: dict[str, str] = {
    "opencode": "https://opencode.ai/zen/v1",
}

# Optional gateway providers — only configured when the user has the
# corresponding API key set.  Setting baseURL without a key causes the
# provider to appear in OpenCode's model picker TUI, polluting the UI.
#
# TODO: When user adds a new provider via TUI (/connect), detect and
# configure the proxy for it automatically (watch auth.json or re-run
# configure on next heartbeat/protection toggle).
OPTIONAL_GATEWAY_PROVIDERS: dict[str, tuple[str, str]] = {
    # provider_id: (upstream_url, env_var_for_api_key)
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY"),
    "mistral": ("https://api.mistral.ai/v1", "MISTRAL_API_KEY"),
    "xai": ("https://api.x.ai/v1", "XAI_API_KEY"),
    "deepinfra": ("https://api.deepinfra.com/v1/openai", "DEEPINFRA_API_KEY"),
    "cerebras": ("https://api.cerebras.ai/v1", "CEREBRAS_API_KEY"),
    "togetherai": ("https://api.together.xyz/v1", "TOGETHER_API_KEY"),
    "perplexity": ("https://api.perplexity.ai", "PERPLEXITY_API_KEY"),
    "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
    "cohere": ("https://api.cohere.com/v2", "CO_API_KEY"),
    "deepseek": ("https://api.deepseek.com", "DEEPSEEK_API_KEY"),
}

# Providers excluded (complex auth, not simple baseURL proxy):
#   amazon-bedrock  — AWS SigV4 signing
#   azure           — Azure AD / managed identity
#   google-vertex   — Google Cloud ADC
#   github-copilot  — OAuth device flow
#   gitlab          — GitLab personal access token + custom UA

# ---------------------------------------------------------------------------
# Config file paths
# ---------------------------------------------------------------------------

# User-level config — writable by any user, overridable by project config.
OPENCODE_CONFIG_PATH = "~/.config/opencode/opencode.json"

# Managed config paths — highest priority in OpenCode's merge chain.
# Cannot be overridden by user or project configs.  Requires elevated
# privileges (sudo/admin) to write.  Used by enterprise MDM deployments
# and DMG installers to enforce proxy routing.
OPENCODE_MANAGED_PATHS: dict[str, str] = {
    "darwin": "/Library/Application Support/opencode/opencode.json",
    "linux": "/etc/opencode/opencode.json",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def build_provider_overrides(proxy_url: str) -> dict[str, dict[str, object]]:
    """Build the ``provider`` section for opencode.json.

    Standard and default gateway providers are always included.
    Optional gateway providers are only included when the user has the
    corresponding API key env var set — otherwise they pollute the
    OpenCode model picker TUI.

    Args:
        proxy_url: The proxy (or relay) base URL, e.g. ``http://localhost:8070``.
    """
    import os

    base = proxy_url.rstrip("/")
    overrides: dict[str, dict[str, object]] = {}

    for provider_id in STANDARD_PROVIDERS:
        overrides[provider_id] = {"options": {"baseURL": base}}

    for provider_id in GATEWAY_PROVIDERS:
        overrides[provider_id] = {
            "options": {"baseURL": "%s/_upstream/%s" % (base, provider_id)},
        }

    for provider_id, (_, env_var) in OPTIONAL_GATEWAY_PROVIDERS.items():
        if os.environ.get(env_var):
            overrides[provider_id] = {
                "options": {"baseURL": "%s/_upstream/%s" % (base, provider_id)},
            }

    return overrides


def get_all_upstream_defaults() -> dict[str, str]:
    """Return upstream URL mapping for all gateway providers.

    Includes both default and optional — the proxy must be ready to
    route any of them if a request arrives.

    Suitable for passing to ``ProviderRouter(upstreams=...)``.
    """
    result = dict(GATEWAY_PROVIDERS)
    for provider_id, (url, _) in OPTIONAL_GATEWAY_PROVIDERS.items():
        result[provider_id] = url
    return result
