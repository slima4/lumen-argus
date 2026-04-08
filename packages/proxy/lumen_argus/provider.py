"""Provider routing: map inbound requests to upstream HTTPS targets.

Supports two routing modes:

1. **Auto-detect** (default) — path + header heuristics select one of the
   three built-in providers (Anthropic, OpenAI, Gemini).

2. **Named upstream** — requests with a ``/_upstream/<name>/`` path prefix
   are routed to a pre-configured upstream URL.  This is required for
   gateway providers (OpenCode Zen, Groq, OpenRouter, etc.) whose API
   endpoints are not one of the three built-in targets.  Configure in
   ``config.yaml``::

       proxy:
         upstream:
           opencode_zen: https://opencode.ai/zen/v1

   Then point the tool's ``baseURL`` at
   ``http://proxy:8080/_upstream/opencode_zen``.  The proxy strips the
   prefix and forwards ``/chat/completions`` to the configured URL.
"""

import logging
from urllib.parse import urlparse

log = logging.getLogger("argus.provider")

# Path prefix for named upstream routing.
_UPSTREAM_PREFIX = "/_upstream/"

# Default upstream URLs per provider.
DEFAULT_UPSTREAMS = {
    "anthropic": "https://api.anthropic.com",
    "openai": "https://api.openai.com",
    "gemini": "https://generativelanguage.googleapis.com",
}

# Well-known gateway provider upstreams for /_upstream/<name> routing.
# These are loaded from core's OpenCode provider registry so that
# /_upstream/ works out of the box without manual config.yaml entries.
_GATEWAY_DEFAULTS: dict[str, str] = {}
try:
    from lumen_argus_core.opencode_providers import get_all_upstream_defaults

    _GATEWAY_DEFAULTS = get_all_upstream_defaults()
except ImportError:
    pass  # core not installed — gateway routing requires config.yaml


class ProviderRouter:
    """Routes proxy requests to the correct upstream AI provider."""

    def __init__(self, upstreams: dict[str, str] | None = None):
        self._upstreams = dict(DEFAULT_UPSTREAMS)
        self._upstreams.update(_GATEWAY_DEFAULTS)
        if upstreams:
            self._upstreams.update(upstreams)  # config.yaml overrides defaults

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def route(self, path: str, headers: dict[str, str]) -> tuple[str, int, bool, str]:
        """Determine upstream host, port, SSL flag, and provider name.

        Args:
            path: Request path (e.g. "/v1/messages").
            headers: Request headers dict.

        Returns:
            (upstream_host, upstream_port, use_ssl, provider_name)
        """
        provider = self._detect_provider(path, headers)
        upstream_url = self._upstreams.get(provider, self._upstreams["anthropic"])
        return self._parse_upstream(upstream_url, provider)

    def resolve_named_upstream(self, path: str) -> tuple[str, int, bool, str, str] | None:
        """Resolve a ``/_upstream/<name>/...`` path to upstream + effective path.

        Returns ``(host, port, use_ssl, provider_name, effective_path)`` or
        ``None`` if *path* does not use the named upstream prefix or the name
        is not configured.
        """
        if not path.startswith(_UPSTREAM_PREFIX):
            return None

        rest = path[len(_UPSTREAM_PREFIX) :]  # "opencode_zen/chat/completions?k=v"
        # Name ends at first "/" or "?" — query string must not poison the name
        slash_idx = rest.find("/")
        qs_idx = rest.find("?")
        boundary = min(
            slash_idx if slash_idx != -1 else len(rest),
            qs_idx if qs_idx != -1 else len(rest),
        )
        name = rest[:boundary]
        suffix = rest[boundary:]  # "/chat/completions?k=v" or "?stream=true"

        upstream_url = self._upstreams.get(name)
        if not upstream_url:
            log.warning("named upstream '%s' not configured — rejecting", name)
            return None

        host, port, use_ssl, base_path = self._parse_upstream_with_path(upstream_url)
        effective_path = base_path.rstrip("/") + suffix if suffix else base_path
        log.debug("named upstream '%s' -> %s:%d%s", name, host, port, effective_path)
        return host, port, use_ssl, name, effective_path

    def has_named_upstreams(self) -> bool:
        """Return True if any non-default upstreams are configured."""
        return bool(set(self._upstreams) - set(DEFAULT_UPSTREAMS))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_upstream(self, upstream_url: str, provider: str) -> tuple[str, int, bool, str]:
        """Parse upstream URL into (host, port, use_ssl, provider)."""
        host, port, use_ssl, _ = self._parse_upstream_with_path(upstream_url)
        return host, port, use_ssl, provider

    @staticmethod
    def _parse_upstream_with_path(upstream_url: str) -> tuple[str, int, bool, str]:
        """Parse upstream URL into (host, port, use_ssl, base_path)."""
        parsed = urlparse(upstream_url)
        use_ssl = parsed.scheme == "https"
        host = parsed.hostname or ""
        port = parsed.port or (443 if use_ssl else 80)
        base_path = parsed.path or ""
        return host, port, use_ssl, base_path

    def detect_api_provider(self, path: str) -> str:
        """Detect the API format from the effective upstream path.

        Used for named upstreams where the provider name is the upstream
        key (e.g. ``"opencode"``) but the API format is OpenAI-compatible.
        Returns ``"anthropic"``, ``"openai"``, ``"gemini"``, or ``"openai"``
        as default (most gateway providers are OpenAI-compatible).
        """
        if "/messages" in path:
            return "anthropic"
        if "/chat/completions" in path or "/completions" in path:
            return "openai"
        if "/generateContent" in path or "/v1beta/" in path:
            return "gemini"
        return "openai"  # most gateway providers are OpenAI-compatible

    def _detect_provider(self, path: str, headers: dict[str, str]) -> str:
        """Detect provider from path and headers."""
        # Anthropic-specific paths and headers
        if path.startswith(("/v1/messages", "/v1/complete")):
            if headers.get("x-api-key") or headers.get("anthropic-version"):
                return "anthropic"

        # OpenAI-specific paths
        if path.startswith("/v1/chat/completions"):
            return "openai"
        if path.startswith("/v1/completions"):
            return "openai"
        if path.startswith("/v1/embeddings"):
            return "openai"

        # Gemini-specific paths
        if "/generateContent" in path or path.startswith("/v1beta/"):
            return "gemini"

        # Check for authorization header patterns
        auth = headers.get("authorization", "")
        if "x-api-key" in headers:
            return "anthropic"
        if auth.startswith("Bearer sk-ant-"):
            return "anthropic"
        if auth.startswith("Bearer sk-"):
            return "openai"

        # Default to anthropic (most common use case)
        return "anthropic"
