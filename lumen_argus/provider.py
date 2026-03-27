"""Provider routing: map inbound requests to upstream HTTPS targets."""

import logging

log = logging.getLogger("argus.provider")

# Default upstream URLs per provider.
DEFAULT_UPSTREAMS = {
    "anthropic": "https://api.anthropic.com",
    "openai": "https://api.openai.com",
    "gemini": "https://generativelanguage.googleapis.com",
}


class ProviderRouter:
    """Routes proxy requests to the correct upstream AI provider."""

    def __init__(self, upstreams: dict[str, str] | None = None):
        self._upstreams = dict(DEFAULT_UPSTREAMS)
        if upstreams:
            self._upstreams.update(upstreams)

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

        # Parse URL into host, port, and protocol
        if upstream_url.startswith("https://"):
            host = upstream_url[8:]
            port = 443
            use_ssl = True
        elif upstream_url.startswith("http://"):
            host = upstream_url[7:]
            port = 80
            use_ssl = False
        else:
            host = upstream_url
            port = 443
            use_ssl = True

        # Handle host:port format
        if ":" in host:
            parts = host.rsplit(":", 1)
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                log.debug("invalid port in host header: %s", parts[1])

        # Strip trailing slash
        host = host.rstrip("/")

        return host, port, use_ssl, provider

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
