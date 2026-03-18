"""Extension registry with entry point discovery.

Any pip-installed package can register extensions by declaring an entry point
in the "lumen_argus.extensions" group. The entry point should point to a
callable that accepts an ExtensionRegistry instance:

    # In the extension's pyproject.toml:
    [project.entry-points."lumen_argus.extensions"]
    my_plugin = "my_package:register"

    # In my_package/__init__.py:
    def register(registry):
        from my_package.detectors import MyDetector
        registry.add_detector(MyDetector())

This is how lumen-argus-pro registers itself. Community users can also
write custom detectors using the same mechanism.
"""

import logging
from typing import Callable, List, Optional

from lumen_argus.detectors import BaseDetector
from lumen_argus.models import Finding

log = logging.getLogger("argus.extensions")


class ExtensionRegistry:
    """Discovers and loads extensions via Python entry points."""

    # Type for redact hook: (body: bytes, findings: List[Finding]) -> bytes
    RedactHook = Callable[[bytes, List[Finding]], bytes]

    def __init__(self):
        self._detectors = []  # type: List[BaseDetector]
        self._notifiers = []  # type: list
        self._redact_hook = None  # type: Optional[ExtensionRegistry.RedactHook]
        self._post_scan_hook = None  # type: Optional[Callable]
        self._config_reload_hook = None  # type: Optional[Callable]
        self._evaluate_hook = None  # type: Optional[Callable]
        self._pre_request_hook = None  # type: Optional[Callable]
        self._proxy_server = None  # type: Optional[object]
        self._loaded_plugins = []  # type: List[tuple]
        # Dashboard extension hooks
        self._dashboard_pages = []  # type: list
        self._dashboard_css = []  # type: List[str]
        self._dashboard_api_handler = None  # type: Optional[Callable]
        self._analytics_store = None  # type: Optional[object]
        self._auth_providers = []  # type: list
        self._sse_broadcaster = None  # type: Optional[object]

    def add_detector(self, detector: BaseDetector, priority: bool = False) -> None:
        """Register an additional detector.

        Args:
            detector: Detector instance to register.
            priority: If True, prepend (runs before community detectors).
        """
        if priority:
            self._detectors.insert(0, detector)
        else:
            self._detectors.append(detector)

    def add_notifier(self, notifier: object) -> None:
        """Register an additional notifier."""
        self._notifiers.append(notifier)

    def set_redact_hook(self, hook: "ExtensionRegistry.RedactHook") -> None:
        """Register a redaction callback: (body, findings) -> redacted_body."""
        self._redact_hook = hook

    def get_redact_hook(self) -> "Optional[ExtensionRegistry.RedactHook]":
        """Return the registered redaction hook, or None."""
        return self._redact_hook

    def set_post_scan_hook(self, hook: Callable) -> None:
        """Register: hook(scan_result, body, provider) called after each scan."""
        self._post_scan_hook = hook

    def get_post_scan_hook(self) -> Optional[Callable]:
        return self._post_scan_hook

    def set_config_reload_hook(self, hook: Callable) -> None:
        """Register: hook(pipeline) called after SIGHUP config reload."""
        self._config_reload_hook = hook

    def get_config_reload_hook(self) -> Optional[Callable]:
        return self._config_reload_hook

    def set_evaluate_hook(self, hook: Callable) -> None:
        """Register: hook(findings, policy) -> ActionDecision.

        If set, called INSTEAD of PolicyEngine.evaluate() — the hook
        fully replaces policy evaluation. The hook receives the findings
        list and the policy instance for access to config (overrides,
        default_action), but should NOT call policy.evaluate() because
        Community Edition downgrades "redact" to "alert" inside it.

        The hook must return an ActionDecision with action and findings.
        On exception, falls back to default policy.evaluate().
        """
        self._evaluate_hook = hook

    def get_evaluate_hook(self) -> Optional[Callable]:
        return self._evaluate_hook

    def set_pre_request_hook(self, hook: Callable) -> None:
        """Register: hook(request_id) called at the start of each request."""
        self._pre_request_hook = hook

    def get_pre_request_hook(self) -> Optional[Callable]:
        return self._pre_request_hook

    def set_proxy_server(self, server: object) -> None:
        """Store server reference for Pro runtime config updates."""
        self._proxy_server = server

    def get_proxy_server(self) -> Optional[object]:
        return self._proxy_server

    def extra_detectors(self) -> List[BaseDetector]:
        return list(self._detectors)

    def extra_notifiers(self) -> list:
        return list(self._notifiers)

    # --- Dashboard extension hooks ---

    def register_dashboard_pages(self, pages: list) -> None:
        """Register additional dashboard pages from a plugin.

        Each page is a dict:
          {"name": "notifications", "label": "Notifications",
           "js": "<JS source>", "html": "<HTML template>", "order": 55}

        Pages whose name matches a locked community placeholder unlock it.
        New names create entirely new pages.
        """
        self._dashboard_pages.extend(pages)

    def get_dashboard_pages(self) -> list:
        """Return list of plugin-registered pages."""
        return list(self._dashboard_pages)

    def register_dashboard_css(self, css: str) -> None:
        """Register additional CSS from a plugin (injected after community CSS)."""
        self._dashboard_css.append(css)

    def get_dashboard_css(self) -> List[str]:
        """Return list of plugin-registered CSS strings."""
        return list(self._dashboard_css)

    def register_dashboard_api(self, handler: Callable) -> None:
        """Register a plugin API handler.

        Signature: handler(path, method, body, store, audit_reader) -> (status, body) or None
        Return None to fall through to community handler.
        """
        self._dashboard_api_handler = handler

    def get_dashboard_api_handler(self) -> Optional[Callable]:
        """Return plugin-provided API handler, or None."""
        return self._dashboard_api_handler

    def set_analytics_store(self, store: object) -> None:
        """Set a plugin-provided analytics store (Pro passes its extended store)."""
        self._analytics_store = store

    def get_analytics_store(self) -> Optional[object]:
        """Return plugin-provided analytics store, or None (use community default)."""
        return self._analytics_store

    def set_sse_broadcaster(self, broadcaster: object) -> None:
        """Store the SSE broadcaster so plugins can broadcast events.

        Called by cli.py after creating the broadcaster, before loading plugins.
        Pro uses this to broadcast real-time finding events.
        """
        self._sse_broadcaster = broadcaster

    def get_sse_broadcaster(self) -> Optional[object]:
        """Return the SSE broadcaster, or None if dashboard is disabled."""
        return self._sse_broadcaster

    def register_auth_provider(self, provider: object) -> None:
        """Register an authentication provider (Django auth backend pattern).

        Providers are tried in order after the built-in session check.
        Provider interface: provider.authenticate(headers) -> dict or None
        Return dict: {"user_id": "...", "roles": [...], "provider": "..."}
        """
        self._auth_providers.append(provider)

    def get_auth_providers(self) -> list:
        """Return list of registered auth providers."""
        return list(self._auth_providers)

    def loaded_plugins(self) -> List[tuple]:
        """Return list of (name, version) for loaded plugins."""
        return list(self._loaded_plugins)

    def load_plugins(self) -> None:
        """Discover and load all installed lumen_argus.extensions entry points."""
        try:
            from importlib.metadata import entry_points
        except ImportError:
            # Python 3.8 fallback
            try:
                from importlib_metadata import entry_points
            except ImportError:
                return

        try:
            # Python 3.12+ returns SelectableGroups; 3.9+ supports group kwarg
            eps = entry_points(group="lumen_argus.extensions")
        except TypeError:
            # Python 3.8-3.9: entry_points() returns a dict
            eps = entry_points().get("lumen_argus.extensions", [])

        for ep in eps:
            try:
                register_fn = ep.load()
                register_fn(self)
                # Get version from the distribution that provided this entry point
                version = "unknown"
                try:
                    version = ep.dist.metadata["Version"]
                except Exception:
                    pass
                self._loaded_plugins.append((ep.name, version))
                log.info("loaded extension: %s", ep.name)
            except Exception as e:
                log.error("failed to load extension '%s': %s", ep.name, e)
