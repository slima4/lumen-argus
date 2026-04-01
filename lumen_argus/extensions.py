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

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore

from lumen_argus.detectors import BaseDetector
from lumen_argus.models import Finding

log = logging.getLogger("argus.extensions")


@dataclass(frozen=True)
class CliCommandDef:
    """Definition of a plugin-provided CLI subcommand."""

    name: str  # subcommand name (e.g., "enroll")
    handler: Callable[..., Any]  # callable(args) invoked when subcommand runs
    help: str = ""  # help text for argparse
    arguments: list[dict[str, Any]] = field(default_factory=list)  # list of {"args": [...], "kwargs": {...}}


class ExtensionRegistry:
    """Discovers and loads extensions via Python entry points."""

    # Type for redact hook: (body: bytes, findings: list[Finding]) -> bytes
    RedactHook = Callable[[bytes, list[Finding]], bytes]

    def __init__(self) -> None:
        self._detectors: list[BaseDetector] = []
        self._notifiers: list[Any] = []
        self._redact_hook: ExtensionRegistry.RedactHook | None = None
        self._post_scan_hook: Callable[..., Any] | None = None
        self._config_reload_hook: Callable[..., Any] | None = None
        self._evaluate_hook: Callable[..., Any] | None = None
        self._pre_request_hook: Callable[..., Any] | None = None
        self._proxy_server: Any | None = None
        self._loaded_plugins: list[tuple[str, str]] = []
        # Dashboard extension hooks
        self._dashboard_pages: list[dict[str, Any]] = []
        self._dashboard_css: list[str] = []
        self._dashboard_api_handler: Callable[..., Any] | None = None
        self._analytics_store: AnalyticsStore | None = None
        self._auth_providers: list[Any] = []
        self._sse_broadcaster: Any | None = None
        # Notification channel hooks
        self._channel_types: dict[str, Any] = {}
        self._notifier_builder: Callable[..., Any] | None = None
        self._dispatcher: Any | None = None
        self._channel_limit: int | None = 1
        self._health_hook: Callable[..., Any] | None = None
        self._metrics_hook: Callable[..., Any] | None = None
        self._trace_request_hook: Callable[..., Any] | None = None
        self._license_checker: Any | None = None
        self._response_scan_hook: Callable[..., Any] | None = None
        self._ws_connection_hook: Callable[..., Any] | None = None
        self._rule_metrics_collector: Any | None = None
        self._accelerator_factory: Callable[..., Any] | None = None
        self._extra_clients: list[Any] = []
        self._extra_cli_commands: list[CliCommandDef] = []
        self._allowlist_matcher_factory: Callable[..., Any] | None = None
        self._rule_skip_list: set[str] = set()
        self._rule_skip_list_callback: Callable[..., Any] | None = None
        # MCP Pro hooks
        self._mcp_policy_engine: Any | None = None
        self._mcp_session_escalation: Callable[..., Any] | None = None

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

    def get_redact_hook(self) -> "ExtensionRegistry.RedactHook | None":
        """Return the registered redaction hook, or None."""
        return self._redact_hook

    def set_post_scan_hook(self, hook: Callable[..., Any]) -> None:
        """Register: hook(scan_result, body, provider, session=ctx) after each scan.

        The session kwarg (SessionContext or None) was added in v0.3.
        Hooks should accept **kwargs for forward compatibility.
        """
        self._post_scan_hook = hook

    def get_post_scan_hook(self) -> Callable[..., Any] | None:
        return self._post_scan_hook

    def set_config_reload_hook(self, hook: Callable[..., Any]) -> None:
        """Register: hook(pipeline) called after SIGHUP config reload."""
        self._config_reload_hook = hook

    def get_config_reload_hook(self) -> Callable[..., Any] | None:
        return self._config_reload_hook

    def set_evaluate_hook(self, hook: Callable[..., Any]) -> None:
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

    def get_evaluate_hook(self) -> Callable[..., Any] | None:
        return self._evaluate_hook

    def set_pre_request_hook(self, hook: Callable[..., Any]) -> None:
        """Register: hook(request_id) called at the start of each request."""
        self._pre_request_hook = hook

    def get_pre_request_hook(self) -> Callable[..., Any] | None:
        return self._pre_request_hook

    def set_proxy_server(self, server: object) -> None:
        """Store server reference for Pro runtime config updates."""
        self._proxy_server = server

    def get_proxy_server(self) -> Any | None:
        return self._proxy_server

    def get_ws_active_count(self) -> int:
        """Return number of active WebSocket connections.

        Used by Pro metrics for Prometheus gauge. Reads from the proxy
        server's thread-safe counter rather than internal data structures.
        """
        proxy = self._proxy_server
        if proxy and hasattr(proxy, "active_ws_connections"):
            return proxy.active_ws_connections  # type: ignore[no-any-return]
        return 0

    def extra_detectors(self) -> list[BaseDetector]:
        return list(self._detectors)

    def extra_notifiers(self) -> list[Any]:
        return list(self._notifiers)

    # --- Dashboard extension hooks ---

    def register_dashboard_pages(self, pages: list[dict[str, Any]]) -> None:
        """Register additional dashboard pages from a plugin.

        Each page is a dict:
          {"name": "notifications", "label": "Notifications",
           "js": "<JS source>", "html": "<HTML template>", "order": 55}

        Pages whose name matches a locked community placeholder unlock it.
        New names create entirely new pages.

        Security: "js" is injected as a raw <script> block server-side and
        executes in the dashboard origin. Only register pages from trusted
        entry-point plugins (installed via pip). The "html" field is
        sanitized client-side via _safeInjectHTML (strips scripts and
        on* handlers), but "js" is not — it is trusted code by design.
        """
        self._dashboard_pages.extend(pages)

    def get_dashboard_pages(self) -> list[dict[str, Any]]:
        """Return list of plugin-registered pages."""
        return list(self._dashboard_pages)

    def clear_dashboard_pages(self) -> None:
        """Clear all plugin-registered dashboard pages, CSS, and API handler.

        Called by Pro on SIGHUP when license state changes — allows Pro to
        re-register (license renewed) or leave empty (license expired,
        so community shows locked placeholders on next page load).
        """
        self._dashboard_pages = []
        self._dashboard_css = []
        self._dashboard_api_handler = None

    def register_dashboard_css(self, css: str) -> None:
        """Register additional CSS from a plugin (injected after community CSS)."""
        self._dashboard_css.append(css)

    def get_dashboard_css(self) -> list[str]:
        """Return list of plugin-registered CSS strings."""
        return list(self._dashboard_css)

    def register_dashboard_api(self, handler: Callable[..., Any]) -> None:
        """Register a plugin API handler (async).

        Signature: async handler(path, method, body, store, audit_reader)
                   -> (status, body) | (status, content_type, body) | None
        Return None to fall through to community handler.
        """
        self._dashboard_api_handler = handler

    def get_dashboard_api_handler(self) -> Callable[..., Any] | None:
        """Return plugin-provided API handler, or None."""
        return self._dashboard_api_handler

    def set_analytics_store(self, store: AnalyticsStore) -> None:
        """Set a plugin-provided analytics store (Pro passes its extended store)."""
        self._analytics_store = store

    def get_analytics_store(self) -> AnalyticsStore | None:
        """Return plugin-provided analytics store, or None (use community default)."""
        return self._analytics_store

    def set_sse_broadcaster(self, broadcaster: object) -> None:
        """Store the SSE broadcaster so plugins can broadcast events.

        Called by cli.py after creating the broadcaster, before loading plugins.
        Pro uses this to broadcast real-time finding events.
        """
        self._sse_broadcaster = broadcaster

    def get_sse_broadcaster(self) -> Any | None:
        """Return the SSE broadcaster, or None if dashboard is disabled."""
        return self._sse_broadcaster

    def register_auth_provider(self, provider: object) -> None:
        """Register an authentication provider (async).

        Providers are tried in order after the built-in session check.
        Provider interface: async provider.authenticate(headers) -> dict or None
        Return dict: {"user_id": "...", "roles": [...], "provider": "..."}
        """
        self._auth_providers.append(provider)

    def get_auth_providers(self) -> list[Any]:
        """Return list of registered auth providers."""
        return list(self._auth_providers)

    # --- Client registry hooks ---

    def register_clients(self, clients: list[Any]) -> None:
        """Register additional client definitions from a plugin (Pro/Enterprise)."""
        self._extra_clients.extend(clients)

    def get_extra_clients(self) -> list[Any]:
        """Return plugin-registered client definitions."""
        return list(self._extra_clients)

    # --- CLI extension hooks ---

    def register_cli_commands(self, commands: list[CliCommandDef]) -> None:
        """Register additional CLI subcommands from a plugin.

        Args:
            commands: List of CliCommandDef instances defining subcommands.
        """
        for cmd in commands:
            if not isinstance(cmd, CliCommandDef):
                raise TypeError(
                    "expected CliCommandDef, got %s (name=%r)" % (type(cmd).__name__, getattr(cmd, "name", "?"))
                )
            if not cmd.name:
                raise ValueError("CliCommandDef.name must not be empty")
            if not callable(cmd.handler):
                raise ValueError("CliCommandDef.handler must be callable for command %r" % cmd.name)
        self._extra_cli_commands.extend(commands)
        log.debug("registered %d CLI command(s): %s", len(commands), ", ".join(c.name for c in commands))

    def get_extra_cli_commands(self) -> list[CliCommandDef]:
        """Return plugin-registered CLI commands."""
        return list(self._extra_cli_commands)

    # --- Notification channel hooks ---

    def register_channel_types(self, types: dict[str, Any]) -> None:
        """Register notification channel types from a plugin.

        Pro calls this to register all channel types (webhook, email,
        slack, teams, pagerduty, opsgenie, jira). Without Pro, no types
        are available and the dashboard shows "install from PyPI".
        """
        self._channel_types.update(types)

    def get_channel_types(self) -> dict[str, Any]:
        """Return all registered channel types. Empty if Pro not loaded."""
        return dict(self._channel_types)

    def set_notifier_builder(self, builder: Callable[..., Any]) -> None:
        """Register a notifier factory: builder(channel_dict) -> notifier or None."""
        self._notifier_builder = builder

    def get_notifier_builder(self) -> Callable[..., Any] | None:
        return self._notifier_builder

    def set_dispatcher(self, dispatcher: object) -> None:
        """Set the notification dispatcher (Pro creates and registers this)."""
        self._dispatcher = dispatcher

    def get_dispatcher(self) -> Any | None:
        return self._dispatcher

    def set_channel_limit(self, limit: int | None) -> None:
        """Set notification channel limit. None=unlimited, 1=freemium default."""
        self._channel_limit = limit

    def get_channel_limit(self) -> int | None:
        """Return channel limit. None=unlimited, int=max channels."""
        return self._channel_limit

    def set_health_hook(self, hook: Callable[..., Any]) -> None:
        """Register: hook() -> dict merged into /health response.
        Pro uses this to add license, notification, analytics health."""
        self._health_hook = hook

    def get_health_hook(self) -> Callable[..., Any] | None:
        return self._health_hook

    def set_metrics_hook(self, hook: Callable[..., Any]) -> None:
        """Register: hook() -> str of Prometheus metric lines appended to /metrics."""
        self._metrics_hook = hook

    def get_metrics_hook(self) -> Callable[..., Any] | None:
        return self._metrics_hook

    def set_trace_request_hook(self, hook: Callable[..., Any]) -> None:
        """Register: hook(method, path) -> context manager.
        Wraps the full request lifecycle. Pro uses this to create an OTel
        root span that parents detector/redaction/notification spans.
        Provider is set as a span attribute after routing (inside _do_forward).
        __enter__/__exit__ always called on the same thread."""
        self._trace_request_hook = hook

    def get_trace_request_hook(self) -> Callable[..., Any] | None:
        return self._trace_request_hook

    def set_response_scan_hook(self, hook: Callable[..., Any]) -> None:
        """Register: hook(text, provider, model, session) -> (action, findings).

        Pro registers this for buffered/blocking response scanning. When set,
        runs INSTEAD of community's async scan. If action is "block", proxy
        returns error to client instead of forwarding the response.
        """
        self._response_scan_hook = hook

    def get_response_scan_hook(self) -> Callable[..., Any] | None:
        return self._response_scan_hook

    def set_ws_connection_hook(self, hook: Callable[..., Any]) -> None:
        """Register: hook(event_type, connection_id, metadata).

        event_type: "open" | "close" | "finding_detected"
        connection_id: unique ID per WebSocket connection (uuid4)
        metadata: dict with event-specific fields

        "finding_detected" fires only for text frames with findings (findings_count > 0).
        Hook runs in thread pool via asyncio.to_thread() — safe for blocking I/O.

        Pro can override or wrap the default community hook to add
        per-connection analytics, dashboard charts, etc.
        """
        self._ws_connection_hook = hook

    def get_ws_connection_hook(self) -> Callable[..., Any] | None:
        return self._ws_connection_hook

    def set_accelerator_factory(self, factory: Callable[..., Any]) -> None:
        """Register a factory callable that returns an accelerator instance.

        Factory signature: factory() -> accelerator
        Accelerator must implement: build(compiled_rules), filter(text) -> set[int],
        filter_ratio(candidates) -> float, available (property), stats (property)
        """
        self._accelerator_factory = factory

    def get_accelerator_factory(self) -> Callable[..., Any] | None:
        return self._accelerator_factory

    def set_allowlist_matcher_factory(self, factory: Callable[..., Any]) -> None:
        """Register a factory for custom allowlist matching (Enterprise: Hyperscan).

        Factory signature: factory(secrets=[], pii=[], paths=[]) -> matcher
        Matcher must implement: is_allowed_secret(value), is_allowed_pii(value), is_allowed_path(path)
        """
        self._allowlist_matcher_factory = factory

    def get_allowlist_matcher_factory(self) -> Callable[..., Any] | None:
        return self._allowlist_matcher_factory

    def set_mcp_policy_engine(self, engine: object) -> None:
        """Register Pro's MCP policy engine for tool call validation.

        Engine interface:
          engine.evaluate(tool_name: str, arguments: dict) -> list[Finding]
            Validates tool call arguments against policy rules with shell
            evasion normalization. Returns findings for blocked/warned calls.
        """
        self._mcp_policy_engine = engine

    def get_mcp_policy_engine(self) -> Any | None:
        return self._mcp_policy_engine

    def set_mcp_session_escalation(self, fn: Callable[..., Any]) -> None:
        """Register Pro's adaptive enforcement callback.

        Callback signature:
          fn(signal_type: str, session_id: str, details: dict) -> str
            signal_type: "block", "near_miss", "drift", "unknown_tool", "clean"
            Returns the current enforcement level: "normal", "elevated", "high", "critical"
        """
        self._mcp_session_escalation = fn

    def get_mcp_session_escalation(self) -> Callable[..., Any] | None:
        return self._mcp_session_escalation

    def set_rule_metrics_collector(self, collector: object) -> None:
        """Register a rule metrics collector for Pro performance dashboard.

        Collector interface: collector.record(rule_name: str, elapsed_ms: float)
        MUST be thread-safe — record() is called from ThreadPoolExecutor
        workers when parallel rule batching is enabled.
        Pro creates a RuleMetricsCollector with in-memory aggregation
        (protected by threading.Lock) and periodic async flush.
        """
        self._rule_metrics_collector = collector

    def get_rule_metrics_collector(self) -> Any | None:
        return self._rule_metrics_collector

    def set_rule_skip_list(self, skip_set: set[str] | None) -> None:
        """Register a set of rule names to skip during scanning.

        Pro computes this from analysis results (fully redundant subset rules)
        to reduce scan time without disabling rules in the DB.
        Automatically propagates to the RulesDetector if a callback is wired.
        """
        self._rule_skip_list = set(skip_set) if skip_set else set()
        log.info("rule skip list updated: %d rules", len(self._rule_skip_list))
        if self._rule_skip_list_callback:
            self._rule_skip_list_callback(self._rule_skip_list)

    def get_rule_skip_list(self) -> set[str]:
        """Return the skip set, or empty set."""
        return self._rule_skip_list

    def set_rule_skip_list_callback(self, callback: Callable[..., Any]) -> None:
        """Register callback invoked when skip list changes. Used by pipeline."""
        self._rule_skip_list_callback = callback

    def set_license_checker(self, checker: object) -> None:
        """Register a license checker with is_valid() method for rule-tier gating."""
        self._license_checker = checker

    def get_license_checker(self) -> Any | None:
        return self._license_checker

    def loaded_plugins(self) -> list[tuple[str, str]]:
        """Return list of (name, version) for loaded plugins."""
        return list(self._loaded_plugins)

    def load_plugins(self) -> None:
        """Discover and load all installed lumen_argus.extensions entry points."""
        from importlib.metadata import entry_points

        eps = entry_points(group="lumen_argus.extensions")

        for ep in eps:
            try:
                register_fn = ep.load()
                register_fn(self)
                version = "unknown"
                try:
                    if ep.dist:
                        version = ep.dist.metadata["Version"]
                except Exception as ve:
                    log.debug("could not read version for %s: %s", ep.name, ve)
                self._loaded_plugins.append((ep.name, version))
                log.info("loaded extension: %s", ep.name)
            except Exception as e:
                log.error("failed to load extension '%s': %s", ep.name, e, exc_info=True)
