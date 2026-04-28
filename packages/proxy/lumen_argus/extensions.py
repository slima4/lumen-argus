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
import os
import sys
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
        # Parallel to _loaded_plugins: ep.name -> module object, populated on
        # successful load. Used by loaded_plugin_build_infos() to read each
        # plugin's ``__build_info__`` (sidecar-build-identity-spec.md).
        self._loaded_plugin_modules: dict[str, Any] = {}
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
        self._channel_limit: int | None = None
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
        # MCP plugin hooks
        self._mcp_policy_engine: Any | None = None
        self._mcp_session_escalation: Callable[..., Any] | None = None
        self._tool_policy_evaluator: Any | None = None
        self._approval_gate: Any | None = None
        # Database adapter hook
        self._database_adapter: Any | None = None
        # Agent auth hook
        self._agent_auth_provider: Any | None = None
        # Plugin instance registry — shared state between installed plugins
        self._plugin_instances: dict[str, Any] = {}
        # Schema extension DDL registered by plugins
        self._schema_extensions: list[str] = []
        # Additional static file directories provided by plugins
        self._static_dirs: list[str] = []

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
        default_action).

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
        """Store server reference for plugin runtime config updates."""
        self._proxy_server = server

    def get_proxy_server(self) -> Any | None:
        return self._proxy_server

    def get_ws_active_count(self) -> int:
        """Return number of active WebSocket connections.

        Used by plugin metrics for Prometheus gauges. Reads from the
        proxy server's thread-safe counter rather than internal data
        structures.
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
        """Clear plugin-registered dashboard pages, CSS, and API handler.

        Called during SIGHUP config reload when a plugin needs to
        re-register its UI elements — e.g. a license state change that
        toggles which pages are available. The plugin is expected to
        call ``register_dashboard_pages`` / ``register_dashboard_css`` /
        ``register_dashboard_api`` again from its reload callback.

        **Does not clear ``_static_dirs``.** Static directories are
        filesystem paths tied to installed plugin packages — they are
        registered once at ``load_plugins()`` time from each plugin's
        ``register()`` entry point, which is *not* re-invoked on SIGHUP.
        Clearing them here would permanently lose the registration for
        any plugin that doesn't also re-register from a reload hook
        (e.g. a package that only installs static files).

        The dashboard server's cached static-file bundle *is* busted, so
        any file content changes on disk are picked up on the next
        page load even though the dirs list is unchanged.
        """
        self._dashboard_pages = []
        self._dashboard_css = []
        self._dashboard_api_handler = None
        # Bust the dashboard server's cached static-file bundle. Imported
        # lazily to avoid a circular import at module load time. If the
        # import fails (packaging fault, test environment where server.py
        # couldn't load), log a warning — the reload is non-fatal, but a
        # stale cache after a reload would serve outdated plugin files
        # with no diagnostic trace.
        try:
            from lumen_argus.dashboard.server import clear_static_cache

            clear_static_cache()
        except ImportError as e:
            log.warning("clear_dashboard_pages: could not bust static cache: %s", e)

    def register_dashboard_css(self, css: str) -> None:
        """Register additional CSS from a plugin (injected after community CSS)."""
        self._dashboard_css.append(css)

    def get_dashboard_css(self) -> list[str]:
        """Return list of plugin-registered CSS strings."""
        return list(self._dashboard_css)

    def register_dashboard_api(self, handler: Callable[..., Any]) -> None:
        """Register a plugin API handler (async).

        Signature: async handler(path, method, body, store, audit_reader, agent_identity)
                   -> (status, body) | (status, content_type, body) | None
        agent_identity is AgentIdentity | None (None for dashboard users).
        Return None to fall through to community handler.
        """
        self._dashboard_api_handler = handler

    def get_dashboard_api_handler(self) -> Callable[..., Any] | None:
        """Return plugin-provided API handler, or None."""
        return self._dashboard_api_handler

    def set_analytics_store(self, store: AnalyticsStore) -> None:
        """Set a plugin-provided analytics store (e.g. a subclass with extra tables)."""
        self._analytics_store = store

    def get_analytics_store(self) -> AnalyticsStore | None:
        """Return plugin-provided analytics store, or None (use community default)."""
        return self._analytics_store

    def set_sse_broadcaster(self, broadcaster: object) -> None:
        """Store the SSE broadcaster so plugins can broadcast events.

        Called by cli.py after creating the broadcaster, before loading
        plugins. Plugins use this to broadcast real-time finding events.
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
        """Register additional client definitions from a plugin."""
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

        A plugin calls this to register channel types (webhook, email,
        slack, teams, pagerduty, opsgenie, jira, etc.). With no plugin
        registered, no types are available and the dashboard shows
        "install from PyPI".
        """
        self._channel_types.update(types)

    def get_channel_types(self) -> dict[str, Any]:
        """Return all registered channel types. Empty if no plugin has registered any."""
        return dict(self._channel_types)

    def set_notifier_builder(self, builder: Callable[..., Any]) -> None:
        """Register a notifier factory: builder(channel_dict) -> notifier or None."""
        self._notifier_builder = builder

    def get_notifier_builder(self) -> Callable[..., Any] | None:
        return self._notifier_builder

    def set_dispatcher(self, dispatcher: object) -> None:
        """Set the notification dispatcher (plugins create and register this)."""
        self._dispatcher = dispatcher

    def get_dispatcher(self) -> Any | None:
        return self._dispatcher

    def set_channel_limit(self, limit: int | None) -> None:
        """Set notification channel cap. None=unlimited (community default)."""
        self._channel_limit = limit

    def get_channel_limit(self) -> int | None:
        """Return channel limit. None=unlimited, int=max channels."""
        return self._channel_limit

    def set_health_hook(self, hook: Callable[..., Any]) -> None:
        """Register: hook() -> dict merged into /health response.
        Plugins use this to add license, notification, analytics health."""
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
        Wraps the full request lifecycle. Plugins use this to create an
        OTel root span that parents detector/redaction/notification
        spans. Provider is set as a span attribute after routing
        (inside _do_forward). __enter__/__exit__ always called on the
        same thread."""
        self._trace_request_hook = hook

    def get_trace_request_hook(self) -> Callable[..., Any] | None:
        return self._trace_request_hook

    def set_response_scan_hook(self, hook: Callable[..., Any]) -> None:
        """Register: hook(text, provider, model, session) -> (action, findings).

        A plugin registers this for buffered/blocking response scanning.
        When set, runs INSTEAD of community's async scan. If action is
        "block", the proxy returns an error to the client instead of
        forwarding the response.
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

        Plugins can override or wrap the default community hook to add
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
        """Register a plugin's MCP policy engine for tool call validation.

        Engine interface:
          engine.evaluate(tool_name: str, arguments: dict) -> list[Finding]
            Validates tool call arguments against policy rules with shell
            evasion normalization. Returns findings for blocked/warned calls.
        """
        self._mcp_policy_engine = engine

    def get_mcp_policy_engine(self) -> Any | None:
        return self._mcp_policy_engine

    def set_mcp_session_escalation(self, fn: Callable[..., Any]) -> None:
        """Register a plugin's adaptive enforcement callback.

        Callback signature:
          fn(signal_type: str, session_id: str, details: dict) -> str
            signal_type: "block", "near_miss", "drift", "unknown_tool", "clean"
            Returns the current enforcement level: "normal", "elevated", "high", "critical"
        """
        self._mcp_session_escalation = fn

    def get_mcp_session_escalation(self) -> Callable[..., Any] | None:
        return self._mcp_session_escalation

    def set_tool_policy_evaluator(self, evaluator: object) -> None:
        """Register a plugin's tool policy evaluator for ABAC-style tool authorization.

        Evaluator interface:
          evaluator.evaluate(tool_name: str, arguments: dict, server_id: str, context: dict) -> PolicyDecision
            Returns a PolicyDecision with action (allow/block/alert/approval),
            matched policy name, reason, severity, and optional rate_limit/approval config.
        """
        self._tool_policy_evaluator = evaluator

    def get_tool_policy_evaluator(self) -> Any | None:
        return self._tool_policy_evaluator

    def set_approval_gate(self, gate: object) -> None:
        """Register a plugin's approval gate for human-in-the-loop tool call authorization.

        Gate interface:
          gate.request_approval(tool_name, arguments, server_id, session_id,
                                identity, client_name, policy) -> ApprovalDecision
            Suspends the tool call and waits for admin decision (within timeout).
            Returns ApprovalDecision with status (approved/denied/expired).

          gate.decide(approval_id: str, status: str, decided_by: str, reason: str) -> bool
            Records an admin decision for a pending approval.
        """
        self._approval_gate = gate

    def get_approval_gate(self) -> Any | None:
        return self._approval_gate

    def set_rule_metrics_collector(self, collector: object) -> None:
        """Register a rule metrics collector for the performance dashboard.

        Collector interface: collector.record(rule_name: str, elapsed_ms: float)
        MUST be thread-safe — record() is called from ThreadPoolExecutor
        workers when parallel rule batching is enabled. Plugins typically
        implement this with in-memory aggregation protected by a
        ``threading.Lock`` and a periodic async flush.
        """
        self._rule_metrics_collector = collector

    def get_rule_metrics_collector(self) -> Any | None:
        return self._rule_metrics_collector

    def set_rule_skip_list(self, skip_set: set[str] | None) -> None:
        """Register a set of rule names to skip during scanning.

        Plugins compute this from analysis results (fully redundant
        subset rules) to reduce scan time without disabling rules in
        the DB. Automatically propagates to the RulesDetector if a
        callback is wired.
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

    def set_database_adapter(self, adapter: object) -> None:
        """Register a database adapter (e.g. a PostgreSQL adapter).

        Must implement the DatabaseAdapter interface from
        ``analytics.adapter``. Called by a plugin at startup, before
        AnalyticsStore is created.
        """
        self._database_adapter = adapter
        log.info("database adapter registered: %s", getattr(adapter, "engine_name", "unknown"))

    def get_database_adapter(self) -> Any | None:
        return self._database_adapter

    def set_agent_auth_provider(self, provider: object) -> None:
        """Register the agent authentication provider.

        Must implement the AgentAuthProvider interface from auth.py.
        Only one provider active at a time (last wins). Called by a
        plugin at startup to enable agent bearer token auth, OIDC,
        mTLS, or SaaS token validation.
        """
        self._agent_auth_provider = provider
        log.info("agent auth provider registered: %s", type(provider).__name__)

    def get_agent_auth_provider(self) -> Any | None:
        return self._agent_auth_provider

    # --- Plugin instance registry ---

    def set_plugin(self, name: str, instance: Any) -> None:
        """Register a plugin instance under a stable name.

        Enables plugins to share state without reaching into each other's
        private module attributes. A late-loading plugin can call
        ``registry.get_plugin("<name>")`` from its ``register()`` entry
        point to access handles the early-loading plugin chose to expose
        on its own instance, without importing the other plugin's
        internal modules directly.

        Idempotent (last write wins). No type constraint on ``instance`` —
        the caller knows the shape. Convention for ``name``: the package
        name without the ``lumen_argus_`` prefix.
        """
        self._plugin_instances[name] = instance
        log.info("plugin instance registered: %s (%s)", name, type(instance).__name__)

    def get_plugin(self, name: str) -> Any | None:
        """Return the plugin instance registered under ``name``, or ``None``."""
        return self._plugin_instances.get(name)

    # --- Schema extension registration ---

    def register_schema_extension(self, ddl: str) -> None:
        """Register additional DDL to run during analytics store initialization.

        Lets plugins own their own database tables instead of having the
        community store (or another plugin) carry their schema. Extensions
        run after the community schema in registration order. Each DDL
        string must be idempotent — use ``CREATE TABLE IF NOT EXISTS`` /
        ``CREATE INDEX IF NOT EXISTS``.

        The DDL may reference adapter dialect placeholders; the store
        resolves them via ``str.format`` before executing:

        - ``{auto_id}`` → ``adapter.auto_id_type()``
        - ``{ts}``      → ``adapter.timestamp_type()``

        Registration must happen before ``AnalyticsStore`` is constructed
        (i.e. from a plugin's ``register()`` entry point), otherwise the
        extension will not be applied until the next restart.
        """
        self._schema_extensions.append(ddl)
        log.info("schema extension registered (%d chars)", len(ddl))

    def get_schema_extensions(self) -> list[str]:
        """Return the list of registered schema-extension DDL strings."""
        return list(self._schema_extensions)

    # --- Static file directory registration ---

    def register_static_dir(self, path: str) -> None:
        """Register an additional directory to scan for dashboard static files.

        The dashboard HTML assembler reads ``js/*.js``, ``css/*.css``, and
        ``html/*.html`` from each registered directory in registration
        order (community first, then plugins in entry-point order). File
        name collisions resolve last-write-wins, so a plugin can override
        a community file by registering a directory containing a file of
        the same name — this should be rare.

        If ``path`` does not exist at registration time, a warning is
        logged and the directory is skipped.
        """
        if not os.path.isdir(path):
            log.warning("register_static_dir: path does not exist, skipping: %s", path)
            return
        self._static_dirs.append(path)
        log.info("plugin static dir registered: %s", path)

    def get_static_dirs(self) -> list[str]:
        """Return the list of registered plugin static directories."""
        return list(self._static_dirs)

    def loaded_plugins(self) -> list[tuple[str, str]]:
        """Return list of (name, version) for loaded plugins."""
        return list(self._loaded_plugins)

    def loaded_plugin_build_infos(self) -> list[dict[str, Any]]:
        """Return each loaded plugin's build identity for ``/api/v1/build``.

        Contract (set by ``sidecar-build-identity-spec.md`` §2) — plugin
        modules should expose a module-level attribute::

            __build_info__: dict = {
                "name":       "<dist-name>",         # optional
                "version":    "<semver>",            # optional
                "git_commit": "<40-char sha>",       # optional
                "build_id":   "sha256:<hex>",        # optional
            }

        All four keys are optional and filled from fallbacks when absent:

        * ``name`` / ``version`` fall back to the entry-point name and
          the plugin distribution's ``Version`` metadata (already
          captured in ``_loaded_plugins`` during ``load_plugins()``).
        * ``git_commit`` falls back to ``UNKNOWN`` from
          ``lumen_argus_core.build_info``.
        * ``build_id`` falls back to ``BUILD_ID_UNKNOWN``.

        Plugins that have not shipped ``__build_info__`` at all still
        appear in the returned list with fallback values only — the
        contract is additive (for operator visibility), not gating.
        A non-dict ``__build_info__`` is logged at WARNING and treated
        as missing; the result row falls back entirely.

        Output order matches ``_loaded_plugins`` iteration order (the
        topologically-sorted load order set by ``load_plugins()``).
        """
        from lumen_argus_core.build_info import BUILD_ID_UNKNOWN, UNKNOWN

        out: list[dict[str, Any]] = []
        for name, version in self._loaded_plugins:
            entry: dict[str, Any] = {
                "name": name,
                "version": version,
                "git_commit": UNKNOWN,
                "build_id": BUILD_ID_UNKNOWN,
            }
            module = self._loaded_plugin_modules.get(name)
            build_info = getattr(module, "__build_info__", None) if module is not None else None
            if isinstance(build_info, dict):
                for field_name in ("name", "version", "git_commit", "build_id"):
                    value = build_info.get(field_name)
                    if value:
                        entry[field_name] = value
            elif build_info is not None:
                log.warning(
                    "plugin %r __build_info__ is %s, expected dict; ignoring",
                    name,
                    type(build_info).__name__,
                )
            out.append(entry)
        return out

    @staticmethod
    def _resolve_plugin_load_order(
        plugin_deps: list[tuple[str, tuple[str, ...]]],
    ) -> tuple[list[str], dict[str, str]]:
        """Compute the load order for plugins given their declared deps.

        Plugins may declare load-order dependencies via a module-level
        ``LUMEN_ARGUS_PLUGIN_DEPENDS_ON`` tuple of entry-point names.
        This helper takes those declarations (in entry-point iteration
        order, which is alphabetical because ``entry_points.txt`` is
        written sorted by setuptools) and returns the resolved order
        plus any plugins dropped from the result.

        Args:
            plugin_deps: ``(name, deps)`` pairs in entry-point iteration
                order. Duplicate names are tolerated; the first
                occurrence's deps win for graph purposes, and downstream
                callers are responsible for emitting all entries with a
                given name when that name is loaded.

        Returns:
            ``(sorted_names, dropped)``:
              - ``sorted_names``: unique plugin names in resolved load
                order. Plugins involved in a cycle fall back to
                entry-point iteration order at the tail of the list so
                the proxy still boots — a misconfigured plugin must not
                crash the registry.
              - ``dropped``: ``name -> reason`` for any plugin excluded
                because a declared dependency is not installed (or was
                itself dropped transitively).

        Side effects: warnings/errors are emitted to the module logger.
        """
        deps_by_name: dict[str, tuple[str, ...]] = {}
        first_seen_order: list[str] = []
        for name, deps in plugin_deps:
            if name not in deps_by_name:
                deps_by_name[name] = deps
                first_seen_order.append(name)

        dropped: dict[str, str] = {}

        def _drop(name: str, reason: str) -> None:
            if name in dropped:
                return
            dropped[name] = reason
            log.warning("plugin %r dropped: %s", name, reason)

        changed = True
        while changed:
            changed = False
            for name in first_seen_order:
                if name in dropped:
                    continue
                for dep in deps_by_name[name]:
                    if dep not in deps_by_name:
                        _drop(
                            name,
                            "depends on %r which is not installed" % dep,
                        )
                        changed = True
                        break
                    if dep in dropped:
                        _drop(
                            name,
                            "depends on %r which was dropped" % dep,
                        )
                        changed = True
                        break

        order_index = {n: i for i, n in enumerate(first_seen_order)}
        remaining: dict[str, set[str]] = {
            name: {d for d in deps_by_name[name] if d not in dropped}
            for name in first_seen_order
            if name not in dropped
        }

        sorted_names: list[str] = []
        while remaining:
            ready = sorted(
                (n for n, d in remaining.items() if not d),
                key=lambda n: order_index[n],
            )
            if not ready:
                cycle = sorted(remaining.keys(), key=lambda n: order_index[n])
                log.error(
                    "plugin dependency cycle detected among %s; "
                    "falling back to entry-point iteration order for involved plugins",
                    ", ".join(repr(n) for n in cycle),
                )
                sorted_names.extend(cycle)
                break
            for n in ready:
                sorted_names.append(n)
                del remaining[n]
                for d in remaining.values():
                    d.discard(n)

        return sorted_names, dropped

    def load_plugins(self) -> None:
        """Discover and load installed ``lumen_argus.extensions`` entry points.

        Plugins may declare load-order dependencies via a module-level
        ``LUMEN_ARGUS_PLUGIN_DEPENDS_ON`` tuple on the plugin package::

            # In any plugin's __init__.py
            LUMEN_ARGUS_PLUGIN_DEPENDS_ON: tuple[str, ...] = ("other-plugin",)

        Strings refer to entry-point names declared in
        ``[project.entry-points."lumen_argus.extensions"]``, not Python
        module names. ``load_plugins`` topologically sorts plugins so a
        plugin's declared dependencies have ``register()`` called first.
        Plugins without the attribute fall back to entry-point iteration
        order (alphabetical, set by setuptools) — fully backward
        compatible.

        Failure modes:
          - **Missing dependency** (X declares dep on Y, Y not installed):
            X (and anything transitively depending on X) is dropped with
            a WARNING. Other plugins continue loading.
          - **Cycle** (A → B → A): logged as ERROR; the involved plugins
            fall back to entry-point iteration order. The proxy still
            boots — a plugin misconfiguration must not crash it.
          - **Import or register error**: logged as ERROR; other plugins
            continue loading.
        """
        from importlib import import_module
        from importlib.metadata import entry_points

        eps_iter = list(entry_points(group="lumen_argus.extensions"))
        if not eps_iter:
            return

        # Import the module before ``ep.load()`` so we can read
        # ``LUMEN_ARGUS_PLUGIN_DEPENDS_ON`` and decide load order. Once
        # the module is in ``sys.modules`` the later ``ep.load()`` is a
        # cache hit, not a re-import.
        records: list[tuple[Any, tuple[str, ...]]] = []
        for ep in eps_iter:
            try:
                module = import_module(ep.module)
            except Exception as e:
                log.error(
                    "failed to import extension module for '%s': %s",
                    ep.name,
                    e,
                    exc_info=True,
                )
                continue
            deps_attr = getattr(module, "LUMEN_ARGUS_PLUGIN_DEPENDS_ON", ())
            try:
                deps = tuple(str(d) for d in deps_attr)
            except TypeError:
                log.warning(
                    "plugin %r has non-iterable LUMEN_ARGUS_PLUGIN_DEPENDS_ON (%r); ignoring",
                    ep.name,
                    deps_attr,
                )
                deps = ()
            records.append((ep, deps))

        if not records:
            return

        sorted_names, dropped = self._resolve_plugin_load_order([(ep.name, deps) for ep, deps in records])

        # Duplicate entry-point names (rare, pathological) are loaded
        # together in original iteration order to preserve historical
        # behavior — the dep graph keys on first occurrence.
        eps_by_name: dict[str, list[Any]] = {}
        for ep, _ in records:
            if ep.name in dropped:
                continue
            eps_by_name.setdefault(ep.name, []).append(ep)

        for name in sorted_names:
            for ep in eps_by_name.get(name, ()):
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
                    # sys.modules hit (already imported above for dep reading).
                    self._loaded_plugin_modules[ep.name] = sys.modules.get(ep.module)
                    log.info("loaded extension: %s", ep.name)
                except Exception as e:
                    log.error("failed to load extension '%s': %s", ep.name, e, exc_info=True)
