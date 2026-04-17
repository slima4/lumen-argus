"""Server startup — build components and run the async event loop.

Extracted from cli.py to follow Single Responsibility Principle.
Handles: pipeline construction, response/MCP/WebSocket scanners,
proxy server, dashboard, relay, signal handlers, graceful shutdown.
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import signal
import sys
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import argparse

    from lumen_argus.config import Config
    from lumen_argus.extensions import ExtensionRegistry

log = logging.getLogger("argus.cli")


# ---------------------------------------------------------------------------
# Scanner setup helpers
# ---------------------------------------------------------------------------


def load_mcp_tool_lists(config: Any, store: Any) -> tuple[set[str], set[str]]:
    """Load allowed/blocked MCP tool sets from config + DB."""
    mcp_cfg = getattr(config, "mcp", None)
    allowed = set(mcp_cfg.allowed_tools) if mcp_cfg and mcp_cfg.allowed_tools else set()
    blocked = set(mcp_cfg.blocked_tools) if mcp_cfg and mcp_cfg.blocked_tools else set()
    if store:
        try:
            db_lists = store.get_mcp_tool_lists()
            allowed.update(e["tool_name"] for e in db_lists.get("allowed", []))
            blocked.update(e["tool_name"] for e in db_lists.get("blocked", []))
        except Exception:
            log.warning("failed to load MCP tool lists from DB", exc_info=True)
    return allowed, blocked


def setup_mcp_scanning(config: Any, server: Any, pipeline: Any, analytics_store: Any) -> None:
    """Configure MCP tool argument/response scanning on the HTTP proxy."""
    mcp_args_enabled = config.pipeline.mcp_arguments.enabled
    mcp_resp_enabled = config.pipeline.mcp_responses.enabled
    if not (mcp_args_enabled or mcp_resp_enabled):
        return

    from lumen_argus.mcp.scanner import MCPScanner

    allowed_tools, blocked_tools = load_mcp_tool_lists(config, analytics_store)

    server.mcp_scanner = MCPScanner(
        detectors=pipeline._detectors,
        allowlist=pipeline._allowlist,
        response_scanner=server.response_scanner,
        scan_arguments=mcp_args_enabled,
        scan_responses=mcp_resp_enabled,
        allowed_tools=allowed_tools or None,
        blocked_tools=blocked_tools or None,
        action=config.pipeline.mcp_arguments.action or config.default_action,
    )
    log.info(
        "MCP proxy scanning enabled: arguments=%s responses=%s",
        mcp_args_enabled,
        mcp_resp_enabled,
    )


def setup_ws_scanning(config: Any, server: Any, pipeline: Any, analytics_store: Any, extensions: Any) -> None:
    """Configure WebSocket frame scanning and connection lifecycle hook."""
    from lumen_argus.ws_proxy import WebSocketScanner

    ws_outbound = config.pipeline.websocket_outbound.enabled
    ws_inbound = config.pipeline.websocket_inbound.enabled
    if ws_outbound or ws_inbound:
        server.ws_scanner = WebSocketScanner(
            detectors=pipeline._detectors,
            allowlist=pipeline._allowlist,
            response_scanner=server.response_scanner,
            scan_outbound=ws_outbound,
            scan_inbound=ws_inbound,
            max_frame_size=config.websocket.max_frame_size,
        )
        server.ws_allowed_origins = config.websocket.allowed_origins or []
        log.info("WebSocket scanning enabled on same port: outbound=%s inbound=%s", ws_outbound, ws_inbound)

    # Register default WS connection lifecycle hook (records to analytics store).
    if analytics_store and not extensions.get_ws_connection_hook():

        def _default_ws_hook(event_type: str, connection_id: str, metadata: dict[str, Any]) -> None:
            if event_type == "open":
                analytics_store.record_ws_connection_open(
                    connection_id,
                    metadata["target_url"],
                    metadata.get("origin", ""),
                    metadata["timestamp"],
                )
            elif event_type == "close":
                analytics_store.record_ws_connection_close(
                    connection_id,
                    metadata["timestamp"],
                    metadata["duration_seconds"],
                    metadata["frames_sent"],
                    metadata["frames_received"],
                    0,
                    metadata.get("close_code", 1000),
                )
            elif event_type == "finding_detected" and metadata["findings_count"] > 0:
                analytics_store.increment_ws_findings(connection_id, metadata["findings_count"])

        extensions.set_ws_connection_hook(_default_ws_hook)
        log.debug("default WebSocket connection hook registered")


def build_pipeline_config(cfg: Any) -> dict[str, Any]:
    """Build flat dict from PipelineConfig for ScannerPipeline."""
    enc = cfg.pipeline.encoding_decode
    return {
        "outbound_dlp_enabled": cfg.pipeline.outbound_dlp.enabled,
        "encoding_decode_enabled": enc.enabled,
        "encoding_base64": enc.base64,
        "encoding_hex": enc.hex,
        "encoding_url": enc.url,
        "encoding_unicode": enc.unicode,
        "encoding_max_depth": enc.max_depth,
        "encoding_min_decoded_length": enc.min_decoded_length,
        "encoding_max_decoded_length": enc.max_decoded_length,
    }


def run_server(
    config: Config,
    args: argparse.Namespace,
    extensions: ExtensionRegistry,
    *,
    console_level: int,
    file_handler: logging.Handler,
    root_logger: logging.Logger,
    log_file_path: str,
) -> None:
    """Build all server components from loaded config and run the event loop."""
    from dataclasses import asdict

    from lumen_argus import __version__
    from lumen_argus.audit import AuditLogger
    from lumen_argus.config_loader import initialize_analytics
    from lumen_argus.display import JsonDisplay, TerminalDisplay
    from lumen_argus.pipeline import ScannerPipeline
    from lumen_argus.provider import ProviderRouter
    from lumen_argus.reload import do_reload

    # CLI args override config
    port = args.port or config.proxy.port
    bind = args.host or config.proxy.bind
    audit_log_dir = args.log_dir or config.audit.log_dir

    # Combined relay+engine mode: engine binds to --engine-port, relay on --port
    engine_port = getattr(args, "engine_port", None)
    relay_fail_mode = getattr(args, "fail_mode", None) or config.relay.fail_mode
    relay_port = port  # only used when engine_port is set
    if engine_port:
        port = engine_port

    # Startup summary
    config_path_display = args.config or "~/.lumen-argus/config.yaml"
    log.info("lumen-argus v%s starting", __version__)
    log.info("python: %s, os: %s, pid: %d", platform.python_version(), sys.platform, os.getpid())
    log.info("config: %s", config_path_display)
    log.info(
        "detectors: secrets=%s pii=%s proprietary=%s",
        config.secrets.action or config.default_action,
        config.pii.action or config.default_action,
        config.proprietary.action or config.default_action,
    )
    log.info(
        "allowlist: %d secrets, %d pii, %d paths",
        len(config.allowlist.secrets),
        len(config.allowlist.pii),
        len(config.allowlist.paths),
    )
    if config.custom_rules:
        log.info("custom rules: %d", len(config.custom_rules))

    # Build action overrides from per-detector config
    action_overrides: dict[str, str] = {}
    if config.secrets.action:
        action_overrides["secrets"] = config.secrets.action
    if config.pii.action:
        action_overrides["pii"] = config.pii.action
    if config.proprietary.action:
        action_overrides["proprietary"] = config.proprietary.action

    # Construct display and audit
    display: JsonDisplay | TerminalDisplay
    if args.output_format == "json":
        display = JsonDisplay()
    else:
        display = TerminalDisplay(no_color=args.no_color)
    audit = AuditLogger(log_dir=audit_log_dir, retention_days=config.audit.retention_days)

    # Register community notification defaults
    from lumen_argus.notifiers import WEBHOOK_CHANNEL_TYPE, build_notifier

    if not extensions.get_notifier_builder():
        extensions.set_notifier_builder(build_notifier)
    if not extensions.get_channel_types():
        extensions.register_channel_types(WEBHOOK_CHANNEL_TYPE)

    for pname, pver in extensions.loaded_plugins():
        log.info("plugin: %s v%s", pname, pver)
    log.info("audit log: %s", os.path.expanduser(audit_log_dir))
    log.info("app log: %s (%s level)", log_file_path, config.logging_config.file_level)

    router = ProviderRouter(upstreams=config.upstreams or None)

    # Build SSL context for upstream connections
    from lumen_argus.async_proxy import build_ssl_context

    ssl_context = build_ssl_context(
        ca_bundle=config.proxy.ca_bundle,
        verify_ssl=config.proxy.verify_ssl,
    )

    # Analytics store and rules (must happen before pipeline creation)
    analytics_store = initialize_analytics(config, args, extensions, action_overrides)

    # Allowlist (YAML config + DB entries)
    from lumen_argus.scanner import _build_allowlist

    allowlist = _build_allowlist(config, store=analytics_store, extensions=extensions)

    # Pipeline (created after store + rules so RulesDetector sees imported rules)

    pipeline = ScannerPipeline(
        default_action=config.default_action,
        action_overrides=action_overrides,
        allowlist=allowlist,
        entropy_threshold=config.entropy_threshold,
        extensions=extensions,
        custom_rules=config.custom_rules,
        dedup_config=asdict(config.dedup),
        pipeline_config=build_pipeline_config(config),
        rebuild_delay=config.rules.rebuild_delay_seconds,
    )

    if pipeline._rules_detector:
        pipeline._rules_detector.set_parallel(config.pipeline.parallel_batching)

    # Build response scanner
    response_scanner = _build_response_scanner(config, pipeline, analytics_store)

    # Start server
    try:
        from lumen_argus.async_proxy import AsyncArgusProxy

        server = AsyncArgusProxy(
            bind=bind,
            port=port,
            pipeline=pipeline,
            router=router,
            audit=audit,
            display=display,  # type: ignore[arg-type]
            timeout=config.proxy.timeout,
            connect_timeout=config.proxy.connect_timeout,
            retries=config.proxy.retries,
            max_body_size=config.proxy.max_body_size,
            redact_hook=extensions.get_redact_hook(),
            ssl_context=ssl_context,
            max_connections=config.proxy.max_connections,
        )
        standalone = not getattr(args, "no_standalone", False) and config.proxy.standalone
        server.standalone = standalone
        extensions.set_proxy_server(server)
        server.extensions = extensions
        server.response_scanner = response_scanner
        if analytics_store and analytics_store._hmac_key:
            server.hmac_key = analytics_store._hmac_key
    except OSError as e:
        print("Error: Could not bind to %s:%d — %s" % (bind, port, e), file=sys.stderr)
        sys.exit(1)

    display.show_banner(port, bind)
    log.info("listening on http://%s:%d", bind, port)
    start_time = time.monotonic()

    # Dashboard
    dashboard_server, sse_broadcaster = _build_dashboard(config, args, analytics_store, extensions, audit_log_dir)

    # MCP-aware scanning in HTTP proxy
    setup_mcp_scanning(config, server, pipeline, analytics_store)

    # WebSocket scanning (same port, handled by async proxy)
    setup_ws_scanning(config, server, pipeline, analytics_store, extensions)

    # Track current config for diff on reload
    current_config = [config]
    server.ready = True
    log.debug("engine ready: pipeline loaded, scanners initialized")

    # Combined mode: create relay if --engine-port was given
    relay_instance = None
    if engine_port:
        from lumen_argus.relay import ArgusRelay

        relay_instance = ArgusRelay(
            bind=bind,
            port=relay_port,
            engine_url="http://%s:%d" % (bind, port),
            fail_mode=relay_fail_mode,
            router=router,
            health_interval=config.relay.health_check_interval,
            health_timeout=config.relay.health_check_timeout,
            queue_timeout=config.relay.queue_on_startup,
            timeout=config.relay.timeout,
            connect_timeout=config.relay.connect_timeout,
            max_connections=config.relay.max_connections,
        )
        log.info("combined mode: relay :%d → engine :%d (fail_mode=%s)", relay_port, port, relay_fail_mode)

    async def _run_async() -> None:
        await server.start()
        if relay_instance:
            await relay_instance.start()
        if sse_broadcaster:
            sse_broadcaster.start()
        if dashboard_server:
            try:
                await dashboard_server.start()
            except OSError:
                log.warning("dashboard unavailable — continuing without it")

        loop = asyncio.get_running_loop()
        shutdown_event = asyncio.Event()

        def _shutdown() -> None:
            shutdown_event.set()

        def _reload() -> None:
            task = asyncio.ensure_future(
                asyncio.to_thread(
                    do_reload,
                    server,
                    args.config,
                    file_handler,
                    console_level,
                    root_logger,
                    extensions,
                    current_config,
                )
            )
            server._background_tasks.add(task)
            task.add_done_callback(server._background_tasks.discard)

        loop.add_signal_handler(signal.SIGINT, _shutdown)
        loop.add_signal_handler(signal.SIGTERM, _shutdown)
        if hasattr(signal, "SIGHUP"):
            loop.add_signal_handler(signal.SIGHUP, _reload)

        await shutdown_event.wait()

        # Graceful drain
        drain_timeout = current_config[0].proxy.drain_timeout
        remaining = await server.drain(timeout=drain_timeout)
        if remaining and drain_timeout > 0:
            log.warning("shutdown: %d requests force-closed after %ds drain timeout", remaining, drain_timeout)

        if dashboard_server:
            await dashboard_server.stop()
        if sse_broadcaster:
            await sse_broadcaster.stop()
        if relay_instance:
            await relay_instance.drain(timeout=5)
            await relay_instance.stop()
        await server.stop()

        uptime = time.monotonic() - start_time
        log.info("shutdown: %d requests, uptime %.0fs", server.stats.total_requests, uptime)
        display.show_shutdown(server.stats.summary())
        audit.close()

    asyncio.run(_run_async())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_response_scanner(config: Any, pipeline: Any, store: Any) -> Any:
    """Build response scanner if enabled."""
    resp_secrets = config.pipeline.response_secrets.enabled
    resp_injection = config.pipeline.response_injection.enabled
    if not (resp_secrets or resp_injection):
        return None
    from lumen_argus.response_scanner import ResponseScanner

    scanner = ResponseScanner(
        detectors=pipeline._detectors if resp_secrets else [],
        allowlist=pipeline._allowlist if resp_secrets else None,
        store=store,
        scan_secrets=resp_secrets,
        scan_injection=resp_injection,
        max_response_size=config.pipeline.response_max_size,
    )
    log.info("response scanning enabled: secrets=%s injection=%s", resp_secrets, resp_injection)
    return scanner


def _build_dashboard(
    config: Any,
    args: Any,
    analytics_store: Any,
    extensions: Any,
    audit_log_dir: str,
) -> tuple[Any, Any]:
    """Build dashboard server and SSE broadcaster. Returns (server, broadcaster)."""
    if not config.dashboard.enabled:
        return None, None

    from lumen_argus.dashboard.audit_reader import AuditReader
    from lumen_argus.dashboard.server import AsyncDashboardServer
    from lumen_argus.dashboard.sse import SSEBroadcaster

    sse_broadcaster = SSEBroadcaster()
    extensions.set_sse_broadcaster(sse_broadcaster)

    audit_reader = AuditReader(log_dir=audit_log_dir)
    dash_password = config.dashboard.password
    dash_bind = args.host or config.dashboard.bind
    dash_port = getattr(args, "dashboard_port", None) or config.dashboard.port

    dashboard_server = AsyncDashboardServer(
        bind=dash_bind,
        port=dash_port,
        analytics_store=analytics_store,
        extensions=extensions,
        password=dash_password,
        audit_reader=audit_reader,
        sse_broadcaster=sse_broadcaster,
        config=config,
    )

    # Reconcile YAML notification channels to DB
    if analytics_store and config.notifications:
        limit = extensions.get_channel_limit()
        result = analytics_store.reconcile_yaml_channels(
            config.notifications,
            channel_limit=limit,
        )
        for action_name in ("created", "updated", "deleted"):
            if result[action_name]:
                log.info("notification channels %s from config: %s", action_name, ", ".join(result[action_name]))

    # Create basic dispatcher if Pro hasn't registered one
    if analytics_store and not extensions.get_dispatcher():
        from lumen_argus.notifiers.dispatcher import BasicDispatcher

        basic_dispatcher = BasicDispatcher(
            store=analytics_store,
            builder=extensions.get_notifier_builder(),
        )
        basic_dispatcher.rebuild()
        extensions.set_dispatcher(basic_dispatcher)
        log.debug("community dispatcher registered")

    return dashboard_server, sse_broadcaster
