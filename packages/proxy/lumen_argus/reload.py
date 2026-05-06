"""Hot-reload logic executed on SIGHUP.

Reloads config from disk, reconciles rules and channels, rebuilds
pipeline/scanners/dispatcher, applies DB overrides. Runs in a thread
pool via asyncio.to_thread — must be safe to call off the event loop.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.extensions import ExtensionRegistry

log = logging.getLogger("argus.cli")


def _record_mode_finding(server: Any, old_mode: str, new_mode: str) -> None:
    """Emit a framework finding when proxy mode transitions to passthrough.

    Routes through `pipeline.emit_findings` so the finding lands in
    analytics, dispatcher (rate-limited per origin), SSE event stream,
    and post_scan_hook — same fan-out as a real scan finding. Direct
    `store.record_findings` here would silence the dispatcher and SSE,
    which is the exact gap A1+ closes for issue #81.
    """
    if not server or not getattr(server, "pipeline", None):
        return
    try:
        from lumen_argus.models import Finding, FindingOrigin, ScanResult

        finding = Finding(
            detector="proxy",
            type="mode_changed",
            severity="warning",
            location="proxy.mode",
            value_preview="%s -> %s" % (old_mode, new_mode),
            matched_value="",
            action="log",
            origin=FindingOrigin.FRAMEWORK,
        )
        server.pipeline.emit_findings(
            ScanResult(action="pass", findings=[finding]),
            provider="",
            model="",
            session=None,
            body=b"",
        )
    except Exception:
        log.warning("failed to emit mode change finding", exc_info=True)


def do_reload(
    server: Any,
    config_path: str | None,
    file_handler: logging.Handler,
    console_level: int,
    root_logger: logging.Logger,
    extensions: ExtensionRegistry,
    current_config: list[Any],
) -> None:
    """Reload config from disk — runs in main thread, safe for locks."""
    try:
        from lumen_argus.config import load_config
        from lumen_argus.config_loader import apply_config_overrides, reconcile_yaml_rules
        from lumen_argus.log_utils import config_diff
        from lumen_argus.scanner import _build_allowlist

        new_config = load_config(config_path=config_path)

        # Reconcile YAML custom rules to DB BEFORE pipeline reload
        # so RulesDetector.reload() sees the updated rules
        analytics_store = extensions.get_analytics_store()

        new_allowlist = _build_allowlist(new_config, store=analytics_store, extensions=extensions)
        if analytics_store:
            reconcile_yaml_rules(analytics_store, new_config)

        new_overrides: dict[str, str] = {}
        if new_config.secrets.action:
            new_overrides["secrets"] = new_config.secrets.action
        if new_config.pii.action:
            new_overrides["pii"] = new_config.pii.action
        if new_config.proprietary.action:
            new_overrides["proprietary"] = new_config.proprietary.action

        # Apply DB config overrides on top of YAML (dashboard-saved settings)
        if analytics_store:
            apply_config_overrides(new_config, analytics_store, new_overrides)
            # proxy.mode is reload-only (requires server reference)
            _apply_mode_override(server, analytics_store)

        # Diff after DB overrides so phantom changes don't appear
        old = current_config[0]
        changes = config_diff(old, new_config)
        if changes:
            log.info("config reloaded: %s", "; ".join(changes))
        else:
            log.debug("config reloaded (no YAML changes, DB overrides applied)")
        current_config[0] = new_config

        from lumen_argus.startup import build_pipeline_config

        server.pipeline.reload(
            allowlist=new_allowlist,
            default_action=new_config.default_action,
            action_overrides=new_overrides,
            custom_rules=new_config.custom_rules,
            pipeline_config=build_pipeline_config(new_config),
        )
        server.timeout = new_config.proxy.timeout
        server.connect_timeout = new_config.proxy.connect_timeout
        server.retries = new_config.proxy.retries

        # Hot-reload max_body_size
        if old.proxy.max_body_size != new_config.proxy.max_body_size:
            server.max_body_size = new_config.proxy.max_body_size
            if server._app is not None:
                server._app._client_max_size = new_config.proxy.max_body_size + 1024
            log.info(
                "proxy.max_body_size changed (%d -> %d)",
                old.proxy.max_body_size,
                new_config.proxy.max_body_size,
            )

        # Hot-reload port/bind via async rebind on the event loop
        _reload_port_bind(server, old, new_config)

        # Apply parallel batching toggle on reload
        if server.pipeline._rules_detector:
            server.pipeline._rules_detector.set_parallel(new_config.pipeline.parallel_batching)

        # Rebuild response scanner on reload
        _reload_response_scanner(server, new_config, analytics_store)

        # Rebuild MCP scanner for proxy on reload
        _reload_mcp_scanner(server, new_config, analytics_store)

        # Rebuild WebSocket scanner on reload
        _reload_ws_scanner(server, new_config)

        # Warnings for restart-required changes
        if old.proxy.max_connections != new_config.proxy.max_connections:
            log.warning(
                "proxy.max_connections changed (%d -> %d) — requires restart to take effect",
                old.proxy.max_connections,
                new_config.proxy.max_connections,
            )
        if old.proxy.drain_timeout != new_config.proxy.drain_timeout:
            log.warning(
                "proxy.drain_timeout changed (%d -> %d) — takes effect on next shutdown",
                old.proxy.drain_timeout,
                new_config.proxy.drain_timeout,
            )
        if old.proxy.ca_bundle != new_config.proxy.ca_bundle or old.proxy.verify_ssl != new_config.proxy.verify_ssl:
            log.warning("proxy.ca_bundle or proxy.verify_ssl changed — requires restart to take effect")

        # Hot-reload file log level
        new_file_level = getattr(logging, new_config.logging_config.file_level.upper())
        if file_handler.level != new_file_level:
            log.info(
                "file log level: %s -> %s",
                logging.getLevelName(file_handler.level).lower(),
                new_config.logging_config.file_level,
            )
            file_handler.setLevel(new_file_level)
            root_logger.setLevel(min(console_level, new_file_level))

        # Run Pro reload hook first — it may update channel limit, dispatcher, etc.
        reload_hook = extensions.get_config_reload_hook()
        if reload_hook:
            try:
                reload_hook(server.pipeline)
            except Exception:
                log.warning("SIGHUP: config reload hook failed", exc_info=True)

        # Re-reconcile YAML notification channels (after Pro hook updates limit)
        _reload_channels(analytics_store, extensions, new_config)

        # Single summary line for the entire reload
        stages = []
        for s in (
            "outbound_dlp",
            "encoding_decode",
            "response_secrets",
            "response_injection",
            "mcp_arguments",
            "mcp_responses",
            "websocket_outbound",
            "websocket_inbound",
        ):
            cfg = getattr(new_config.pipeline, s, None)
            if cfg and cfg.enabled:
                stages.append(s)
        rd = server.pipeline._rules_detector
        rule_count = rd.rule_count if rd and hasattr(rd, "rule_count") else 0
        log.info("reload complete: %d rules, stages=[%s]", rule_count, ", ".join(stages) or "none")
    except Exception:
        log.error("config reload failed", exc_info=True)


# ---------------------------------------------------------------------------
# Reload sub-steps
# ---------------------------------------------------------------------------


def _apply_mode_override(server: Any, store: Any) -> None:
    """Handle proxy.mode override (reload-only, requires server reference)."""
    try:
        db_overrides = store.get_config_overrides()
    except Exception:
        return
    value = db_overrides.get("proxy.mode", "")
    if value in ("active", "passthrough") and value != server.mode:
        old_mode = server.mode
        server.mode = value
        log.info("proxy mode changed: %s -> %s", old_mode, value)
        if value == "passthrough":
            _record_mode_finding(server, old_mode, value)


def _reload_port_bind(server: Any, old: Any, new_config: Any) -> None:
    """Hot-reload port/bind via async rebind on the event loop."""
    port_changed = old.proxy.port != new_config.proxy.port
    bind_changed = old.proxy.bind != new_config.proxy.bind
    if not (port_changed or bind_changed):
        return
    loop = getattr(server, "_loop", None)
    if loop is None or loop.is_closed():
        log.warning("proxy.port/bind changed but event loop not available — requires restart")
        return
    import asyncio

    future = asyncio.run_coroutine_threadsafe(
        server.rebind(
            new_port=new_config.proxy.port if port_changed else None,
            new_bind=new_config.proxy.bind if bind_changed else None,
        ),
        loop,
    )
    try:
        future.result(timeout=10)
    except Exception:
        log.error("proxy rebind failed", exc_info=True)


def _reload_response_scanner(server: Any, config: Any, store: Any) -> None:
    """Rebuild response scanner on reload."""
    resp_secrets = config.pipeline.response_secrets.enabled
    resp_injection = config.pipeline.response_injection.enabled
    if not (resp_secrets or resp_injection):
        server.response_scanner = None
        return
    from lumen_argus.response_scanner import ResponseScanner

    server.response_scanner = ResponseScanner(
        detectors=server.pipeline._detectors if resp_secrets else [],
        allowlist=server.pipeline._allowlist if resp_secrets else None,
        store=store,
        scan_secrets=resp_secrets,
        scan_injection=resp_injection,
        max_response_size=config.pipeline.response_max_size,
    )
    log.debug("response scanning reloaded: secrets=%s injection=%s", resp_secrets, resp_injection)


def _reload_mcp_scanner(server: Any, config: Any, store: Any) -> None:
    """Rebuild MCP scanner for proxy on reload."""
    mcp_args_enabled = config.pipeline.mcp_arguments.enabled
    mcp_resp_enabled = config.pipeline.mcp_responses.enabled
    if not (mcp_args_enabled or mcp_resp_enabled):
        server.mcp_scanner = None
        return
    from lumen_argus.mcp.scanner import MCPScanner
    from lumen_argus.startup import load_mcp_tool_lists

    allowed_tools, blocked_tools = load_mcp_tool_lists(config, store)
    server.mcp_scanner = MCPScanner(
        detectors=server.pipeline._detectors,
        allowlist=server.pipeline._allowlist,
        response_scanner=server.response_scanner,
        scan_arguments=mcp_args_enabled,
        scan_responses=mcp_resp_enabled,
        allowed_tools=allowed_tools or None,
        blocked_tools=blocked_tools or None,
        action=config.pipeline.mcp_arguments.action or config.default_action,
    )
    log.debug("MCP proxy scanning reloaded")


def _reload_ws_scanner(server: Any, config: Any) -> None:
    """Rebuild WebSocket scanner on reload."""
    from lumen_argus.ws_proxy import WebSocketScanner

    ws_outbound = config.pipeline.websocket_outbound.enabled
    ws_inbound = config.pipeline.websocket_inbound.enabled
    if not (ws_outbound or ws_inbound):
        server.ws_scanner = None
        server.ws_allowed_origins = []
        log.debug("ws scanning disabled via config")
        return
    server.ws_scanner = WebSocketScanner(
        detectors=server.pipeline._detectors,
        allowlist=server.pipeline._allowlist,
        response_scanner=server.response_scanner,
        scan_outbound=ws_outbound,
        scan_inbound=ws_inbound,
        max_frame_size=config.websocket.max_frame_size,
    )
    server.ws_allowed_origins = config.websocket.allowed_origins or []
    log.debug("ws scanner reloaded: outbound=%s inbound=%s", ws_outbound, ws_inbound)


def _reload_channels(store: Any, extensions: Any, config: Any) -> None:
    """Re-reconcile YAML notification channels."""
    if not store:
        store = extensions.get_analytics_store()
    if not store:
        return
    limit = extensions.get_channel_limit()
    result = store.reconcile_yaml_channels(config.notifications, channel_limit=limit)
    for action_name in ("created", "updated", "deleted"):
        if result[action_name]:
            log.info("notification channels %s from config: %s", action_name, ", ".join(result[action_name]))
    dispatcher = extensions.get_dispatcher()
    if dispatcher and hasattr(dispatcher, "rebuild"):
        try:
            dispatcher.rebuild()
        except Exception:
            log.warning("dispatcher rebuild failed on SIGHUP", exc_info=True)
