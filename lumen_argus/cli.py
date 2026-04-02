"""CLI entry point: argument parsing, startup, and run loop."""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import signal
import sys
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore

from lumen_argus import __version__
from lumen_argus.audit import AuditLogger
from lumen_argus.config import Config, load_config
from lumen_argus.display import JsonDisplay, TerminalDisplay
from lumen_argus.extensions import ExtensionRegistry
from lumen_argus.log_utils import setup_file_logging
from lumen_argus.pipeline import ScannerPipeline
from lumen_argus.provider import ProviderRouter

log = logging.getLogger("argus.cli")


def _setup_minimal_logging() -> None:
    """Configure minimal stderr logging for non-serve CLI commands."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("  [%(name)s] %(levelname)s: %(message)s"))
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.WARNING)


def _trigger_auto_analysis(
    store: AnalyticsStore | None, extensions: ExtensionRegistry | None, config: Config | None = None
) -> None:
    """Run rule overlap analysis in background if crossfire is available and enabled."""
    if config and not config.rule_analysis.auto_on_import:
        return
    if not store:
        return
    try:
        from lumen_argus.rule_analysis import run_analysis_in_background
    except ImportError:
        return
    run_analysis_in_background(store, extensions, thread_name="rule-analysis-auto", config=config)


def _initialize_analytics(
    config: Config, args: argparse.Namespace, extensions: ExtensionRegistry, action_overrides: dict[str, str]
) -> AnalyticsStore | None:
    """Initialize analytics store, auto-import rules, reconcile YAML, apply DB overrides.

    Returns the AnalyticsStore instance (or None if dashboard is disabled).
    Mutates config and action_overrides with DB overrides.
    """
    if not config.dashboard.enabled:
        return None

    from lumen_argus.analytics.store import AnalyticsStore

    # Load or generate HMAC key for value hashing
    hmac_key = None
    if config.analytics.hash_secrets:
        hmac_key = _load_hmac_key()

    # Create analytics store (or use plugin-provided one)
    analytics_store: AnalyticsStore | None = extensions.get_analytics_store()
    if analytics_store is None and config.analytics.enabled:
        analytics_store = AnalyticsStore(db_path=config.analytics.db_path, hmac_key=hmac_key)
        extensions.set_analytics_store(analytics_store)
        analytics_store.start_cleanup_scheduler(config.analytics.retention_days)
    elif analytics_store is not None and hmac_key:
        # Plugin-provided store (Pro) — inject HMAC key for value hashing
        analytics_store._hmac_key = hmac_key

    # Auto-import community rules on first run if DB has zero rules
    if analytics_store and not args.no_default_rules and config.rules.auto_import:
        if analytics_store.get_rules_count() == 0:
            rules, version, tier = _load_rules_bundle()
            result = analytics_store.import_rules(rules, tier=tier)
            log.info("auto-imported %d community rules v%s", result["created"], version)
            _trigger_auto_analysis(analytics_store, extensions, config=config)

    # Reconcile YAML custom_rules to DB (Kubernetes-style)
    if analytics_store and config.custom_rules:
        yaml_rules = [
            {
                "name": r.name,
                "pattern": r.pattern,
                "severity": r.severity,
                "action": r.action,
                "detector": r.detector,
            }
            for r in config.custom_rules
        ]
        rules_result = analytics_store.reconcile_yaml_rules(yaml_rules)
        for action_name in ("created", "updated", "deleted"):
            if rules_result[action_name]:
                log.info(
                    "custom rules %s: %s",
                    action_name,
                    ", ".join(rules_result[action_name]),
                )

    # Apply DB config overrides on top of YAML (dashboard-saved settings)
    if analytics_store:
        try:
            db_overrides = analytics_store.get_config_overrides()
            for key, value in db_overrides.items():
                if key == "proxy.timeout":
                    config.proxy.timeout = int(value)
                elif key == "proxy.retries":
                    config.proxy.retries = int(value)
                elif key == "default_action":
                    config.default_action = value
                elif key == "detectors.secrets.action":
                    action_overrides["secrets"] = value
                    config.secrets.action = value
                elif key == "detectors.pii.action":
                    action_overrides["pii"] = value
                    config.pii.action = value
                elif key == "detectors.proprietary.action":
                    action_overrides["proprietary"] = value
                    config.proprietary.action = value
                elif key == "detectors.secrets.enabled":
                    config.secrets.enabled = value.lower() == "true"
                elif key == "detectors.pii.enabled":
                    config.pii.enabled = value.lower() == "true"
                elif key == "detectors.proprietary.enabled":
                    config.proprietary.enabled = value.lower() == "true"
                elif key == "pipeline.parallel_batching":
                    config.pipeline.parallel_batching = value.lower() == "true"
                elif key.startswith("pipeline.stages."):
                    parts = key.split(".")
                    stage_name = parts[2]
                    field_name = parts[3] if len(parts) > 3 else ""
                    stage_cfg = getattr(config.pipeline, stage_name, None)
                    if stage_cfg is not None and field_name:
                        if field_name == "enabled" or field_name in ("base64", "hex", "url", "unicode"):
                            setattr(stage_cfg, field_name, value.lower() == "true")
                        elif field_name in ("max_depth", "min_decoded_length", "max_decoded_length"):
                            setattr(stage_cfg, field_name, int(value))
            if db_overrides:
                log.info("applied %d config override(s) from DB", len(db_overrides))
        except Exception:
            log.warning("failed to apply DB config overrides", exc_info=True)

    return analytics_store


def _setup_mcp_scanning(
    config: Config, server: Any, pipeline: ScannerPipeline, analytics_store: AnalyticsStore | None
) -> None:
    """Configure MCP tool argument/response scanning on the HTTP proxy."""
    mcp_args_enabled = config.pipeline.mcp_arguments.enabled
    mcp_resp_enabled = config.pipeline.mcp_responses.enabled
    if not (mcp_args_enabled or mcp_resp_enabled):
        return

    from lumen_argus.mcp.scanner import MCPScanner

    mcp_cfg = getattr(config, "mcp", None)
    allowed_tools = set(mcp_cfg.allowed_tools) if mcp_cfg and mcp_cfg.allowed_tools else set()
    blocked_tools = set(mcp_cfg.blocked_tools) if mcp_cfg and mcp_cfg.blocked_tools else set()

    # Merge DB tool lists
    if analytics_store:
        try:
            db_lists = analytics_store.get_mcp_tool_lists()
            for entry in db_lists.get("allowed", []):
                allowed_tools.add(entry["tool_name"])
            for entry in db_lists.get("blocked", []):
                blocked_tools.add(entry["tool_name"])
        except Exception:
            log.warning("failed to load MCP tool lists from DB", exc_info=True)

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


def _setup_ws_scanning(
    config: Config,
    server: Any,
    pipeline: ScannerPipeline,
    analytics_store: AnalyticsStore | None,
    extensions: ExtensionRegistry,
) -> None:
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
    # Pro can override via extensions.set_ws_connection_hook() to add richer analytics.
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


def _build_pipeline_config(cfg: Any) -> dict[str, Any]:
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


def main(argv: list[str] | None = None) -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="lumen-argus",
        description="AI coding tool DLP proxy — scan outbound requests for secrets, PII, and proprietary data.",
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version="lumen-argus %s" % __version__,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- "serve" command ---
    serve_parser = subparsers.add_parser("serve", help="Run the proxy server")
    serve_parser.add_argument("--port", "-p", type=int, default=None, help="Proxy port (default: 8080)")
    serve_parser.add_argument(
        "--host",
        "-H",
        type=str,
        default=None,
        help="Bind address for proxy and dashboard (default: 127.0.0.1, use 0.0.0.0 for Docker)",
    )
    serve_parser.add_argument("--config", "-c", type=str, default=None, help="Config YAML path")
    serve_parser.add_argument("--log-dir", type=str, default=None, help="Audit log directory")
    serve_parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    serve_parser.add_argument(
        "--format", "-f", type=str, default="text", choices=["text", "json"], dest="output_format", help="Output format"
    )
    serve_parser.add_argument(
        "--log-level",
        type=str,
        default="warning",
        choices=["debug", "info", "warning", "error"],
        help="Logging verbosity",
    )
    serve_parser.add_argument(
        "--no-default-rules",
        action="store_true",
        help="Skip auto-import of community rules on first run",
    )
    serve_parser.add_argument(
        "--dashboard-port",
        type=int,
        default=None,
        help="Dashboard port (default: 8081)",
    )
    serve_parser.add_argument(
        "--no-standalone",
        action="store_true",
        help="Mark as managed by tray app (default: standalone)",
    )
    serve_parser.add_argument(
        "--engine-port",
        type=int,
        default=None,
        help="Enable relay+engine mode: engine binds to this port, relay on --port",
    )
    serve_parser.add_argument(
        "--fail-mode",
        type=str,
        default=None,
        choices=["open", "closed"],
        help="Relay fail mode when engine is down (default: open)",
    )

    # relay subcommand — lightweight forwarder for fault isolation
    relay_parser = subparsers.add_parser("relay", help="Run the relay (lightweight forwarder to engine)")
    relay_parser.add_argument("--port", "-p", type=int, default=None, help="Relay port (default: 8080)")
    relay_parser.add_argument("--host", "-H", type=str, default=None, help="Bind address")
    relay_parser.add_argument("--engine", type=str, default=None, help="Engine URL (default: http://localhost:8090)")
    relay_parser.add_argument(
        "--fail-mode", type=str, default=None, choices=["open", "closed"], help="Fail mode (default: open)"
    )
    relay_parser.add_argument("--config", "-c", type=str, default=None, help="Config YAML path")
    relay_parser.add_argument(
        "--log-level", type=str, default="info", choices=["debug", "info", "warning", "error"], help="Log level"
    )

    # engine subcommand — full inspection pipeline on internal port
    engine_parser = subparsers.add_parser("engine", help="Run the engine (inspection pipeline, internal port)")
    engine_parser.add_argument("--port", "-p", type=int, default=None, help="Engine port (default: 8090)")
    engine_parser.add_argument("--host", "-H", type=str, default=None, help="Bind address")
    engine_parser.add_argument("--config", "-c", type=str, default=None, help="Config YAML path")
    engine_parser.add_argument("--log-dir", type=str, default=None, help="Audit log directory")
    engine_parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    engine_parser.add_argument(
        "--format", "-f", type=str, default="text", choices=["text", "json"], dest="output_format", help="Output format"
    )
    engine_parser.add_argument(
        "--log-level", type=str, default="warning", choices=["debug", "info", "warning", "error"], help="Log level"
    )
    engine_parser.add_argument("--no-default-rules", action="store_true", help="Skip auto-import of community rules")
    engine_parser.add_argument(
        "--dashboard-port",
        type=int,
        default=None,
        help="Dashboard port (default: 8081)",
    )
    engine_parser.add_argument(
        "--no-standalone",
        action="store_true",
        help="Mark as managed by tray app (default: standalone)",
    )

    # --- "scan" command ---
    scan_parser = subparsers.add_parser("scan", help="Scan files or stdin for secrets/PII (pre-commit hook)")
    scan_parser.add_argument("files", nargs="*", help="Files to scan (reads stdin if none)")
    scan_parser.add_argument(
        "--diff",
        nargs="?",
        const="",
        default=None,
        metavar="REF",
        help="Scan git diff only (staged changes by default, or diff against REF)",
    )
    scan_parser.add_argument(
        "--baseline", type=str, default=None, metavar="FILE", help="Ignore findings in baseline file"
    )
    scan_parser.add_argument(
        "--create-baseline", type=str, default=None, metavar="FILE", help="Save current findings as baseline"
    )
    scan_parser.add_argument("--config", "-c", type=str, default=None, help="Config YAML path")
    scan_parser.add_argument(
        "--format", "-f", type=str, default="text", choices=["text", "json"], dest="output_format", help="Output format"
    )

    # --- "logs" command ---
    logs_parser = subparsers.add_parser("logs", help="Log file utilities")
    logs_sub = logs_parser.add_subparsers(dest="logs_command", required=True)
    export_parser = logs_sub.add_parser("export", help="Export log file for support sharing")
    export_parser.add_argument("--sanitize", action="store_true", help="Strip IPs, hostnames, and file paths")
    export_parser.add_argument("--config", "-c", type=str, default=None, help="Config YAML path")

    # --- "rules" command ---
    rules_parser = subparsers.add_parser("rules", help="Manage detection rules")
    rules_sub = rules_parser.add_subparsers(dest="rules_command", required=True)
    import_parser = rules_sub.add_parser("import", help="Import rules from bundled JSON into DB")
    import_parser.add_argument("--pro", action="store_true", help="Import Pro rules (requires license)")
    import_parser.add_argument("--file", type=str, default=None, help="Import from custom JSON file")
    import_parser.add_argument("--force", action="store_true", help="Reset action/enabled to defaults")
    import_parser.add_argument("--dry-run", action="store_true", help="Show what would be imported")
    import_parser.add_argument("--config", "-c", type=str, default=None, help="Config YAML path")
    export_rules_parser = rules_sub.add_parser("export", help="Export rules as JSON")
    export_rules_parser.add_argument("--tier", type=str, default=None, help="Filter by tier")
    export_rules_parser.add_argument("--detector", type=str, default=None, help="Filter by detector")
    export_rules_parser.add_argument("--config", "-c", type=str, default=None, help="Config YAML path")
    list_parser = rules_sub.add_parser("list", help="List loaded rules")
    list_parser.add_argument("--tier", type=str, default=None, help="Filter by tier")
    list_parser.add_argument("--detector", type=str, default=None, help="Filter by detector")
    list_parser.add_argument("--config", "-c", type=str, default=None, help="Config YAML path")
    validate_parser = rules_sub.add_parser("validate", help="Validate rules JSON file")
    validate_parser.add_argument("--file", type=str, required=True, help="JSON file to validate")

    # clients subcommand — list supported AI CLI agents
    clients_parser = subparsers.add_parser("clients", help="List supported AI CLI agents")
    clients_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # detect subcommand — scan for installed AI CLI agents
    detect_parser = subparsers.add_parser("detect", help="Detect installed AI CLI agents")
    detect_parser.add_argument("--versions", action="store_true", help="Detect versions (slower, runs subprocesses)")
    detect_parser.add_argument("--json", action="store_true", help="Output as JSON")
    detect_parser.add_argument("--audit", action="store_true", help="Audit proxy configuration compliance")
    detect_parser.add_argument(
        "--check-quiet",
        action="store_true",
        help="Shell hook mode: print warning if unconfigured tools found, exit silently otherwise",
    )
    detect_parser.add_argument("--proxy-url", type=str, default="http://localhost:8080", help="Expected proxy URL")

    # setup subcommand — configure tools to use proxy
    setup_parser = subparsers.add_parser("setup", help="Configure AI tools to route through proxy")
    setup_parser.add_argument("client", nargs="?", default="", help="Configure specific client (e.g., 'aider')")
    setup_parser.add_argument("--proxy-url", type=str, default="http://localhost:8080", help="Proxy URL to configure")
    setup_parser.add_argument("--undo", action="store_true", help="Remove all proxy configuration")
    setup_parser.add_argument("--dry-run", action="store_true", help="Show changes without applying")
    setup_parser.add_argument("--non-interactive", action="store_true", help="Auto-configure without prompting")

    # protection subcommand — toggle proxy routing for tray app integration
    protection_parser = subparsers.add_parser("protection", help="Toggle proxy routing (enable/disable/status)")
    protection_parser.add_argument(
        "action", choices=["enable", "disable", "status"], help="Enable, disable, or check protection status"
    )
    protection_parser.add_argument(
        "--proxy-url", type=str, default="http://localhost:8080", help="Proxy URL (for enable)"
    )

    # watch subcommand — background daemon for new tool detection
    watch_parser = subparsers.add_parser("watch", help="Background daemon to detect and configure new AI tools")
    watch_parser.add_argument("--proxy-url", type=str, default="http://localhost:8080", help="Proxy URL to configure")
    watch_parser.add_argument("--interval", type=int, default=300, help="Scan interval in seconds (default: 300)")
    watch_parser.add_argument(
        "--auto-configure", action="store_true", help="Auto-configure new tools without prompting"
    )
    watch_parser.add_argument("--install", action="store_true", help="Install as system service (launchd/systemd)")
    watch_parser.add_argument("--uninstall", action="store_true", help="Remove system service")
    watch_parser.add_argument("--status", action="store_true", help="Show watch daemon status")

    # mcp subcommand — unified MCP proxy with multiple transport modes
    mcp_parser = subparsers.add_parser(
        "mcp",
        help="MCP scanning proxy (stdio, HTTP, WebSocket transport modes)",
    )
    mcp_parser.add_argument("--config", type=str, default=None, help="Config file path")
    mcp_parser.add_argument(
        "--log-level",
        type=str,
        default="warning",
        choices=["debug", "info", "warning", "error"],
        help="Log level (default: warning)",
    )
    mcp_parser.add_argument(
        "--upstream",
        type=str,
        default=None,
        help="Upstream MCP server URL (http://, https://, ws://, wss://)",
    )
    mcp_parser.add_argument(
        "--listen",
        type=str,
        default=None,
        help="Listen address for HTTP reverse proxy mode (HOST:PORT)",
    )
    mcp_parser.add_argument(
        "--action",
        type=str,
        default=None,
        choices=["block", "alert", "log"],
        help="Override default action for findings",
    )
    mcp_parser.add_argument(
        "--env",
        type=str,
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Pass additional env var to subprocess (repeatable)",
    )
    mcp_parser.add_argument(
        "--no-env-filter",
        action="store_true",
        default=False,
        help="Disable environment variable restriction for subprocess mode",
    )
    mcp_parser.add_argument(
        "server_command",
        nargs=argparse.REMAINDER,
        help="MCP server command (after --)",
    )

    # Register plugin CLI commands (Pro adds "enroll", "enrollment", etc.)
    extensions = ExtensionRegistry()
    extensions.load_plugins()
    plugin_commands = {}  # name -> handler
    for cmd in extensions.get_extra_cli_commands():
        try:
            sub = subparsers.add_parser(cmd.name, help=cmd.help)
            for arg in cmd.arguments:
                sub.add_argument(*arg["args"], **arg["kwargs"])
            plugin_commands[cmd.name] = cmd.handler
        except (KeyError, TypeError) as exc:
            log.error("skipping malformed plugin command %r: %s", cmd.name, exc)

    args = parser.parse_args(argv)

    if args.command in plugin_commands:
        _setup_minimal_logging()
        try:
            plugin_commands[args.command](args)
        except Exception:
            log.error("plugin command %r failed", args.command, exc_info=True)
            sys.exit(1)
        return

    if args.command in ("scan", "logs", "rules", "mcp", "clients", "detect", "setup", "watch", "protection", "relay"):
        _setup_minimal_logging()
        if args.command == "scan":
            _run_scan(args)
        elif args.command == "rules":
            _run_rules(args)
        elif args.command == "mcp":
            _run_mcp(args, extensions=extensions)
        elif args.command == "clients":
            _run_clients(args)
        elif args.command == "detect":
            _run_detect(args)
        elif args.command == "setup":
            _run_setup(args)
        elif args.command == "watch":
            _run_watch(args)
        elif args.command == "protection":
            _run_protection(args)
        elif args.command == "relay":
            _run_relay(args)
        elif args.command == "engine":
            # Engine = full proxy on engine port — fall through to serve path below
            config = load_config(config_path=args.config)
            if not args.port:
                args.port = config.engine.port
            # Set serve-only attributes that engine parser doesn't have
            if not hasattr(args, "engine_port"):
                args.engine_port = None
            if not hasattr(args, "fail_mode"):
                args.fail_mode = None
        else:
            _run_logs(args)
            return
        if args.command not in ("serve", "engine"):
            return

    # command == "serve" or "engine"

    # Configure logging — explicit handler setup instead of basicConfig()
    # to avoid silent no-op if any import triggered basicConfig earlier.
    console_level = getattr(logging, args.log_level.upper())
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(
        logging.Formatter(
            "  %(asctime)s [%(name)s] %(levelname)s: %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    console_handler.setLevel(console_level)
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(console_handler)

    # Load config
    config = load_config(config_path=args.config)

    # Set up file logging with rotation
    file_handler, log_file_path, file_level = setup_file_logging(config.logging_config)
    root_logger.addHandler(file_handler)

    # Root logger level = most verbose of console and file
    root_logger.setLevel(min(console_level, file_level))

    # CLI args override config
    port = args.port or config.proxy.port
    bind = args.host or config.proxy.bind
    audit_log_dir = args.log_dir or config.audit.log_dir

    # Combined relay+engine mode: engine binds to --engine-port, relay on --port
    engine_port = getattr(args, "engine_port", None)
    relay_fail_mode = getattr(args, "fail_mode", None) or config.relay.fail_mode
    if engine_port:
        relay_port = port  # user-facing port goes to relay
        port = engine_port  # engine binds to engine-port

    # Startup summary — always at INFO regardless of console level
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
    action_overrides = {}
    if config.secrets.action:
        action_overrides["secrets"] = config.secrets.action
    if config.pii.action:
        action_overrides["pii"] = config.pii.action
    if config.proprietary.action:
        action_overrides["proprietary"] = config.proprietary.action

    # Construct components
    display: JsonDisplay | TerminalDisplay
    if args.output_format == "json":
        display = JsonDisplay()
    else:
        display = TerminalDisplay(no_color=args.no_color)
    audit = AuditLogger(log_dir=audit_log_dir, retention_days=config.audit.retention_days)
    # Reuse the registry created before parse_args (plugins already loaded)

    # Register community notification defaults — Pro registers its own
    # hooks during load_plugins(), so community only sets defaults when
    # Pro is absent (first-write-wins: Pro loads first, community defers).
    from lumen_argus.notifiers import WEBHOOK_CHANNEL_TYPE, build_notifier

    if not extensions.get_notifier_builder():
        extensions.set_notifier_builder(build_notifier)
    if not extensions.get_channel_types():
        extensions.register_channel_types(WEBHOOK_CHANNEL_TYPE)

    for pname, pver in extensions.loaded_plugins():
        log.info("plugin: %s v%s", pname, pver)
    log.info("audit log: %s", os.path.expanduser(audit_log_dir))
    log.info("app log: %s (%s level)", log_file_path, config.logging_config.file_level)
    from dataclasses import asdict

    router = ProviderRouter(upstreams=config.upstreams or None)

    # Build SSL context for upstream connections
    from lumen_argus.async_proxy import build_ssl_context

    ssl_context = build_ssl_context(
        ca_bundle=config.proxy.ca_bundle,
        verify_ssl=config.proxy.verify_ssl,
    )

    # --- Analytics store and rules (must happen before pipeline creation) ---
    analytics_store = _initialize_analytics(config, args, extensions, action_overrides)

    # --- Allowlist (YAML config + DB entries) ---
    from lumen_argus.scanner import _build_allowlist

    allowlist = _build_allowlist(config, store=analytics_store, extensions=extensions)

    # --- Pipeline (created after store + rules so RulesDetector sees imported rules) ---
    pipeline = ScannerPipeline(
        default_action=config.default_action,
        action_overrides=action_overrides,
        allowlist=allowlist,
        entropy_threshold=config.entropy_threshold,
        extensions=extensions,
        custom_rules=config.custom_rules,
        dedup_config=asdict(config.dedup),
        pipeline_config=_build_pipeline_config(config),
        rebuild_delay=config.rules.rebuild_delay_seconds,
    )

    # Apply parallel batching toggle to RulesDetector
    # (applied out-of-band from _build_pipeline_config — parallel_batching
    # is a detector-level setting, not a pipeline stage config)
    if pipeline._rules_detector:
        pipeline._rules_detector.set_parallel(config.pipeline.parallel_batching)

    # --- Build response scanner ---
    response_scanner = None
    resp_secrets = config.pipeline.response_secrets.enabled
    resp_injection = config.pipeline.response_injection.enabled
    if resp_secrets or resp_injection:
        from lumen_argus.response_scanner import ResponseScanner

        response_scanner = ResponseScanner(
            detectors=pipeline._detectors if resp_secrets else [],
            allowlist=pipeline._allowlist if resp_secrets else None,
            store=analytics_store,
            scan_secrets=resp_secrets,
            scan_injection=resp_injection,
            max_response_size=config.pipeline.response_max_size,
        )
        log.info("response scanning enabled: secrets=%s injection=%s", resp_secrets, resp_injection)

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
    except OSError as e:
        print("Error: Could not bind to %s:%d — %s" % (bind, port, e), file=sys.stderr)
        sys.exit(1)

    display.show_banner(port, bind)
    log.info("listening on http://%s:%d", bind, port)
    start_time = time.monotonic()

    # --- Dashboard ---
    dashboard_server = None
    sse_broadcaster = None
    if config.dashboard.enabled:
        from lumen_argus.dashboard.audit_reader import AuditReader
        from lumen_argus.dashboard.server import AsyncDashboardServer
        from lumen_argus.dashboard.sse import SSEBroadcaster

        # Create SSE broadcaster and register with extensions so Pro can use it
        sse_broadcaster = SSEBroadcaster()
        extensions.set_sse_broadcaster(sse_broadcaster)

        # Create audit reader (use CLI-overridden log dir, same as AuditLogger)
        audit_reader = AuditReader(log_dir=audit_log_dir)

        # Dashboard password from config or env
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

    # --- MCP-aware scanning in HTTP proxy ---
    _setup_mcp_scanning(config, server, pipeline, analytics_store)

    # --- WebSocket scanning (same port, handled by async proxy) ---
    _setup_ws_scanning(config, server, pipeline, analytics_store, extensions)

    # Track current config for diff on reload
    current_config = [config]

    # Mark engine as ready — pipeline and scanners are fully initialized
    server.ready = True
    log.debug("engine ready: pipeline loaded, scanners initialized")

    # --- Async run loop ---
    import asyncio

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
            max_connections=config.proxy.max_connections,
        )
        log.info("combined mode: relay :%d → engine :%d (fail_mode=%s)", relay_port, port, relay_fail_mode)

    async def _run_async() -> None:
        await server.start()
        if relay_instance:
            await relay_instance.start()
        if sse_broadcaster:
            await sse_broadcaster.start()
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
            # Run reload in thread pool to avoid blocking event loop
            # with file I/O (YAML load) and SQLite reads (config overrides).
            task = asyncio.ensure_future(
                asyncio.to_thread(
                    _do_reload,
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

        # Wait for shutdown signal
        await shutdown_event.wait()

        # Graceful drain — wait for in-flight requests to finish
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


def _load_hmac_key() -> bytes:
    """Load or generate the HMAC key for value hashing.

    Stored at ~/.lumen-argus/hmac.key with 0o600 permissions.
    Auto-generated (32 bytes) on first run. If deleted, a new key is
    generated and old hashes become unmatchable (graceful degradation).
    HMAC-SHA-256 accepts any key length — no truncation applied.
    """
    key_path = os.path.expanduser("~/.lumen-argus/hmac.key")
    try:
        with open(key_path, "rb") as f:
            key = f.read()
        if len(key) >= 32:
            return key
    except FileNotFoundError:
        log.debug("HMAC key not found at %s, generating new key", key_path)
    # Generate new key — use exclusive create to avoid race conditions
    key = os.urandom(32)
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    try:
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, key)
        os.close(fd)
    except FileExistsError:
        # Another process created it first — read theirs
        with open(key_path, "rb") as f:
            key = f.read()
    return key


def _record_mode_finding(store: Any, old_mode: str, new_mode: str) -> None:
    """Record a finding when proxy mode transitions to passthrough."""
    if not store:
        return
    try:
        from lumen_argus.models import Finding

        finding = Finding(
            detector="proxy",
            type="mode_changed",
            severity="warning",
            location="proxy.mode",
            value_preview="%s -> %s" % (old_mode, new_mode),
            matched_value="",
            action="log",
        )
        store.record_findings([finding], provider="", model="")
    except Exception:
        log.warning("failed to record mode change finding", exc_info=True)


def _do_reload(
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
        from lumen_argus.log_utils import config_diff

        new_config = load_config(config_path=config_path)

        # Reconcile YAML custom rules to DB BEFORE pipeline reload
        # so RulesDetector.reload() sees the updated rules
        analytics_store: AnalyticsStore | None = extensions.get_analytics_store()
        from lumen_argus.scanner import _build_allowlist

        new_allowlist = _build_allowlist(new_config, store=analytics_store, extensions=extensions)
        if analytics_store and new_config.custom_rules:
            yaml_rules = [
                {
                    "name": r.name,
                    "pattern": r.pattern,
                    "severity": r.severity,
                    "action": r.action,
                    "detector": r.detector,
                }
                for r in new_config.custom_rules
            ]
            rules_result = analytics_store.reconcile_yaml_rules(yaml_rules)
            for action_name in ("created", "updated", "deleted"):
                if rules_result[action_name]:
                    log.info("custom rules %s: %s", action_name, ", ".join(rules_result[action_name]))

        new_overrides = {}
        if new_config.secrets.action:
            new_overrides["secrets"] = new_config.secrets.action
        if new_config.pii.action:
            new_overrides["pii"] = new_config.pii.action
        if new_config.proprietary.action:
            new_overrides["proprietary"] = new_config.proprietary.action

        # Apply DB config overrides on top of YAML (dashboard-saved settings)
        if analytics_store:
            try:
                db_overrides = analytics_store.get_config_overrides()
                for key, value in db_overrides.items():
                    if key == "proxy.timeout":
                        new_config.proxy.timeout = int(value)
                    elif key == "proxy.retries":
                        new_config.proxy.retries = int(value)
                    elif key == "default_action":
                        new_config.default_action = value
                    elif key == "detectors.secrets.action":
                        new_overrides["secrets"] = value
                        new_config.secrets.action = value
                    elif key == "detectors.pii.action":
                        new_overrides["pii"] = value
                        new_config.pii.action = value
                    elif key == "detectors.proprietary.action":
                        new_overrides["proprietary"] = value
                        new_config.proprietary.action = value
                    elif key == "detectors.secrets.enabled":
                        new_config.secrets.enabled = value.lower() == "true"
                    elif key == "detectors.pii.enabled":
                        new_config.pii.enabled = value.lower() == "true"
                    elif key == "detectors.proprietary.enabled":
                        new_config.proprietary.enabled = value.lower() == "true"
                    elif key == "proxy.mode":
                        # TODO: gate mode changes on auth/RBAC when available
                        if value in ("active", "passthrough"):
                            old_mode = server.mode
                            server.mode = value
                            if old_mode != value:
                                log.info("proxy mode changed: %s -> %s", old_mode, value)
                                # Record audit finding so the transition is visible
                                # in the dashboard findings list, not just logs
                                if value == "passthrough":
                                    _record_mode_finding(analytics_store, old_mode, value)
                    elif key == "pipeline.parallel_batching":
                        new_config.pipeline.parallel_batching = value.lower() == "true"
                    elif key.startswith("pipeline.stages."):
                        parts = key.split(".")
                        stage_name = parts[2]
                        field_name = parts[3] if len(parts) > 3 else ""
                        stage_cfg = getattr(new_config.pipeline, stage_name, None)
                        if stage_cfg is not None and field_name:
                            if field_name == "enabled" or field_name in ("base64", "hex", "url", "unicode"):
                                setattr(stage_cfg, field_name, value.lower() == "true")
                            elif field_name in ("max_depth", "min_decoded_length", "max_decoded_length"):
                                setattr(stage_cfg, field_name, int(value))
                if db_overrides:
                    log.debug("applied %d config override(s) from DB", len(db_overrides))
            except Exception:
                log.debug("no config overrides from DB")

        # Diff after DB overrides so phantom changes don't appear
        old = current_config[0]
        changes = config_diff(old, new_config)
        if changes:
            log.info("config reloaded: %s", "; ".join(changes))
        else:
            log.debug("config reloaded (no YAML changes, DB overrides applied)")
        current_config[0] = new_config

        server.pipeline.reload(
            allowlist=new_allowlist,
            default_action=new_config.default_action,
            action_overrides=new_overrides,
            custom_rules=new_config.custom_rules,
            pipeline_config=_build_pipeline_config(new_config),
        )
        server.timeout = new_config.proxy.timeout
        server.retries = new_config.proxy.retries

        # Hot-reload max_body_size — used for scan decisions and aiohttp rejection limit
        if old.proxy.max_body_size != new_config.proxy.max_body_size:
            server.max_body_size = new_config.proxy.max_body_size
            if server._app is not None:
                # Private aiohttp attr — the real enforcement is server.max_body_size
                # in _handle_request(); this just updates aiohttp's safety net.
                server._app._client_max_size = new_config.proxy.max_body_size + 1024
            log.info(
                "proxy.max_body_size changed (%d -> %d)",
                old.proxy.max_body_size,
                new_config.proxy.max_body_size,
            )

        # Hot-reload port/bind via async rebind on the event loop
        port_changed = old.proxy.port != new_config.proxy.port
        bind_changed = old.proxy.bind != new_config.proxy.bind
        if port_changed or bind_changed:
            loop = getattr(server, "_loop", None)
            if loop is not None and not loop.is_closed():
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
                except OSError as e:
                    log.error("proxy rebind failed: %s", e)
                except Exception:
                    log.error("proxy rebind failed", exc_info=True)
            else:
                log.warning("proxy.port/bind changed but event loop not available — requires restart")

        # Apply parallel batching toggle on reload.
        if server.pipeline._rules_detector:
            server.pipeline._rules_detector.set_parallel(new_config.pipeline.parallel_batching)

        # Rebuild response scanner on reload
        resp_secrets = new_config.pipeline.response_secrets.enabled
        resp_injection = new_config.pipeline.response_injection.enabled
        if resp_secrets or resp_injection:
            from lumen_argus.response_scanner import ResponseScanner

            analytics_store = extensions.get_analytics_store() if extensions else None
            server.response_scanner = ResponseScanner(
                detectors=server.pipeline._detectors if resp_secrets else [],
                allowlist=server.pipeline._allowlist if resp_secrets else None,
                store=analytics_store,
                scan_secrets=resp_secrets,
                scan_injection=resp_injection,
                max_response_size=new_config.pipeline.response_max_size,
            )
            log.debug("response scanning reloaded: secrets=%s injection=%s", resp_secrets, resp_injection)
        else:
            server.response_scanner = None

        # Rebuild MCP scanner for proxy on reload
        mcp_args_enabled = new_config.pipeline.mcp_arguments.enabled
        mcp_resp_enabled = new_config.pipeline.mcp_responses.enabled
        if mcp_args_enabled or mcp_resp_enabled:
            from lumen_argus.mcp.scanner import MCPScanner as _MCPScanner

            mcp_cfg = getattr(new_config, "mcp", None)
            allowed_tools = set(mcp_cfg.allowed_tools) if mcp_cfg and mcp_cfg.allowed_tools else set()
            blocked_tools = set(mcp_cfg.blocked_tools) if mcp_cfg and mcp_cfg.blocked_tools else set()
            if analytics_store:
                try:
                    db_lists = analytics_store.get_mcp_tool_lists()
                    for entry in db_lists.get("allowed", []):
                        allowed_tools.add(entry["tool_name"])
                    for entry in db_lists.get("blocked", []):
                        blocked_tools.add(entry["tool_name"])
                except Exception:
                    log.warning("SIGHUP: failed to reload MCP tool lists from DB", exc_info=True)
            server.mcp_scanner = _MCPScanner(
                detectors=server.pipeline._detectors,
                allowlist=server.pipeline._allowlist,
                response_scanner=server.response_scanner,
                scan_arguments=mcp_args_enabled,
                scan_responses=mcp_resp_enabled,
                allowed_tools=allowed_tools or None,
                blocked_tools=blocked_tools or None,
                action=new_config.pipeline.mcp_arguments.action or new_config.default_action,
            )
            log.debug("MCP proxy scanning reloaded")
        else:
            server.mcp_scanner = None

        # Rebuild WebSocket scanner on reload (same port — no server restart needed)
        from lumen_argus.ws_proxy import WebSocketScanner

        ws_enabled = new_config.pipeline.websocket_outbound.enabled or new_config.pipeline.websocket_inbound.enabled
        if ws_enabled:
            server.ws_scanner = WebSocketScanner(
                detectors=server.pipeline._detectors,
                allowlist=server.pipeline._allowlist,
                response_scanner=server.response_scanner,
                scan_outbound=new_config.pipeline.websocket_outbound.enabled,
                scan_inbound=new_config.pipeline.websocket_inbound.enabled,
                max_frame_size=new_config.websocket.max_frame_size,
            )
            server.ws_allowed_origins = new_config.websocket.allowed_origins or []
            log.debug(
                "ws scanner reloaded: outbound=%s inbound=%s",
                new_config.pipeline.websocket_outbound.enabled,
                new_config.pipeline.websocket_inbound.enabled,
            )
        else:
            server.ws_scanner = None
            server.ws_allowed_origins = []
            log.debug("ws scanning disabled via config")

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

        # SSL context changes require restart — aiohttp.TCPConnector holds
        # its own SSL state and cannot be hot-reloaded.
        if old.proxy.ca_bundle != new_config.proxy.ca_bundle or old.proxy.verify_ssl != new_config.proxy.verify_ssl:
            log.warning("proxy.ca_bundle or proxy.verify_ssl changed — requires restart to take effect")

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
        if not analytics_store:
            analytics_store = extensions.get_analytics_store()
        if analytics_store:
            limit = extensions.get_channel_limit()
            notif_result = analytics_store.reconcile_yaml_channels(
                new_config.notifications,
                channel_limit=limit,
            )
            for action_name in ("created", "updated", "deleted"):
                if notif_result[action_name]:
                    log.info(
                        "notification channels %s from config: %s", action_name, ", ".join(notif_result[action_name])
                    )
            dispatcher = extensions.get_dispatcher()
            if dispatcher and hasattr(dispatcher, "rebuild"):
                try:
                    dispatcher.rebuild()
                except Exception:
                    log.warning("dispatcher rebuild failed on SIGHUP", exc_info=True)

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
    except Exception as e:
        log.error("config reload failed: %s", e)


def _run_scan(args: argparse.Namespace) -> None:
    """Execute the 'scan' subcommand."""
    from lumen_argus.scanner import scan_diff, scan_files, scan_text

    if args.diff is not None:
        if args.create_baseline:
            print("lumen-argus: --create-baseline not supported with --diff", file=sys.stderr)
        exit_code = scan_diff(
            ref=args.diff or None,
            config_path=args.config,
            output_format=args.output_format,
            baseline_path=args.baseline,
        )
    elif args.files:
        exit_code = scan_files(
            args.files,
            config_path=args.config,
            output_format=args.output_format,
            baseline_path=args.baseline,
            create_baseline_path=args.create_baseline,
        )
    else:
        # Read from stdin — warn if it's a terminal
        if sys.stdin.isatty():
            print("lumen-argus scan: reading from stdin (Ctrl+D to finish, or pass filenames)", file=sys.stderr)
        text = sys.stdin.read()
        exit_code = scan_text(text, config_path=args.config, output_format=args.output_format)

    sys.exit(exit_code)


def _run_logs(args: argparse.Namespace) -> None:
    """Execute the 'logs' subcommand."""
    from lumen_argus.config import load_config as _load_config
    from lumen_argus.log_utils import export_logs

    config = _load_config(config_path=args.config)
    exit_code = export_logs(config, sanitize=args.sanitize)
    sys.exit(exit_code)


def _run_clients(args: argparse.Namespace) -> None:
    """Execute the 'clients' subcommand — list supported AI CLI agents."""
    from lumen_argus_core.clients import get_all_clients

    clients = get_all_clients()

    if args.json:
        print(json.dumps({"clients": clients}, indent=2))
        return

    print("Supported AI CLI agents (%d):\n" % len(clients))
    for c in clients:
        provider = c["provider"]
        if provider == "multi":
            provider = "anthropic/openai"
        pc = c["proxy_config"]
        config_type = pc["config_type"]
        if config_type == "env_var":
            config_info = pc["env_var"]
        elif config_type == "ide_settings":
            config_info = "IDE: %s" % pc["ide_settings_key"]
        elif config_type == "config_file":
            config_info = "File: %s" % pc["config_file_path"]
        elif config_type == "manual":
            config_info = "Manual setup"
        else:
            config_info = "Not supported"
        print("  %-20s %-5s %-18s %s" % (c["display_name"], c["category"], provider, config_info))
    print("\nRun 'lumen-argus detect' to scan for installed tools.")
    print("Run 'lumen-argus setup' to auto-configure detected tools.")


def _run_detect(args: argparse.Namespace) -> None:
    """Execute the 'detect' subcommand — scan for installed AI CLI agents."""
    from lumen_argus_core.detect import detect_installed_clients

    report = detect_installed_clients(
        proxy_url=args.proxy_url,
        include_versions=args.versions,
    )

    if args.check_quiet:
        # Shell hook mode: print warning only if unconfigured tools exist
        unconfigured = [c for c in report.clients if c.installed and not c.proxy_configured]
        if unconfigured:
            names = ", ".join(c.display_name for c in unconfigured)
            # Output a shell-visible warning (stderr so it doesn't interfere with eval)
            sys.stderr.write(
                "\033[33m[lumen-argus]\033[0m %d unconfigured tool(s): %s"
                " — run 'lumen-argus setup'\n" % (len(unconfigured), names)
            )
        return

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return

    if args.audit:
        # Audit mode — focus on compliance
        print("AI Tool Proxy Compliance Audit:\n")
        detected = [c for c in report.clients if c.installed]
        if not detected:
            print("  No AI tools detected on this machine.")
            return
        for c in detected:
            ver = " %s" % c.version if c.version else ""
            if c.proxy_configured:
                print("  [OK]   %-20s%s  Proxied (%s)" % (c.display_name, ver, c.proxy_config_location))
            elif c.proxy_config_type == "unsupported":
                print("  [N/A]  %-20s%s  No reverse proxy support" % (c.display_name, ver))
            else:
                print("  [FAIL] %-20s%s  NOT PROXIED — %s" % (c.display_name, ver, c.setup_instructions))
        print("\nSummary: %d/%d tools routed through proxy" % (report.total_configured, report.total_detected))
        if report.total_configured < report.total_detected:
            print("Action required: run 'lumen-argus setup' to configure uncovered tools.")
        return

    # Standard output
    if report.total_detected == 0:
        print("No AI tools detected on this machine.\n")
        print("Popular tools you can install:")
        print("  Claude Code    pip install claude-code        https://claude.ai/code")
        print("  Aider          pip install aider-chat         https://aider.chat")
        print("  Codex CLI      npm install -g @openai/codex   https://github.com/openai/codex")
        print("  OpenCode       npm install -g opencode        https://opencode.ai")
        return

    print("Detected AI tools (%d):\n" % report.total_detected)
    for c in report.clients:
        if not c.installed:
            continue
        ver = " %s" % c.version if c.version else ""
        status = "proxied" if c.proxy_configured else "not configured"
        marker = "+" if c.proxy_configured else "-"
        method = c.install_method.value if hasattr(c.install_method, "value") else c.install_method
        print("  [%s] %-20s%-12s %-10s %s" % (marker, c.display_name, ver, method, status))

    if report.ci_environment:
        print("\nCI/CD environment: %s" % report.ci_environment.display_name)

    print("\n%d/%d configured for proxy (%s)" % (report.total_configured, report.total_detected, args.proxy_url))
    if report.total_configured < report.total_detected:
        print("Run 'lumen-argus setup' to configure remaining tools.")


def _run_setup(args: argparse.Namespace) -> None:
    """Execute the 'setup' subcommand — configure tools to use proxy."""
    from lumen_argus_core.setup_wizard import run_setup, undo_setup

    if args.undo:
        reverted = undo_setup()
        if reverted:
            print("Reverted %d change(s). Proxy configuration removed." % reverted)
        else:
            print("Nothing to undo.")
        return

    run_setup(
        proxy_url=args.proxy_url,
        client_id=args.client,
        non_interactive=args.non_interactive,
        dry_run=args.dry_run,
    )


def _run_protection(args: argparse.Namespace) -> None:
    """Execute the 'protection' subcommand — toggle proxy routing."""
    from lumen_argus_core.setup_wizard import disable_protection, enable_protection, protection_status

    if args.action == "enable":
        result = enable_protection(proxy_url=args.proxy_url)
        print(json.dumps(result, indent=2))
    elif args.action == "disable":
        result = disable_protection()
        print(json.dumps(result, indent=2))
    elif args.action == "status":
        result = protection_status()
        print(json.dumps(result, indent=2))


def _run_relay(args: argparse.Namespace) -> None:
    """Execute the 'relay' subcommand — lightweight forwarder to engine."""
    import asyncio
    import signal

    from lumen_argus.config import load_config
    from lumen_argus.provider import ProviderRouter
    from lumen_argus.relay import ArgusRelay

    config = load_config(config_path=args.config)
    bind = args.host or "127.0.0.1"
    port = args.port or config.relay.port
    engine_url = args.engine or config.relay.engine_url
    fail_mode = getattr(args, "fail_mode", None) or config.relay.fail_mode
    router = ProviderRouter(upstreams=config.upstreams)

    # Configure logging
    log_level = getattr(logging, args.log_level.upper())
    logging.basicConfig(level=log_level, format="%(levelname)s %(name)s: %(message)s")

    relay = ArgusRelay(
        bind=bind,
        port=port,
        engine_url=engine_url,
        fail_mode=fail_mode,
        router=router,
        health_interval=config.relay.health_check_interval,
        health_timeout=config.relay.health_check_timeout,
        queue_timeout=config.relay.queue_on_startup,
        timeout=config.relay.timeout,
        max_connections=config.proxy.max_connections,
    )

    async def _run() -> None:
        await relay.start()
        loop = asyncio.get_running_loop()
        shutdown = asyncio.Event()
        loop.add_signal_handler(signal.SIGINT, shutdown.set)
        loop.add_signal_handler(signal.SIGTERM, shutdown.set)

        def _reload_relay() -> None:
            # Sync config read in signal handler — acceptable for a single
            # small YAML file on localhost (unlike engine which uses to_thread
            # because it also reads SQLite overrides).
            new_cfg = load_config(config_path=args.config)
            relay.reload(
                fail_mode=new_cfg.relay.fail_mode,
                engine_url=new_cfg.relay.engine_url,
                health_interval=new_cfg.relay.health_check_interval,
                health_timeout=new_cfg.relay.health_check_timeout,
                timeout=new_cfg.relay.timeout,
            )
            log.info("relay config reloaded via SIGHUP")

        if hasattr(signal, "SIGHUP"):
            loop.add_signal_handler(signal.SIGHUP, _reload_relay)

        await shutdown.wait()
        await relay.drain(timeout=5)
        await relay.stop()

    try:
        asyncio.run(_run())
    except OSError as e:
        print("Error: Could not bind relay to %s:%d — %s" % (bind, port, e), file=sys.stderr)
        sys.exit(1)


def _run_watch(args: argparse.Namespace) -> None:
    """Execute the 'watch' subcommand — background daemon for new tool detection."""
    from lumen_argus_core.watch import (
        get_service_status,
        install_service,
        run_watch_loop,
        uninstall_service,
    )

    if args.status:
        status = get_service_status()
        print("Watch daemon status:")
        print("  Platform:    %s" % status["platform"])
        print("  Installed:   %s" % status["installed"])
        if status["service_path"]:
            print("  Service:     %s" % status["service_path"])
        if status["last_scan"]:
            print("  Last scan:   %s" % status["last_scan"])
            print("  Known tools: %s" % status["known_tools"])
        else:
            print("  Last scan:   never")
        return

    if args.uninstall:
        if uninstall_service():
            print("Watch service removed.")
            print("Note: stop the running service manually:")
            if platform.system() == "Darwin":
                print("  launchctl unload ~/Library/LaunchAgents/io.lumen-argus.watch.plist")
            else:
                print("  systemctl --user stop lumen-argus-watch")
        else:
            print("No watch service found to remove.")
        return

    if args.install:
        path = install_service(
            proxy_url=args.proxy_url,
            interval=args.interval,
            auto_configure=args.auto_configure,
        )
        if path:
            print("Watch service installed: %s" % path)
            print("\nTo start the service:")
            if platform.system() == "Darwin":
                print("  launchctl load %s" % path)
            else:
                print("  systemctl --user daemon-reload")
                print("  systemctl --user enable --now lumen-argus-watch")
        else:
            print("Service install not supported on this platform.")
            print("Run 'lumen-argus watch' directly instead.")
        return

    # Run foreground watch loop
    print("Starting watch daemon (interval=%ds, proxy=%s)" % (args.interval, args.proxy_url))
    print("Press Ctrl+C to stop.\n")
    run_watch_loop(
        proxy_url=args.proxy_url,
        interval=args.interval,
        auto_configure=args.auto_configure,
    )


def _load_rules_bundle(path: str | None = None, pro: bool = False) -> tuple[list[Any], str, str]:
    """Load a rules JSON bundle. Returns (rules_list, version, tier)."""
    if path:
        with open(path, encoding="utf-8") as f:
            bundle = json.loads(f.read())
        return bundle.get("rules", []), bundle.get("version", ""), bundle.get("tier", "custom")

    if pro:
        # Pro bundle loaded via entry point
        try:
            from importlib.resources import files as _files

            pro_path = str(_files("lumen_argus_pro.rules").joinpath("pro.json"))
        except (ImportError, ModuleNotFoundError):
            # Fallback for edge cases (frozen apps, etc.)
            import importlib.resources as _resources

            try:
                with _resources.open_text("lumen_argus_pro.rules", "pro.json") as f:
                    bundle = json.loads(f.read())
                return bundle.get("rules", []), bundle.get("version", ""), "pro"
            except (ModuleNotFoundError, FileNotFoundError):
                print("lumen-argus: Pro rules bundle not found. Is lumen-argus-pro installed?", file=sys.stderr)
                sys.exit(1)
        try:
            with open(pro_path, encoding="utf-8") as f:
                bundle = json.loads(f.read())
            return bundle.get("rules", []), bundle.get("version", ""), "pro"
        except FileNotFoundError:
            print("lumen-argus: Pro rules bundle not found. Is lumen-argus-pro installed?", file=sys.stderr)
            sys.exit(1)

    # Community bundle
    bundle_path = os.path.join(os.path.dirname(__file__), "rules", "community.json")
    with open(bundle_path, encoding="utf-8") as f:
        bundle = json.loads(f.read())
    return bundle.get("rules", []), bundle.get("version", ""), "community"


def _run_rules(args: argparse.Namespace) -> None:
    """Execute the 'rules' subcommand."""
    from lumen_argus.analytics.store import AnalyticsStore
    from lumen_argus.config import load_config as _load_config

    config_path = getattr(args, "config", None)
    config = _load_config(config_path=config_path)
    store = AnalyticsStore(db_path=config.analytics.db_path)

    if args.rules_command == "import":
        if args.pro:
            try:
                from lumen_argus_pro.license import get_license  # type: ignore[import-not-found]

                lic = get_license()
                if not lic.is_valid:
                    print(
                        "lumen-argus: Pro license required. Activate with: lumen-argus license activate",
                        file=sys.stderr,
                    )
                    sys.exit(1)
            except ImportError:
                print("lumen-argus: lumen-argus-pro not installed", file=sys.stderr)
                sys.exit(1)
        if args.dry_run:
            rules, version, tier = _load_rules_bundle(path=args.file, pro=args.pro)
            print("lumen-argus: dry run — %d %s rules (v%s)" % (len(rules), tier, version))
            return
        rules, version, tier = _load_rules_bundle(path=args.file, pro=args.pro)
        print("lumen-argus: importing %s rules v%s" % (tier, version))
        result = store.import_rules(rules, tier=tier, force=args.force)
        print(
            "  %d rules imported (%d new, %d updated, %d skipped)"
            % (result["created"] + result["updated"], result["created"], result["updated"], result["skipped"])
        )
        total = store.get_rules_count()
        print("  total: %d rules in DB" % total)
        _trigger_auto_analysis(store, None)

    elif args.rules_command == "export":
        rules = store.export_rules(tier=args.tier, detector=args.detector)
        bundle = {"version": "0.4.0", "tier": args.tier or "all", "rules": rules}
        print(json.dumps(bundle, indent=2, default=str))

    elif args.rules_command == "list":
        rules = store.export_rules(tier=args.tier, detector=args.detector)
        if not rules:
            print("lumen-argus: no rules found. Run 'lumen-argus rules import' first.")
            return
        print("\n  %-30s %-10s %-10s %-8s %-12s %s" % ("NAME", "DETECTOR", "SEVERITY", "ACTION", "TIER", "ENABLED"))
        print("  " + "-" * 90)
        for r in rules:
            print(
                "  %-30s %-10s %-10s %-8s %-12s %s"
                % (
                    r["name"][:30],
                    r["detector"],
                    r["severity"],
                    r.get("action") or "(default)",
                    r["tier"],
                    "yes" if r["enabled"] else "no",
                )
            )
        stats = store.get_rule_stats()
        by_tier = ", ".join("%d %s" % (v, k) for k, v in stats["by_tier"].items())
        print("\n  %d rules (%s)\n" % (stats["total"], by_tier))

    elif args.rules_command == "validate":
        import re as re_mod

        with open(args.file, encoding="utf-8") as f:
            bundle = json.loads(f.read())
        rules = bundle.get("rules", [])
        errors = 0
        for i, r in enumerate(rules):
            name = r.get("name", "rule_%d" % i)
            pattern = r.get("pattern", "")
            if not name:
                print("  ERROR: rule %d — missing name" % i)
                errors += 1
            if not pattern:
                print("  ERROR: rule '%s' — missing pattern" % name)
                errors += 1
            else:
                try:
                    re_mod.compile(pattern)
                except re_mod.error as e:
                    print("  ERROR: rule '%s' — invalid regex: %s" % (name, e))
                    errors += 1
        if errors:
            print("\n  %d rules validated, %d errors" % (len(rules), errors))
            sys.exit(1)
        else:
            print("  %d rules validated, 0 errors" % len(rules))


def _run_mcp(args: argparse.Namespace, extensions: ExtensionRegistry | None = None) -> None:
    """Run the unified MCP scanning proxy."""
    import asyncio

    log = logging.getLogger("argus.mcp")

    from lumen_argus.config import load_config
    from lumen_argus.mcp.scanner import MCPScanner
    from lumen_argus.scanner import _build_allowlist

    # Determine transport mode from flags
    upstream = getattr(args, "upstream", None)
    listen = getattr(args, "listen", None)
    cmd = args.server_command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]

    # Validate mode
    if listen and not upstream:
        print("Error: --listen requires --upstream", file=sys.stderr)
        sys.exit(1)
    if not upstream and not cmd:
        print(
            "Error: Provide a server command (lumen-argus mcp -- <command>) or --upstream URL",
            file=sys.stderr,
        )
        sys.exit(1)
    if upstream and cmd:
        print("Error: Cannot use both --upstream and a server command", file=sys.stderr)
        sys.exit(1)

    # Set log level
    log_level = getattr(logging, args.log_level.upper())
    logging.getLogger().setLevel(log_level)

    # Load config
    config = load_config(config_path=args.config)

    # Build detectors (lightweight — no DB, no rules engine, just hardcoded patterns)
    from lumen_argus.detectors import BaseDetector
    from lumen_argus.detectors.pii import PIIDetector
    from lumen_argus.detectors.secrets import SecretsDetector

    detectors: list[BaseDetector] = []
    if config.secrets.enabled:
        detectors.append(SecretsDetector(entropy_threshold=config.entropy_threshold))
    if config.pii.enabled:
        detectors.append(PIIDetector())

    allowlist = _build_allowlist(config)

    # Build response scanner for injection detection in tool responses
    response_scanner = None
    if config.pipeline.mcp_responses.enabled:
        from lumen_argus.response_scanner import ResponseScanner

        response_scanner = ResponseScanner(scan_secrets=False, scan_injection=True)

    # Parse allow/block lists from config + DB
    mcp_cfg = getattr(config, "mcp", None)
    allowed_tools = set(mcp_cfg.allowed_tools) if mcp_cfg and mcp_cfg.allowed_tools else set()
    blocked_tools = set(mcp_cfg.blocked_tools) if mcp_cfg and mcp_cfg.blocked_tools else set()

    # Merge DB entries (dashboard-managed)
    if config.analytics.enabled:
        try:
            from lumen_argus.analytics.store import AnalyticsStore

            _mcp_store = AnalyticsStore(db_path=os.path.expanduser(config.analytics.db_path))
            db_lists = _mcp_store.get_mcp_tool_lists()
            for entry in db_lists.get("allowed", []):
                allowed_tools.add(entry["tool_name"])
            for entry in db_lists.get("blocked", []):
                blocked_tools.add(entry["tool_name"])
            # Reconcile YAML entries to DB
            _mcp_store.reconcile_mcp_tool_lists(
                mcp_cfg.allowed_tools if mcp_cfg else [],
                mcp_cfg.blocked_tools if mcp_cfg else [],
            )
        except Exception as e:
            log.warning("mcp: could not load tool lists from DB: %s", e)

    allowed_tools_opt: set[Any] | None = allowed_tools or None
    blocked_tools_opt: set[Any] | None = blocked_tools or None

    # Load extensions (Pro hooks for policy engine + adaptive enforcement)
    if extensions is None:
        extensions = ExtensionRegistry()
        extensions.load_plugins()
    policy_engine = extensions.get_mcp_policy_engine()
    escalation_fn = extensions.get_mcp_session_escalation()

    # Determine action (CLI flag > config)
    action_override = getattr(args, "action", None)
    action = action_override or config.pipeline.mcp_arguments.action or config.default_action

    # Phase 2 security features
    request_tracker = None
    if mcp_cfg and mcp_cfg.request_tracking:
        from lumen_argus.mcp.request_tracker import RequestTracker

        request_tracker = RequestTracker(action=mcp_cfg.unsolicited_response_action)

    session_binding_obj = None
    if mcp_cfg and mcp_cfg.session_binding:
        from lumen_argus.mcp.session_binding import SessionBinding

        session_binding_obj = SessionBinding(action=mcp_cfg.unknown_tool_action)

    # Analytics store for drift detection
    mcp_store = None
    if mcp_cfg and mcp_cfg.detect_drift and config.analytics.enabled:
        try:
            from lumen_argus.analytics.store import AnalyticsStore

            mcp_store = AnalyticsStore(db_path=os.path.expanduser(config.analytics.db_path))
        except Exception as e:
            log.warning("mcp: could not open store for drift detection: %s", e)

    scanner = MCPScanner(
        detectors=detectors,
        allowlist=allowlist,
        response_scanner=response_scanner,
        scan_arguments=config.pipeline.mcp_arguments.enabled,
        scan_responses=config.pipeline.mcp_responses.enabled,
        allowed_tools=allowed_tools_opt,
        blocked_tools=blocked_tools_opt,
        action=action,
        request_tracker=request_tracker,
        session_binding=session_binding_obj,
        scan_tool_descriptions=mcp_cfg.scan_tool_descriptions if mcp_cfg else True,
        detect_drift=mcp_cfg.detect_drift if mcp_cfg else True,
        drift_action=mcp_cfg.drift_action if mcp_cfg else "alert",
        store=mcp_store,
    )

    # Dispatch to appropriate transport mode
    if cmd:
        # Stdio subprocess mode
        from lumen_argus.mcp.proxy import run_stdio_proxy

        env = None
        no_env_filter = getattr(args, "no_env_filter", False)
        if not no_env_filter:
            from lumen_argus.mcp.env_filter import filter_env

            extra_vars = {}
            for item in getattr(args, "env", []):
                if "=" in item:
                    k, v = item.split("=", 1)
                    extra_vars[k] = v
            env_allowlist = getattr(mcp_cfg, "env_allowlist", []) if mcp_cfg else []
            env = filter_env(extra_vars=extra_vars, config_allowlist=env_allowlist)

        exit_code = asyncio.run(
            run_stdio_proxy(cmd, scanner, env=env, policy_engine=policy_engine, escalation_fn=escalation_fn)
        )
        sys.exit(exit_code)

    elif listen:
        # HTTP reverse proxy mode
        from lumen_argus.mcp.proxy import run_http_listener

        if upstream is None:
            print("Error: --upstream is required with --listen", file=sys.stderr)
            sys.exit(1)
        # Parse listen address
        if ":" in listen:
            parts = listen.rsplit(":", 1)
            host = parts[0] or "127.0.0.1"
            port = int(parts[1])
        else:
            host = "127.0.0.1"
            port = int(listen)

        asyncio.run(
            run_http_listener(host, port, upstream, scanner, policy_engine=policy_engine, escalation_fn=escalation_fn)
        )

    else:
        # upstream must be set here (validated above)
        if upstream is None:
            print("Error: --upstream is required for bridge mode", file=sys.stderr)
            sys.exit(1)
        if upstream.startswith(("ws://", "wss://")):
            # WebSocket bridge mode
            from lumen_argus.mcp.proxy import run_ws_bridge

            exit_code = asyncio.run(
                run_ws_bridge(upstream, scanner, policy_engine=policy_engine, escalation_fn=escalation_fn)
            )
            sys.exit(exit_code)

        else:
            # HTTP bridge mode (stdio client -> HTTP upstream)
            from lumen_argus.mcp.proxy import run_http_bridge

            exit_code = asyncio.run(
                run_http_bridge(upstream, scanner, policy_engine=policy_engine, escalation_fn=escalation_fn)
            )
            sys.exit(exit_code)


if __name__ == "__main__":
    main()
