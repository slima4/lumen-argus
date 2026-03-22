"""CLI entry point: argument parsing, startup, and run loop."""

import argparse
import json
import logging
import os
import platform
import signal
import sys
import time

from lumen_argus import __version__
from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.audit import AuditLogger
from lumen_argus.config import load_config
from lumen_argus.display import JsonDisplay, TerminalDisplay
from lumen_argus.extensions import ExtensionRegistry
from lumen_argus.log_utils import setup_file_logging
from lumen_argus.pipeline import ScannerPipeline
from lumen_argus.provider import ProviderRouter
from lumen_argus.proxy import ArgusProxyServer


def _build_pipeline_config(cfg):
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


def main(argv=None):
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

    # mcp-wrap subcommand
    mcp_parser = subparsers.add_parser(
        "mcp-wrap",
        help="Wrap an MCP server with DLP scanning (stdio transport)",
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
        "server_command",
        nargs=argparse.REMAINDER,
        help="MCP server command (after --)",
    )

    args = parser.parse_args(argv)

    if args.command in ("scan", "logs", "rules", "mcp-wrap"):
        # Set up minimal logging for non-serve commands so config
        # warnings (log.warning) display cleanly on stderr.
        _handler = logging.StreamHandler(sys.stderr)
        _handler.setFormatter(logging.Formatter("  [%(name)s] %(levelname)s: %(message)s"))
        logging.getLogger().addHandler(_handler)
        logging.getLogger().setLevel(logging.WARNING)
        if args.command == "scan":
            _run_scan(args)
        elif args.command == "rules":
            _run_rules(args)
        elif args.command == "mcp-wrap":
            _run_mcp_wrap(args)
        else:
            _run_logs(args)
        return

    # command == "serve"

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

    log = logging.getLogger("argus.cli")

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
    if args.output_format == "json":
        display = JsonDisplay()
    else:
        display = TerminalDisplay(no_color=args.no_color)
    audit = AuditLogger(log_dir=audit_log_dir, retention_days=config.audit.retention_days)
    extensions = ExtensionRegistry()
    extensions.load_plugins()
    for pname, pver in extensions.loaded_plugins():
        log.info("plugin: %s v%s", pname, pver)
    log.info("audit log: %s", os.path.expanduser(audit_log_dir))
    log.info("app log: %s (%s level)", log_file_path, config.logging_config.file_level)
    allowlist = AllowlistMatcher(
        secrets=config.allowlist.secrets,
        pii=config.allowlist.pii,
        paths=config.allowlist.paths,
    )
    from dataclasses import asdict

    router = ProviderRouter(upstreams=config.upstreams or None)

    # Build SSL context for upstream connections
    from lumen_argus.pool import build_ssl_context

    ssl_context = build_ssl_context(
        ca_bundle=config.proxy.ca_bundle,
        verify_ssl=config.proxy.verify_ssl,
    )

    # --- Analytics store and rules (must happen before pipeline creation) ---
    dashboard_server = None
    analytics_store = None
    if config.dashboard.enabled:
        from lumen_argus.analytics.store import AnalyticsStore
        from lumen_argus.dashboard.audit_reader import AuditReader
        from lumen_argus.dashboard.server import start_dashboard
        from lumen_argus.dashboard.sse import SSEBroadcaster

        # Load or generate HMAC key for value hashing
        hmac_key = None
        if config.analytics.hash_secrets:
            hmac_key = _load_hmac_key()

        # Create analytics store (or use plugin-provided one)
        analytics_store = extensions.get_analytics_store()
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
            pass

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
    )

    # Start server
    try:
        server = ArgusProxyServer(
            bind=bind,
            port=port,
            pipeline=pipeline,
            router=router,
            audit=audit,
            display=display,
            timeout=config.proxy.timeout,
            retries=config.proxy.retries,
            max_body_size=config.proxy.max_body_size,
            redact_hook=extensions.get_redact_hook(),
            ssl_context=ssl_context,
            max_connections=config.proxy.max_connections,
        )
        extensions.set_proxy_server(server)
        server.extensions = extensions

        # Response scanner — enabled when either response stage is active
        resp_secrets = config.pipeline.response_secrets.enabled
        resp_injection = config.pipeline.response_injection.enabled
        if resp_secrets or resp_injection:
            from lumen_argus.response_scanner import ResponseScanner

            server.response_scanner = ResponseScanner(
                detectors=pipeline._detectors if resp_secrets else [],
                allowlist=pipeline._allowlist if resp_secrets else None,
                store=analytics_store,
                scan_secrets=resp_secrets,
                scan_injection=resp_injection,
                max_response_size=config.pipeline.response_max_size,
            )
            log.info(
                "response scanning enabled: secrets=%s injection=%s",
                resp_secrets,
                resp_injection,
            )
    except OSError as e:
        print("Error: Could not bind to %s:%d — %s" % (bind, port, e), file=sys.stderr)
        sys.exit(1)

    display.show_banner(port, bind)
    log.info("listening on http://%s:%d", bind, port)
    start_time = time.monotonic()

    # --- Dashboard ---
    if config.dashboard.enabled:
        # Create SSE broadcaster and register with extensions so Pro can use it
        sse_broadcaster = SSEBroadcaster()
        extensions.set_sse_broadcaster(sse_broadcaster)

        # Create audit reader (use CLI-overridden log dir, same as AuditLogger)
        audit_reader = AuditReader(log_dir=audit_log_dir)

        # Dashboard password from config or env
        dash_password = config.dashboard.password

        dash_bind = args.host or config.dashboard.bind

        dashboard_server = start_dashboard(
            bind=dash_bind,
            port=config.dashboard.port,
            analytics_store=analytics_store,
            extensions=extensions,
            password=dash_password,
            audit_reader=audit_reader,
            sse_broadcaster=sse_broadcaster,
            config=config,
        )
        if dashboard_server:
            log.info("dashboard: http://%s:%d", dash_bind, config.dashboard.port)

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
            # Warn if channels exist but no dispatcher (source install)
            if not extensions.get_dispatcher():
                count = analytics_store.count_notification_channels()
                if count > 0:
                    log.warning(
                        "%d notification channel(s) configured but dispatch "
                        "unavailable — install from PyPI: pip install lumen-argus",
                        count,
                    )

    # --- MCP-aware scanning in HTTP proxy ---
    mcp_args_enabled = config.pipeline.mcp_arguments.enabled
    mcp_resp_enabled = config.pipeline.mcp_responses.enabled
    if mcp_args_enabled or mcp_resp_enabled:
        from lumen_argus.mcp_scanner import MCPScanner

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
                pass

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

    # --- WebSocket proxy ---
    from lumen_argus.ws_proxy import WebSocketScanner, start_ws_proxy, _HAS_WEBSOCKETS

    server._ws_handle = None  # WebSocketProxyHandle for SIGHUP start/stop
    ws_enabled = config.pipeline.websocket_outbound.enabled or config.pipeline.websocket_inbound.enabled
    if ws_enabled and _HAS_WEBSOCKETS:
        ws_scanner = WebSocketScanner(
            detectors=pipeline._detectors,
            allowlist=pipeline._allowlist,
            response_scanner=server.response_scanner,
            scan_outbound=config.pipeline.websocket_outbound.enabled,
            scan_inbound=config.pipeline.websocket_inbound.enabled,
            max_frame_size=config.websocket.max_frame_size,
        )
        ws_port = config.dashboard.port + 2  # 8083 by default
        server._ws_handle = start_ws_proxy(
            bind=bind,
            port=ws_port,
            scanner=ws_scanner,
            allowed_origins=config.websocket.allowed_origins or None,
        )

    # --- Signal-safe shutdown and reload ---
    #
    # Signal handlers must not acquire locks (logging, threading, I/O)
    # because the signal may arrive while a request thread holds a lock,
    # causing deadlock. Instead, handlers only set flags and wake the
    # main loop. All lock-acquiring work runs in the main thread.
    shutting_down = [False]
    reload_requested = [False]

    def shutdown_handler(signum, frame):
        if shutting_down[0]:
            os._exit(1)  # Second signal — force exit
        shutting_down[0] = True
        # Close the listening socket to wake select() — no locks needed
        try:
            server.socket.close()
        except Exception:
            pass

    def reload_handler(signum, frame):
        reload_requested[0] = True
        # set_wakeup_fd pipe write wakes select() automatically

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    # Self-pipe trick: signal.set_wakeup_fd writes a byte to the pipe
    # on any signal, waking select() in serve_forever() immediately
    # (PEP 475 auto-retries select on EINTR, so without this SIGHUP
    # would not wake the main loop until the next poll_interval).
    wakeup_r, wakeup_w = os.pipe()
    os.set_blocking(wakeup_r, False)
    os.set_blocking(wakeup_w, False)
    signal.set_wakeup_fd(wakeup_w)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, reload_handler)

    # Track current config for diff on reload
    current_config = [config]

    # Patch service_actions to handle reload in the main thread.
    # service_actions() is called by serve_forever() on every poll
    # cycle (~0.5s), safe for locks since it runs in the main thread.
    _orig_service_actions = server.service_actions

    def _service_actions():
        _orig_service_actions()
        # Drain the wakeup pipe
        try:
            os.read(wakeup_r, 1024)
        except OSError:
            pass
        if reload_requested[0]:
            reload_requested[0] = False
            _do_reload(
                server,
                args.config,
                file_handler,
                console_level,
                root_logger,
                extensions,
                current_config,
                log,
            )

    server.service_actions = _service_actions

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    except OSError:
        if not shutting_down[0]:
            raise

    # Graceful drain — wait for in-flight requests to finish
    drain_timeout = config.proxy.drain_timeout
    remaining = server.drain(timeout=drain_timeout)
    if remaining and drain_timeout > 0:
        log.warning("shutdown: %d requests force-closed after %ds drain timeout", remaining, drain_timeout)

    uptime = time.monotonic() - start_time
    log.info("shutdown: %d requests, uptime %.0fs", server.stats.total_requests, uptime)
    display.show_shutdown(server.stats.summary())
    server.pool.close_all()
    audit.close()
    # Close wakeup pipe
    try:
        os.close(wakeup_r)
        os.close(wakeup_w)
    except OSError:
        pass


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
        pass
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


def _do_reload(server, config_path, file_handler, console_level, root_logger, extensions, current_config, log):
    """Reload config from disk — runs in main thread, safe for locks."""
    try:
        from lumen_argus.log_utils import config_diff
        from lumen_argus.pool import build_ssl_context

        new_config = load_config(config_path=config_path)

        new_allowlist = AllowlistMatcher(
            secrets=new_config.allowlist.secrets,
            pii=new_config.allowlist.pii,
            paths=new_config.allowlist.paths,
        )
        # Reconcile YAML custom rules to DB BEFORE pipeline reload
        # so RulesDetector.reload() sees the updated rules
        analytics_store = extensions.get_analytics_store()
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
                    log.info("applied %d config override(s) from DB", len(db_overrides))
            except Exception:
                log.debug("no config overrides from DB")

        # Diff after DB overrides so phantom changes don't appear
        old = current_config[0]
        changes = config_diff(old, new_config)
        if changes:
            log.info("config reloaded: %d changes", len(changes))
            for change in changes:
                log.info("  %s", change)
        else:
            log.info("config reloaded (no changes)")
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
            log.info("response scanning reloaded: secrets=%s injection=%s", resp_secrets, resp_injection)
        else:
            server.response_scanner = None

        # Rebuild MCP scanner for proxy on reload
        mcp_args_enabled = new_config.pipeline.mcp_arguments.enabled
        mcp_resp_enabled = new_config.pipeline.mcp_responses.enabled
        if mcp_args_enabled or mcp_resp_enabled:
            from lumen_argus.mcp_scanner import MCPScanner as _MCPScanner

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
                    pass
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
            log.info("MCP proxy scanning reloaded")
        else:
            server.mcp_scanner = None

        # Rebuild WebSocket proxy on reload (start/stop/restart)
        from lumen_argus.ws_proxy import WebSocketScanner, start_ws_proxy, _HAS_WEBSOCKETS

        ws_enabled = new_config.pipeline.websocket_outbound.enabled or new_config.pipeline.websocket_inbound.enabled
        ws_running = hasattr(server, "_ws_handle") and server._ws_handle and server._ws_handle.running

        if ws_enabled and _HAS_WEBSOCKETS:
            # Stop existing if running (config may have changed)
            if ws_running:
                server._ws_handle.stop()
            ws_scanner = WebSocketScanner(
                detectors=server.pipeline._detectors,
                allowlist=server.pipeline._allowlist,
                response_scanner=server.response_scanner,
                scan_outbound=new_config.pipeline.websocket_outbound.enabled,
                scan_inbound=new_config.pipeline.websocket_inbound.enabled,
                max_frame_size=new_config.websocket.max_frame_size,
            )
            ws_port = new_config.dashboard.port + 2
            server._ws_handle = start_ws_proxy(
                bind=server.server_address[0],
                port=ws_port,
                scanner=ws_scanner,
                allowed_origins=new_config.websocket.allowed_origins or None,
            )
            log.info(
                "ws proxy reloaded: outbound=%s inbound=%s",
                new_config.pipeline.websocket_outbound.enabled,
                new_config.pipeline.websocket_inbound.enabled,
            )
        elif ws_enabled and not _HAS_WEBSOCKETS:
            # WS enabled but package missing — stop stale handle if any
            if ws_running:
                server._ws_handle.stop()
                server._ws_handle = None
            log.warning("ws proxy enabled but websockets package not installed")
        elif ws_running:
            # WS now disabled — stop it
            server._ws_handle.stop()
            server._ws_handle = None
            log.info("ws proxy stopped (disabled via config)")

        if old.proxy.max_connections != new_config.proxy.max_connections:
            log.warning(
                "proxy.max_connections changed (%d -> %d) — requires restart to take effect",
                old.proxy.max_connections,
                new_config.proxy.max_connections,
            )

        # Rebuild SSL context if ca_bundle or verify_ssl changed
        new_ssl_ctx = build_ssl_context(
            ca_bundle=new_config.proxy.ca_bundle,
            verify_ssl=new_config.proxy.verify_ssl,
        )
        server.pool._ssl_ctx = new_ssl_ctx
        server.pool.close_all()

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
                pass

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
    except Exception as e:
        log.error("config reload failed: %s", e)


def _run_scan(args):
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


def _run_logs(args):
    """Execute the 'logs' subcommand."""
    from lumen_argus.config import load_config as _load_config
    from lumen_argus.log_utils import export_logs

    config = _load_config(config_path=args.config)
    exit_code = export_logs(config, sanitize=args.sanitize)
    sys.exit(exit_code)


def _load_rules_bundle(path: str = None, pro: bool = False) -> tuple:
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
            # Fallback for Python 3.9-3.11
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


def _run_rules(args):
    """Execute the 'rules' subcommand."""
    from lumen_argus.analytics.store import AnalyticsStore
    from lumen_argus.config import load_config as _load_config

    config_path = getattr(args, "config", None)
    config = _load_config(config_path=config_path)
    store = AnalyticsStore(db_path=config.analytics.db_path)

    if args.rules_command == "import":
        if args.pro:
            try:
                from lumen_argus_pro.license import get_license

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


def _run_mcp_wrap(args):
    """Run the MCP stdio wrapper."""
    import asyncio

    log = logging.getLogger("argus.mcp")

    from lumen_argus.allowlist import AllowlistMatcher
    from lumen_argus.config import load_config
    from lumen_argus.mcp_scanner import MCPScanner
    from lumen_argus.mcp_wrap import _run_wrapper

    # Parse server command (strip leading --)
    cmd = args.server_command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("Error: No MCP server command provided. Usage: lumen-argus mcp-wrap -- <command>", file=sys.stderr)
        sys.exit(1)

    # Set log level for mcp-wrap
    log_level = getattr(logging, args.log_level.upper())
    logging.getLogger().setLevel(log_level)

    # Load config
    config = load_config(config_path=args.config)

    # Build detectors (lightweight — no DB, no rules engine, just hardcoded patterns)
    from lumen_argus.detectors.secrets import SecretsDetector
    from lumen_argus.detectors.pii import PIIDetector

    detectors = []
    if config.secrets.enabled:
        detectors.append(SecretsDetector(entropy_threshold=config.entropy_threshold))
    if config.pii.enabled:
        detectors.append(PIIDetector())

    allowlist = AllowlistMatcher(
        secrets=config.allowlist.secrets,
        pii=config.allowlist.pii,
        paths=config.allowlist.paths,
    )

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
            log.warning("mcp-wrap: could not load tool lists from DB: %s", e)

    allowed_tools = allowed_tools or None
    blocked_tools = blocked_tools or None

    scanner = MCPScanner(
        detectors=detectors,
        allowlist=allowlist,
        response_scanner=response_scanner,
        scan_arguments=config.pipeline.mcp_arguments.enabled,
        scan_responses=config.pipeline.mcp_responses.enabled,
        allowed_tools=allowed_tools,
        blocked_tools=blocked_tools,
        action=config.pipeline.mcp_arguments.action or config.default_action,
    )

    exit_code = asyncio.run(_run_wrapper(cmd, scanner))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
