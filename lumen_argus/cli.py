"""CLI entry point: argument parsing, startup, and run loop."""

import argparse
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


def main(argv=None):
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="lumen-argus",
        description="AI coding tool DLP proxy — scan outbound requests for secrets, PII, and proprietary data.",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version="lumen-argus %s" % __version__,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- "serve" command ---
    serve_parser = subparsers.add_parser("serve", help="Run the proxy server")
    serve_parser.add_argument("--port", "-p", type=int, default=None, help="Proxy port (default: 8080)")
    serve_parser.add_argument("--config", "-c", type=str, default=None, help="Config YAML path")
    serve_parser.add_argument("--log-dir", type=str, default=None, help="Audit log directory")
    serve_parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    serve_parser.add_argument("--format", "-f", type=str, default="text", choices=["text", "json"], dest="output_format", help="Output format")
    serve_parser.add_argument("--log-level", type=str, default="warning", choices=["debug", "info", "warning", "error"], help="Logging verbosity")

    # --- "scan" command ---
    scan_parser = subparsers.add_parser("scan", help="Scan files or stdin for secrets/PII (pre-commit hook)")
    scan_parser.add_argument("files", nargs="*", help="Files to scan (reads stdin if none)")
    scan_parser.add_argument("--diff", nargs="?", const="", default=None, metavar="REF", help="Scan git diff only (staged changes by default, or diff against REF)")
    scan_parser.add_argument("--baseline", type=str, default=None, metavar="FILE", help="Ignore findings in baseline file")
    scan_parser.add_argument("--create-baseline", type=str, default=None, metavar="FILE", help="Save current findings as baseline")
    scan_parser.add_argument("--config", "-c", type=str, default=None, help="Config YAML path")
    scan_parser.add_argument("--format", "-f", type=str, default="text", choices=["text", "json"], dest="output_format", help="Output format")

    # --- "logs" command ---
    logs_parser = subparsers.add_parser("logs", help="Log file utilities")
    logs_sub = logs_parser.add_subparsers(dest="logs_command", required=True)
    export_parser = logs_sub.add_parser("export", help="Export log file for support sharing")
    export_parser.add_argument("--sanitize", action="store_true", help="Strip IPs, hostnames, and file paths")
    export_parser.add_argument("--config", "-c", type=str, default=None, help="Config YAML path")

    args = parser.parse_args(argv)

    if args.command in ("scan", "logs"):
        # Set up minimal logging for non-serve commands so config
        # warnings (log.warning) display cleanly on stderr.
        _handler = logging.StreamHandler(sys.stderr)
        _handler.setFormatter(logging.Formatter("  [%(name)s] %(levelname)s: %(message)s"))
        logging.getLogger().addHandler(_handler)
        logging.getLogger().setLevel(logging.WARNING)
        if args.command == "scan":
            _run_scan(args)
        else:
            _run_logs(args)
        return

    # command == "serve"

    # Configure logging — explicit handler setup instead of basicConfig()
    # to avoid silent no-op if any import triggered basicConfig earlier.
    console_level = getattr(logging, args.log_level.upper())
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(logging.Formatter(
        "  %(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    ))
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
    bind = config.proxy.bind
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
    log.info("allowlist: %d secrets, %d pii, %d paths",
        len(config.allowlist.secrets), len(config.allowlist.pii), len(config.allowlist.paths),
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
    pipeline = ScannerPipeline(
        default_action=config.default_action,
        action_overrides=action_overrides,
        allowlist=allowlist,
        entropy_threshold=config.entropy_threshold,
        extensions=extensions,
        custom_rules=config.custom_rules,
    )
    router = ProviderRouter(upstreams=config.upstreams or None)

    # Build SSL context for upstream connections
    from lumen_argus.pool import build_ssl_context
    ssl_context = build_ssl_context(
        ca_bundle=config.proxy.ca_bundle,
        verify_ssl=config.proxy.verify_ssl,
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
    except OSError as e:
        print("Error: Could not bind to %s:%d — %s" % (bind, port, e), file=sys.stderr)
        sys.exit(1)

    display.show_banner(port, bind)
    log.info("listening on http://%s:%d", bind, port)
    start_time = time.monotonic()

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
                server, args.config, file_handler, console_level,
                root_logger, extensions, current_config, log,
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


def _do_reload(server, config_path, file_handler, console_level,
               root_logger, extensions, current_config, log):
    """Reload config from disk — runs in main thread, safe for locks."""
    try:
        from lumen_argus.log_utils import config_diff
        from lumen_argus.pool import build_ssl_context

        new_config = load_config(config_path=config_path)
        old = current_config[0]
        changes = config_diff(old, new_config)
        if changes:
            log.info("config reloaded: %d changes", len(changes))
            for change in changes:
                log.info("  %s", change)
        current_config[0] = new_config

        new_allowlist = AllowlistMatcher(
            secrets=new_config.allowlist.secrets,
            pii=new_config.allowlist.pii,
            paths=new_config.allowlist.paths,
        )
        new_overrides = {}
        if new_config.secrets.action:
            new_overrides["secrets"] = new_config.secrets.action
        if new_config.pii.action:
            new_overrides["pii"] = new_config.pii.action
        if new_config.proprietary.action:
            new_overrides["proprietary"] = new_config.proprietary.action
        server.pipeline.reload(
            allowlist=new_allowlist,
            default_action=new_config.default_action,
            action_overrides=new_overrides,
            custom_rules=new_config.custom_rules,
        )
        server.timeout = new_config.proxy.timeout
        server.retries = new_config.proxy.retries
        if old.proxy.max_connections != new_config.proxy.max_connections:
            log.warning(
                "proxy.max_connections changed (%d -> %d) — requires restart to take effect",
                old.proxy.max_connections, new_config.proxy.max_connections,
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
            log.info("file log level: %s -> %s",
                logging.getLevelName(file_handler.level).lower(),
                new_config.logging_config.file_level,
            )
            file_handler.setLevel(new_file_level)
            root_logger.setLevel(min(console_level, new_file_level))

        reload_hook = extensions.get_config_reload_hook()
        if reload_hook:
            try:
                reload_hook(server.pipeline)
            except Exception:
                pass
        if not changes:
            log.info("config reloaded (no changes)")
    except Exception as e:
        log.error("config reload failed: %s", e)


def _run_scan(args):
    """Execute the 'scan' subcommand."""
    from lumen_argus.scanner import scan_diff, scan_files, scan_text

    if args.diff is not None:
        if args.baseline or args.create_baseline:
            print("lumen-argus: --baseline/--create-baseline not supported with --diff", file=sys.stderr)
        exit_code = scan_diff(ref=args.diff or None, config_path=args.config, output_format=args.output_format)
    elif args.files:
        exit_code = scan_files(
            args.files, config_path=args.config, output_format=args.output_format,
            baseline_path=args.baseline, create_baseline_path=args.create_baseline,
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


if __name__ == "__main__":
    main()
