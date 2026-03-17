"""CLI entry point: argument parsing, startup, and run loop."""

import argparse
import logging
import logging.handlers
import os
import platform
import signal
import sys
import threading

from lumen_argus import __version__
from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.audit import AuditLogger
from lumen_argus.config import load_config
from lumen_argus.display import JsonDisplay, TerminalDisplay
from lumen_argus.extensions import ExtensionRegistry
from lumen_argus.pipeline import ScannerPipeline
from lumen_argus.provider import ProviderRouter
from lumen_argus.proxy import ArgusProxyServer


class _SecureRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """RotatingFileHandler that enforces 0o600 on rotated files."""

    def doRollover(self):
        super().doRollover()
        if self.baseFilename and os.path.exists(self.baseFilename):
            os.chmod(self.baseFilename, 0o600)


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
    scan_parser.add_argument("--config", "-c", type=str, default=None, help="Config YAML path")
    scan_parser.add_argument("--format", "-f", type=str, default="text", choices=["text", "json"], dest="output_format", help="Output format")

    args = parser.parse_args(argv)

    if args.command == "scan":
        _run_scan(args)
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
    file_level = getattr(logging, config.logging_config.file_level.upper())
    log_dir_path = os.path.expanduser(config.logging_config.log_dir)
    os.makedirs(log_dir_path, mode=0o700, exist_ok=True)
    log_file_path = os.path.join(log_dir_path, "lumen-argus.log")
    file_handler = _SecureRotatingFileHandler(
        log_file_path,
        maxBytes=config.logging_config.max_size_mb * 1024 * 1024,
        backupCount=config.logging_config.backup_count,
        encoding="utf-8",
    )
    file_handler.setLevel(file_level)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s.%(msecs)03d %(levelname)-5s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    os.chmod(log_file_path, 0o600)
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
    )
    router = ProviderRouter(upstreams=config.upstreams or None)

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
        )
        # Store server reference for Pro runtime config updates
        extensions._proxy_server = server
    except OSError as e:
        print("Error: Could not bind to %s:%d — %s" % (bind, port, e), file=sys.stderr)
        sys.exit(1)

    display.show_banner(port, bind)
    log.info("listening on http://%s:%d", bind, port)

    # Handle graceful shutdown — signal handler must not call
    # server.shutdown() directly because serve_forever() runs in the
    # same thread, causing a deadlock.  Instead, set a flag and let
    # the main thread break out of serve_forever() via _BaseServer
    # internals, or simply close the socket and exit.
    shutting_down = [False]

    def shutdown_handler(signum, frame):
        if shutting_down[0]:
            # Second signal — force exit immediately
            os._exit(1)
        shutting_down[0] = True
        display.show_shutdown(server.stats.summary())
        server.pool.close_all()
        audit.close()
        # Close the listening socket so select() unblocks
        try:
            server.socket.close()
        except Exception:
            pass

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    # SIGHUP: reload config without restarting (Unix only).
    # Build replacement objects fully, then swap references atomically
    # to avoid race conditions with request handler threads.
    def reload_handler(signum, frame):
        try:
            new_config = load_config(config_path=args.config)
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
            from lumen_argus.policy import PolicyEngine
            new_policy = PolicyEngine(
                default_action=new_config.default_action,
                action_overrides=new_overrides,
            )
            # Atomic swaps — each is a single reference assignment
            server.pipeline._allowlist = new_allowlist
            server.pipeline._policy = new_policy
            server.timeout = new_config.proxy.timeout
            server.retries = new_config.proxy.retries
            # Update file log level if changed
            new_file_level = getattr(logging, new_config.logging_config.file_level.upper())
            if file_handler.level != new_file_level:
                log.info("file log level: %s -> %s",
                    logging.getLevelName(file_handler.level).lower(),
                    new_config.logging_config.file_level,
                )
                file_handler.setLevel(new_file_level)
                root_logger.setLevel(min(console_level, new_file_level))
            # Notify plugins of config reload
            reload_hook = extensions.get_config_reload_hook()
            if reload_hook:
                try:
                    reload_hook(server.pipeline)
                except Exception:
                    pass
            log.info("config reloaded")
            print("  [config] reloaded %s" % (args.config or "~/.lumen-argus/config.yaml"), file=sys.stderr)
        except Exception as e:
            print("  [config] reload failed: %s" % e, file=sys.stderr)

    if hasattr(signal, "SIGHUP"):  # not available on Windows
        signal.signal(signal.SIGHUP, reload_handler)

    try:
        server.serve_forever()
    except (KeyboardInterrupt, OSError):
        if not shutting_down[0]:
            display.show_shutdown(server.stats.summary())
            server.pool.close_all()
            audit.close()


def _run_scan(args):
    """Execute the 'scan' subcommand."""
    from lumen_argus.scanner import scan_files, scan_text

    if args.files:
        exit_code = scan_files(args.files, config_path=args.config, output_format=args.output_format)
    else:
        # Read from stdin — warn if it's a terminal
        if sys.stdin.isatty():
            print("lumen-argus scan: reading from stdin (Ctrl+D to finish, or pass filenames)", file=sys.stderr)
        text = sys.stdin.read()
        exit_code = scan_text(text, config_path=args.config, output_format=args.output_format)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
