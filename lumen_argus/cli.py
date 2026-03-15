"""CLI entry point: argument parsing, startup, and run loop."""

import argparse
import logging
import os
import signal
import sys
import threading

from lumen_argus import __version__
from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.audit import AuditLogger
from lumen_argus.config import load_config
from lumen_argus.display import TerminalDisplay
from lumen_argus.extensions import ExtensionRegistry
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
        "--port", "-p",
        type=int, default=None,
        help="Proxy port (default: 8080, or from config)",
    )
    parser.add_argument(
        "--config", "-c",
        type=str, default=None,
        help="Path to config YAML (default: ~/.lumen-argus/config.yaml)",
    )
    parser.add_argument(
        "--log-dir",
        type=str, default=None,
        help="Audit log directory (default: ~/.lumen-argus/audit/)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output",
    )
    parser.add_argument(
        "--log-level",
        type=str, default="warning",
        choices=["debug", "info", "warning", "error"],
        help="Logging verbosity (default: warning)",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version="lumen-argus %s" % __version__,
    )

    args = parser.parse_args(argv)

    # Configure logging — explicit handler setup instead of basicConfig()
    # to avoid silent no-op if any import triggered basicConfig earlier.
    log_level = getattr(logging, args.log_level.upper())
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(
        "  %(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    ))
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level)

    log = logging.getLogger("argus.cli")

    # Load config
    config = load_config(config_path=args.config)

    # CLI args override config
    port = args.port or config.proxy.port
    bind = config.proxy.bind
    log_dir = args.log_dir or config.audit.log_dir

    log.info("config: default_action=%s", config.default_action)
    log.info(
        "config: secrets=%s pii=%s proprietary=%s",
        config.secrets.action or config.default_action,
        config.pii.action or config.default_action,
        config.proprietary.action or config.default_action,
    )
    log.info("config: allowlist secrets=%d pii=%d paths=%d",
        len(config.allowlist.secrets), len(config.allowlist.pii), len(config.allowlist.paths),
    )
    log.info("config: timeout=%ds retries=%d", config.proxy.timeout, config.proxy.retries)

    # Build action overrides from per-detector config
    action_overrides = {}
    if config.secrets.action:
        action_overrides["secrets"] = config.secrets.action
    if config.pii.action:
        action_overrides["pii"] = config.pii.action
    if config.proprietary.action:
        action_overrides["proprietary"] = config.proprietary.action

    # Construct components
    display = TerminalDisplay(no_color=args.no_color)
    audit = AuditLogger(log_dir=log_dir, retention_days=config.audit.retention_days)
    extensions = ExtensionRegistry()
    extensions.load_plugins()
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
    except OSError as e:
        print("Error: Could not bind to %s:%d — %s" % (bind, port, e), file=sys.stderr)
        sys.exit(1)

    display.show_banner(port, bind)

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

    try:
        server.serve_forever()
    except (KeyboardInterrupt, OSError):
        if not shutting_down[0]:
            display.show_shutdown(server.stats.summary())
            server.pool.close_all()
            audit.close()


if __name__ == "__main__":
    main()
