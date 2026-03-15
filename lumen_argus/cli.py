"""CLI entry point: argument parsing, startup, and run loop."""

import argparse
import signal
import sys

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
        "--version", "-V",
        action="version",
        version="lumen-argus %s" % __version__,
    )

    args = parser.parse_args(argv)

    # Load config
    config = load_config(config_path=args.config)

    # CLI args override config
    port = args.port or config.proxy.port
    bind = config.proxy.bind
    log_dir = args.log_dir or config.audit.log_dir

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
        )
    except OSError as e:
        print("Error: Could not bind to %s:%d — %s" % (bind, port, e), file=sys.stderr)
        sys.exit(1)

    display.show_banner(port, bind)

    # Handle graceful shutdown
    request_count = [0]

    original_handler = signal.getsignal(signal.SIGINT)

    def shutdown_handler(signum, frame):
        display.show_shutdown(request_count[0])
        audit.close()
        server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        display.show_shutdown(0)
        audit.close()


if __name__ == "__main__":
    main()
