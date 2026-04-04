"""CLI entry point: argument parsing, startup, and run loop."""

from __future__ import annotations

import argparse
import json
import logging
import platform
import signal
import sys

from lumen_argus import __version__
from lumen_argus.config import load_config
from lumen_argus.config_loader import load_rules_bundle, trigger_auto_analysis
from lumen_argus.extensions import ExtensionRegistry
from lumen_argus.log_utils import setup_file_logging
from lumen_argus.provider import ProviderRouter

log = logging.getLogger("argus.cli")


def _setup_minimal_logging() -> None:
    """Configure minimal stderr logging for non-serve CLI commands."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("  [%(name)s] %(levelname)s: %(message)s"))
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.WARNING)


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

    # Engine = full proxy on engine port — set defaults then fall through to serve
    if args.command == "engine":
        config = load_config(config_path=args.config)
        if not args.port:
            args.port = config.engine.port
        if not hasattr(args, "engine_port"):
            args.engine_port = None
        if not hasattr(args, "fail_mode"):
            args.fail_mode = None

    handlers = {
        "scan": lambda: _run_scan(args),
        "rules": lambda: _run_rules(args),
        "mcp": lambda: _run_mcp(args, extensions=extensions),
        "clients": lambda: _run_clients(args),
        "detect": lambda: _run_detect(args),
        "setup": lambda: _run_setup(args),
        "watch": lambda: _run_watch(args),
        "protection": lambda: _run_protection(args),
        "relay": lambda: _run_relay(args),
        "logs": lambda: _run_logs(args),
    }
    if args.command in handlers:
        _setup_minimal_logging()
        handlers[args.command]()
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

    config = load_config(config_path=args.config)

    file_handler, log_file_path, file_level = setup_file_logging(config.logging_config)
    root_logger.addHandler(file_handler)
    root_logger.setLevel(min(console_level, file_level))

    from lumen_argus.startup import run_server

    run_server(
        config,
        args,
        extensions,
        console_level=console_level,
        file_handler=file_handler,
        root_logger=root_logger,
        log_file_path=log_file_path,
    )


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

    from lumen_argus.config import load_config
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
            rules, version, tier = load_rules_bundle(path=args.file, pro=args.pro)
            print("lumen-argus: dry run — %d %s rules (v%s)" % (len(rules), tier, version))
            return
        rules, version, tier = load_rules_bundle(path=args.file, pro=args.pro)
        print("lumen-argus: importing %s rules v%s" % (tier, version))
        result = store.import_rules(rules, tier=tier, force=args.force)
        print(
            "  %d rules imported (%d new, %d updated, %d skipped)"
            % (result["created"] + result["updated"], result["created"], result["updated"], result["skipped"])
        )
        total = store.get_rules_count()
        print("  total: %d rules in DB" % total)
        trigger_auto_analysis(store, None)

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
    from lumen_argus.mcp_cmd import run_mcp

    run_mcp(args, extensions=extensions)


if __name__ == "__main__":
    main()
