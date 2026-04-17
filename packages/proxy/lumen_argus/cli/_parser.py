"""CLI argument definitions — all subcommand parsers.

Changes when: the CLI surface changes (new flags, renamed args, new subcommands).
"""

from __future__ import annotations

import argparse


def build_parser() -> tuple[argparse.ArgumentParser, argparse._SubParsersAction[argparse.ArgumentParser]]:
    """Build the top-level argument parser with all subcommands."""
    from lumen_argus import __version__

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

    _add_serve_parser(subparsers)
    _add_relay_parser(subparsers)
    _add_engine_parser(subparsers)
    _add_scan_parser(subparsers)
    _add_logs_parser(subparsers)
    _add_rules_parser(subparsers)
    _add_clients_parser(subparsers)
    _add_detect_parser(subparsers)
    _add_setup_parser(subparsers)
    _add_protection_parser(subparsers)
    _add_watch_parser(subparsers)
    _add_mcp_parser(subparsers)

    return parser, subparsers


def _add_serve_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
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


def _add_relay_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
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


def _add_engine_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
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


def _add_scan_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
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


def _add_logs_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    logs_parser = subparsers.add_parser("logs", help="Log file utilities")
    logs_sub = logs_parser.add_subparsers(dest="logs_command", required=True)
    export_parser = logs_sub.add_parser("export", help="Export log file for support sharing")
    export_parser.add_argument("--sanitize", action="store_true", help="Strip IPs, hostnames, and file paths")
    export_parser.add_argument("--config", "-c", type=str, default=None, help="Config YAML path")


def _add_rules_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
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


def _add_clients_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    clients_parser = subparsers.add_parser("clients", help="List supported AI CLI agents")
    clients_parser.add_argument("--json", action="store_true", help="Output as JSON")


def _add_detect_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    detect_parser = subparsers.add_parser("detect", help="Detect installed AI CLI agents")
    detect_parser.add_argument("--versions", action="store_true", help="Detect versions (slower, runs subprocesses)")
    detect_parser.add_argument("--json", action="store_true", help="Output as JSON")
    detect_parser.add_argument("--audit", action="store_true", help="Audit proxy configuration compliance")
    detect_parser.add_argument("--mcp", action="store_true", help="Include MCP servers from AI tool config files")
    detect_parser.add_argument(
        "--check-quiet",
        action="store_true",
        help="Shell hook mode: print warning if unconfigured tools found, exit silently otherwise",
    )
    detect_parser.add_argument("--proxy-url", type=str, default="http://localhost:8080", help="Expected proxy URL")


def _add_setup_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    setup_parser = subparsers.add_parser("setup", help="Configure AI tools to route through proxy")
    setup_parser.add_argument("client", nargs="?", default="", help="Configure specific client (e.g., 'aider')")
    setup_parser.add_argument("--proxy-url", type=str, default="http://localhost:8080", help="Proxy URL to configure")
    setup_parser.add_argument("--undo", action="store_true", help="Remove all proxy configuration")
    setup_parser.add_argument("--dry-run", action="store_true", help="Show changes without applying")
    setup_parser.add_argument("--non-interactive", action="store_true", help="Auto-configure without prompting")
    setup_parser.add_argument("--mcp", action="store_true", help="Wrap MCP servers through scanning proxy")
    setup_parser.add_argument("--server", type=str, default="", help="MCP server name (with --mcp)")
    setup_parser.add_argument(
        "--source", type=str, default="", help="Source tool ID (with --mcp, e.g. 'claude_desktop')"
    )


def _add_protection_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    from lumen_argus_core.env_template import ManagedBy

    protection_parser = subparsers.add_parser("protection", help="Toggle proxy routing (enable/disable/status)")
    protection_parser.add_argument(
        "action", choices=["enable", "disable", "status"], help="Enable, disable, or check protection status"
    )
    protection_parser.add_argument(
        "--proxy-url", type=str, default="http://localhost:8080", help="Proxy URL (for enable)"
    )
    protection_parser.add_argument(
        "--managed-by",
        choices=[m.value for m in ManagedBy],
        default=ManagedBy.CLI.value,
        help=(
            "Lifecycle owner of the env file (default: cli). "
            "Pass 'tray' when invoked by the desktop app or the enrollment flow "
            "to emit the self-healing liveness guard."
        ),
    )


def _add_watch_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    watch_parser = subparsers.add_parser("watch", help="Background daemon to detect and configure new AI tools")
    watch_parser.add_argument("--proxy-url", type=str, default="http://localhost:8080", help="Proxy URL to configure")
    watch_parser.add_argument("--interval", type=int, default=300, help="Scan interval in seconds (default: 300)")
    watch_parser.add_argument(
        "--auto-configure", action="store_true", help="Auto-configure new tools without prompting"
    )
    watch_parser.add_argument("--install", action="store_true", help="Install as system service (launchd/systemd)")
    watch_parser.add_argument("--uninstall", action="store_true", help="Remove system service")
    watch_parser.add_argument("--status", action="store_true", help="Show watch daemon status")


def _add_mcp_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
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
