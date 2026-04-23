"""CLI dispatch — plugin registration, command routing, and serve/engine entry.

Changes when: dispatch logic, plugin registration, or serve/engine startup changes.
"""

from __future__ import annotations

import argparse
import logging
import sys

from lumen_argus.cli._commands import run_clients, run_logs, run_mcp, run_scan
from lumen_argus.cli._detect_cmd import run_detect
from lumen_argus.cli._parser import build_parser
from lumen_argus.cli._relay_cmd import run_relay
from lumen_argus.cli._rules_cmd import run_rules
from lumen_argus.config import load_config
from lumen_argus.extensions import ExtensionRegistry

log = logging.getLogger("argus.cli")

# Subcommands moved to the workstation agent. Rejected with a pointer rather
# than argparse's generic "invalid choice", so operators know exactly which
# binary owns the concern now.
_REMOVED_SUBCOMMANDS: dict[str, str] = {
    "setup": "lumen-argus-agent setup",
    "protection": "lumen-argus-agent protection",
    "watch": "lumen-argus-agent watch",
}


def _reject_removed_subcommand(argv: list[str] | None) -> None:
    """Exit early with a helpful pointer if the user invoked a migrated subcommand.

    The proxy is a server binary; workstation-side concerns (env-file writes,
    shell-profile mutation, service daemons) live in ``lumen-argus-agent``.
    Pre-empts argparse so the user sees the new command verbatim.
    """
    effective = sys.argv[1:] if argv is None else argv
    if not effective:
        return
    cmd = effective[0]
    replacement = _REMOVED_SUBCOMMANDS.get(cmd)
    if replacement is None:
        return
    log.warning("proxy CLI rejected removed subcommand %r — use %r", cmd, replacement)
    print(
        "lumen-argus: '%s' is a workstation concern — use '%s' instead." % (cmd, replacement),
        file=sys.stderr,
    )
    sys.exit(2)


def _setup_minimal_logging() -> None:
    """Configure minimal stderr logging for non-serve CLI commands."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("  [%(name)s] %(levelname)s: %(message)s"))
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.WARNING)


def main(argv: list[str] | None = None) -> None:
    """Main entry point."""
    _reject_removed_subcommand(argv)

    parser, subparsers = build_parser()

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
        "scan": lambda: run_scan(args),
        "rules": lambda: run_rules(args),
        "mcp": lambda: run_mcp(args, extensions=extensions),
        "clients": lambda: run_clients(args),
        "detect": lambda: run_detect(args),
        "relay": lambda: run_relay(args),
        "logs": lambda: run_logs(args),
    }
    if args.command in handlers:
        _setup_minimal_logging()
        handlers[args.command]()
        return

    # command == "serve" or "engine"
    _run_serve(args, extensions)


def _run_serve(args: argparse.Namespace, extensions: ExtensionRegistry) -> None:
    """Configure logging and launch the proxy server."""
    from lumen_argus.log_utils import setup_file_logging

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
