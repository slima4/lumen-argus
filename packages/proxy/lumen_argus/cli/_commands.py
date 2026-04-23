"""Thin command handlers that delegate to domain modules.

Changes when: the delegation interface to a domain module changes.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lumen_argus.extensions import ExtensionRegistry


def run_scan(args: argparse.Namespace) -> None:
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


def run_logs(args: argparse.Namespace) -> None:
    """Execute the 'logs' subcommand."""
    from lumen_argus.config import load_config as _load_config
    from lumen_argus.log_utils import export_logs

    config = _load_config(config_path=args.config)
    exit_code = export_logs(config, sanitize=args.sanitize)
    sys.exit(exit_code)


def run_clients(args: argparse.Namespace) -> None:
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
    print("Run 'lumen-argus-agent setup' to auto-configure detected tools.")


def run_mcp(args: argparse.Namespace, extensions: ExtensionRegistry | None = None) -> None:
    """Execute the 'mcp' subcommand."""
    from lumen_argus.mcp_cmd import run_mcp

    run_mcp(args, extensions=extensions)
