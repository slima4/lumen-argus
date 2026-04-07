"""CLI for lumen-argus-agent — lightweight workstation agent.

Commands: detect, setup, watch, protection, clients.
All business logic lives in lumen_argus_core — this is a thin CLI wrapper.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lumen_argus_core.detect_models import DetectionReport, MCPDetectionReport

__version__ = "0.1.0"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lumen-argus-agent",
        description="Lightweight workstation agent for lumen-argus",
    )
    parser.add_argument("--version", "-V", action="version", version=f"lumen-argus-agent {__version__}")

    subparsers = parser.add_subparsers(dest="command")

    # clients
    clients_parser = subparsers.add_parser("clients", help="List supported AI CLI agents")
    clients_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # detect
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

    # setup
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

    # protection
    protection_parser = subparsers.add_parser("protection", help="Toggle proxy routing (enable/disable/status)")
    protection_parser.add_argument(
        "action", choices=["enable", "disable", "status"], help="Enable, disable, or check protection status"
    )
    protection_parser.add_argument(
        "--proxy-url", type=str, default="http://localhost:8080", help="Proxy URL (for enable)"
    )

    # watch
    watch_parser = subparsers.add_parser("watch", help="Background daemon to detect and configure new AI tools")
    watch_parser.add_argument("--proxy-url", type=str, default="http://localhost:8080", help="Proxy URL to configure")
    watch_parser.add_argument("--interval", type=int, default=300, help="Scan interval in seconds (default: 300)")
    watch_parser.add_argument(
        "--auto-configure", action="store_true", help="Auto-configure new tools without prompting"
    )
    watch_parser.add_argument("--install", action="store_true", help="Install as system service (launchd/systemd)")
    watch_parser.add_argument("--uninstall", action="store_true", help="Remove system service")
    watch_parser.add_argument("--status", action="store_true", help="Show watch daemon status")

    # enroll
    enroll_parser = subparsers.add_parser("enroll", help="Enroll with a central lumen-argus proxy")
    enroll_parser.add_argument("--server", type=str, default="", help="Central proxy server URL")
    enroll_parser.add_argument("--token", type=str, default="", help="Enrollment token")
    enroll_parser.add_argument("--non-interactive", action="store_true", help="No prompts")
    enroll_parser.add_argument("--undo", action="store_true", help="Unenroll and remove configuration")

    # heartbeat
    subparsers.add_parser("heartbeat", help="Send a single heartbeat to the central proxy")

    # relay
    relay_parser = subparsers.add_parser("relay", help="Start local forwarding proxy with identity enrichment")
    relay_parser.add_argument("--port", type=int, default=8070, help="Listen port (default: 8070)")
    relay_parser.add_argument("--host", type=str, default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    relay_parser.add_argument(
        "--upstream", type=str, default="", help="Proxy URL (default: from enrollment or http://localhost:8080)"
    )
    relay_parser.add_argument(
        "--fail-mode",
        type=str,
        choices=["open", "closed"],
        default="open",
        help="Behavior when proxy unreachable (default: open)",
    )
    relay_parser.add_argument("--log-level", type=str, default="info", help="Log level (default: info)")
    relay_parser.add_argument("--install", action="store_true", help="Install as system service (launchd/systemd)")
    relay_parser.add_argument("--uninstall", action="store_true", help="Remove system service")
    relay_parser.add_argument("--status", action="store_true", help="Show relay status")

    return parser


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def _resolve_relay_url() -> str:
    """Check if the agent relay is running and return its URL, or empty string."""
    from lumen_argus_agent.relay import load_relay_state

    state = load_relay_state()
    if not state:
        return ""
    bind = state.get("bind", "127.0.0.1")
    port = state.get("port", 8070)
    url = "http://%s:%d" % (bind, port)
    return url


def _run_clients(args: argparse.Namespace) -> None:
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
    print("\nRun 'lumen-argus-agent detect' to scan for installed tools.")
    print("Run 'lumen-argus-agent setup' to auto-configure detected tools.")


def _detect_check_quiet(report: DetectionReport) -> None:
    """Output for --check-quiet: warn on stderr if unconfigured tools exist."""
    unconfigured = [c for c in report.clients if c.installed and not c.proxy_configured]
    if unconfigured:
        names = ", ".join(c.display_name for c in unconfigured)
        sys.stderr.write(
            "\033[33m[lumen-argus]\033[0m %d unconfigured tool(s): %s"
            " — run 'lumen-argus-agent setup'\n" % (len(unconfigured), names)
        )


def _detect_audit(report: DetectionReport) -> None:
    """Output for --audit: compliance report."""
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
        print("Action required: run 'lumen-argus-agent setup' to configure uncovered tools.")


def _detect_table(report: DetectionReport, proxy_url: str) -> None:
    """Output for default mode: table of detected tools."""
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

    print("\n%d/%d configured for proxy (%s)" % (report.total_configured, report.total_detected, proxy_url))
    if report.total_configured < report.total_detected:
        print("Run 'lumen-argus-agent setup' to configure remaining tools.")


def _detect_mcp_table(mcp_report: MCPDetectionReport) -> None:
    """Output MCP server detection results."""
    from lumen_argus_core.detect_models import format_mcp_table

    print(format_mcp_table(mcp_report, setup_command="lumen-argus-agent setup --mcp"))


def _run_detect(args: argparse.Namespace) -> None:
    from lumen_argus_core.detect import detect_installed_clients

    report = detect_installed_clients(
        proxy_url=args.proxy_url,
        include_versions=args.versions,
    )

    if args.check_quiet:
        _detect_check_quiet(report)
        return

    mcp_report = None
    if getattr(args, "mcp", False):
        from lumen_argus_core.detect import detect_mcp_servers

        mcp_report = detect_mcp_servers()

    if args.json:
        result = report.to_dict()
        if mcp_report:
            result["mcp_servers"] = mcp_report.to_dict()
        print(json.dumps(result, indent=2))
    elif args.audit:
        _detect_audit(report)
    else:
        _detect_table(report, args.proxy_url)
        if mcp_report:
            _detect_mcp_table(mcp_report)


def _run_setup(args: argparse.Namespace) -> None:
    if getattr(args, "mcp", False):
        from lumen_argus_core.mcp_setup import dispatch_mcp_setup

        dispatch_mcp_setup(args)
        return

    from lumen_argus_core.setup_wizard import run_setup, undo_setup

    if args.undo:
        reverted = undo_setup()
        if reverted:
            print("Reverted %d change(s). Proxy configuration removed." % reverted)
        else:
            print("Nothing to undo.")
        return

    # Use relay URL if relay is active and user didn't explicitly set --proxy-url
    proxy_url = args.proxy_url
    if proxy_url == "http://localhost:8080":
        relay_url = _resolve_relay_url()
        if relay_url:
            proxy_url = relay_url

    run_setup(
        proxy_url=proxy_url,
        client_id=args.client,
        non_interactive=args.non_interactive,
        dry_run=args.dry_run,
    )


def _run_protection(args: argparse.Namespace) -> None:
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


def _watch_status() -> None:
    """Print watch daemon status."""
    from lumen_argus_core.watch import get_service_status

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


def _watch_uninstall() -> None:
    """Remove the watch daemon service."""
    from lumen_argus_core.watch import uninstall_service

    if not uninstall_service():
        print("No watch service found to remove.")
        return
    print("Watch service removed.")
    print("Note: stop the running service manually:")
    if platform.system() == "Darwin":
        print("  launchctl unload ~/Library/LaunchAgents/io.lumen-argus.watch.plist")
    else:
        print("  systemctl --user stop lumen-argus-watch")


def _watch_install(args: argparse.Namespace) -> None:
    """Install the watch daemon as a system service."""
    from lumen_argus_core.watch import install_service

    path = install_service(
        proxy_url=args.proxy_url,
        interval=args.interval,
        auto_configure=args.auto_configure,
    )
    if not path:
        print("Service install not supported on this platform.")
        print("Run 'lumen-argus-agent watch' directly instead.")
        return
    print("Watch service installed: %s" % path)
    print("\nTo start the service:")
    if platform.system() == "Darwin":
        print("  launchctl load %s" % path)
    else:
        print("  systemctl --user daemon-reload")
        print("  systemctl --user enable --now lumen-argus-watch")


def _run_watch(args: argparse.Namespace) -> None:
    if args.status:
        _watch_status()
    elif args.uninstall:
        _watch_uninstall()
    elif args.install:
        _watch_install(args)
    else:
        from lumen_argus_core.watch import run_watch_loop

        run_watch_loop(
            proxy_url=args.proxy_url,
            interval=args.interval,
            auto_configure=args.auto_configure,
        )


def _run_enroll(args: argparse.Namespace) -> None:
    from lumen_argus_core.enrollment import EnrollmentError, enroll, load_enrollment, unenroll

    if args.undo:
        if unenroll():
            # Also undo tool configuration and protection
            from lumen_argus_core.setup_wizard import disable_protection, undo_setup
            from lumen_argus_core.watch import uninstall_service

            undo_setup()
            disable_protection()
            uninstall_service()
            print("Unenrolled. All proxy configuration removed.")
        else:
            print("Not currently enrolled.")
        return

    existing = load_enrollment()
    if existing:
        print("Already enrolled with %s (%s)" % (existing["server"], existing.get("organization", "")))
        print("Run 'lumen-argus-agent enroll --undo' to unenroll first.")
        return

    server = args.server
    if not server and not args.non_interactive:
        server = input("Enter server URL: ").strip()
    if not server:
        print("Error: --server URL is required", file=sys.stderr)
        sys.exit(1)

    try:
        state = enroll(server, token=args.token)
    except EnrollmentError as e:
        print("Enrollment failed: %s" % e, file=sys.stderr)
        sys.exit(1)

    print("Enrolled with %s" % state["server"])
    if state.get("organization"):
        print("Organization: %s" % state["organization"])

    # Auto-configure tools and enable protection
    from lumen_argus_core.setup_wizard import enable_protection, run_setup

    proxy_url = state["proxy_url"]
    print("\nConfiguring AI tools for %s..." % proxy_url)
    run_setup(proxy_url=proxy_url, non_interactive=True)
    enable_protection(proxy_url=proxy_url)
    print("Protection enabled.")

    # Send first heartbeat
    from lumen_argus_core.telemetry import send_heartbeat

    if send_heartbeat():
        print("Heartbeat sent.")


def _run_relay(args: argparse.Namespace) -> None:
    # Handle --status, --install, --uninstall before starting relay
    if getattr(args, "status", False):
        _relay_status()
        return
    if getattr(args, "uninstall", False):
        _relay_uninstall()
        return
    if getattr(args, "install", False):
        _relay_install(args)
        return

    import asyncio
    import logging

    level = getattr(logging, args.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(levelname)-5s [%(name)s] %(message)s",
    )

    # Lazy import — aiohttp only loaded for relay command
    from lumen_argus_agent.relay import RelayConfig, run_relay

    # Resolve upstream URL: CLI flag > enrollment > default
    upstream = args.upstream
    if not upstream:
        from lumen_argus_core.enrollment import load_enrollment

        enrollment = load_enrollment()
        if enrollment:
            upstream = enrollment.get("proxy_url", "")
    if not upstream:
        upstream = "http://localhost:8080"

    # Load enrollment identity and policy
    agent_id = ""
    agent_token = ""
    machine_id = ""
    fail_mode = args.fail_mode
    send_username = True
    send_hostname = True
    from lumen_argus_core.enrollment import load_enrollment

    enrollment = load_enrollment()
    if enrollment:
        agent_id = enrollment.get("agent_id", "")
        agent_token = enrollment.get("agent_token", "")
        machine_id = enrollment.get("machine_id", "")
        # Enrollment policy can override relay behavior
        policy = enrollment.get("policy", {})
        if isinstance(policy, dict):
            if "fail_mode" in policy:
                policy_fm = policy["fail_mode"]
                if policy_fm in ("open", "closed"):
                    fail_mode = policy_fm
            if "relay_send_username" in policy:
                send_username = bool(policy["relay_send_username"])
            if "relay_send_hostname" in policy:
                send_hostname = bool(policy["relay_send_hostname"])

    config = RelayConfig(
        bind=args.host,
        port=args.port,
        upstream_url=upstream,
        fail_mode=fail_mode,
        agent_id=agent_id,
        agent_token=agent_token,
        machine_id=machine_id,
        send_username=send_username,
        send_hostname=send_hostname,
    )

    asyncio.run(run_relay(config))


def _relay_status() -> None:
    """Print relay service status."""
    from lumen_argus_core.relay_service import get_service_status

    status = get_service_status()
    print("Relay status:")
    print("  Platform:    %s" % status["platform"])
    print("  Service:     %s" % ("installed" if status["installed"] == "true" else "not installed"))
    if status.get("service_path"):
        print("  Service file: %s" % status["service_path"])
    running = status.get("running", "unknown")
    print("  Running:     %s" % running)
    if running == "true":
        print("  Port:        %s" % status.get("port", ""))
        print("  Upstream:    %s" % status.get("upstream_url", ""))
        print("  PID:         %s" % status.get("pid", ""))


def _relay_install(args: argparse.Namespace) -> None:
    """Install relay as system service."""
    from lumen_argus_core.relay_service import install_service

    upstream = args.upstream or ""
    path = install_service(upstream=upstream, fail_mode=args.fail_mode, port=args.port)
    if not path:
        print("Service install not supported on this platform.")
        print("Run 'lumen-argus-agent relay' directly instead.")
        return
    print("Relay service installed: %s" % path)
    print("\nTo start the service:")
    if platform.system() == "Darwin":
        print("  launchctl load %s" % path)
    else:
        print("  systemctl --user daemon-reload")
        print("  systemctl --user enable --now lumen-argus-relay")


def _relay_uninstall() -> None:
    """Remove relay system service."""
    from lumen_argus_core.relay_service import uninstall_service

    if not uninstall_service():
        print("No relay service found to remove.")
        return
    print("Relay service removed.")
    if platform.system() == "Darwin":
        print("Stop the running service: launchctl unload ~/Library/LaunchAgents/io.lumen-argus.relay.plist")
    else:
        print("Stop the running service: systemctl --user stop lumen-argus-relay")


def _run_heartbeat(_args: argparse.Namespace) -> None:
    from lumen_argus_core.enrollment import is_enrolled
    from lumen_argus_core.telemetry import send_heartbeat

    if not is_enrolled():
        print("Not enrolled. Run 'lumen-argus-agent enroll' first.", file=sys.stderr)
        sys.exit(1)

    if send_heartbeat():
        print("Heartbeat sent.")
    else:
        print("Heartbeat failed.", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    handlers = {
        "clients": _run_clients,
        "detect": _run_detect,
        "setup": _run_setup,
        "protection": _run_protection,
        "watch": _run_watch,
        "enroll": _run_enroll,
        "heartbeat": _run_heartbeat,
        "relay": _run_relay,
    }

    handler = handlers.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()
        sys.exit(1)
