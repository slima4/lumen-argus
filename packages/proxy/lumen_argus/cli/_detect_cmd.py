"""Detect command — scan for installed AI CLI agents with multiple output modes.

Changes when: detection output format or audit logic changes.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lumen_argus_core.detect_models import DetectionReport, MCPDetectionReport


def run_detect(args: argparse.Namespace) -> None:
    """Execute the 'detect' subcommand — scan for installed AI CLI agents."""
    from lumen_argus_core.detect import detect_installed_clients

    report: DetectionReport = detect_installed_clients(
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
                " — run 'lumen-argus-agent setup'\n" % (len(unconfigured), names)
            )
        return

    mcp_report: MCPDetectionReport | None = None
    if getattr(args, "mcp", False):
        from lumen_argus_core.detect import detect_mcp_servers

        mcp_report = detect_mcp_servers()

    if args.json:
        result = report.to_dict()
        if mcp_report:
            result["mcp_servers"] = mcp_report.to_dict()
        print(json.dumps(result, indent=2))
        return

    if args.audit:
        _print_audit(report)
        return

    _print_standard(report, args.proxy_url)

    if mcp_report:
        _print_mcp(mcp_report)


def _print_audit(report: "DetectionReport") -> None:
    """Audit mode — focus on compliance."""
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


def _print_standard(report: "DetectionReport", proxy_url: str) -> None:
    """Standard output mode."""
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


def _print_mcp(mcp_report: "MCPDetectionReport") -> None:
    """MCP server detection output."""
    from lumen_argus_core.detect_models import format_mcp_table

    print(format_mcp_table(mcp_report, setup_command="lumen-argus-agent setup --mcp"))
