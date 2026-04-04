"""MCP scanning proxy CLI — 'lumen-argus mcp' subcommand.

Builds a lightweight detector stack (no DB, no pipeline, no rules engine),
resolves transport mode, and dispatches to mcp/proxy.py.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.extensions import ExtensionRegistry

log = logging.getLogger("argus.mcp")


def run_mcp(args: argparse.Namespace, extensions: ExtensionRegistry | None = None) -> None:
    """Run the unified MCP scanning proxy."""
    from lumen_argus.config import load_config
    from lumen_argus.extensions import ExtensionRegistry as _ER
    from lumen_argus.mcp.scanner import MCPScanner
    from lumen_argus.scanner import _build_allowlist

    # Determine transport mode from flags
    upstream = getattr(args, "upstream", None)
    listen = getattr(args, "listen", None)
    cmd = args.server_command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]

    _validate_transport_args(upstream, listen, cmd)

    # Set log level
    log_level = getattr(logging, args.log_level.upper())
    logging.getLogger().setLevel(log_level)

    # Load config
    config = load_config(config_path=args.config)

    # Build detectors (lightweight — no DB, no rules engine, just hardcoded patterns)
    from lumen_argus.detectors import BaseDetector
    from lumen_argus.detectors.pii import PIIDetector
    from lumen_argus.detectors.secrets import SecretsDetector

    detectors: list[BaseDetector] = []
    if config.secrets.enabled:
        detectors.append(SecretsDetector(entropy_threshold=config.entropy_threshold))
    if config.pii.enabled:
        detectors.append(PIIDetector())

    allowlist = _build_allowlist(config)

    # Build response scanner for injection detection in tool responses
    response_scanner = None
    if config.pipeline.mcp_responses.enabled:
        from lumen_argus.response_scanner import ResponseScanner

        response_scanner = ResponseScanner(scan_secrets=False, scan_injection=True)

    # Parse allow/block lists from config + DB
    mcp_cfg = getattr(config, "mcp", None)
    mcp_store = _open_mcp_store(config, mcp_cfg)
    allowed_tools, blocked_tools = _load_mcp_tool_sets(config, mcp_cfg, mcp_store)

    # Load extensions (Pro hooks for policy engine + adaptive enforcement)
    if extensions is None:
        extensions = _ER()
        extensions.load_plugins()
    policy_engine = extensions.get_mcp_policy_engine()
    escalation_fn = extensions.get_mcp_session_escalation()

    # Determine action (CLI flag > config)
    action_override = getattr(args, "action", None)
    action = action_override or config.pipeline.mcp_arguments.action or config.default_action

    # Phase 2 security features
    request_tracker = _build_request_tracker(mcp_cfg)
    session_binding_obj = _build_session_binding(mcp_cfg)

    scanner = MCPScanner(
        detectors=detectors,
        allowlist=allowlist,
        response_scanner=response_scanner,
        scan_arguments=config.pipeline.mcp_arguments.enabled,
        scan_responses=config.pipeline.mcp_responses.enabled,
        allowed_tools=allowed_tools or None,
        blocked_tools=blocked_tools or None,
        action=action,
        request_tracker=request_tracker,
        session_binding=session_binding_obj,
        scan_tool_descriptions=mcp_cfg.scan_tool_descriptions if mcp_cfg else True,
        detect_drift=mcp_cfg.detect_drift if mcp_cfg else True,
        drift_action=mcp_cfg.drift_action if mcp_cfg else "alert",
        store=mcp_store if (mcp_cfg and mcp_cfg.detect_drift) else None,
    )

    # Dispatch to appropriate transport mode
    if cmd:
        _run_stdio(args, cmd, scanner, mcp_cfg, policy_engine, escalation_fn)
    elif listen:
        _run_http_listener(listen, upstream, scanner, policy_engine, escalation_fn)
    else:
        _run_bridge(upstream, scanner, policy_engine, escalation_fn)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validate_transport_args(upstream: str | None, listen: str | None, cmd: list[str] | None) -> None:
    """Validate mutually exclusive transport mode arguments."""
    if listen and not upstream:
        print("Error: --listen requires --upstream", file=sys.stderr)
        sys.exit(1)
    if not upstream and not cmd:
        print(
            "Error: Provide a server command (lumen-argus mcp -- <command>) or --upstream URL",
            file=sys.stderr,
        )
        sys.exit(1)
    if upstream and cmd:
        print("Error: Cannot use both --upstream and a server command", file=sys.stderr)
        sys.exit(1)


def _open_mcp_store(config: Any, mcp_cfg: Any) -> Any:
    """Open a single AnalyticsStore for tool lists and drift detection."""
    if not config.analytics.enabled:
        return None
    try:
        from lumen_argus.analytics.store import AnalyticsStore

        return AnalyticsStore(db_path=os.path.expanduser(config.analytics.db_path))
    except Exception as e:
        log.warning("mcp: could not open analytics store: %s", e)
        return None


def _load_mcp_tool_sets(config: Any, mcp_cfg: Any, store: Any) -> tuple[set[str], set[str]]:
    """Load allowed/blocked tool sets from config + DB."""
    allowed = set(mcp_cfg.allowed_tools) if mcp_cfg and mcp_cfg.allowed_tools else set()
    blocked = set(mcp_cfg.blocked_tools) if mcp_cfg and mcp_cfg.blocked_tools else set()
    if store:
        try:
            db_lists = store.get_mcp_tool_lists()
            allowed.update(e["tool_name"] for e in db_lists.get("allowed", []))
            blocked.update(e["tool_name"] for e in db_lists.get("blocked", []))
            store.reconcile_mcp_tool_lists(
                mcp_cfg.allowed_tools if mcp_cfg else [],
                mcp_cfg.blocked_tools if mcp_cfg else [],
            )
        except Exception as e:
            log.warning("mcp: could not load tool lists from DB: %s", e)
    return allowed, blocked


def _build_request_tracker(mcp_cfg: Any) -> Any:
    if mcp_cfg and mcp_cfg.request_tracking:
        from lumen_argus.mcp.request_tracker import RequestTracker

        return RequestTracker(action=mcp_cfg.unsolicited_response_action)
    return None


def _build_session_binding(mcp_cfg: Any) -> Any:
    if mcp_cfg and mcp_cfg.session_binding:
        from lumen_argus.mcp.session_binding import SessionBinding

        return SessionBinding(action=mcp_cfg.unknown_tool_action)
    return None


def _run_stdio(args: Any, cmd: list[str], scanner: Any, mcp_cfg: Any, policy_engine: Any, escalation_fn: Any) -> None:
    import asyncio

    from lumen_argus.mcp.proxy import run_stdio_proxy

    env = None
    no_env_filter = getattr(args, "no_env_filter", False)
    if not no_env_filter:
        from lumen_argus.mcp.env_filter import filter_env

        extra_vars = {}
        for item in getattr(args, "env", []):
            if "=" in item:
                k, v = item.split("=", 1)
                extra_vars[k] = v
        env_allowlist = getattr(mcp_cfg, "env_allowlist", []) if mcp_cfg else []
        env = filter_env(extra_vars=extra_vars, config_allowlist=env_allowlist)

    exit_code = asyncio.run(
        run_stdio_proxy(cmd, scanner, env=env, policy_engine=policy_engine, escalation_fn=escalation_fn)
    )
    sys.exit(exit_code)


def _run_http_listener(listen: str, upstream: str | None, scanner: Any, policy_engine: Any, escalation_fn: Any) -> None:
    import asyncio

    from lumen_argus.mcp.proxy import run_http_listener

    if upstream is None:
        print("Error: --upstream is required with --listen", file=sys.stderr)
        sys.exit(1)
    if ":" in listen:
        parts = listen.rsplit(":", 1)
        host = parts[0] or "127.0.0.1"
        port = int(parts[1])
    else:
        host = "127.0.0.1"
        port = int(listen)

    asyncio.run(
        run_http_listener(host, port, upstream, scanner, policy_engine=policy_engine, escalation_fn=escalation_fn)
    )


def _run_bridge(upstream: str | None, scanner: Any, policy_engine: Any, escalation_fn: Any) -> None:
    import asyncio

    if upstream is None:
        print("Error: --upstream is required for bridge mode", file=sys.stderr)
        sys.exit(1)
    if upstream.startswith(("ws://", "wss://")):
        from lumen_argus.mcp.proxy import run_ws_bridge

        exit_code = asyncio.run(
            run_ws_bridge(upstream, scanner, policy_engine=policy_engine, escalation_fn=escalation_fn)
        )
    else:
        from lumen_argus.mcp.proxy import run_http_bridge

        exit_code = asyncio.run(
            run_http_bridge(upstream, scanner, policy_engine=policy_engine, escalation_fn=escalation_fn)
        )
    sys.exit(exit_code)
