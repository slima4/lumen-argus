"""Relay command — lightweight forwarder with async lifecycle and signal handling.

Changes when: relay startup, signal handling, or reload logic changes.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys

log = logging.getLogger("argus.cli")


def run_relay(args: argparse.Namespace) -> None:
    """Execute the 'relay' subcommand — lightweight forwarder to engine."""
    import asyncio

    from lumen_argus.config import load_config
    from lumen_argus.provider import ProviderRouter
    from lumen_argus.relay import ArgusRelay

    config = load_config(config_path=args.config)
    bind = args.host or "127.0.0.1"
    port = args.port or config.relay.port
    engine_url = args.engine or config.relay.engine_url
    fail_mode = getattr(args, "fail_mode", None) or config.relay.fail_mode
    router = ProviderRouter(upstreams=config.upstreams)

    # Configure logging — reconfigure the root logger directly since
    # _setup_minimal_logging() already added a handler (basicConfig is a no-op).
    log_level = getattr(logging, args.log_level.upper())
    root = logging.getLogger()
    root.setLevel(log_level)
    for h in root.handlers:
        h.setLevel(log_level)

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
        connect_timeout=config.relay.connect_timeout,
        max_connections=config.relay.max_connections,
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
