"""Background watch daemon — detects newly installed AI tools and auto-configures them.

Periodically rescans the system for AI CLI agents. When a new unconfigured tool
is found, it can optionally auto-configure it to route through the proxy.

Supports launchd (macOS) and systemd (Linux) service file generation for
persistent background monitoring.
"""

import json
import logging
import os
import platform
import signal
import sys
import time
from dataclasses import asdict, dataclass, field

log = logging.getLogger("argus.watch")

# Default scan interval: 5 minutes
DEFAULT_INTERVAL_SECONDS = 300

# State file — tracks last known tool set to detect new additions
_STATE_DIR = os.path.expanduser("~/.lumen-argus/watch")
_STATE_FILE = os.path.join(_STATE_DIR, "state.json")

# Service identifiers
_LAUNCHD_LABEL = "io.lumen-argus.watch"
_LAUNCHD_PLIST_DIR = os.path.expanduser("~/Library/LaunchAgents")
_LAUNCHD_PLIST_PATH = os.path.join(_LAUNCHD_PLIST_DIR, "%s.plist" % _LAUNCHD_LABEL)

_SYSTEMD_UNIT_DIR = os.path.expanduser("~/.config/systemd/user")
_SYSTEMD_SERVICE = "lumen-argus-watch.service"
_SYSTEMD_SERVICE_PATH = os.path.join(_SYSTEMD_UNIT_DIR, _SYSTEMD_SERVICE)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class WatchState:
    """Persisted state for the watch daemon."""

    known_clients: dict[str, str] = field(default_factory=dict)  # {client_id: install_method}
    last_scan: str = ""  # ISO timestamp
    proxy_url: str = "http://localhost:8080"


def _load_state() -> WatchState:
    """Load watch state from disk."""
    if not os.path.isfile(_STATE_FILE):
        return WatchState()
    try:
        with open(_STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return WatchState(
            known_clients=data.get("known_clients", {}),
            last_scan=data.get("last_scan", ""),
            proxy_url=data.get("proxy_url", "http://localhost:8080"),
        )
    except (json.JSONDecodeError, OSError) as e:
        log.warning("could not load watch state: %s", e)
        return WatchState()


def _save_state(state: WatchState) -> None:
    """Save watch state to disk."""
    os.makedirs(_STATE_DIR, exist_ok=True)
    try:
        with open(_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(asdict(state), f, indent=2)
    except OSError as e:
        log.error("could not save watch state: %s", e, exc_info=True)


# ---------------------------------------------------------------------------
# Core watch loop
# ---------------------------------------------------------------------------


def scan_once(
    proxy_url: str = "http://localhost:8080",
    auto_configure: bool = False,
    non_interactive: bool = True,
    dry_run: bool = False,
) -> list[str]:
    """Run a single detection pass. Returns list of newly found client IDs.

    Args:
        proxy_url: Expected proxy URL.
        auto_configure: If True, auto-configure new tools via setup wizard.
        non_interactive: Passed to setup wizard.
        dry_run: Passed to setup wizard.

    Returns:
        List of client_id strings for newly detected (previously unknown) tools.
    """
    from lumen_argus_core import detect as _detect_mod
    from lumen_argus_core.time_utils import now_iso

    state = _load_state()
    state.proxy_url = proxy_url

    report = _detect_mod.detect_installed_clients(proxy_url=proxy_url)
    current = {c.client_id: c.install_method for c in report.clients if c.installed}

    # Find new tools (not previously known)
    new_ids = [cid for cid in current if cid not in state.known_clients]

    if new_ids:
        log.info("new tools detected: %s", ", ".join(new_ids))

        if auto_configure:
            from lumen_argus_core.setup.orchestrator import run_setup

            for cid in new_ids:
                log.info("auto-configuring %s", cid)
                run_setup(
                    proxy_url=proxy_url,
                    client_id=cid,
                    non_interactive=non_interactive,
                    dry_run=dry_run,
                )
    else:
        log.debug("no new tools found")

    # Update state
    state.known_clients = current
    state.last_scan = now_iso()
    _save_state(state)

    return new_ids


def run_watch_loop(
    proxy_url: str = "http://localhost:8080",
    interval: int = DEFAULT_INTERVAL_SECONDS,
    auto_configure: bool = False,
) -> None:
    """Run the watch daemon loop. Blocks until SIGTERM/SIGINT.

    Args:
        proxy_url: Expected proxy URL.
        interval: Seconds between scans.
        auto_configure: If True, auto-configure new tools.
    """
    log.info(
        "watch daemon starting (interval=%ds, proxy=%s, auto_configure=%s)",
        interval,
        proxy_url,
        auto_configure,
    )

    running = True

    def _handle_signal(signum: int, _frame: object) -> None:
        nonlocal running
        log.info("received signal %d, shutting down", signum)
        running = False

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    # Initial scan
    scan_once(proxy_url=proxy_url, auto_configure=auto_configure)

    while running:
        # Sleep in small increments to respond to signals quickly
        for _ in range(interval):
            if not running:
                break
            time.sleep(1)

        if running:
            try:
                new = scan_once(proxy_url=proxy_url, auto_configure=auto_configure)
                if new:
                    print("New tools detected: %s" % ", ".join(new))
            except Exception as e:
                log.error("watch scan failed: %s", e, exc_info=True)

    log.info("watch daemon stopped")


# ---------------------------------------------------------------------------
# Service file generation
# ---------------------------------------------------------------------------


def _find_lumen_argus_bin() -> str:
    """Find the lumen-argus binary path."""
    import shutil

    path = shutil.which("lumen-argus")
    if path:
        return path
    # Fallback: python -m lumen_argus
    return "%s -m lumen_argus" % sys.executable


def _validate_proxy_url(url: str) -> str:
    """Validate proxy URL is safe for service file injection. Returns sanitized URL."""
    # Reject newlines, control chars, and shell metacharacters
    if any(c in url for c in ("\n", "\r", "\0", ";", "&", "|", "`", "$", '"', "'")):
        raise ValueError("proxy_url contains unsafe characters: %r" % url)
    if not url.startswith(("http://", "https://")):
        raise ValueError("proxy_url must start with http:// or https://: %r" % url)
    return url


def generate_launchd_plist(
    proxy_url: str = "http://localhost:8080",
    interval: int = DEFAULT_INTERVAL_SECONDS,
    auto_configure: bool = False,
) -> str:
    """Generate a macOS launchd plist for the watch daemon."""
    proxy_url = _validate_proxy_url(proxy_url)
    binary = _find_lumen_argus_bin()
    args = ["watch", "--proxy-url", proxy_url, "--interval", str(interval)]
    if auto_configure:
        args.append("--auto-configure")

    # Build ProgramArguments — handle "python -m lumen_argus" case
    if " -m " in binary:
        parts = binary.split()
        program_args = parts + args
    else:
        program_args = [binary, *args]

    args_xml = "\n".join("        <string>%s</string>" % a for a in program_args)
    log_dir = os.path.expanduser("~/.lumen-argus/logs")

    return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
{args}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log_dir}/watch.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/watch.err</string>
</dict>
</plist>""".format(label=_LAUNCHD_LABEL, args=args_xml, log_dir=log_dir)


def generate_systemd_unit(
    proxy_url: str = "http://localhost:8080",
    interval: int = DEFAULT_INTERVAL_SECONDS,
    auto_configure: bool = False,
) -> str:
    """Generate a Linux systemd user unit for the watch daemon."""
    proxy_url = _validate_proxy_url(proxy_url)
    binary = _find_lumen_argus_bin()
    args = "watch --proxy-url %s --interval %d" % (proxy_url, interval)
    if auto_configure:
        args += " --auto-configure"

    exec_start = "%s %s" % (binary, args)

    return """[Unit]
Description=lumen-argus-agent watch daemon — monitors for new AI tools
After=network.target

[Service]
Type=simple
ExecStart={exec_start}
Restart=on-failure
RestartSec=30

[Install]
WantedBy=default.target""".format(exec_start=exec_start)


# ---------------------------------------------------------------------------
# Service install/uninstall
# ---------------------------------------------------------------------------


def install_service(
    proxy_url: str = "http://localhost:8080",
    interval: int = DEFAULT_INTERVAL_SECONDS,
    auto_configure: bool = False,
) -> str:
    """Install the watch daemon as a system service.

    Returns the path to the installed service file.
    """
    system = platform.system()

    if system == "Darwin":
        content = generate_launchd_plist(proxy_url, interval, auto_configure)
        os.makedirs(_LAUNCHD_PLIST_DIR, exist_ok=True)
        with open(_LAUNCHD_PLIST_PATH, "w", encoding="utf-8") as f:
            f.write(content)
        log.info("launchd plist installed: %s", _LAUNCHD_PLIST_PATH)
        return _LAUNCHD_PLIST_PATH

    elif system == "Linux":
        content = generate_systemd_unit(proxy_url, interval, auto_configure)
        os.makedirs(_SYSTEMD_UNIT_DIR, exist_ok=True)
        with open(_SYSTEMD_SERVICE_PATH, "w", encoding="utf-8") as f:
            f.write(content)
        log.info("systemd unit installed: %s", _SYSTEMD_SERVICE_PATH)
        return _SYSTEMD_SERVICE_PATH

    else:
        log.warning("service install not supported on %s", system)
        return ""


def uninstall_service() -> bool:
    """Remove the watch daemon service file.

    Returns True if a service file was removed.
    """
    system = platform.system()

    if system == "Darwin":
        if os.path.exists(_LAUNCHD_PLIST_PATH):
            os.remove(_LAUNCHD_PLIST_PATH)
            log.info("launchd plist removed: %s", _LAUNCHD_PLIST_PATH)
            return True

    elif system == "Linux" and os.path.exists(_SYSTEMD_SERVICE_PATH):
        os.remove(_SYSTEMD_SERVICE_PATH)
        log.info("systemd unit removed: %s", _SYSTEMD_SERVICE_PATH)
        return True

    return False


def get_service_status() -> dict[str, str]:
    """Get the current watch daemon status.

    Returns dict with keys: installed, running, service_path, state_file,
    last_scan, known_tools_count.
    """
    system = platform.system()
    status: dict[str, str] = {
        "platform": system,
        "installed": "false",
        "service_path": "",
        "last_scan": "",
        "known_tools": "0",
    }

    # Check service file
    if system == "Darwin" and os.path.exists(_LAUNCHD_PLIST_PATH):
        status["installed"] = "true"
        status["service_path"] = _LAUNCHD_PLIST_PATH
    elif system == "Linux" and os.path.exists(_SYSTEMD_SERVICE_PATH):
        status["installed"] = "true"
        status["service_path"] = _SYSTEMD_SERVICE_PATH

    # Check state
    state = _load_state()
    if state.last_scan:
        status["last_scan"] = state.last_scan
        status["known_tools"] = str(len(state.known_clients))

    return status
