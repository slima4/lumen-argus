"""Relay service installation — launchd (macOS) and systemd (Linux).

Installs the agent relay as a system service that starts on login,
so AI tools always have a local identity enrichment proxy at :8070.
"""

import logging
import os
import platform
import shlex
import shutil
from xml.sax.saxutils import escape as xml_escape

log = logging.getLogger("argus.relay.service")

_LAUNCHD_LABEL = "io.lumen-argus.relay"
_LAUNCHD_PLIST_DIR = os.path.expanduser("~/Library/LaunchAgents")
_LAUNCHD_PLIST_PATH = os.path.join(_LAUNCHD_PLIST_DIR, "%s.plist" % _LAUNCHD_LABEL)

_SYSTEMD_UNIT_DIR = os.path.expanduser("~/.config/systemd/user")
_SYSTEMD_SERVICE = "lumen-argus-relay.service"
_SYSTEMD_SERVICE_PATH = os.path.join(_SYSTEMD_UNIT_DIR, _SYSTEMD_SERVICE)


def _find_agent_binary() -> str:
    """Find the lumen-argus-agent binary path."""
    path = shutil.which("lumen-argus-agent")
    if path:
        return path
    # Fallback: check common pip install locations
    import sys

    bin_dir = os.path.dirname(sys.executable)
    candidate = os.path.join(bin_dir, "lumen-argus-agent")
    if os.path.isfile(candidate):
        return candidate
    return "lumen-argus-agent"  # hope it's on PATH at login


def generate_launchd_plist(upstream: str = "", fail_mode: str = "open", port: int = 8070) -> str:
    """Generate a macOS LaunchAgent plist for the relay."""
    binary = _find_agent_binary()
    args = [binary, "relay", "--port", str(port)]
    if upstream:
        args.extend(["--upstream", upstream])
    if fail_mode != "open":
        args.extend(["--fail-mode", fail_mode])

    args_xml = "\n".join("        <string>%s</string>" % xml_escape(a) for a in args)

    return """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
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
    <string>{log_dir}/relay.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/relay.log</string>
</dict>
</plist>
""".format(
        label=_LAUNCHD_LABEL,
        args=args_xml,
        log_dir=os.path.expanduser("~/.lumen-argus/logs"),
    )


def generate_systemd_unit(upstream: str = "", fail_mode: str = "open", port: int = 8070) -> str:
    """Generate a Linux systemd user unit for the relay."""
    binary = _find_agent_binary()
    parts = [binary, "relay", "--port", str(port)]
    if upstream:
        parts.extend(["--upstream", upstream])
    if fail_mode != "open":
        parts.extend(["--fail-mode", fail_mode])
    cmd = " ".join(shlex.quote(p) for p in parts)

    return """\
[Unit]
Description=lumen-argus agent relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={cmd}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
""".format(cmd=cmd)


def install_service(upstream: str = "", fail_mode: str = "open", port: int = 8070) -> str:
    """Install the relay as a system service.

    Returns the path to the installed service file, or empty string on
    unsupported platforms.
    """
    system = platform.system()

    if system == "Darwin":
        content = generate_launchd_plist(upstream, fail_mode, port)
        os.makedirs(_LAUNCHD_PLIST_DIR, exist_ok=True)
        log_dir = os.path.expanduser("~/.lumen-argus/logs")
        os.makedirs(log_dir, exist_ok=True)
        with open(_LAUNCHD_PLIST_PATH, "w", encoding="utf-8") as f:
            f.write(content)
        log.info("launchd plist installed: %s", _LAUNCHD_PLIST_PATH)
        return _LAUNCHD_PLIST_PATH

    if system == "Linux":
        content = generate_systemd_unit(upstream, fail_mode, port)
        os.makedirs(_SYSTEMD_UNIT_DIR, exist_ok=True)
        with open(_SYSTEMD_SERVICE_PATH, "w", encoding="utf-8") as f:
            f.write(content)
        log.info("systemd unit installed: %s", _SYSTEMD_SERVICE_PATH)
        return _SYSTEMD_SERVICE_PATH

    log.warning("service install not supported on %s", system)
    return ""


def uninstall_service() -> bool:
    """Remove the relay service file. Returns True if removed."""
    system = platform.system()

    if system == "Darwin" and os.path.exists(_LAUNCHD_PLIST_PATH):
        os.remove(_LAUNCHD_PLIST_PATH)
        log.info("launchd plist removed: %s", _LAUNCHD_PLIST_PATH)
        return True

    if system == "Linux" and os.path.exists(_SYSTEMD_SERVICE_PATH):
        os.remove(_SYSTEMD_SERVICE_PATH)
        log.info("systemd unit removed: %s", _SYSTEMD_SERVICE_PATH)
        return True

    return False


def get_service_status() -> dict[str, str]:
    """Get the relay service status."""
    system = platform.system()
    status: dict[str, str] = {
        "platform": system,
        "installed": "false",
        "service_path": "",
    }

    if system == "Darwin" and os.path.exists(_LAUNCHD_PLIST_PATH):
        status["installed"] = "true"
        status["service_path"] = _LAUNCHD_PLIST_PATH
    elif system == "Linux" and os.path.exists(_SYSTEMD_SERVICE_PATH):
        status["installed"] = "true"
        status["service_path"] = _SYSTEMD_SERVICE_PATH

    # Check relay state file for runtime info
    try:
        from lumen_argus_agent.relay import load_relay_state

        state = load_relay_state()
        if state:
            status["running"] = "true"
            status["port"] = str(state.get("port", ""))
            status["upstream_url"] = state.get("upstream_url", "")
            status["pid"] = str(state.get("pid", ""))
        else:
            status["running"] = "false"
    except ImportError:
        # Agent package not installed (running from core only)
        status["running"] = "unknown"

    return status
