"""Log utilities: file handler setup, sanitization, export, and config diffing."""

import logging
import logging.handlers
import os
import re
import sys
from urllib.parse import urlparse

from lumen_argus.provider import DEFAULT_UPSTREAMS


# ---------------------------------------------------------------------------
# Secure rotating file handler and setup
# ---------------------------------------------------------------------------

class SecureRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """RotatingFileHandler that enforces 0o600 on rotated files."""

    def doRollover(self):
        super().doRollover()
        # Secure the new (empty) base file
        if self.baseFilename and os.path.exists(self.baseFilename):
            os.chmod(self.baseFilename, 0o600)
        # Secure the just-rotated file (.1)
        rotated = self.baseFilename + ".1"
        if os.path.exists(rotated):
            os.chmod(rotated, 0o600)


def setup_file_logging(logging_config):
    """Create and configure a secure rotating file handler.

    Args:
        logging_config: LoggingConfig dataclass with log_dir, file_level,
                        max_size_mb, backup_count.

    Returns:
        (file_handler, log_file_path, file_level) tuple.
    """
    file_level = getattr(logging, logging_config.file_level.upper())
    log_dir_path = os.path.expanduser(logging_config.log_dir)
    os.makedirs(log_dir_path, mode=0o700, exist_ok=True)
    log_file_path = os.path.join(log_dir_path, "lumen-argus.log")

    file_handler = SecureRotatingFileHandler(
        log_file_path,
        maxBytes=logging_config.max_size_mb * 1024 * 1024,
        backupCount=logging_config.backup_count,
        encoding="utf-8",
    )
    file_handler.setLevel(file_level)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s.%(msecs)03d %(levelname)-5s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    os.chmod(log_file_path, 0o600)

    return file_handler, log_file_path, file_level


# ---------------------------------------------------------------------------
# Sanitization and export
# ---------------------------------------------------------------------------


def _build_provider_hosts():
    """Derive known provider hostnames from DEFAULT_UPSTREAMS."""
    hosts = set()
    for url in DEFAULT_UPSTREAMS.values():
        try:
            parsed = urlparse(url)
            if parsed.hostname:
                hosts.add(parsed.hostname)
        except Exception:
            pass
    return frozenset(hosts)


_PROVIDER_HOSTS = _build_provider_hosts()

# Regex patterns for sanitization
_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_HOST_RE = re.compile(r"\b([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
_PATH_RE = re.compile(r"(?<!\w)(/[\w./-]+/)([\w.-]+)")


def sanitize_log_line(line, extra_hosts=None):
    """Strip IPs, non-provider hostnames, and file paths from a log line.

    Args:
        line: A single log line string.
        extra_hosts: Optional set of additional hostnames to preserve
                     (e.g. from user-configured upstreams).
    """
    safe_hosts = _PROVIDER_HOSTS
    if extra_hosts:
        safe_hosts = safe_hosts | set(extra_hosts)

    # Replace IP addresses
    line = _IP_RE.sub("[IP]", line)

    # Replace hostnames except known providers
    def replace_host(m):
        host = m.group(0)
        if host in safe_hosts:
            return host
        return "[HOST]"

    line = _HOST_RE.sub(replace_host, line)

    # Replace file paths with basename only (keep the filename)
    line = _PATH_RE.sub(lambda m: m.group(2), line)
    return line


def config_diff(old, new):
    """Compare two Config objects and return list of change descriptions."""
    changes = []
    if old.default_action != new.default_action:
        changes.append("default_action: %s -> %s" % (old.default_action, new.default_action))
    for name in ("secrets", "pii", "proprietary"):
        old_det = getattr(old, name)
        new_det = getattr(new, name)
        if old_det.action != new_det.action:
            changes.append(
                "detectors.%s.action: %s -> %s"
                % (name, old_det.action or "(default)", new_det.action or "(default)")
            )
        if old_det.enabled != new_det.enabled:
            changes.append("detectors.%s.enabled: %s -> %s" % (name, old_det.enabled, new_det.enabled))
    for list_name in ("secrets", "pii", "paths"):
        old_list = getattr(old.allowlist, list_name)
        new_list = getattr(new.allowlist, list_name)
        if sorted(old_list) != sorted(new_list):
            diff = len(new_list) - len(old_list)
            if diff != 0:
                sign = "+" if diff > 0 else ""
                changes.append("allowlist.%s: %s%d entries (now %d)" % (list_name, sign, diff, len(new_list)))
            else:
                changes.append("allowlist.%s: %d entries changed" % (list_name, len(new_list)))
    if old.proxy.timeout != new.proxy.timeout:
        changes.append("proxy.timeout: %d -> %d" % (old.proxy.timeout, new.proxy.timeout))
    if old.proxy.retries != new.proxy.retries:
        changes.append("proxy.retries: %d -> %d" % (old.proxy.retries, new.proxy.retries))
    if old.logging_config.file_level != new.logging_config.file_level:
        changes.append("logging.file_level: %s -> %s" % (old.logging_config.file_level, new.logging_config.file_level))
    return changes


def export_logs(config, sanitize=False):
    """Export log files to stdout, optionally sanitized.

    Reads rotated files in chronological order (oldest first), then current.
    """
    log_dir = os.path.expanduser(config.logging_config.log_dir)
    log_file = os.path.join(log_dir, "lumen-argus.log")

    if not os.path.exists(log_file):
        print("No log file found at %s" % log_file, file=sys.stderr)
        return 1

    # Build extra safe hosts from user-configured upstreams
    extra_hosts = set()
    if sanitize:
        for url in (config.upstreams or {}).values():
            try:
                parsed = urlparse(url)
                if parsed.hostname:
                    extra_hosts.add(parsed.hostname)
            except Exception:
                pass

    # Read rotated files in order (oldest first), then current
    files_to_read = []
    for i in range(config.logging_config.backup_count, 0, -1):
        rotated = "%s.%d" % (log_file, i)
        if os.path.exists(rotated):
            files_to_read.append(rotated)
    files_to_read.append(log_file)

    for path in files_to_read:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if sanitize:
                    line = sanitize_log_line(line, extra_hosts=extra_hosts)
                sys.stdout.write(line)

    return 0
