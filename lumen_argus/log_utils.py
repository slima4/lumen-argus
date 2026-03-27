"""Log utilities: file handler setup, sanitization, export, and config diffing."""

import io
import logging
import logging.handlers
import os
import re
import sys
from typing import Any
from urllib.parse import urlparse

from lumen_argus.provider import DEFAULT_UPSTREAMS

log = logging.getLogger("argus.log_utils")

# ---------------------------------------------------------------------------
# Input sanitization — log injection prevention (OWASP / Sonar S5145)
# ---------------------------------------------------------------------------

_CONTROL_CHAR_RE = re.compile(r"[\r\n\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _strip_control_chars(value: str) -> str:
    """Strip control characters that enable log injection / CRLF attacks."""
    return _CONTROL_CHAR_RE.sub("", value)


def sanitize_user_input(data: Any) -> Any:
    """Recursively sanitize user-controlled data at the API boundary.

    Strips control characters from all string keys and values in dicts,
    lists, and scalar strings. Non-string scalars pass through unchanged.
    Call once at the entry point — all downstream code (logging, storage,
    validation) then works with clean data.
    """
    if isinstance(data, dict):
        return {_strip_control_chars(str(k)): sanitize_user_input(v) for k, v in data.items()}
    if isinstance(data, list):
        return [sanitize_user_input(item) for item in data]
    if isinstance(data, str):
        return _strip_control_chars(data)
    return data


# ---------------------------------------------------------------------------
# Secure rotating file handler and setup
# ---------------------------------------------------------------------------


class SecureRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """RotatingFileHandler that creates files with 0o600 permissions.

    Overrides _open() to use os.open() with O_CREAT for atomic permission
    setting — no race window between file creation and chmod. Follows the
    same pattern as AuditLogger.
    """

    def _open(self) -> io.TextIOWrapper:
        """Open the log file with 0o600 permissions atomically."""
        fd = os.open(
            self.baseFilename,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600,
        )
        return io.TextIOWrapper(io.FileIO(fd, self.mode), encoding=self.encoding)


def setup_file_logging(logging_config: Any) -> tuple[SecureRotatingFileHandler, str, int]:
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
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s.%(msecs)03d %(levelname)-5s [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    return file_handler, log_file_path, file_level


# ---------------------------------------------------------------------------
# Sanitization and export
# ---------------------------------------------------------------------------


def _build_provider_hosts() -> frozenset[str]:
    """Derive known provider hostnames from DEFAULT_UPSTREAMS."""
    hosts: set[str] = set()
    for url in DEFAULT_UPSTREAMS.values():
        try:
            parsed = urlparse(url)
            if parsed.hostname:
                hosts.add(parsed.hostname)
        except Exception:
            log.debug("failed to parse provider URL: %s", url, exc_info=True)
    return frozenset(hosts)


_PROVIDER_HOSTS = _build_provider_hosts()

# Regex patterns for sanitization
_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_HOST_RE = re.compile(r"\b([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
# Match absolute paths: /dir/dir/file or /dir/file or ~/dir/file
_PATH_RE = re.compile(r"(?<!\w)(~?/[\w./-]+)")


def sanitize_log_line(line: str, extra_hosts: set[str] | None = None) -> str:
    """Strip IPs, non-provider hostnames, and file paths from a log line.

    Args:
        line: A single log line string.
        extra_hosts: Optional set of additional hostnames to preserve
                     (e.g. from user-configured upstreams).
    """
    safe_hosts: frozenset[str] | set[str] = _PROVIDER_HOSTS
    if extra_hosts:
        safe_hosts = _PROVIDER_HOSTS | set(extra_hosts)

    # Replace IP addresses
    line = _IP_RE.sub("[IP]", line)

    # Replace hostnames except known providers
    def replace_host(m: re.Match[str]) -> str:
        host = m.group(0)
        if host in safe_hosts:
            return host
        return "[HOST]"

    line = _HOST_RE.sub(replace_host, line)

    # Replace file paths with basename only (keep the filename)
    line = _PATH_RE.sub(lambda m: os.path.basename(m.group(1)) or "[PATH]", line)
    return line


def config_diff(old: Any, new: Any) -> list[str]:
    """Compare two Config objects and return list of change descriptions."""
    changes = []
    if old.default_action != new.default_action:
        changes.append("default_action: %s -> %s" % (old.default_action, new.default_action))
    for name in ("secrets", "pii", "proprietary"):
        old_det = getattr(old, name)
        new_det = getattr(new, name)
        if old_det.action != new_det.action:
            changes.append(
                "detectors.%s.action: %s -> %s" % (name, old_det.action or "(default)", new_det.action or "(default)")
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
    if old.proxy.max_connections != new.proxy.max_connections:
        changes.append("proxy.max_connections: %d -> %d" % (old.proxy.max_connections, new.proxy.max_connections))
    if old.proxy.drain_timeout != new.proxy.drain_timeout:
        changes.append("proxy.drain_timeout: %d -> %d" % (old.proxy.drain_timeout, new.proxy.drain_timeout))
    if old.proxy.ca_bundle != new.proxy.ca_bundle:
        changes.append(
            "proxy.ca_bundle: %s -> %s" % (old.proxy.ca_bundle or "(system)", new.proxy.ca_bundle or "(system)")
        )
    if old.proxy.verify_ssl != new.proxy.verify_ssl:
        changes.append("proxy.verify_ssl: %s -> %s" % (old.proxy.verify_ssl, new.proxy.verify_ssl))
    # Dashboard (requires restart)
    if old.dashboard.enabled != new.dashboard.enabled:
        changes.append(
            "dashboard.enabled: %s -> %s (restart required)" % (old.dashboard.enabled, new.dashboard.enabled)
        )
    if old.dashboard.port != new.dashboard.port:
        changes.append("dashboard.port: %d -> %d (restart required)" % (old.dashboard.port, new.dashboard.port))
    if old.dashboard.bind != new.dashboard.bind:
        changes.append("dashboard.bind: %s -> %s (restart required)" % (old.dashboard.bind, new.dashboard.bind))
    if old.dashboard.password != new.dashboard.password:
        changes.append("dashboard.password: changed (restart required)")
    # Analytics (requires restart)
    if old.analytics.enabled != new.analytics.enabled:
        changes.append(
            "analytics.enabled: %s -> %s (restart required)" % (old.analytics.enabled, new.analytics.enabled)
        )
    if old.analytics.db_path != new.analytics.db_path:
        changes.append("analytics.db_path: changed (restart required)")
    if old.analytics.retention_days != new.analytics.retention_days:
        changes.append(
            "analytics.retention_days: %d -> %d (restart required)"
            % (old.analytics.retention_days, new.analytics.retention_days)
        )
    return changes


def export_logs(config: Any, sanitize: bool = False) -> int:
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
                log.debug("failed to parse upstream URL: %s", url, exc_info=True)

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
