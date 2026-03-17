"""Audit logger: thread-safe JSONL writer with secure file permissions."""

import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from lumen_argus.models import AuditEntry

log = logging.getLogger("argus.audit")

_LOG_FILENAME_RE = re.compile(r"^guard-(\d{8})-\d{6}\.jsonl$")


class AuditLogger:
    """Thread-safe JSONL audit log writer."""

    def __init__(self, log_dir: Optional[str] = None, retention_days: int = 90):
        if log_dir:
            self._log_dir = Path(os.path.expanduser(log_dir))
        else:
            self._log_dir = Path.home() / ".lumen-argus" / "audit"

        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._retention_days = retention_days

        # Open log file with secure permissions
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        self._log_path = self._log_dir / ("guard-%s.jsonl" % timestamp)

        # Use os.open for atomic permission setting
        fd = os.open(
            str(self._log_path),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        self._file = os.fdopen(fd, "w")
        self._lock = threading.Lock()

        # Clean up old logs on startup
        self._cleanup_old_logs()

    @property
    def log_path(self) -> Path:
        return self._log_path

    def log(self, entry: AuditEntry) -> None:
        """Write an audit entry as a single JSONL line."""
        line = json.dumps(entry.to_dict(), separators=(",", ":"))
        try:
            with self._lock:
                self._file.write(line + "\n")
                self._file.flush()
        except OSError as e:
            log.error("audit log write failed: %s", e)

    def close(self) -> None:
        """Flush and close the log file. Safe to call multiple times."""
        with self._lock:
            if self._file.closed:
                return
            self._file.flush()
            self._file.close()

    def _cleanup_old_logs(self) -> None:
        """Delete guard-*.jsonl files older than retention_days."""
        if self._retention_days <= 0:
            return
        now = datetime.now(timezone.utc)
        for entry in self._log_dir.iterdir():
            if entry == self._log_path:
                continue  # Don't delete the current log
            m = _LOG_FILENAME_RE.match(entry.name)
            if not m:
                continue
            try:
                file_date = datetime.strptime(m.group(1), "%Y%m%d").replace(
                    tzinfo=timezone.utc
                )
                age_days = (now - file_date).days
                if age_days > self._retention_days:
                    entry.unlink()
                    log.info("audit log rotation: deleted %s (%d days old)", entry.name, age_days)
            except (ValueError, OSError) as e:
                log.error("audit log cleanup failed for %s: %s", entry.name, e)
                continue
