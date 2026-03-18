"""Audit log reader — parses JSONL files from the audit directory.

Reads guard-YYYYMMDD-HHMMSS.jsonl files, parses entries, and serves them
with pagination and filtering. Includes a brief TTL cache to avoid
re-reading files on every dashboard poll.
"""

import glob
import json
import logging
import os
import threading
import time
from typing import List, Optional, Tuple

log = logging.getLogger("argus.audit_reader")

# Cache TTL in seconds
_CACHE_TTL = 10


class AuditReader:
    """Reads and caches audit log entries from JSONL files."""

    def __init__(self, log_dir: str = "~/.lumen-argus/audit"):
        self._log_dir = os.path.expanduser(log_dir)
        self._cache = []  # type: List[dict]
        self._cache_time = 0.0
        self._lock = threading.Lock()

    def read_entries(
        self,
        limit: int = 50,
        offset: int = 0,
        action: Optional[str] = None,
        provider: Optional[str] = None,
        search: Optional[str] = None,
    ) -> Tuple[List[dict], int]:
        """Read audit entries with pagination and filtering.

        Returns (entries, total_count).
        """
        all_entries = self._get_cached_entries()

        filtered = all_entries
        if action:
            filtered = [e for e in filtered if e.get("action") == action]
        if provider:
            filtered = [e for e in filtered if e.get("provider") == provider]
        if search:
            search_lower = search.lower()
            filtered = [
                e for e in filtered
                if search_lower in e.get("endpoint", "").lower()
                or search_lower in e.get("model", "").lower()
                or search_lower in e.get("provider", "").lower()
            ]

        total = len(filtered)
        page = filtered[offset:offset + limit]
        return page, total

    def get_providers(self) -> List[str]:
        """Return list of unique providers from cached entries."""
        entries = self._get_cached_entries()
        providers = set()
        for e in entries:
            p = e.get("provider", "")
            if p:
                providers.add(p)
        return sorted(providers)

    def _get_cached_entries(self) -> List[dict]:
        """Return all parsed entries, using cache if fresh. Thread-safe."""
        with self._lock:
            now = time.monotonic()
            if self._cache_time > 0 and now - self._cache_time < _CACHE_TTL:
                return list(self._cache)

        entries = self._parse_all_files()
        with self._lock:
            self._cache = entries
            self._cache_time = time.monotonic()
            return list(entries)

    _MAX_ENTRIES = 10000

    def _parse_all_files(self) -> List[dict]:
        """Parse JSONL files in the audit directory, newest entries first."""
        if not os.path.isdir(self._log_dir):
            return []

        pattern = os.path.join(self._log_dir, "guard-*.jsonl")
        files = glob.glob(pattern)
        if not files:
            return []

        files.sort(reverse=True)

        all_entries = []
        for filepath in files:
            try:
                entries = self._parse_file(filepath)
                all_entries.extend(entries)
                if len(all_entries) >= self._MAX_ENTRIES:
                    break
            except Exception as e:
                log.warning("failed to read audit file %s: %s", filepath, e)

        all_entries.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        all_entries = all_entries[:self._MAX_ENTRIES]
        return all_entries

    @staticmethod
    def _parse_file(filepath: str) -> List[dict]:
        """Parse a single JSONL file. Skips malformed lines."""
        entries = []
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if isinstance(entry, dict):
                        findings = entry.get("findings", [])
                        entry["finding_count"] = len(findings) if isinstance(findings, list) else 0
                        entries.append(entry)
                except (json.JSONDecodeError, ValueError):
                    continue
        return entries
