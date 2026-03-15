"""Allowlist matching — skip known-safe values from detection."""

import fnmatch
from typing import List


class AllowlistMatcher:
    """Checks values against configured allowlists."""

    def __init__(
        self,
        secrets: List[str] = None,
        pii: List[str] = None,
        paths: List[str] = None,
    ):
        self._secrets = secrets or []
        self._pii = pii or []
        self._paths = paths or []

    def is_allowed_secret(self, value: str) -> bool:
        """Check if a secret value is in the allowlist."""
        for pattern in self._secrets:
            if pattern == value:
                return True
            if fnmatch.fnmatch(value, pattern):
                return True
        return False

    def is_allowed_pii(self, value: str) -> bool:
        """Check if a PII value is in the allowlist."""
        for pattern in self._pii:
            if pattern == value:
                return True
            if fnmatch.fnmatch(value, pattern):
                return True
        return False

    def is_allowed_path(self, path: str) -> bool:
        """Check if a file path is in the path allowlist."""
        for pattern in self._paths:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False
