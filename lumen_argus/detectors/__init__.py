"""Detection engine base class and exports."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from lumen_argus.allowlist import AllowlistMatcher
    from lumen_argus.models import Finding, ScanField


class BaseDetector(ABC):
    """Abstract base for all detectors."""

    @abstractmethod
    def scan(
        self,
        fields: "List[ScanField]",
        allowlist: "AllowlistMatcher",
    ) -> "List[Finding]":
        """Scan extracted fields and return findings."""
        ...
