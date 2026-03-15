"""Extension registry with entry point discovery.

Any pip-installed package can register extensions by declaring an entry point
in the "lumen_argus.extensions" group. The entry point should point to a
callable that accepts an ExtensionRegistry instance:

    # In the extension's pyproject.toml:
    [project.entry-points."lumen_argus.extensions"]
    my_plugin = "my_package:register"

    # In my_package/__init__.py:
    def register(registry):
        from my_package.detectors import MyDetector
        registry.add_detector(MyDetector())

This is how lumen-argus-pro registers itself. Community users can also
write custom detectors using the same mechanism.
"""

import logging
import sys
from typing import Callable, List, Optional

from lumen_argus.detectors import BaseDetector
from lumen_argus.models import Finding

log = logging.getLogger("argus.extensions")


class ExtensionRegistry:
    """Discovers and loads extensions via Python entry points."""

    # Type for redact hook: (body: bytes, findings: List[Finding]) -> bytes
    RedactHook = Callable[[bytes, List[Finding]], bytes]

    def __init__(self):
        self._detectors = []  # type: List[BaseDetector]
        self._notifiers = []  # type: list
        self._redact_hook = None  # type: Optional[ExtensionRegistry.RedactHook]

    def add_detector(self, detector: BaseDetector, priority: bool = False) -> None:
        """Register an additional detector.

        Args:
            detector: Detector instance to register.
            priority: If True, prepend (runs before community detectors).
        """
        if priority:
            self._detectors.insert(0, detector)
        else:
            self._detectors.append(detector)

    def add_notifier(self, notifier: object) -> None:
        """Register an additional notifier."""
        self._notifiers.append(notifier)

    def set_redact_hook(self, hook: "ExtensionRegistry.RedactHook") -> None:
        """Register a redaction callback: (body, findings) -> redacted_body."""
        self._redact_hook = hook

    def get_redact_hook(self) -> "Optional[ExtensionRegistry.RedactHook]":
        """Return the registered redaction hook, or None."""
        return self._redact_hook

    def extra_detectors(self) -> List[BaseDetector]:
        return list(self._detectors)

    def extra_notifiers(self) -> list:
        return list(self._notifiers)

    def load_plugins(self) -> None:
        """Discover and load all installed lumen_argus.extensions entry points."""
        try:
            from importlib.metadata import entry_points
        except ImportError:
            # Python 3.8 fallback
            try:
                from importlib_metadata import entry_points
            except ImportError:
                return

        try:
            # Python 3.12+ returns SelectableGroups; 3.9+ supports group kwarg
            eps = entry_points(group="lumen_argus.extensions")
        except TypeError:
            # Python 3.8-3.9: entry_points() returns a dict
            eps = entry_points().get("lumen_argus.extensions", [])

        for ep in eps:
            try:
                register_fn = ep.load()
                register_fn(self)
                log.info("loaded extension: %s", ep.name)
            except Exception as e:
                print(
                    "  [extensions] warning: failed to load '%s': %s" % (ep.name, e),
                    file=sys.stderr,
                )
