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
        self._post_scan_hook = None  # type: Optional[Callable]
        self._config_reload_hook = None  # type: Optional[Callable]
        self._evaluate_hook = None  # type: Optional[Callable]
        self._loaded_plugins = []  # type: List[tuple]

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

    def set_post_scan_hook(self, hook: Callable) -> None:
        """Register: hook(scan_result, body, provider) called after each scan."""
        self._post_scan_hook = hook

    def get_post_scan_hook(self) -> Optional[Callable]:
        return self._post_scan_hook

    def set_config_reload_hook(self, hook: Callable) -> None:
        """Register: hook(pipeline) called after SIGHUP config reload."""
        self._config_reload_hook = hook

    def get_config_reload_hook(self) -> Optional[Callable]:
        return self._config_reload_hook

    def set_evaluate_hook(self, hook: Callable) -> None:
        """Register: hook(findings, policy) -> ActionDecision.

        If set, called INSTEAD of PolicyEngine.evaluate() — the hook
        fully replaces policy evaluation. The hook receives the findings
        list and the policy instance for access to config (overrides,
        default_action), but should NOT call policy.evaluate() because
        Community Edition downgrades "redact" to "alert" inside it.

        The hook must return an ActionDecision with action and findings.
        On exception, falls back to default policy.evaluate().
        """
        self._evaluate_hook = hook

    def get_evaluate_hook(self) -> Optional[Callable]:
        return self._evaluate_hook

    def extra_detectors(self) -> List[BaseDetector]:
        return list(self._detectors)

    def extra_notifiers(self) -> list:
        return list(self._notifiers)

    def loaded_plugins(self) -> List[tuple]:
        """Return list of (name, version) for loaded plugins."""
        return list(self._loaded_plugins)

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
                # Try to get version from the plugin's distribution
                version = "unknown"
                try:
                    from importlib.metadata import version as get_version
                    version = get_version(ep.name.replace("_", "-"))
                except Exception:
                    pass
                self._loaded_plugins.append((ep.name, version))
                log.info("loaded extension: %s", ep.name)
            except Exception as e:
                log.error("failed to load extension '%s': %s", ep.name, e)
