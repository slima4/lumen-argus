"""Extension registry stub for Community Edition.

Pro/Enterprise editions install a separate package that registers
additional detectors, notifiers, and exporters via this registry.
The community engine never imports or requires pro code.
"""

from typing import List

from lumen_argus.detectors import BaseDetector


class ExtensionRegistry:
    """No-op registry for Community Edition."""

    def extra_detectors(self) -> List[BaseDetector]:
        return []

    def extra_notifiers(self) -> list:
        return []
