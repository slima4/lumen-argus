"""Verify core modules don't import from proxy-only modules.

Enforces the core/proxy package split boundary. Core modules live in
packages/core/lumen_argus_core/ and must only import from stdlib or
other core modules.

See: agent-package-split-spec.md
"""

import ast
import unittest
from pathlib import Path

CORE_DIR = Path("packages/core/lumen_argus_core")

CORE_MODULES = ["clients.py", "detect.py", "setup_wizard.py", "watch.py", "time_utils.py"]

# Proxy-only modules that core must never import
PROXY_ONLY_PACKAGES = [
    "async_proxy",
    "pipeline",
    "dashboard",
    "analytics",
    "detectors",
    "patterns",
    "policy",
    "audit",
    "relay",
    "response_scanner",
    "ws_proxy",
    "mcp",
    "decoders",
    "validators",
    "session",
    "models",
    "config",
    "rule_analysis",
    "notifiers",
]


class TestModuleBoundaries(unittest.TestCase):
    """Core modules must not import from proxy-only modules."""

    def test_core_modules_dont_import_proxy(self):
        violations = []
        for mod_file in CORE_MODULES:
            path = CORE_DIR / mod_file
            if not path.exists():
                continue
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    for proxy_pkg in PROXY_ONLY_PACKAGES:
                        if node.module.startswith(f"lumen_argus.{proxy_pkg}"):
                            violations.append(f"{mod_file}:{node.lineno} imports lumen_argus.{proxy_pkg}")
        self.assertEqual(
            violations,
            [],
            "Core modules must not import proxy-only modules "
            "(violates core/proxy package boundary):\n" + "\n".join(f"  - {v}" for v in violations),
        )


if __name__ == "__main__":
    unittest.main()
