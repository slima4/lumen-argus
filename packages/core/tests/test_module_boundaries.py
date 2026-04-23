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


def _iter_core_modules() -> list[Path]:
    """Return every ``.py`` file under ``CORE_DIR`` except ``__pycache__``.

    Recursive walk (was a hardcoded list) so that new subpackages — e.g.
    ``setup/`` — are checked automatically. A silent coverage gap here
    would let a subpackage import from the agent/proxy without the test
    noticing, which is exactly the regression the list was meant to
    prevent.
    """
    return sorted(p for p in CORE_DIR.rglob("*.py") if "__pycache__" not in p.parts)


# Proxy-only modules that core must never import
# Known-but-tracked violations. Each entry is a `(relative_path, module)` pair
# that the agent-import check tolerates while a proper fix (adapter inversion)
# is scheduled. Empty the set — do not add to it — once the inversion lands.
# See task: "Invert relay_service → agent dep via adapter".
_KNOWN_LAZY_AGENT_IMPORTS: set[tuple[str, str]] = {
    ("relay_service.py", "lumen_argus_agent.relay"),
}


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
        for path in _iter_core_modules():
            rel = path.relative_to(CORE_DIR)
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    for proxy_pkg in PROXY_ONLY_PACKAGES:
                        if node.module.startswith(f"lumen_argus.{proxy_pkg}"):
                            violations.append(f"{rel}:{node.lineno} imports lumen_argus.{proxy_pkg}")
        self.assertEqual(
            violations,
            [],
            "Core modules must not import proxy-only modules "
            "(violates core/proxy package boundary):\n" + "\n".join(f"  - {v}" for v in violations),
        )

    def test_core_modules_dont_import_agent(self):
        """Core must not import from lumen_argus_agent — agent depends on core, not reverse.

        Forward-proxy setup previously violated this by importing
        lumen_argus_agent.ca from setup_wizard. The fix inverts the
        dependency via forward_proxy.ForwardProxySetupAdapter; regressing
        here would reintroduce the PyInstaller-bundle breakage where the
        proxy binary has no agent package to import.
        """
        violations = []
        for path in _iter_core_modules():
            rel = str(path.relative_to(CORE_DIR))
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    if node.module == "lumen_argus_agent" or node.module.startswith("lumen_argus_agent."):
                        if (rel, node.module) in _KNOWN_LAZY_AGENT_IMPORTS:
                            continue
                        violations.append(f"{rel}:{node.lineno} imports {node.module}")
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "lumen_argus_agent" or alias.name.startswith("lumen_argus_agent."):
                            if (rel, alias.name) in _KNOWN_LAZY_AGENT_IMPORTS:
                                continue
                            violations.append(f"{rel}:{node.lineno} imports {alias.name}")
        self.assertEqual(
            violations,
            [],
            "Core modules must not import lumen_argus_agent "
            "(reverses the package dependency direction):\n" + "\n".join(f"  - {v}" for v in violations),
        )


if __name__ == "__main__":
    unittest.main()
