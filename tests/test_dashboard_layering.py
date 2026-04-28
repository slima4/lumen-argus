"""Regression tests for community dashboard layering.

The community proxy must ship without any tier-aware gating, locked
placeholders, or upsell copy. These tests pin the boundary so future
edits cannot silently re-introduce hardcoded tier branches in
community-owned files. Tier-aware UI lives in plugin packages.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

DASHBOARD_DIR = Path(__file__).resolve().parents[1] / "packages" / "proxy" / "lumen_argus" / "dashboard"
STATIC_DIR = DASHBOARD_DIR / "static"

# Patterns that must NOT appear anywhere in the community dashboard
# (JS + HTML + CSS + Python handlers). Each tuple is (regex, reason).
FORBIDDEN_PATTERNS: list[tuple[str, str]] = [
    (r"isProActive", "runtime tier gate must live in plugin code"),
    (r"_addLockedSG", "locked-section helper must live in plugin code"),
    (r"_showUpgradePrompt", "upsell prompt must live in plugin code"),
    (r"_renderUpgradePrompt", "upsell prompt helper renamed to _renderLockedCard"),
    (r"\bnotif-upgrade\b", "upsell banner element removed"),
    (r"\bnotif-limit\b", "channel-limit display removed (community is unlimited)"),
    (r"\bproDescription\b", "page option renamed to lockedDescription"),
    (r"\bpro-badge\b", "pro tier badge belongs to plugin code"),
    (r"\bpro_required\b", "402 tier-gating responses live in plugin code"),
    (r"lumen-argus\.com/pro", "marketing URLs must live in plugin code"),
    (r"lumen-argus\.com/trial", "marketing URLs must live in plugin code"),
    (r"Requires Pro", "marketing copy must live in plugin code"),
    (r"Upgrade to Pro", "marketing copy must live in plugin code"),
    (r"Free tier allows", "marketing copy must live in plugin code"),
    (r"Start Free Trial", "marketing copy must live in plugin code"),
    (r"requires.*Pro license", "marketing copy must live in plugin code"),
    (r"freemium", "tier-aware framing must live in plugin code"),
    (r"_PRO_ENDPOINTS", "community must not maintain a list of plugin endpoint prefixes"),
]


def _iter_dashboard_files() -> list[Path]:
    """All community dashboard sources that must stay tier-pure."""
    files: list[Path] = []
    for ext in ("*.js", "*.html", "*.css"):
        files.extend(STATIC_DIR.rglob(ext))
    files.extend(sorted(DASHBOARD_DIR.glob("api*.py")))
    files.append(DASHBOARD_DIR / "server.py")
    return sorted(files)


class TestCommunityDashboardLayering(unittest.TestCase):
    def test_no_forbidden_patterns(self) -> None:
        violations: list[str] = []
        for path in _iter_dashboard_files():
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8")
            for pattern, reason in FORBIDDEN_PATTERNS:
                for match in re.finditer(pattern, text):
                    line_no = text.count("\n", 0, match.start()) + 1
                    violations.append(f"{path.relative_to(DASHBOARD_DIR)}:{line_no}: {pattern} — {reason}")
        if violations:
            self.fail("Community dashboard leaked tier-aware marketing or gating:\n  " + "\n  ".join(violations))

    def test_init_js_does_not_pre_register_locked_pages(self) -> None:
        init_js = (STATIC_DIR / "js" / "init.js").read_text(encoding="utf-8")
        self.assertNotRegex(
            init_js,
            r"registerPage\([^)]*locked\s*:\s*true",
            "init.js must not pre-register locked placeholder pages",
        )


class TestExtensionRegistryDefaults(unittest.TestCase):
    def test_channel_limit_unlimited_by_default(self) -> None:
        from lumen_argus.extensions import ExtensionRegistry

        self.assertIsNone(
            ExtensionRegistry().get_channel_limit(),
            "community ships with no artificial webhook channel cap",
        )


class TestPipelineJSExtensionHook(unittest.TestCase):
    def test_pipeline_js_exposes_register_pipeline_action(self) -> None:
        text = (STATIC_DIR / "js" / "pipeline.js").read_text(encoding="utf-8")
        self.assertIn("registerPipelineAction", text)
        # Base action set is now sourced from core.js ACTIONS
        self.assertIn("ACTIONS.slice()", text)
        self.assertIn("ACTIONS.concat(_extraPipelineActions)", text)


class TestCoreJSSharedActionConstant(unittest.TestCase):
    def test_core_js_uses_actions_placeholder(self) -> None:
        # Raw source must keep the placeholder — no hardcoded JS literal
        text = (STATIC_DIR / "js" / "core.js").read_text(encoding="utf-8")
        self.assertIn("const ACTIONS={{ACTIONS_JSON}}", text)

    def test_rendered_html_substitutes_python_actions(self) -> None:
        from lumen_argus.dashboard.html import COMMUNITY_DASHBOARD_HTML
        from lumen_argus.models import ACTIONS as PY_ACTIONS

        # Placeholder must be gone after render
        self.assertNotIn("{{ACTIONS_JSON}}", COMMUNITY_DASHBOARD_HTML)

        # JSON-encoded Python ACTIONS appears in the rendered JS
        m = re.search(r"const ACTIONS=(\[[^\]]+\])", COMMUNITY_DASHBOARD_HTML)
        self.assertIsNotNone(m, "ACTIONS literal not found in rendered HTML")
        import json as _json

        rendered_actions = tuple(_json.loads(m.group(1)))
        self.assertEqual(
            rendered_actions,
            PY_ACTIONS,
            "Rendered JS ACTIONS must mirror lumen_argus.models.ACTIONS exactly",
        )


class TestSettingsJSExtensionHook(unittest.TestCase):
    def test_settings_js_exposes_register_settings_section(self) -> None:
        text = (STATIC_DIR / "js" / "settings.js").read_text(encoding="utf-8")
        self.assertIn("registerSettingsSection", text)
        self.assertIn("_settingsSections", text)


class TestCoreJSLockedCardContract(unittest.TestCase):
    def test_locked_card_helper_renamed(self) -> None:
        text = (STATIC_DIR / "js" / "core.js").read_text(encoding="utf-8")
        self.assertIn("_renderLockedCard", text)
        # Plugins use lockedDescription, not the old proDescription option.
        self.assertIn("lockedDescription", text)


if __name__ == "__main__":
    unittest.main()
