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

# Patterns that must NOT appear anywhere in the community dashboard JS or
# HTML template. Each tuple is (regex, human-readable reason).
FORBIDDEN_PATTERNS: list[tuple[str, str]] = [
    (r"isProActive", "runtime tier gate must live in plugin code"),
    (r"_addLockedSG", "locked-section helper must live in plugin code"),
    (r"_showUpgradePrompt", "upsell prompt must live in plugin code"),
    (r"\bnotif-upgrade\b", "upsell banner element removed"),
    (r"\bnotif-limit\b", "channel-limit display removed (community is unlimited)"),
    (r"Requires Pro", "marketing copy must live in plugin code"),
    (r"Upgrade to Pro", "marketing copy must live in plugin code"),
    (r"Free tier allows", "marketing copy must live in plugin code"),
]

# core.js still owns the generic locked-page mechanism (used by plugins
# for the Enrollment tab via the `locked: true` page option). The
# `registerPage` locked branch and `_renderUpgradePrompt` are
# intentionally retained as generic plumbing that community itself
# never invokes.
ALLOW_PRO_DESCRIPTION_IN = {STATIC_DIR / "js" / "core.js"}


def _iter_dashboard_files() -> list[Path]:
    files: list[Path] = []
    for ext in ("*.js", "*.html"):
        files.extend(STATIC_DIR.rglob(ext))
    return sorted(files)


class TestCommunityDashboardLayering(unittest.TestCase):
    def test_no_forbidden_patterns(self) -> None:
        violations: list[str] = []
        for path in _iter_dashboard_files():
            text = path.read_text(encoding="utf-8")
            for pattern, reason in FORBIDDEN_PATTERNS:
                for match in re.finditer(pattern, text):
                    line_no = text.count("\n", 0, match.start()) + 1
                    violations.append(f"{path.relative_to(DASHBOARD_DIR)}:{line_no}: {pattern} — {reason}")
        if violations:
            self.fail("Community dashboard leaked tier-aware marketing or gating:\n  " + "\n  ".join(violations))

    def test_pro_description_only_in_core_js(self) -> None:
        """`proDescription` is part of the generic locked-page contract in core.js.

        Community files (init.js, settings.js, etc.) must never pass it,
        because that would mean community is pre-registering a placeholder
        page with marketing copy baked in. Plugins can still set the
        option when they call registerPage themselves.
        """
        violations: list[str] = []
        for path in _iter_dashboard_files():
            if path in ALLOW_PRO_DESCRIPTION_IN:
                continue
            text = path.read_text(encoding="utf-8")
            for match in re.finditer(r"proDescription", text):
                line_no = text.count("\n", 0, match.start()) + 1
                violations.append(f"{path.relative_to(DASHBOARD_DIR)}:{line_no}")
        if violations:
            self.fail("`proDescription` leaked outside core.js:\n  " + "\n  ".join(violations))

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
        self.assertIn("_BASE_PIPELINE_ACTIONS=['log','alert','block']", text)


class TestSettingsJSExtensionHook(unittest.TestCase):
    def test_settings_js_exposes_register_settings_section(self) -> None:
        text = (STATIC_DIR / "js" / "settings.js").read_text(encoding="utf-8")
        self.assertIn("registerSettingsSection", text)
        self.assertIn("_settingsSections", text)


if __name__ == "__main__":
    unittest.main()
