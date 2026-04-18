"""Tests for the shared build_info helper (sidecar-build-identity-spec.md)."""

from __future__ import annotations

import hashlib
import importlib
import sys
import types
import unittest

from lumen_argus_core import build_info as bi


class TestComputeBuildId(unittest.TestCase):
    def setUp(self):
        bi.compute_build_id.cache_clear()

    def tearDown(self):
        bi.compute_build_id.cache_clear()

    def test_shape(self):
        result = bi.compute_build_id()
        self.assertTrue(result.startswith("sha256:"))
        # Either a 64-char hex digest or the "unknown" sentinel.
        suffix = result[len("sha256:") :]
        self.assertTrue(suffix == "unknown" or (len(suffix) == 64 and all(c in "0123456789abcdef" for c in suffix)))

    def test_matches_sys_executable_hash(self):
        with open(sys.executable, "rb") as f:
            expected = "sha256:" + hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(bi.compute_build_id(), expected)

    def test_stable_across_calls(self):
        self.assertEqual(bi.compute_build_id(), bi.compute_build_id())


class TestGetBuildInfoFallback(unittest.TestCase):
    """When _build_info is absent (dev runs) the helper falls back cleanly."""

    def setUp(self):
        bi.compute_build_id.cache_clear()
        # Ensure no stale _build_info modules linger from other tests.
        for mod in ("lumen_argus._build_info", "lumen_argus_agent._build_info"):
            sys.modules.pop(mod, None)

    def test_proxy_fallback(self):
        info = bi.get_build_info("lumen-argus", "9.9.9")
        self.assertEqual(info["service"], "lumen-argus")
        self.assertEqual(info["version"], "9.9.9")
        self.assertEqual(info["git_commit"], "unknown")
        self.assertEqual(info["built_at"], "unknown")
        self.assertTrue(info["build_id"].startswith("sha256:"))

    def test_agent_fallback(self):
        info = bi.get_build_info("lumen-argus-agent", "0.2.0")
        self.assertEqual(info["service"], "lumen-argus-agent")
        self.assertEqual(info["version"], "0.2.0")

    def test_unknown_service_fallback(self):
        info = bi.get_build_info("something-else", "1.0.0")
        self.assertEqual(info["service"], "something-else")
        self.assertEqual(info["version"], "1.0.0")
        self.assertEqual(info["git_commit"], "unknown")


class TestGetBuildInfoPopulated(unittest.TestCase):
    """When _build_info is present the helper reads it verbatim."""

    def setUp(self):
        bi.compute_build_id.cache_clear()
        # Install a synthetic _build_info module for the proxy service.
        mod = types.ModuleType("lumen_argus._build_info")
        mod.VERSION = "1.2.3"
        mod.GIT_COMMIT = "deadbeef" * 5
        mod.BUILT_AT = "2026-04-15T12:34:56Z"
        # Parent package may not be on the path in test mode — stub it too.
        parent = sys.modules.get("lumen_argus")
        if parent is None:
            parent = types.ModuleType("lumen_argus")
            sys.modules["lumen_argus"] = parent
            self._added_parent = True
        else:
            self._added_parent = False
        sys.modules["lumen_argus._build_info"] = mod

    def tearDown(self):
        sys.modules.pop("lumen_argus._build_info", None)
        if self._added_parent:
            sys.modules.pop("lumen_argus", None)
        importlib.invalidate_caches()

    def test_reads_module_constants(self):
        info = bi.get_build_info("lumen-argus", "ignored-fallback")
        self.assertEqual(info["version"], "1.2.3")
        self.assertEqual(info["git_commit"], "deadbeef" * 5)
        self.assertEqual(info["built_at"], "2026-04-15T12:34:56Z")


if __name__ == "__main__":
    unittest.main()
