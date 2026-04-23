"""Tests for _setup_forward_proxy dispatch through the adapter registry.

Covers both sides of the inversion:

* adapter present — wizard calls ensure_ca / get_ca_cert_path / etc.
* adapter absent — wizard raises ForwardProxyUnavailable so the caller
  can skip the tool cleanly (this is the case in proxy-only PyInstaller
  bundles, which is the bug that motivated the refactor).
"""

from __future__ import annotations

import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from lumen_argus_core import forward_proxy, setup_wizard
from lumen_argus_core.detect_models import DetectedClient


class _RecordingAdapter:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def ca_exists(self) -> bool:
        self.calls.append("ca_exists")
        return True  # skip generation branch — simpler assertion

    def ensure_ca(self) -> str:
        self.calls.append("ensure_ca")
        return "/tmp/ca.pem"

    def get_ca_cert_path(self) -> str:
        self.calls.append("get_ca_cert_path")
        return "/tmp/ca.pem"

    def is_ca_trusted(self) -> bool:
        self.calls.append("is_ca_trusted")
        return True  # skip install prompt

    def install_ca_system(self) -> bool:
        self.calls.append("install_ca_system")
        return True


class TestForwardProxyDispatch(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = forward_proxy.get_adapter()
        forward_proxy.unregister_adapter()
        self._tmp = tempfile.mkdtemp()
        self._aliases_patch = mock.patch.object(
            setup_wizard, "_ALIASES_PATH", os.path.join(self._tmp, "forward-proxy-aliases.sh")
        )
        self._aliases_patch.start()

    def tearDown(self) -> None:
        self._aliases_patch.stop()
        forward_proxy.unregister_adapter()
        if self._saved is not None:
            forward_proxy.register_adapter(self._saved)
        import shutil

        shutil.rmtree(self._tmp, ignore_errors=True)

    def _target(self) -> DetectedClient:
        return DetectedClient(
            client_id="copilot_cli",
            display_name="GitHub Copilot CLI",
            installed=True,
            forward_proxy=True,
        )

    def test_adapter_absent_raises_unavailable(self) -> None:
        """Proxy-only PyInstaller bundle case: no adapter, clean error."""
        buf = io.StringIO()
        with redirect_stdout(buf), self.assertRaises(forward_proxy.ForwardProxyUnavailable) as ctx:
            setup_wizard._setup_forward_proxy(
                self._target(),
                "",
                non_interactive=True,
                dry_run=True,
            )
        # Message must name the agent binary so the CLI surface forwards it.
        self.assertIn("lumen-argus-agent", str(ctx.exception))
        # Human-readable pointer printed before the exception. Uses the
        # positional form that both lumen-argus and lumen-argus-agent
        # argparse parsers actually accept (no --client flag exists).
        self.assertIn("lumen-argus-agent setup copilot_cli", buf.getvalue())
        self.assertNotIn("--client", buf.getvalue())

    def test_adapter_present_dispatches_ca_calls(self) -> None:
        adapter = _RecordingAdapter()
        forward_proxy.register_adapter(adapter)

        buf = io.StringIO()
        with redirect_stdout(buf):
            changes = setup_wizard._setup_forward_proxy(
                self._target(),
                profile_path="",
                non_interactive=True,
                dry_run=True,
            )

        # ca_exists short-circuits the generation branch; ensure_ca must NOT
        # have been called in that case.
        self.assertIn("ca_exists", adapter.calls)
        self.assertNotIn("ensure_ca", adapter.calls)
        self.assertIn("get_ca_cert_path", adapter.calls)
        # Dry-run + non-interactive means no profile changes, but an alias
        # SetupChange is still recorded.
        self.assertTrue(any(c.method == "forward_proxy_aliases" for c in changes))

    def test_adapter_present_generates_ca_when_missing(self) -> None:
        class _MissingCA(_RecordingAdapter):
            def ca_exists(self) -> bool:
                self.calls.append("ca_exists")
                return False

        adapter = _MissingCA()
        forward_proxy.register_adapter(adapter)

        buf = io.StringIO()
        with redirect_stdout(buf):
            setup_wizard._setup_forward_proxy(
                self._target(),
                profile_path="",
                non_interactive=True,
                dry_run=False,
            )

        self.assertIn("ensure_ca", adapter.calls)


if __name__ == "__main__":
    unittest.main()
