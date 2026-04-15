"""Shared test helpers — reduces duplication across 40+ test files.

Usage:
    from tests.helpers import make_finding, make_store, free_port, StoreTestCase
"""

import os
import shutil
import socket
import tempfile
import unittest

from lumen_argus.analytics.store import AnalyticsStore
from lumen_argus.models import Finding


def free_port() -> int:
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_store(tmpdir: str | None = None, hmac_key: bytes | None = None) -> tuple[AnalyticsStore, str]:
    """Create an AnalyticsStore in a temp directory.

    Returns (store, tmpdir). If tmpdir is None, creates a new one — caller
    must clean it up (e.g. shutil.rmtree in tearDown). Prefer StoreTestCase
    for automatic lifecycle management.
    """
    if tmpdir is None:
        tmpdir = tempfile.mkdtemp()
    db_path = os.path.join(tmpdir, "test.db")
    return AnalyticsStore(db_path=db_path, hmac_key=hmac_key), tmpdir


def make_finding(
    detector: str = "secrets",
    type_: str = "aws_access_key",
    severity: str = "critical",
    location: str = "messages[0].content",
    value_preview: str = "AKIA****",
    matched_value: str = "AKIAIOSFODNN7EXAMPLE",
    action: str = "block",
) -> Finding:
    """Create a Finding with sensible test defaults."""
    return Finding(
        detector=detector,
        type=type_,
        severity=severity,
        location=location,
        value_preview=value_preview,
        matched_value=matched_value,
        action=action,
    )


def register_agent(
    store: AnalyticsStore,
    agent_id: str = "agent_1",
    machine_id: str = "machine_1",
    hostname: str = "test-host",
    *,
    os: str = "darwin",
    arch: str = "arm64",
    agent_version: str = "0.1.0",
    enrolled_at: str = "2026-04-15T00:00:00Z",
    seat_cap: int | None = None,
) -> None:
    """Register a test agent with sensible defaults."""
    store.enrollment.register(
        agent_id=agent_id,
        machine_id=machine_id,
        hostname=hostname,
        os=os,
        arch=arch,
        agent_version=agent_version,
        enrolled_at=enrolled_at,
        seat_cap=seat_cap,
    )


def seed_findings(store: AnalyticsStore, count: int = 5) -> list[Finding]:
    """Insert sample findings into the store. Returns the finding list."""
    findings = [
        Finding(
            detector="secrets",
            type="aws_access_key_%d" % i,
            severity="critical",
            location="user_message[%d]" % i,
            matched_value="AKIA" + "X" * 16,
            value_preview="AKIA****%d" % i,
            action="alert",
        )
        for i in range(count)
    ]
    store.record_findings(findings, provider="anthropic", model="claude-opus-4-6")
    return findings


class StoreTestCase(unittest.TestCase):
    """Base test case that sets up and tears down an AnalyticsStore with temp dir.

    Attributes:
        store: AnalyticsStore instance backed by a temp SQLite DB.
        _tmpdir / tmpdir: Path to temp directory (both names for compat).
    """

    store: AnalyticsStore
    _tmpdir: str
    tmpdir: str

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self.tmpdir = self._tmpdir
        self.store = AnalyticsStore(db_path=os.path.join(self._tmpdir, "test.db"))

    def tearDown(self) -> None:
        shutil.rmtree(self._tmpdir, ignore_errors=True)
