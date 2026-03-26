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


def make_store(tmpdir: str = None, hmac_key: bytes = None) -> AnalyticsStore:
    """Create an AnalyticsStore in a temp directory.

    If tmpdir is None, creates a new temp directory (caller must clean up).
    """
    if tmpdir is None:
        tmpdir = tempfile.mkdtemp()
    db_path = os.path.join(tmpdir, "test.db")
    return AnalyticsStore(db_path=db_path, hmac_key=hmac_key)


def make_finding(
    detector="secrets",
    type_="aws_access_key",
    severity="critical",
    location="messages[0].content",
    value_preview="AKIA****",
    matched_value="AKIAIOSFODNN7EXAMPLE",
    action="block",
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


def seed_findings(store: AnalyticsStore, count: int = 5) -> list:
    """Insert sample findings into the store. Returns the finding list."""
    findings = []
    for i in range(count):
        findings.append(
            Finding(
                detector="secrets",
                type="aws_access_key_%d" % i,
                severity="critical",
                location="user_message[%d]" % i,
                matched_value="AKIA" + "X" * 16,
                value_preview="AKIA****%d" % i,
                action="alert",
            )
        )
    store.record_findings(findings, provider="anthropic", model="claude-opus-4-6")
    return findings


class StoreTestCase(unittest.TestCase):
    """Base test case that sets up and tears down an AnalyticsStore with temp dir."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.store = AnalyticsStore(db_path=os.path.join(self._tmpdir, "test.db"))

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)
