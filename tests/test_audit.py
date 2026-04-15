"""Tests for the audit logger."""

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from lumen_argus.audit import AuditLogger
from lumen_argus.models import AuditEntry, Finding


class TestAuditLogger(unittest.TestCase):
    def test_creates_log_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(log_dir=tmpdir)
            self.assertTrue(logger.log_path.exists())
            logger.close()

    def test_file_permissions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(log_dir=tmpdir)
            stat = os.stat(logger.log_path)
            mode = oct(stat.st_mode & 0o777)
            self.assertEqual(mode, "0o600")
            logger.close()

    def test_writes_jsonl(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(log_dir=tmpdir)
            entry = AuditEntry(
                timestamp="2026-03-14T10:30:00.123Z",
                request_id=1,
                provider="anthropic",
                model="claude-opus-4-6",
                endpoint="/v1/messages",
                action="alert",
                findings=[
                    Finding(
                        detector="secrets",
                        type="aws_access_key",
                        severity="critical",
                        location="messages[4]",
                        value_preview="AKIA****",
                        matched_value="AKIAIOSFODNN7REAL",
                        action="alert",
                    ),
                ],
                scan_duration_ms=12.5,
                request_size_bytes=45000,
                passed=True,
            )
            logger.log(entry)
            logger.close()

            # Read and verify
            with open(logger.log_path) as f:
                line = f.readline()
                data = json.loads(line)

            self.assertEqual(data["request_id"], 1)
            self.assertEqual(data["provider"], "anthropic")
            self.assertEqual(data["action"], "alert")
            self.assertEqual(len(data["findings"]), 1)
            self.assertEqual(data["findings"][0]["type"], "aws_access_key")
            self.assertEqual(data["findings"][0]["value_preview"], "AKIA****")

    def test_matched_value_not_in_log(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(log_dir=tmpdir)
            entry = AuditEntry(
                timestamp="2026-03-14T10:30:00.123Z",
                request_id=1,
                provider="anthropic",
                model="claude-opus-4-6",
                endpoint="/v1/messages",
                action="block",
                findings=[
                    Finding(
                        detector="secrets",
                        type="aws_access_key",
                        severity="critical",
                        location="messages[0]",
                        value_preview="AKIA****",
                        matched_value="AKIAIOSFODNN7SECRETVALUE",
                        action="block",
                    ),
                ],
                scan_duration_ms=5.0,
                request_size_bytes=1000,
                passed=False,
            )
            logger.log(entry)
            logger.close()

            # Verify matched_value is NOT in the log output
            with open(logger.log_path) as f:
                content = f.read()
            self.assertNotIn("AKIAIOSFODNN7SECRETVALUE", content)
            self.assertNotIn("matched_value", content)

    def test_multiple_entries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(log_dir=tmpdir)
            for i in range(5):
                entry = AuditEntry(
                    timestamp="2026-03-14T10:30:0%d.000Z" % i,
                    request_id=i + 1,
                    provider="anthropic",
                    model="claude-opus-4-6",
                    endpoint="/v1/messages",
                    action="pass",
                    scan_duration_ms=1.0,
                    request_size_bytes=100,
                    passed=True,
                )
                logger.log(entry)
            logger.close()

            with open(logger.log_path) as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 5)


class TestLogRotation(unittest.TestCase):
    def test_old_logs_deleted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Dates must be computed relative to "now" — hardcoded stamps
            # eventually fall outside the retention window as real time moves.
            now = datetime.now(timezone.utc)
            old_stamp = (now - timedelta(days=60)).strftime("%Y%m%d-%H%M%S")
            recent_stamp = (now - timedelta(days=1)).strftime("%Y%m%d-%H%M%S")
            old_file = os.path.join(tmpdir, "guard-%s.jsonl" % old_stamp)
            recent_file = os.path.join(tmpdir, "guard-%s.jsonl" % recent_stamp)
            with open(old_file, "w") as f:
                f.write("{}\n")
            with open(recent_file, "w") as f:
                f.write("{}\n")

            logger = AuditLogger(log_dir=tmpdir, retention_days=30)
            logger.close()

            self.assertFalse(os.path.exists(old_file))
            self.assertTrue(os.path.exists(recent_file))

    def test_current_log_not_deleted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(log_dir=tmpdir, retention_days=1)
            self.assertTrue(logger.log_path.exists())
            logger.close()

    def test_non_log_files_ignored(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            other_file = os.path.join(tmpdir, "notes.txt")
            with open(other_file, "w") as f:
                f.write("keep me")

            logger = AuditLogger(log_dir=tmpdir, retention_days=1)
            logger.close()

            self.assertTrue(os.path.exists(other_file))


if __name__ == "__main__":
    unittest.main()
