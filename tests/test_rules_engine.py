"""Tests for the DB-backed rules engine (Phase 1)."""

import json
import os
import shutil
import tempfile
import unittest

from lumen_argus.analytics.store import AnalyticsStore
from lumen_argus.detectors.rules import RulesDetector
from lumen_argus.models import ScanField
from lumen_argus.allowlist import AllowlistMatcher


class TestRulesImportExport(unittest.TestCase):
    """Test rules import/export round-trip."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.store = AnalyticsStore(db_path=self._tmpdir + "/test.db")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_import_creates_rules(self):
        rules = [
            {"name": "test_key", "pattern": "TEST_[A-Z]{10}", "detector": "secrets", "severity": "high"},
            {"name": "test_email", "pattern": "[a-z]+@test\\.com", "detector": "pii", "severity": "warning"},
        ]
        result = self.store.import_rules(rules, tier="community")
        self.assertEqual(result["created"], 2)
        self.assertEqual(result["updated"], 0)
        self.assertEqual(self.store.get_rules_count(), 2)

    def test_reimport_updates_not_duplicates(self):
        rules = [{"name": "test_key", "pattern": "TEST_[A-Z]{10}", "detector": "secrets", "severity": "high"}]
        self.store.import_rules(rules, tier="community")
        # Update pattern
        rules[0]["pattern"] = "TEST_[A-Z]{20}"
        result = self.store.import_rules(rules, tier="community")
        self.assertEqual(result["created"], 0)
        self.assertEqual(result["updated"], 1)
        self.assertEqual(self.store.get_rules_count(), 1)
        rule = self.store.get_rule_by_name("test_key")
        self.assertEqual(rule["pattern"], "TEST_[A-Z]{20}")

    def test_reimport_preserves_user_action_override(self):
        rules = [{"name": "test_key", "pattern": "TEST_[A-Z]{10}", "detector": "secrets", "severity": "high"}]
        self.store.import_rules(rules, tier="community")
        # User changes action from dashboard
        self.store.update_rule("test_key", {"action": "block", "updated_by": "dashboard"})
        # Re-import should NOT reset action
        self.store.import_rules(rules, tier="community")
        rule = self.store.get_rule_by_name("test_key")
        self.assertEqual(rule["action"], "block")

    def test_force_reimport_resets_action(self):
        rules = [{"name": "test_key", "pattern": "TEST_[A-Z]{10}", "detector": "secrets", "severity": "high"}]
        self.store.import_rules(rules, tier="community")
        self.store.update_rule("test_key", {"action": "block"})
        self.store.import_rules(rules, tier="community", force=True)
        rule = self.store.get_rule_by_name("test_key")
        self.assertEqual(rule["action"], "")  # reset to default

    def test_import_skips_dashboard_rules(self):
        self.store.create_rule(
            {
                "name": "my_custom",
                "pattern": "CUSTOM_[A-Z]+",
                "source": "dashboard",
                "tier": "custom",
                "created_by": "dashboard",
            }
        )
        # Try to import a rule with same name
        rules = [{"name": "my_custom", "pattern": "OVERRIDE_[A-Z]+", "detector": "secrets", "severity": "high"}]
        result = self.store.import_rules(rules, tier="community")
        self.assertEqual(result["skipped"], 1)
        rule = self.store.get_rule_by_name("my_custom")
        self.assertEqual(rule["pattern"], "CUSTOM_[A-Z]+")  # unchanged

    def test_export_round_trip(self):
        rules = [
            {"name": "r1", "pattern": "A+", "detector": "secrets", "severity": "high", "tags": ["test"]},
            {"name": "r2", "pattern": "B+", "detector": "pii", "severity": "warning"},
        ]
        self.store.import_rules(rules, tier="community")
        exported = self.store.export_rules()
        self.assertEqual(len(exported), 2)
        self.assertEqual(exported[0]["name"], "r1")
        self.assertEqual(exported[0]["tags"], ["test"])

    def test_export_filter_by_tier(self):
        self.store.import_rules(
            [{"name": "comm", "pattern": "A+", "detector": "secrets", "severity": "high"}],
            tier="community",
        )
        self.store.create_rule(
            {
                "name": "custom",
                "pattern": "B+",
                "tier": "custom",
                "source": "dashboard",
                "created_by": "test",
            }
        )
        community_only = self.store.export_rules(tier="community")
        self.assertEqual(len(community_only), 1)
        self.assertEqual(community_only[0]["name"], "comm")

    def test_community_bundle_loads(self):
        bundle_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "lumen_argus",
            "rules",
            "community.json",
        )
        with open(bundle_path, encoding="utf-8") as f:
            bundle = json.load(f)
        self.assertGreater(len(bundle["rules"]), 30)
        self.assertEqual(bundle["tier"], "community")
        # All rules have required fields
        for r in bundle["rules"]:
            self.assertIn("name", r)
            self.assertIn("pattern", r)
            self.assertIn("detector", r)


class TestRulesStoreQueries(unittest.TestCase):
    """Test rules store query methods."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.store = AnalyticsStore(db_path=self._tmpdir + "/test.db")
        self.store.import_rules(
            [
                {"name": "r1", "pattern": "A+", "detector": "secrets", "severity": "critical"},
                {"name": "r2", "pattern": "B+", "detector": "pii", "severity": "warning"},
                {"name": "r3", "pattern": "C+", "detector": "secrets", "severity": "high"},
            ],
            tier="community",
        )

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_get_active_rules(self):
        rules = self.store.get_active_rules()
        self.assertEqual(len(rules), 3)

    def test_get_active_rules_filter_detector(self):
        rules = self.store.get_active_rules(detector="secrets")
        self.assertEqual(len(rules), 2)

    def test_get_active_rules_excludes_disabled(self):
        self.store.update_rule("r1", {"enabled": False})
        rules = self.store.get_active_rules()
        self.assertEqual(len(rules), 2)

    def test_get_rules_page_search(self):
        rules, total = self.store.get_rules_page(search="r1")
        self.assertEqual(total, 1)

    def test_get_rule_by_name(self):
        rule = self.store.get_rule_by_name("r2")
        self.assertEqual(rule["detector"], "pii")

    def test_get_rule_by_name_not_found(self):
        self.assertIsNone(self.store.get_rule_by_name("nonexistent"))

    def test_get_rule_stats(self):
        stats = self.store.get_rule_stats()
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["enabled"], 3)
        self.assertEqual(stats["by_detector"]["secrets"], 2)

    def test_clone_rule(self):
        cloned = self.store.clone_rule("r1", "r1_custom")
        self.assertEqual(cloned["name"], "r1_custom")
        self.assertEqual(cloned["tier"], "custom")
        self.assertEqual(cloned["source"], "dashboard")
        self.assertEqual(cloned["pattern"], "A+")

    def test_delete_only_dashboard_rules(self):
        self.store.create_rule(
            {
                "name": "deletable",
                "pattern": "D+",
                "source": "dashboard",
                "tier": "custom",
                "created_by": "test",
            }
        )
        self.assertTrue(self.store.delete_rule("deletable"))
        # Cannot delete import rules
        self.assertFalse(self.store.delete_rule("r1"))


class TestRulesDetector(unittest.TestCase):
    """Test the RulesDetector scanning."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.store = AnalyticsStore(db_path=self._tmpdir + "/test.db")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_basic_detection(self):
        self.store.import_rules(
            [
                {"name": "test_key", "pattern": "TESTKEY_[A-Z]{10}", "detector": "secrets", "severity": "high"},
            ],
            tier="community",
        )
        detector = RulesDetector(store=self.store)
        fields = [ScanField(path="m[0]", text="My key is TESTKEY_ABCDEFGHIJ here", source_filename="")]
        findings = detector.scan(fields, AllowlistMatcher())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "test_key")
        self.assertEqual(findings[0].matched_value, "TESTKEY_ABCDEFGHIJ")

    def test_validator_filters_invalid(self):
        self.store.import_rules(
            [
                {
                    "name": "test_ssn",
                    "pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
                    "detector": "pii",
                    "severity": "critical",
                    "validator": "ssn_range",
                },
            ],
            tier="community",
        )
        detector = RulesDetector(store=self.store)
        # Valid SSN
        fields = [ScanField(path="m[0]", text="SSN: 123-45-6789", source_filename="")]
        findings = detector.scan(fields, AllowlistMatcher())
        self.assertEqual(len(findings), 1)
        # Invalid SSN (area 000)
        fields = [ScanField(path="m[0]", text="SSN: 000-45-6789", source_filename="")]
        findings = detector.scan(fields, AllowlistMatcher())
        self.assertEqual(len(findings), 0)

    def test_disabled_rules_not_loaded(self):
        self.store.import_rules(
            [
                {"name": "r1", "pattern": "AAA+", "detector": "secrets", "severity": "high"},
            ],
            tier="community",
        )
        self.store.update_rule("r1", {"enabled": False})
        detector = RulesDetector(store=self.store)
        fields = [ScanField(path="m[0]", text="AAAA", source_filename="")]
        findings = detector.scan(fields, AllowlistMatcher())
        self.assertEqual(len(findings), 0)

    def test_license_gating(self):
        self.store.import_rules(
            [
                {"name": "pro_rule", "pattern": "PRO_[A-Z]+", "detector": "secrets", "severity": "high"},
            ],
            tier="pro",
        )

        class FakeLicense:
            def is_valid(self):
                return False

        detector = RulesDetector(store=self.store, license_checker=FakeLicense())
        fields = [ScanField(path="m[0]", text="PRO_ABCDEF", source_filename="")]
        findings = detector.scan(fields, AllowlistMatcher())
        self.assertEqual(len(findings), 0)  # Pro rule skipped

    def test_license_valid_allows_pro_rules(self):
        self.store.import_rules(
            [
                {"name": "pro_rule", "pattern": "PRO_[A-Z]+", "detector": "secrets", "severity": "high"},
            ],
            tier="pro",
        )

        class FakeLicense:
            def is_valid(self):
                return True

        detector = RulesDetector(store=self.store, license_checker=FakeLicense())
        fields = [ScanField(path="m[0]", text="PRO_ABCDEF", source_filename="")]
        findings = detector.scan(fields, AllowlistMatcher())
        self.assertEqual(len(findings), 1)

    def test_reload(self):
        self.store.import_rules(
            [
                {"name": "r1", "pattern": "AAA+", "detector": "secrets", "severity": "high"},
            ],
            tier="community",
        )
        detector = RulesDetector(store=self.store)
        self.assertEqual(len(detector._compiled_rules), 1)
        # Add another rule, reload
        self.store.import_rules(
            [
                {"name": "r2", "pattern": "BBB+", "detector": "secrets", "severity": "high"},
            ],
            tier="community",
        )
        detector.reload()
        self.assertEqual(len(detector._compiled_rules), 2)

    def test_no_license_checker_blocks_pro_rules(self):
        """Pro rules must not run when license_checker is None (community default)."""
        self.store.import_rules(
            [{"name": "pro_rule", "pattern": "PRO_[A-Z]+", "detector": "secrets", "severity": "high"}],
            tier="pro",
        )
        detector = RulesDetector(store=self.store)  # no license_checker
        fields = [ScanField(path="m[0]", text="PRO_ABCDEF", source_filename="")]
        findings = detector.scan(fields, AllowlistMatcher())
        self.assertEqual(len(findings), 0)

    def test_capturing_group_extracts_secret_only(self):
        """Patterns with capture groups should return group(1), not the full match."""
        self.store.import_rules(
            [
                {
                    "name": "test_password",
                    "pattern": r"(?i)password\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
                    "detector": "secrets",
                    "severity": "high",
                }
            ],
            tier="community",
        )
        detector = RulesDetector(store=self.store)
        fields = [ScanField(path="m[0]", text='password="MySuperSecret123"', source_filename="")]
        findings = detector.scan(fields, AllowlistMatcher())
        self.assertEqual(len(findings), 1)
        # Should be the secret value, not "password=\"MySuperSecret123\""
        self.assertEqual(findings[0].matched_value, "MySuperSecret123")
        self.assertTrue(findings[0].value_preview.startswith("MySu"))

    def test_import_skips_invalid_regex(self):
        """import_rules should skip rules with invalid regex patterns."""
        rules = [
            {"name": "good", "pattern": "A+", "detector": "secrets", "severity": "high"},
            {"name": "bad", "pattern": "[invalid(", "detector": "secrets", "severity": "high"},
        ]
        result = self.store.import_rules(rules, tier="community")
        self.assertEqual(result["created"], 1)
        self.assertEqual(result["skipped"], 1)
        self.assertIsNotNone(self.store.get_rule_by_name("good"))
        self.assertIsNone(self.store.get_rule_by_name("bad"))

    def test_community_bundle_scans(self):
        """Import real community bundle and verify it detects known secrets."""
        bundle_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "lumen_argus",
            "rules",
            "community.json",
        )
        with open(bundle_path, encoding="utf-8") as f:
            bundle = json.load(f)
        self.store.import_rules(bundle["rules"], tier="community")
        detector = RulesDetector(store=self.store)
        fields = [ScanField(path="m[0]", text="My key is AKIAIOSFODNN7EXAMPLE", source_filename="")]
        findings = detector.scan(fields, AllowlistMatcher())
        types = {f.type for f in findings}
        self.assertIn("aws_access_key", types)


class TestAutoImport(unittest.TestCase):
    """Test auto-import on first serve."""

    def test_auto_import_condition(self):
        """get_rules_count() returns 0 on empty DB."""
        tmpdir = tempfile.mkdtemp()
        store = AnalyticsStore(db_path=tmpdir + "/test.db")
        self.assertEqual(store.get_rules_count(), 0)
        shutil.rmtree(tmpdir, ignore_errors=True)


class TestYAMLReconciliation(unittest.TestCase):
    """Test YAML custom_rules reconciliation to DB."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.store = AnalyticsStore(db_path=self._tmpdir + "/test.db")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_create_yaml_rules(self):
        result = self.store.reconcile_yaml_rules(
            [
                {"name": "yaml_rule_1", "pattern": "YAML_[A-Z]+", "severity": "high"},
                {"name": "yaml_rule_2", "pattern": "YAML2_[A-Z]+", "severity": "warning"},
            ]
        )
        self.assertEqual(len(result["created"]), 2)
        rule = self.store.get_rule_by_name("yaml_rule_1")
        self.assertEqual(rule["source"], "yaml")
        self.assertEqual(rule["tier"], "custom")

    def test_update_yaml_rules(self):
        self.store.reconcile_yaml_rules(
            [
                {"name": "yr", "pattern": "OLD_[A-Z]+", "severity": "high"},
            ]
        )
        self.store.reconcile_yaml_rules(
            [
                {"name": "yr", "pattern": "NEW_[A-Z]+", "severity": "critical"},
            ]
        )
        rule = self.store.get_rule_by_name("yr")
        self.assertEqual(rule["pattern"], "NEW_[A-Z]+")
        self.assertEqual(rule["severity"], "critical")

    def test_delete_removed_yaml_rules(self):
        self.store.reconcile_yaml_rules(
            [
                {"name": "keep", "pattern": "A+", "severity": "high"},
                {"name": "remove", "pattern": "B+", "severity": "high"},
            ]
        )
        result = self.store.reconcile_yaml_rules(
            [
                {"name": "keep", "pattern": "A+", "severity": "high"},
            ]
        )
        self.assertIn("remove", result["deleted"])
        self.assertIsNone(self.store.get_rule_by_name("remove"))
        self.assertIsNotNone(self.store.get_rule_by_name("keep"))

    def test_yaml_does_not_touch_dashboard_rules(self):
        self.store.create_rule(
            {
                "name": "dashboard_rule",
                "pattern": "D+",
                "source": "dashboard",
                "tier": "custom",
                "created_by": "user",
            }
        )
        result = self.store.reconcile_yaml_rules(
            [
                {"name": "dashboard_rule", "pattern": "OVERWRITE+", "severity": "high"},
            ]
        )
        # Should not create (name conflict) and not modify
        self.assertEqual(len(result["created"]), 0)
        rule = self.store.get_rule_by_name("dashboard_rule")
        self.assertEqual(rule["pattern"], "D+")

    def test_yaml_does_not_touch_import_rules(self):
        self.store.import_rules(
            [
                {"name": "imported", "pattern": "I+", "detector": "secrets", "severity": "high"},
            ],
            tier="community",
        )
        self.store.reconcile_yaml_rules(
            [
                {"name": "imported", "pattern": "OVERWRITE+", "severity": "high"},
            ]
        )
        rule = self.store.get_rule_by_name("imported")
        self.assertEqual(rule["pattern"], "I+")  # unchanged

    def test_invalid_regex_skipped(self):
        result = self.store.reconcile_yaml_rules(
            [
                {"name": "bad", "pattern": "[invalid(", "severity": "high"},
            ]
        )
        self.assertEqual(len(result["created"]), 0)
        self.assertIsNone(self.store.get_rule_by_name("bad"))


class TestPipelineRulesIntegration(unittest.TestCase):
    """Test pipeline uses RulesDetector when rules exist in DB."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.store = AnalyticsStore(db_path=self._tmpdir + "/test.db")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_pipeline_uses_rules_detector_when_rules_exist(self):
        from lumen_argus.extensions import ExtensionRegistry
        from lumen_argus.pipeline import ScannerPipeline

        self.store.import_rules(
            [
                {"name": "test_key", "pattern": "TESTKEY_[A-Z]{10}", "detector": "secrets", "severity": "high"},
            ],
            tier="community",
        )
        ext = ExtensionRegistry()
        ext.set_analytics_store(self.store)
        pipeline = ScannerPipeline(default_action="alert", extensions=ext)
        self.assertIsNotNone(pipeline._rules_detector)

    def test_pipeline_falls_back_to_hardcoded_when_no_rules(self):
        from lumen_argus.extensions import ExtensionRegistry
        from lumen_argus.pipeline import ScannerPipeline

        ext = ExtensionRegistry()
        ext.set_analytics_store(self.store)  # empty DB, no rules
        pipeline = ScannerPipeline(default_action="alert", extensions=ext)
        self.assertIsNone(pipeline._rules_detector)

    def test_pipeline_detects_with_rules_detector(self):
        from lumen_argus.extensions import ExtensionRegistry
        from lumen_argus.pipeline import ScannerPipeline

        self.store.import_rules(
            [
                {"name": "test_key", "pattern": "TESTKEY_[A-Z]{10}", "detector": "secrets", "severity": "high"},
            ],
            tier="community",
        )
        ext = ExtensionRegistry()
        ext.set_analytics_store(self.store)
        pipeline = ScannerPipeline(default_action="alert", extensions=ext)

        body = json.dumps(
            {
                "model": "test",
                "messages": [{"role": "user", "content": "Key: TESTKEY_ABCDEFGHIJ"}],
            }
        ).encode()
        result = pipeline.scan(body, "anthropic")
        types = {f.type for f in result.findings}
        self.assertIn("test_key", types)


if __name__ == "__main__":
    unittest.main()
