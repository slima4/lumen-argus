"""Tests for pipeline configuration — config parsing, API endpoints, stage toggles."""

import json
import shutil
import tempfile
import unittest

from lumen_argus.analytics.store import AnalyticsStore
from lumen_argus.config import (
    Config,
    PipelineConfig,
    _parse_yaml,
    _validate_config,
    load_config,
)
from lumen_argus.dashboard.api import handle_community_api
from lumen_argus.pipeline import ScannerPipeline


class TestPipelineConfigDataclasses(unittest.TestCase):
    """Test PipelineConfig and PipelineStageConfig defaults."""

    def test_default_config_has_pipeline(self):
        config = Config()
        self.assertIsInstance(config.pipeline, PipelineConfig)

    def test_outbound_dlp_enabled_by_default(self):
        config = Config()
        self.assertTrue(config.pipeline.outbound_dlp.enabled)

    def test_encoding_decode_enabled_by_default(self):
        config = Config()
        self.assertTrue(config.pipeline.encoding_decode.enabled)

    def test_response_stages_disabled_by_default(self):
        config = Config()
        self.assertFalse(config.pipeline.response_secrets.enabled)
        self.assertFalse(config.pipeline.response_injection.enabled)

    def test_protocol_stages_defaults(self):
        config = Config()
        self.assertTrue(config.pipeline.mcp_arguments.enabled)
        self.assertTrue(config.pipeline.mcp_responses.enabled)
        # WebSocket stages default to disabled (opt-in)
        self.assertFalse(config.pipeline.websocket_outbound.enabled)
        self.assertFalse(config.pipeline.websocket_inbound.enabled)

    def test_stage_action_empty_by_default(self):
        config = Config()
        self.assertEqual(config.pipeline.outbound_dlp.action, "")


class TestPipelineConfigParsing(unittest.TestCase):
    """Test YAML parsing of pipeline section."""

    def test_pipeline_section_parsed(self):
        data = _parse_yaml("""
pipeline:
  stages:
    outbound_dlp:
      enabled: false
    encoding_decode:
      enabled: true
""")
        config = Config()
        from lumen_argus.config import _apply_config

        _apply_config(config, data)
        self.assertFalse(config.pipeline.outbound_dlp.enabled)
        self.assertTrue(config.pipeline.encoding_decode.enabled)

    def test_no_pipeline_section_uses_defaults(self):
        config = load_config(config_path="/nonexistent/path/config.yaml")
        self.assertTrue(config.pipeline.outbound_dlp.enabled)
        self.assertTrue(config.pipeline.encoding_decode.enabled)

    def test_unknown_stage_name_warns(self):
        data = {"pipeline": {"stages": {"bogus_stage": {"enabled": True}}}}
        warnings = _validate_config(data, "test")
        self.assertTrue(any("unknown pipeline stage" in w for w in warnings))

    def test_unknown_stage_key_warns(self):
        data = {"pipeline": {"stages": {"outbound_dlp": {"enabled": True, "bogus": True}}}}
        warnings = _validate_config(data, "test")
        self.assertTrue(any("bogus" in w for w in warnings))

    def test_invalid_stage_action_warns(self):
        data = {"pipeline": {"stages": {"outbound_dlp": {"action": "nuke"}}}}
        warnings = _validate_config(data, "test")
        self.assertTrue(any("not valid" in w for w in warnings))

    def test_valid_stage_config_no_warnings(self):
        data = {"pipeline": {"stages": {"outbound_dlp": {"enabled": True, "action": "block"}}}}
        warnings = _validate_config(data, "test")
        pipeline_warnings = [w for w in warnings if "pipeline" in w]
        self.assertEqual(len(pipeline_warnings), 0)

    def test_unknown_pipeline_key_warns(self):
        data = {"pipeline": {"bogus": True}}
        warnings = _validate_config(data, "test")
        self.assertTrue(any("pipeline.bogus" in w for w in warnings))


class TestPipelineStageToggle(unittest.TestCase):
    """Test that pipeline stage toggles affect scanning behavior."""

    def test_outbound_dlp_enabled_scans(self):
        pipeline = ScannerPipeline(
            default_action="alert",
            pipeline_config={"outbound_dlp_enabled": True},
        )
        body = json.dumps(
            {
                "model": "test",
                "messages": [{"role": "user", "content": "my key is AKIAIOSFODNN7EXAMPLE"}],
            }
        ).encode()
        result = pipeline.scan(body, "anthropic")
        self.assertTrue(len(result.findings) > 0)

    def test_outbound_dlp_disabled_skips_scanning(self):
        pipeline = ScannerPipeline(
            default_action="alert",
            pipeline_config={"outbound_dlp_enabled": False},
        )
        body = json.dumps(
            {
                "model": "test",
                "messages": [{"role": "user", "content": "my key is AKIAIOSFODNN7EXAMPLE"}],
            }
        ).encode()
        result = pipeline.scan(body, "anthropic")
        self.assertEqual(len(result.findings), 0)
        self.assertEqual(result.action, "pass")

    def test_default_pipeline_config_scans(self):
        """No pipeline_config = default behavior (scanning enabled)."""
        pipeline = ScannerPipeline(default_action="alert")
        body = json.dumps(
            {
                "model": "test",
                "messages": [{"role": "user", "content": "my key is AKIAIOSFODNN7EXAMPLE"}],
            }
        ).encode()
        result = pipeline.scan(body, "anthropic")
        self.assertTrue(len(result.findings) > 0)


class TestPipelineDBOverrides(unittest.TestCase):
    """Test pipeline config overrides via analytics store."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.store = AnalyticsStore(db_path=self._tmpdir + "/test.db")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_set_stage_enabled_override(self):
        self.store.set_config_override("pipeline.stages.outbound_dlp.enabled", "false")
        overrides = self.store.get_config_overrides()
        self.assertEqual(overrides["pipeline.stages.outbound_dlp.enabled"], "false")

    def test_stage_enabled_validation(self):
        with self.assertRaises(ValueError):
            self.store.set_config_override("pipeline.stages.outbound_dlp.enabled", "maybe")

    def test_detector_enabled_override(self):
        self.store.set_config_override("detectors.secrets.enabled", "false")
        overrides = self.store.get_config_overrides()
        self.assertEqual(overrides["detectors.secrets.enabled"], "false")

    def test_all_stage_keys_accepted(self):
        stages = [
            "outbound_dlp",
            "encoding_decode",
            "response_secrets",
            "response_injection",
            "mcp_arguments",
            "mcp_responses",
            "websocket_outbound",
            "websocket_inbound",
        ]
        for stage in stages:
            key = "pipeline.stages.%s.enabled" % stage
            self.store.set_config_override(key, "true")
        overrides = self.store.get_config_overrides()
        self.assertEqual(len(overrides), len(stages))


class TestPipelineAPI(unittest.TestCase):
    """Test GET/PUT /api/v1/pipeline API endpoints."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.store = AnalyticsStore(db_path=self._tmpdir + "/test.db")
        self.config = Config()

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_get_pipeline_returns_stages(self):
        status, body = handle_community_api("/api/v1/pipeline", "GET", b"", self.store, config=self.config)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("stages", data)
        self.assertIn("default_action", data)
        # Should have all 8 stages
        self.assertEqual(len(data["stages"]), 8)

    def test_get_pipeline_stage_structure(self):
        status, body = handle_community_api("/api/v1/pipeline", "GET", b"", self.store, config=self.config)
        data = json.loads(body)
        dlp = next(s for s in data["stages"] if s["name"] == "outbound_dlp")
        self.assertTrue(dlp["enabled"])
        self.assertTrue(dlp["available"])
        self.assertEqual(dlp["group"], "request")
        self.assertIn("sub_detectors", dlp)
        self.assertEqual(len(dlp["sub_detectors"]), 3)

    def test_all_stages_available(self):
        status, body = handle_community_api("/api/v1/pipeline", "GET", b"", self.store, config=self.config)
        data = json.loads(body)
        for stage in data["stages"]:
            self.assertTrue(stage["available"], "%s should be available" % stage["name"])

    def test_get_pipeline_mcp_stages_available(self):
        status, body = handle_community_api("/api/v1/pipeline", "GET", b"", self.store, config=self.config)
        data = json.loads(body)
        mcp_args = next(s for s in data["stages"] if s["name"] == "mcp_arguments")
        self.assertTrue(mcp_args["available"])
        self.assertTrue(mcp_args["enabled"])  # enabled by default

    def test_get_pipeline_response_stages_available(self):
        status, body = handle_community_api("/api/v1/pipeline", "GET", b"", self.store, config=self.config)
        data = json.loads(body)
        resp_secrets = next(s for s in data["stages"] if s["name"] == "response_secrets")
        self.assertTrue(resp_secrets["available"])
        self.assertFalse(resp_secrets["enabled"])  # disabled by default

    def test_put_pipeline_saves_stage_toggle(self):
        changes = {"stages": {"outbound_dlp": {"enabled": False}}}
        status, body = handle_community_api(
            "/api/v1/pipeline", "PUT", json.dumps(changes).encode(), self.store, config=self.config
        )
        self.assertIn(status, (200, 207))
        data = json.loads(body)
        self.assertIn("pipeline.stages.outbound_dlp.enabled", data["applied"])

        # Verify it persisted
        overrides = self.store.get_config_overrides()
        self.assertEqual(overrides["pipeline.stages.outbound_dlp.enabled"], "false")

    def test_put_pipeline_saves_detector_toggle(self):
        changes = {"detectors": {"pii": {"enabled": False}}}
        status, body = handle_community_api(
            "/api/v1/pipeline", "PUT", json.dumps(changes).encode(), self.store, config=self.config
        )
        self.assertIn(status, (200, 207))
        data = json.loads(body)
        self.assertIn("detectors.pii.enabled", data["applied"])

    def test_put_pipeline_saves_default_action(self):
        changes = {"default_action": "block"}
        status, body = handle_community_api(
            "/api/v1/pipeline", "PUT", json.dumps(changes).encode(), self.store, config=self.config
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["applied"]["default_action"], "block")

    def test_put_pipeline_invalid_json(self):
        status, body = handle_community_api("/api/v1/pipeline", "PUT", b"not json", self.store, config=self.config)
        self.assertEqual(status, 400)

    def test_get_pipeline_reflects_db_overrides(self):
        """GET should show DB-overridden values, not just YAML defaults."""
        self.store.set_config_override("pipeline.stages.outbound_dlp.enabled", "false")
        status, body = handle_community_api("/api/v1/pipeline", "GET", b"", self.store, config=self.config)
        data = json.loads(body)
        dlp = next(s for s in data["stages"] if s["name"] == "outbound_dlp")
        self.assertFalse(dlp["enabled"])

    def test_get_pipeline_reflects_detector_overrides(self):
        self.store.set_config_override("detectors.secrets.enabled", "false")
        status, body = handle_community_api("/api/v1/pipeline", "GET", b"", self.store, config=self.config)
        data = json.loads(body)
        dlp = next(s for s in data["stages"] if s["name"] == "outbound_dlp")
        secrets = next(d for d in dlp["sub_detectors"] if d["name"] == "secrets")
        self.assertFalse(secrets["enabled"])

    def test_put_pipeline_saves_detector_action(self):
        changes = {"detectors": {"secrets": {"action": "block"}}}
        status, body = handle_community_api(
            "/api/v1/pipeline", "PUT", json.dumps(changes).encode(), self.store, config=self.config
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["applied"]["detectors.secrets.action"], "block")

        # Verify it persisted and shows in GET
        status, body = handle_community_api("/api/v1/pipeline", "GET", b"", self.store, config=self.config)
        data = json.loads(body)
        dlp = next(s for s in data["stages"] if s["name"] == "outbound_dlp")
        secrets = next(d for d in dlp["sub_detectors"] if d["name"] == "secrets")
        self.assertEqual(secrets["action"], "block")

    def test_put_pipeline_default_action_deletes_override(self):
        """Setting action to 'default' removes the DB override."""
        self.store.set_config_override("detectors.pii.action", "block")
        changes = {"detectors": {"pii": {"action": "default"}}}
        status, body = handle_community_api(
            "/api/v1/pipeline", "PUT", json.dumps(changes).encode(), self.store, config=self.config
        )
        self.assertEqual(status, 200)

        # Verify override was deleted — GET should return "default"
        status, body = handle_community_api("/api/v1/pipeline", "GET", b"", self.store, config=self.config)
        data = json.loads(body)
        dlp = next(s for s in data["stages"] if s["name"] == "outbound_dlp")
        pii = next(d for d in dlp["sub_detectors"] if d["name"] == "pii")
        self.assertEqual(pii["action"], "default")

    def test_get_pipeline_encoding_settings(self):
        status, body = handle_community_api("/api/v1/pipeline", "GET", b"", self.store, config=self.config)
        data = json.loads(body)
        enc = next(s for s in data["stages"] if s["name"] == "encoding_decode")
        self.assertIn("encoding_settings", enc)
        settings = enc["encoding_settings"]
        self.assertTrue(settings["base64"])
        self.assertTrue(settings["hex"])
        self.assertTrue(settings["url"])
        self.assertTrue(settings["unicode"])
        self.assertEqual(settings["max_depth"], 2)
        self.assertEqual(settings["min_decoded_length"], 8)
        self.assertEqual(settings["max_decoded_length"], 10000)

    def test_put_pipeline_encoding_toggles(self):
        changes = {"encoding_settings": {"base64": False, "hex": True}}
        status, body = handle_community_api(
            "/api/v1/pipeline", "PUT", json.dumps(changes).encode(), self.store, config=self.config
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertFalse(data["applied"]["pipeline.stages.encoding_decode.base64"])

        # Verify in GET
        status, body = handle_community_api("/api/v1/pipeline", "GET", b"", self.store, config=self.config)
        data = json.loads(body)
        enc = next(s for s in data["stages"] if s["name"] == "encoding_decode")
        self.assertFalse(enc["encoding_settings"]["base64"])
        self.assertTrue(enc["encoding_settings"]["hex"])

    def test_put_pipeline_encoding_numeric(self):
        changes = {"encoding_settings": {"max_depth": 3, "min_decoded_length": 16}}
        status, body = handle_community_api(
            "/api/v1/pipeline", "PUT", json.dumps(changes).encode(), self.store, config=self.config
        )
        self.assertEqual(status, 200)
        overrides = self.store.get_config_overrides()
        self.assertEqual(overrides["pipeline.stages.encoding_decode.max_depth"], "3")
        self.assertEqual(overrides["pipeline.stages.encoding_decode.min_decoded_length"], "16")

    def test_encoding_config_yaml_parsing(self):
        data = _parse_yaml("""
pipeline:
  stages:
    encoding_decode:
      enabled: true
      base64: false
      url: true
      max_depth: 3
      min_decoded_length: 16
""")
        config = Config()
        from lumen_argus.config import _apply_config

        _apply_config(config, data)
        self.assertTrue(config.pipeline.encoding_decode.enabled)
        self.assertFalse(config.pipeline.encoding_decode.base64)
        self.assertTrue(config.pipeline.encoding_decode.url)
        self.assertEqual(config.pipeline.encoding_decode.max_depth, 3)
        self.assertEqual(config.pipeline.encoding_decode.min_decoded_length, 16)

    def test_put_pipeline_saves_toggle_and_action_together(self):
        changes = {
            "default_action": "block",
            "stages": {"outbound_dlp": {"enabled": True}},
            "detectors": {"pii": {"enabled": False, "action": "log"}},
        }
        status, body = handle_community_api(
            "/api/v1/pipeline", "PUT", json.dumps(changes).encode(), self.store, config=self.config
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["applied"]["default_action"], "block")
        self.assertIn("pipeline.stages.outbound_dlp.enabled", data["applied"])
        self.assertIn("detectors.pii.enabled", data["applied"])
        self.assertEqual(data["applied"]["detectors.pii.action"], "log")


if __name__ == "__main__":
    unittest.main()
