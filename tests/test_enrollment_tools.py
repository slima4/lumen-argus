"""Tests for enrollment_agent_tools table and EnrollmentRepository tool methods."""

from tests.helpers import StoreTestCase


def _register(store, agent_id="agent_1", machine_id="machine_1", hostname="test-host"):
    """Register a test agent with sensible defaults."""
    store.enrollment.register(
        agent_id=agent_id,
        machine_id=machine_id,
        hostname=hostname,
        os="darwin",
        arch="arm64",
        agent_version="0.1.0",
        enrolled_at="2026-04-03T00:00:00Z",
    )


class TestEnrollmentToolsSchema(StoreTestCase):
    """Verify enrollment_agent_tools table is created."""

    def test_table_exists(self):
        with self.store._connect() as conn:
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            self.assertIn("enrollment_agent_tools", tables)

    def test_unconfigured_index_exists(self):
        with self.store._connect() as conn:
            indexes = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()]
            self.assertIn("idx_agent_tools_unconfigured", indexes)


class TestUpsertTools(StoreTestCase):
    """Test EnrollmentRepository.upsert_tools."""

    def test_upsert_inserts_tools(self):
        _register(self.store)
        tools = [
            {
                "client_id": "claude",
                "display_name": "Claude Code",
                "version": "1.2.0",
                "install_method": "binary",
                "proxy_configured": True,
                "routing_active": True,
                "proxy_config_type": "env_var",
            },
            {
                "client_id": "warp",
                "display_name": "Warp",
                "version": "2026.03",
                "install_method": "app_bundle",
                "proxy_configured": False,
                "routing_active": False,
                "proxy_config_type": "unsupported",
            },
        ]
        self.store.enrollment.upsert_tools("agent_1", tools, "2026-04-03T01:00:00Z")

        result = self.store.enrollment.get_agent_tools("agent_1")
        self.assertEqual(len(result), 2)
        claude = next(t for t in result if t["client_id"] == "claude")
        self.assertEqual(claude["display_name"], "Claude Code")
        self.assertEqual(claude["version"], "1.2.0")
        self.assertEqual(claude["proxy_configured"], 1)
        self.assertEqual(claude["proxy_config_type"], "env_var")

    def test_upsert_removes_uninstalled_tools(self):
        _register(self.store)
        tools_v1 = [
            {"client_id": "claude", "proxy_configured": True, "routing_active": True},
            {"client_id": "aider", "proxy_configured": True, "routing_active": True},
        ]
        self.store.enrollment.upsert_tools("agent_1", tools_v1, "2026-04-03T01:00:00Z")
        self.assertEqual(len(self.store.enrollment.get_agent_tools("agent_1")), 2)

        # Next heartbeat: aider uninstalled
        tools_v2 = [
            {"client_id": "claude", "proxy_configured": True, "routing_active": True},
        ]
        self.store.enrollment.upsert_tools("agent_1", tools_v2, "2026-04-03T02:00:00Z")
        result = self.store.enrollment.get_agent_tools("agent_1")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["client_id"], "claude")

    def test_upsert_updates_existing_tool(self):
        _register(self.store)
        tools_v1 = [
            {"client_id": "claude", "version": "1.0.0", "proxy_configured": False, "routing_active": False},
        ]
        self.store.enrollment.upsert_tools("agent_1", tools_v1, "2026-04-03T01:00:00Z")

        tools_v2 = [
            {"client_id": "claude", "version": "1.2.0", "proxy_configured": True, "routing_active": True},
        ]
        self.store.enrollment.upsert_tools("agent_1", tools_v2, "2026-04-03T02:00:00Z")

        result = self.store.enrollment.get_agent_tools("agent_1")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["version"], "1.2.0")
        self.assertEqual(result[0]["proxy_configured"], 1)

    def test_upsert_empty_tools_clears_all(self):
        _register(self.store)
        self.store.enrollment.upsert_tools(
            "agent_1",
            [{"client_id": "claude", "proxy_configured": True, "routing_active": True}],
            "2026-04-03T01:00:00Z",
        )
        self.assertEqual(len(self.store.enrollment.get_agent_tools("agent_1")), 1)

        self.store.enrollment.upsert_tools("agent_1", [], "2026-04-03T02:00:00Z")
        self.assertEqual(len(self.store.enrollment.get_agent_tools("agent_1")), 0)


class TestGetAgentTools(StoreTestCase):
    """Test EnrollmentRepository.get_agent_tools."""

    def test_returns_empty_for_unknown_agent(self):
        self.assertEqual(self.store.enrollment.get_agent_tools("nonexistent"), [])


class TestFleetToolsSummary(StoreTestCase):
    """Test EnrollmentRepository.get_fleet_tools_summary."""

    def _setup_fleet(self) -> None:
        """Register 2 agents with overlapping tools."""
        _register(self.store, "agent_1", "m1", "alice-macbook")
        _register(self.store, "agent_2", "m2", "bob-macbook")

        self.store.enrollment.upsert_tools(
            "agent_1",
            [
                {
                    "client_id": "claude",
                    "display_name": "Claude Code",
                    "proxy_configured": True,
                    "routing_active": True,
                    "proxy_config_type": "env_var",
                },
                {
                    "client_id": "warp",
                    "display_name": "Warp",
                    "proxy_configured": False,
                    "routing_active": False,
                    "proxy_config_type": "unsupported",
                },
            ],
            "2026-04-03T01:00:00Z",
        )

        self.store.enrollment.upsert_tools(
            "agent_2",
            [
                {
                    "client_id": "claude",
                    "display_name": "Claude Code",
                    "proxy_configured": True,
                    "routing_active": True,
                    "proxy_config_type": "env_var",
                },
                {
                    "client_id": "aider",
                    "display_name": "Aider",
                    "proxy_configured": False,
                    "routing_active": False,
                    "proxy_config_type": "env_var",
                },
            ],
            "2026-04-03T01:00:00Z",
        )

    def test_by_tool_aggregation(self):
        self._setup_fleet()
        summary = self.store.enrollment.get_fleet_tools_summary()
        by_tool = {t["client_id"]: t for t in summary["by_tool"]}

        self.assertEqual(by_tool["claude"]["installed"], 2)
        self.assertEqual(by_tool["claude"]["configured"], 2)
        self.assertEqual(by_tool["warp"]["installed"], 1)
        self.assertEqual(by_tool["warp"]["configured"], 0)
        self.assertEqual(by_tool["aider"]["installed"], 1)
        self.assertEqual(by_tool["aider"]["configured"], 0)

    def test_gaps_include_unconfigured_tools(self):
        self._setup_fleet()
        summary = self.store.enrollment.get_fleet_tools_summary()
        gaps = summary["gaps"]

        self.assertEqual(len(gaps), 2)
        gap_ids = {(g["agent_id"], g["client_id"]) for g in gaps}
        self.assertIn(("agent_1", "warp"), gap_ids)
        self.assertIn(("agent_2", "aider"), gap_ids)

    def test_gaps_actionable_flag(self):
        self._setup_fleet()
        summary = self.store.enrollment.get_fleet_tools_summary()
        gaps = {(g["agent_id"], g["client_id"]): g for g in summary["gaps"]}

        self.assertFalse(gaps[("agent_1", "warp")]["actionable"])  # unsupported
        self.assertTrue(gaps[("agent_2", "aider")]["actionable"])  # env_var

    def test_excludes_deregistered_agents(self):
        self._setup_fleet()
        self.store.enrollment.deregister("agent_2")

        summary = self.store.enrollment.get_fleet_tools_summary()
        by_tool = {t["client_id"]: t for t in summary["by_tool"]}

        # Only agent_1's tools should be counted
        self.assertEqual(by_tool["claude"]["installed"], 1)
        self.assertNotIn("aider", by_tool)

    def test_empty_fleet(self):
        summary = self.store.enrollment.get_fleet_tools_summary()
        self.assertEqual(summary["by_tool"], [])
        self.assertEqual(summary["gaps"], [])
