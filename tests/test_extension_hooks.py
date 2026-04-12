"""Tests for the 5 community extension hooks for multi-plugin deployments.

Covers:
1. Plugin instance registry        — ExtensionRegistry.set_plugin / get_plugin
2. Public store execute API        — AnalyticsStore.execute / execute_write / write_transaction
3. Schema extension registration   — ExtensionRegistry.register_schema_extension +
                                      AnalyticsStore._apply_schema_extensions
4. Multi-package static file loading — ExtensionRegistry.register_static_dir +
                                        dashboard server _load_plugin_static
5. Dashboard status data sharing   — init.js exposes window._statusData / _licenseTier
"""

import json
import os
import shutil
import tempfile
import unittest

from lumen_argus.analytics.store import AnalyticsStore, WriteResult
from lumen_argus.dashboard.server import (
    _load_plugin_static,
    clear_static_cache,
)
from lumen_argus.extensions import ExtensionRegistry

# ---------------------------------------------------------------------------
# Hook 1: Plugin instance registry
# ---------------------------------------------------------------------------


class TestPluginInstanceRegistry(unittest.TestCase):
    def test_set_and_get_plugin(self):
        reg = ExtensionRegistry()
        sentinel = object()
        reg.set_plugin("plugin_a", sentinel)
        self.assertIs(reg.get_plugin("plugin_a"), sentinel)

    def test_get_plugin_missing_returns_none(self):
        reg = ExtensionRegistry()
        self.assertIsNone(reg.get_plugin("plugin_a"))

    def test_set_plugin_is_idempotent_last_wins(self):
        reg = ExtensionRegistry()
        first = object()
        second = object()
        reg.set_plugin("plugin_a", first)
        reg.set_plugin("plugin_a", second)
        self.assertIs(reg.get_plugin("plugin_a"), second)

    def test_plugins_are_independent_by_name(self):
        reg = ExtensionRegistry()
        a = object()
        b = object()
        reg.set_plugin("plugin_a", a)
        reg.set_plugin("plugin_b", b)
        self.assertIs(reg.get_plugin("plugin_a"), a)
        self.assertIs(reg.get_plugin("plugin_b"), b)


# ---------------------------------------------------------------------------
# Hook 2: Public store execute API
# ---------------------------------------------------------------------------


class TestPublicStoreExecuteAPI(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = AnalyticsStore(db_path=os.path.join(self.tmpdir, "t.db"))
        # Set up a plugin-owned table directly for test isolation
        self.store._adapter.ensure_schema("CREATE TABLE IF NOT EXISTS plugin_t (id INTEGER PRIMARY KEY, name TEXT)")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_execute_returns_list_of_dicts(self):
        self.store.execute_write("INSERT INTO plugin_t (id, name) VALUES (?, ?)", (1, "alpha"))
        self.store.execute_write("INSERT INTO plugin_t (id, name) VALUES (?, ?)", (2, "beta"))
        rows = self.store.execute("SELECT id, name FROM plugin_t ORDER BY id")
        self.assertEqual(rows, [{"id": 1, "name": "alpha"}, {"id": 2, "name": "beta"}])

    def test_execute_with_params(self):
        self.store.execute_write("INSERT INTO plugin_t (id, name) VALUES (?, ?)", (42, "gamma"))
        rows = self.store.execute("SELECT name FROM plugin_t WHERE id = ?", (42,))
        self.assertEqual(rows, [{"name": "gamma"}])

    def test_execute_empty_result_returns_empty_list(self):
        rows = self.store.execute("SELECT * FROM plugin_t WHERE id = ?", (9999,))
        self.assertEqual(rows, [])

    def test_execute_write_returns_rowcount_and_lastrowid(self):
        result = self.store.execute_write("INSERT INTO plugin_t (name) VALUES (?)", ("delta",))
        self.assertIsInstance(result, WriteResult)
        self.assertEqual(result.rowcount, 1)
        self.assertIsNotNone(result.lastrowid)
        self.assertGreater(result.lastrowid, 0)

    def test_execute_write_update_rowcount(self):
        self.store.execute_write("INSERT INTO plugin_t (id, name) VALUES (?, ?)", (1, "a"))
        self.store.execute_write("INSERT INTO plugin_t (id, name) VALUES (?, ?)", (2, "b"))
        result = self.store.execute_write("UPDATE plugin_t SET name = 'x'")
        self.assertEqual(result.rowcount, 2)

    def test_write_transaction_commits_on_success(self):
        with self.store.write_transaction() as conn:
            conn.execute("INSERT INTO plugin_t (id, name) VALUES (?, ?)", (1, "tx"))
            conn.execute("INSERT INTO plugin_t (id, name) VALUES (?, ?)", (2, "tx"))
        rows = self.store.execute("SELECT COUNT(*) as c FROM plugin_t")
        self.assertEqual(rows[0]["c"], 2)

    def test_write_transaction_rolls_back_on_exception(self):
        class BoomError(RuntimeError):
            pass

        with self.assertRaises(BoomError):
            with self.store.write_transaction() as conn:
                conn.execute("INSERT INTO plugin_t (id, name) VALUES (?, ?)", (1, "x"))
                raise BoomError("fail mid-tx")
        rows = self.store.execute("SELECT COUNT(*) as c FROM plugin_t")
        self.assertEqual(rows[0]["c"], 0)


# ---------------------------------------------------------------------------
# Hook 3: Schema extension registration
# ---------------------------------------------------------------------------


class TestSchemaExtensionRegistration(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_register_and_get_schema_extensions(self):
        reg = ExtensionRegistry()
        reg.register_schema_extension("CREATE TABLE IF NOT EXISTS a (id INTEGER)")
        reg.register_schema_extension("CREATE TABLE IF NOT EXISTS b (id INTEGER)")
        self.assertEqual(len(reg.get_schema_extensions()), 2)

    def test_schema_extension_creates_table(self):
        ddl = """
        CREATE TABLE IF NOT EXISTS plugin_events (
            id {auto_id},
            name TEXT NOT NULL,
            created_at {ts} NOT NULL
        );
        """
        store = AnalyticsStore(
            db_path=os.path.join(self.tmpdir, "t.db"),
            schema_extensions=[ddl],
        )
        # Table should exist — insert and query via public API
        store.execute_write(
            "INSERT INTO plugin_events (name, created_at) VALUES (?, ?)",
            ("event-a", "2026-04-12"),
        )
        rows = store.execute("SELECT name FROM plugin_events")
        self.assertEqual(rows, [{"name": "event-a"}])

    def test_schema_extension_placeholders_resolved(self):
        ddl = "CREATE TABLE IF NOT EXISTS x (id {auto_id}, ts {ts})"
        store = AnalyticsStore(
            db_path=os.path.join(self.tmpdir, "t.db"),
            schema_extensions=[ddl],
        )
        # If placeholders weren't resolved, the CREATE would have failed
        rows = store.execute("SELECT name FROM sqlite_master WHERE name='x'")
        self.assertEqual(rows, [{"name": "x"}])

    def test_no_extensions_is_noop(self):
        # Empty list should not raise, store should work normally
        store = AnalyticsStore(
            db_path=os.path.join(self.tmpdir, "t.db"),
            schema_extensions=[],
        )
        self.assertEqual(store.get_total_count(), 0)

    def test_broken_extension_does_not_crash_store_init(self):
        # A single bad DDL should be logged but not prevent store construction
        bad_ddl = "THIS IS NOT VALID SQL"
        with self.assertLogs("argus.analytics", level="ERROR"):
            store = AnalyticsStore(
                db_path=os.path.join(self.tmpdir, "t.db"),
                schema_extensions=[bad_ddl],
            )
        # Community tables should still be present
        self.assertEqual(store.get_total_count(), 0)

    def test_bad_extension_does_not_block_subsequent_ones(self):
        # Regression for a real bug: the first implementation concatenated
        # all DDL into one executescript call, so a failure in extension #0
        # silently aborted the rest. This test pins the corrected behavior:
        # extension #1 must still create its table even if #0 is invalid SQL.
        bad = "CREATE TABLE bad_table (garbage syntax here"
        good = """
            CREATE TABLE IF NOT EXISTS after_bad (
                id {auto_id},
                name TEXT NOT NULL
            );
        """
        with self.assertLogs("argus.analytics", level="ERROR"):
            store = AnalyticsStore(
                db_path=os.path.join(self.tmpdir, "t.db"),
                schema_extensions=[bad, good],
            )
        # The good extension must still have been applied
        store.execute_write("INSERT INTO after_bad (name) VALUES (?)", ("alpha",))
        rows = store.execute("SELECT name FROM after_bad")
        self.assertEqual(rows, [{"name": "alpha"}])

    def test_placeholder_resolution_failure_does_not_block_later_extensions(self):
        # A DDL referencing an unknown placeholder should be logged and
        # skipped, but subsequent valid extensions must still run.
        bad_placeholder = "CREATE TABLE IF NOT EXISTS x (id {nonexistent})"
        good = "CREATE TABLE IF NOT EXISTS after_placeholder (id {auto_id})"
        with self.assertLogs("argus.analytics", level="ERROR"):
            store = AnalyticsStore(
                db_path=os.path.join(self.tmpdir, "t.db"),
                schema_extensions=[bad_placeholder, good],
            )
        rows = store.execute("SELECT name FROM sqlite_master WHERE name='after_placeholder'")
        self.assertEqual(rows, [{"name": "after_placeholder"}])

    def test_apply_schema_extensions_on_existing_store(self):
        # A plugin may register its own AnalyticsStore subclass via
        # set_analytics_store; the config loader must still be able to
        # apply schema extensions against that store post-construction.
        store = AnalyticsStore(db_path=os.path.join(self.tmpdir, "t.db"))
        store.apply_schema_extensions(["CREATE TABLE IF NOT EXISTS late_added (id {auto_id}, name TEXT)"])
        store.execute_write("INSERT INTO late_added (name) VALUES (?)", ("ok",))
        rows = store.execute("SELECT name FROM late_added")
        self.assertEqual(rows, [{"name": "ok"}])

    def test_config_loader_applies_extensions_to_preregistered_store(self):
        # Regression for the multi-plugin composition path: when one
        # plugin registers its own store via set_analytics_store, schema
        # extensions from another plugin must still be applied against
        # that store — not silently dropped.
        from lumen_argus.config import Config
        from lumen_argus.config_loader import _create_or_get_store

        reg = ExtensionRegistry()
        # Plugin A: constructs a store and registers it as the active store
        preregistered_store = AnalyticsStore(db_path=os.path.join(self.tmpdir, "pre.db"))
        reg.set_analytics_store(preregistered_store)
        # Plugin B: registers a DDL extension
        reg.register_schema_extension("CREATE TABLE IF NOT EXISTS plugin_b_owned (id {auto_id}, name TEXT)")
        # Dispatch through the real code path
        config = Config()
        returned = _create_or_get_store(config, reg, hmac_key=None)
        self.assertIs(returned, preregistered_store)
        # Plugin B's table must exist on plugin A's store
        returned.execute_write("INSERT INTO plugin_b_owned (name) VALUES (?)", ("composed",))
        rows = returned.execute("SELECT name FROM plugin_b_owned")
        self.assertEqual(rows, [{"name": "composed"}])

    def test_apply_schema_extensions_is_idempotent(self):
        # Double-application must be safe because CREATE TABLE IF NOT EXISTS.
        store = AnalyticsStore(db_path=os.path.join(self.tmpdir, "t.db"))
        ddl = ["CREATE TABLE IF NOT EXISTS twice (id {auto_id})"]
        store.apply_schema_extensions(ddl)
        store.apply_schema_extensions(ddl)  # second call must not raise
        rows = store.execute("SELECT name FROM sqlite_master WHERE name='twice'")
        self.assertEqual(rows, [{"name": "twice"}])

    def test_extensions_order_preserved(self):
        reg = ExtensionRegistry()
        reg.register_schema_extension("A")
        reg.register_schema_extension("B")
        reg.register_schema_extension("C")
        self.assertEqual(reg.get_schema_extensions(), ["A", "B", "C"])

    def test_get_schema_extensions_returns_copy(self):
        reg = ExtensionRegistry()
        reg.register_schema_extension("X")
        snapshot = reg.get_schema_extensions()
        snapshot.append("Y")
        self.assertEqual(reg.get_schema_extensions(), ["X"])


# ---------------------------------------------------------------------------
# Hook 4: Multi-package static file loading
# ---------------------------------------------------------------------------


class TestStaticDirRegistration(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        # Static-file cache is module-global; reset it for each test to
        # avoid cross-test pollution from earlier registered dirs.
        clear_static_cache()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        clear_static_cache()

    def _make_static_tree(self, root: str, js=None, css=None, html=None):
        for subdir, files in (("js", js or {}), ("css", css or {}), ("html", html or {})):
            if not files:
                continue
            d = os.path.join(root, subdir)
            os.makedirs(d, exist_ok=True)
            for name, content in files.items():
                with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                    f.write(content)

    def test_register_static_dir_skips_missing_path(self):
        reg = ExtensionRegistry()
        with self.assertLogs("argus.extensions", level="WARNING"):
            reg.register_static_dir("/nonexistent/path/xyzzy")
        self.assertEqual(reg.get_static_dirs(), [])

    def test_register_static_dir_accepts_existing_path(self):
        reg = ExtensionRegistry()
        reg.register_static_dir(self.tmpdir)
        self.assertEqual(reg.get_static_dirs(), [self.tmpdir])

    def test_load_plugin_static_reads_js_css_html(self):
        d = os.path.join(self.tmpdir, "plugin_a")
        self._make_static_tree(
            d,
            js={"a.js": "var a=1;"},
            css={"a.css": ".a{color:red}"},
            html={"home.html": "<div>hi</div>"},
        )
        css, html_vars, js = _load_plugin_static([d])
        self.assertIn("var a=1;", js)
        self.assertIn(".a{color:red}", css)
        self.assertIn("var _pageHtml_home=", html_vars)
        # HTML must be JSON-encoded so it's safe inside a <script> tag
        self.assertIn(json.dumps("<div>hi</div>"), html_vars)

    def test_load_plugin_static_multiple_dirs_concatenated(self):
        a = os.path.join(self.tmpdir, "a")
        b = os.path.join(self.tmpdir, "b")
        self._make_static_tree(a, js={"a.js": "var a=1;"})
        self._make_static_tree(b, js={"b.js": "var b=2;"})
        _css, _html, js = _load_plugin_static([a, b])
        self.assertIn("var a=1;", js)
        self.assertIn("var b=2;", js)

    def test_load_plugin_static_last_write_wins(self):
        a = os.path.join(self.tmpdir, "a")
        b = os.path.join(self.tmpdir, "b")
        self._make_static_tree(a, js={"shared.js": "var shared='A';"})
        self._make_static_tree(b, js={"shared.js": "var shared='B';"})
        _css, _html, js = _load_plugin_static([a, b])
        self.assertIn("var shared='B';", js)
        self.assertNotIn("var shared='A';", js)

    def test_load_plugin_static_handles_partial_trees(self):
        # Plugin provides only JS, no css/, no html/
        d = os.path.join(self.tmpdir, "js_only")
        self._make_static_tree(d, js={"only.js": "var x=1;"})
        css, html_vars, js = _load_plugin_static([d])
        self.assertEqual(css, "")
        self.assertEqual(html_vars, "")
        self.assertIn("var x=1;", js)

    def test_load_plugin_static_empty_dirs_list(self):
        css, html_vars, js = _load_plugin_static([])
        self.assertEqual((css, html_vars, js), ("", "", ""))

    def test_load_plugin_static_sanitizes_js_identifiers(self):
        # Filenames with dashes or dots must not produce invalid JS
        # identifiers like `var _pageHtml_my-page = ...`
        d = os.path.join(self.tmpdir, "dashy")
        self._make_static_tree(d, html={"my-page.v2.html": "<div>x</div>"})
        _css, html_vars, _js = _load_plugin_static([d])
        # All dashes and dots become underscores
        self.assertIn("var _pageHtml_my_page_v2=", html_vars)
        self.assertNotIn("my-page", html_vars)

    def test_load_plugin_static_uses_cache(self):
        d = os.path.join(self.tmpdir, "cached")
        self._make_static_tree(d, js={"a.js": "var a=1;"})
        first = _load_plugin_static([d])
        # Mutating the file on disk should NOT change subsequent calls —
        # proves the cache is returning the memoized result.
        with open(os.path.join(d, "js", "a.js"), "w", encoding="utf-8") as f:
            f.write("var a=2;")
        second = _load_plugin_static([d])
        self.assertEqual(first, second)
        self.assertIn("var a=1;", second[2])

    def test_clear_static_cache_busts_the_cache(self):
        d = os.path.join(self.tmpdir, "busted")
        self._make_static_tree(d, js={"a.js": "var a=1;"})
        _load_plugin_static([d])
        with open(os.path.join(d, "js", "a.js"), "w", encoding="utf-8") as f:
            f.write("var a=2;")
        clear_static_cache()
        _css, _html, js = _load_plugin_static([d])
        self.assertIn("var a=2;", js)

    def test_clear_dashboard_pages_preserves_static_dirs(self):
        # Static dirs are filesystem paths tied to installed plugin
        # packages. They're registered once at load_plugins() time,
        # which is NOT re-invoked on SIGHUP — so clear_dashboard_pages
        # must not drop them. Otherwise a plugin that only registers
        # static files (no pages / css / api handler to re-register
        # in a reload hook) would lose its UI on the first SIGHUP
        # and never recover until proxy restart.
        reg = ExtensionRegistry()
        reg.register_static_dir(self.tmpdir)
        reg.register_dashboard_pages([{"name": "x", "js": "", "html": ""}])
        self.assertEqual(len(reg.get_static_dirs()), 1)
        self.assertEqual(len(reg.get_dashboard_pages()), 1)
        reg.clear_dashboard_pages()
        # Pages are cleared (caller will re-register them from its
        # reload hook), but static dirs survive.
        self.assertEqual(reg.get_dashboard_pages(), [])
        self.assertEqual(len(reg.get_static_dirs()), 1)

    def test_clear_dashboard_pages_still_busts_static_cache(self):
        # Even though _static_dirs survives, the cache must be busted so
        # any on-disk content changes (rare but possible in dev) are
        # picked up on the next dashboard page load.
        d = os.path.join(self.tmpdir, "sighup")
        self._make_static_tree(d, js={"a.js": "var a=1;"})
        _load_plugin_static([d])  # populate cache
        # Mutate the file to prove the cache is the thing being tested
        with open(os.path.join(d, "js", "a.js"), "w", encoding="utf-8") as f:
            f.write("var a=2;")
        reg = ExtensionRegistry()
        reg.register_static_dir(d)
        reg.clear_dashboard_pages()
        _css, _html, js = _load_plugin_static([d])
        self.assertIn("var a=2;", js)


# ---------------------------------------------------------------------------
# Hook 5: Dashboard status data sharing (init.js)
# ---------------------------------------------------------------------------


class TestDashboardStatusDataSharing(unittest.TestCase):
    """Lightweight static check — init.js should wire window._statusData.

    Full browser-level tests live in the e2e suite; here we just verify the
    contract that the JS source file sets the two globals before page loadFns
    run (i.e. synchronously during loadData()).
    """

    def test_init_js_exposes_status_globals(self):
        init_js_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "packages",
            "proxy",
            "lumen_argus",
            "dashboard",
            "static",
            "js",
            "init.js",
        )
        with open(init_js_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("window._statusData", content)
        self.assertIn("window._licenseTier", content)
        # Must default to 'community' when tier is missing
        self.assertIn("'community'", content)
        # Must be set inside loadData() — verify the assignments come before
        # the first renderQuickStats() call (a known page-load render fn).
        status_idx = content.find("window._statusData=st")
        render_idx = content.find("renderQuickStats")
        self.assertGreater(status_idx, 0)
        self.assertGreater(render_idx, status_idx)


if __name__ == "__main__":
    unittest.main()
