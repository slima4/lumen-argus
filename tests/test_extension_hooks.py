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
    """Lightweight static check — init.js should wire window._statusData,
    window._licenseTier, and window._loadDataPromise.

    Full browser-level timing tests live in the e2e suite; here we only
    verify that the JS source file declares the contract correctly
    (globals are written inside loadData(), and the initial loadData()
    call is exposed as window._loadDataPromise so plugins can await it).
    """

    def setUp(self):
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
            self.content = f.read()

    def test_init_js_exposes_status_globals(self):
        self.assertIn("window._statusData", self.content)
        self.assertIn("window._licenseTier", self.content)
        # Must default to 'community' when tier is missing
        self.assertIn("'community'", self.content)
        # Must be set inside loadData() — verify the assignments come before
        # the first renderQuickStats() call (a known page-load render fn).
        status_idx = self.content.find("window._statusData=st")
        render_idx = self.content.find("renderQuickStats")
        self.assertGreater(status_idx, 0)
        self.assertGreater(render_idx, status_idx)

    def test_init_js_exposes_load_data_promise(self):
        # Regression: previously loadData() was called without awaiting
        # the returned promise on init, so plugin modules had no way to
        # know when _statusData would be populated. The contract is now
        # that the initial loadData() call is captured as
        # window._loadDataPromise so plugin code can `.then()` it.
        self.assertIn("window._loadDataPromise", self.content)
        self.assertIn("window._loadDataPromise=loadData()", self.content)

    def test_load_data_promise_assigned_before_init_route(self):
        # The whole point of exposing the promise is to unblock plugin
        # modules that run during initRoute()'s page loadFn. If the
        # assignment happened AFTER initRoute() in the source, a plugin's
        # loadFn could race and read an undefined _loadDataPromise.
        promise_idx = self.content.find("window._loadDataPromise=loadData()")
        init_route_idx = self.content.rfind("initRoute()")
        self.assertGreater(promise_idx, 0)
        self.assertGreater(init_route_idx, promise_idx)

    def test_init_route_waits_for_dom_content_loaded(self):
        # Regression: synchronous initRoute() ran before plugin-injected
        # <script> blocks could call registerPage(); a microtask doesn't
        # fix it because the parser drains microtasks between scripts.
        self.assertRegex(
            self.content,
            r"addEventListener\(\s*['\"]DOMContentLoaded['\"]\s*,\s*initRoute",
        )
        self.assertNotRegex(self.content, r"queueMicrotask\(\s*initRoute\s*\)")


# ---------------------------------------------------------------------------
# Hook 6: Plugin load-order dependencies
# ---------------------------------------------------------------------------


class _FakeEntryPoint:
    """Minimal stand-in for importlib.metadata.EntryPoint.

    Carries the bits load_plugins() touches: name, module, dist, and
    load() — without going through the real entry-point discovery
    machinery, so tests don't have to install anything.
    """

    def __init__(self, name, module_name, register_fn, version="0.0.1"):
        self.name = name
        self.module = module_name
        self._register_fn = register_fn

        class _Dist:
            def __init__(self, v):
                self.metadata = {"Version": v}

        self.dist = _Dist(version)

    def load(self):
        return self._register_fn


class TestPluginLoadOrderResolver(unittest.TestCase):
    """Pure-logic tests for ExtensionRegistry._resolve_plugin_load_order."""

    def test_no_deps_preserves_iteration_order(self):
        order, dropped = ExtensionRegistry._resolve_plugin_load_order([("a", ()), ("b", ()), ("c", ())])
        self.assertEqual(order, ["a", "b", "c"])
        self.assertEqual(dropped, {})

    def test_dependent_loads_after_dependency(self):
        order, dropped = ExtensionRegistry._resolve_plugin_load_order([("b", ("a",)), ("a", ())])
        self.assertEqual(order, ["a", "b"])
        self.assertEqual(dropped, {})

    def test_three_chain_reversed_iteration(self):
        order, dropped = ExtensionRegistry._resolve_plugin_load_order([("c", ("b",)), ("b", ("a",)), ("a", ())])
        self.assertEqual(order, ["a", "b", "c"])
        self.assertEqual(dropped, {})

    def test_missing_dependency_is_dropped(self):
        order, dropped = ExtensionRegistry._resolve_plugin_load_order([("x", ("y",)), ("z", ())])
        self.assertEqual(order, ["z"])
        self.assertIn("x", dropped)
        self.assertIn("y", dropped["x"])

    def test_transitive_drop_cascades(self):
        order, dropped = ExtensionRegistry._resolve_plugin_load_order([("x", ("y",)), ("z", ("x",)), ("w", ())])
        self.assertEqual(order, ["w"])
        self.assertIn("x", dropped)
        self.assertIn("z", dropped)
        self.assertIn("x", dropped["z"])

    def test_cycle_is_logged_and_falls_back(self):
        # Both members of the cycle still emit so the proxy boots —
        # a misconfigured plugin must not silently disappear.
        order, dropped = ExtensionRegistry._resolve_plugin_load_order([("a", ("b",)), ("b", ("a",))])
        self.assertEqual(sorted(order), ["a", "b"])
        self.assertEqual(dropped, {})

    def test_cycle_does_not_affect_unrelated_plugin(self):
        order, _dropped = ExtensionRegistry._resolve_plugin_load_order([("a", ("b",)), ("b", ("a",)), ("c", ())])
        self.assertIn("c", order)
        self.assertIn("a", order)
        self.assertIn("b", order)
        self.assertLess(order.index("c"), order.index("a"))
        self.assertLess(order.index("c"), order.index("b"))


class TestLoadPluginsTopoSort(unittest.TestCase):
    """End-to-end tests for ExtensionRegistry.load_plugins() ordering.

    Patches ``importlib.metadata.entry_points`` and
    ``importlib.import_module`` so we don't have to install fake
    plugins.
    """

    def setUp(self):
        self.calls: list[str] = []

    def _make_plugin(self, name, deps=()):
        """Build a (FakeEntryPoint, fake module) pair for one plugin.

        The plugin's register() appends ``name`` to ``self.calls``, so
        tests can assert load order by reading the list afterwards.
        """
        import types

        module_name = f"fake_mod_{name}"
        mod = types.ModuleType(module_name)
        if deps:
            mod.LUMEN_ARGUS_PLUGIN_DEPENDS_ON = tuple(deps)

        def register(_registry, _captured_name=name):
            self.calls.append(_captured_name)

        return _FakeEntryPoint(name, module_name, register), mod

    def _run(self, plugin_pairs):
        """Run load_plugins() against the given ``[(ep, module), ...]`` list.

        Iteration order of ``plugin_pairs`` becomes the entry-point
        iteration order seen by load_plugins(), so tests can put
        plugins in the "wrong" order to verify the resolver is the
        thing doing the sorting.
        """
        import importlib
        import importlib.metadata
        from unittest.mock import patch

        real_import = importlib.import_module
        eps = [pair[0] for pair in plugin_pairs]
        modules = {ep.module: mod for ep, mod in plugin_pairs}

        def fake_entry_points(group=None):
            if group == "lumen_argus.extensions":
                return list(eps)
            return []

        def fake_import(name, package=None):
            if name in modules:
                return modules[name]
            return real_import(name, package)

        with (
            patch.object(importlib.metadata, "entry_points", fake_entry_points),
            patch.object(importlib, "import_module", fake_import),
        ):
            reg = ExtensionRegistry()
            reg.load_plugins()
            return reg

    def test_dependency_loads_first_even_when_iter_order_reversed(self):
        a = self._make_plugin("a")
        b = self._make_plugin("b", deps=("a",))
        self._run([b, a])
        self.assertEqual(self.calls, ["a", "b"])

    def test_missing_dep_drops_plugin_others_unaffected(self):
        x = self._make_plugin("x", deps=("never_installed",))
        z = self._make_plugin("z")
        reg = self._run([x, z])
        self.assertEqual(self.calls, ["z"])
        self.assertEqual([n for n, _ in reg.loaded_plugins()], ["z"])

    def test_cycle_does_not_crash_proxy(self):
        # Both members of the cycle still register — cycle is logged,
        # not fatal — so the proxy boots through misconfiguration.
        a = self._make_plugin("a", deps=("b",))
        b = self._make_plugin("b", deps=("a",))
        self._run([a, b])
        self.assertEqual(sorted(self.calls), ["a", "b"])

    def test_no_deps_attribute_is_backward_compatible(self):
        a = self._make_plugin("a")
        b = self._make_plugin("b")
        self._run([a, b])
        self.assertEqual(self.calls, ["a", "b"])

    def test_chain_of_three_resolves_correctly(self):
        a = self._make_plugin("a")
        b = self._make_plugin("b", deps=("a",))
        c = self._make_plugin("c", deps=("b",))
        self._run([c, b, a])
        self.assertEqual(self.calls, ["a", "b", "c"])


class TestConfigurePlugins(unittest.TestCase):
    """Two-phase plugin lifecycle: configure_plugins runs after load_plugins
    once load_config has produced a Config. Static contributions stay in
    register(); runtime work moves to configure(registry, config).
    """

    def setUp(self):
        self.events: list[tuple[str, str]] = []  # (phase, plugin_name)

    def _build_module(self, name: str, deps: tuple[str, ...] = (), configure=None, configure_attr=None):
        """Make a fake plugin module that records register/configure calls."""
        import types

        mod = types.ModuleType(f"fake_mod_{name}")
        if deps:
            mod.LUMEN_ARGUS_PLUGIN_DEPENDS_ON = deps

        def register(_registry, _name=name):
            self.events.append(("register", _name))

        mod.register = register

        if configure is not None:
            mod.configure = configure
        elif configure_attr is not None:
            mod.configure = configure_attr  # may be non-callable
        return mod

    def _registry_with_loaded(self, modules) -> ExtensionRegistry:
        """Build an ExtensionRegistry pre-populated as if load_plugins ran."""
        reg = ExtensionRegistry()
        for name, mod in modules.items():
            mod.register(reg)
            reg._loaded_plugins.append((name, "0.0.1"))
            reg._loaded_plugin_modules[name] = mod
        return reg

    def test_configure_called_in_load_order(self):
        """configure_plugins iterates _loaded_plugins, so topo order is preserved."""

        def cfg_a(_r, _c):
            self.events.append(("configure", "a"))

        def cfg_b(_r, _c):
            self.events.append(("configure", "b"))

        a = self._build_module("a", configure=cfg_a)
        b = self._build_module("b", deps=("a",), configure=cfg_b)
        reg = self._registry_with_loaded({"a": a, "b": b})
        reg.configure_plugins(config=object())

        configures = [n for phase, n in self.events if phase == "configure"]
        self.assertEqual(configures, ["a", "b"])

    def test_configure_optional_plugin_without_configure_skipped(self):
        a = self._build_module("a")  # no configure
        reg = self._registry_with_loaded({"a": a})
        reg.configure_plugins(config=object())
        self.assertEqual([phase for phase, _ in self.events], ["register"])
        self.assertIn("a", reg._configured_plugins)

    def test_configure_receives_registry_and_config(self):
        captured = {}

        def cfg(reg, config):
            captured["reg"] = reg
            captured["config"] = config

        a = self._build_module("a", configure=cfg)
        reg = self._registry_with_loaded({"a": a})
        sentinel = object()
        reg.configure_plugins(config=sentinel)
        self.assertIs(captured["reg"], reg)
        self.assertIs(captured["config"], sentinel)

    def test_configure_exception_does_not_abort_siblings(self):
        def cfg_a(_r, _c):
            raise RuntimeError("boom")

        def cfg_b(_r, _c):
            self.events.append(("configure", "b"))

        a = self._build_module("a", configure=cfg_a)
        b = self._build_module("b", configure=cfg_b)
        reg = self._registry_with_loaded({"a": a, "b": b})
        reg.configure_plugins(config=object())

        configures = [n for phase, n in self.events if phase == "configure"]
        self.assertEqual(configures, ["b"])
        # Failed plugin still recorded — best-effort, no retry on next call.
        self.assertIn("a", reg._configured_plugins)
        self.assertIn("b", reg._configured_plugins)

    def test_configure_is_idempotent(self):
        def cfg(_r, _c):
            self.events.append(("configure", "a"))

        a = self._build_module("a", configure=cfg)
        reg = self._registry_with_loaded({"a": a})
        reg.configure_plugins(config=object())
        reg.configure_plugins(config=object())  # second call no-op
        configures = [n for phase, n in self.events if phase == "configure"]
        self.assertEqual(configures, ["a"])

    def test_non_callable_configure_attribute_skipped_with_warning(self):
        a = self._build_module("a", configure_attr="not a function")
        reg = self._registry_with_loaded({"a": a})
        with self.assertLogs("argus.extensions", level="WARNING") as captured:
            reg.configure_plugins(config=object())
        self.assertTrue(any("non-callable configure" in m for m in captured.output))
        self.assertIn("a", reg._configured_plugins)

    def test_configure_skipped_for_plugins_not_in_loaded(self):
        """If a plugin was dropped (missing dep / cycle), it isn't in
        _loaded_plugins, so its configure must not run even if its module
        is sitting in _loaded_plugin_modules from an earlier load."""

        def cfg(_r, _c):
            self.events.append(("configure", "ghost"))

        ghost = self._build_module("ghost", configure=cfg)
        reg = ExtensionRegistry()
        # Module present in modules dict but absent from loaded list — the
        # exact shape produced when a plugin is dropped during load_plugins.
        reg._loaded_plugin_modules["ghost"] = ghost
        reg.configure_plugins(config=object())
        configures = [n for phase, n in self.events if phase == "configure"]
        self.assertEqual(configures, [])

    def test_configure_empty_registry_is_noop(self):
        reg = ExtensionRegistry()
        reg.configure_plugins(config=object())  # must not raise
        self.assertEqual(reg._configured_plugins, set())


class TestConfigurePluginsTopoIntegration(unittest.TestCase):
    """End-to-end: configure_plugins iterates _loaded_plugins in the order
    set by load_plugins() — meaning topo-sort governs configure ordering,
    not the order plugins happen to be discovered.

    The other TestConfigurePlugins suite populates _loaded_plugins
    directly to test the iterator; this suite drives the real
    load_plugins → configure_plugins path through the same fake
    entry-point machinery TestLoadPluginsTopoSort uses, so a regression
    in _resolve_plugin_load_order would surface here.
    """

    def setUp(self):
        self.events: list[tuple[str, str]] = []

    def _make_plugin(self, name, deps=()):
        import types

        module_name = f"fake_mod_topo_cfg_{name}"
        mod = types.ModuleType(module_name)
        if deps:
            mod.LUMEN_ARGUS_PLUGIN_DEPENDS_ON = tuple(deps)

        def register(_registry, _name=name):
            self.events.append(("register", _name))

        def configure(_registry, _config, _name=name):
            self.events.append(("configure", _name))

        mod.register = register
        mod.configure = configure
        return _FakeEntryPoint(name, module_name, register), mod

    def _run(self, plugin_pairs):
        import importlib
        import importlib.metadata
        import sys as _sys
        from unittest.mock import patch

        real_import = importlib.import_module
        eps = [pair[0] for pair in plugin_pairs]
        modules = {ep.module: mod for ep, mod in plugin_pairs}

        def fake_entry_points(group=None):
            if group == "lumen_argus.extensions":
                return list(eps)
            return []

        def fake_import(name, package=None):
            if name in modules:
                return modules[name]
            return real_import(name, package)

        # load_plugins records modules via ``sys.modules.get(ep.module)``,
        # so patched ``import_module`` is not enough — the fake modules
        # must also be visible through sys.modules for configure_plugins
        # to find them later.
        with (
            patch.object(importlib.metadata, "entry_points", fake_entry_points),
            patch.object(importlib, "import_module", fake_import),
            patch.dict(_sys.modules, modules),
        ):
            reg = ExtensionRegistry()
            reg.load_plugins()
            reg.configure_plugins(config=object())
            return reg

    def test_configure_follows_topo_order_under_reverse_iteration(self):
        # Entry-point iteration order puts dependent before dependency;
        # topo-sort must reorder, and configure_plugins must walk the
        # resulting _loaded_plugins order. If configure ran in iteration
        # order, b.configure would fire before a.configure.
        a = self._make_plugin("a")
        b = self._make_plugin("b", deps=("a",))
        self._run([b, a])
        configures = [n for phase, n in self.events if phase == "configure"]
        self.assertEqual(configures, ["a", "b"])

    def test_configure_skips_dropped_plugin_with_missing_dep(self):
        # x depends on never_installed → dropped from _loaded_plugins →
        # x.configure must not fire even though x's module has it.
        x = self._make_plugin("x", deps=("never_installed",))
        z = self._make_plugin("z")
        self._run([x, z])
        configures = [n for phase, n in self.events if phase == "configure"]
        self.assertEqual(configures, ["z"])

    def test_configure_chain_of_three_resolves_correctly(self):
        a = self._make_plugin("a")
        b = self._make_plugin("b", deps=("a",))
        c = self._make_plugin("c", deps=("b",))
        self._run([c, b, a])
        configures = [n for phase, n in self.events if phase == "configure"]
        self.assertEqual(configures, ["a", "b", "c"])


if __name__ == "__main__":
    unittest.main()
