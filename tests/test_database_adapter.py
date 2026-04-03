"""Tests for DatabaseAdapter ABC and SQLiteAdapter."""

import os
import sqlite3
import threading

from lumen_argus.analytics.adapter import DatabaseAdapter, SQLiteAdapter
from tests.helpers import StoreTestCase


class TestSQLiteAdapterConnection(StoreTestCase):
    """Test SQLiteAdapter connection lifecycle."""

    def test_connect_returns_sqlite_connection(self):
        conn = self.store._adapter.connect()
        self.assertIsInstance(conn, sqlite3.Connection)

    def test_connect_reuses_thread_local_connection(self):
        conn1 = self.store._adapter.connect()
        conn2 = self.store._adapter.connect()
        self.assertIs(conn1, conn2)

    def test_connect_different_threads_get_different_connections(self):
        conns = []

        def get_conn():
            conns.append(id(self.store._adapter.connect()))

        t = threading.Thread(target=get_conn)
        t.start()
        t.join()
        main_conn_id = id(self.store._adapter.connect())
        self.assertNotEqual(main_conn_id, conns[0])

    def test_wal_mode_enabled(self):
        conn = self.store._adapter.connect()
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(mode, "wal")

    def test_foreign_keys_enabled(self):
        conn = self.store._adapter.connect()
        fk = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        self.assertEqual(fk, 1)

    def test_row_factory_is_sqlite_row(self):
        conn = self.store._adapter.connect()
        self.assertEqual(conn.row_factory, sqlite3.Row)

    def test_file_permissions(self):
        stat = os.stat(self.store._adapter._db_path)
        self.assertEqual(stat.st_mode & 0o777, 0o600)


class TestSQLiteAdapterDialect(StoreTestCase):
    """Test SQLiteAdapter SQL dialect methods."""

    def test_engine_name(self):
        self.assertEqual(self.store._adapter.engine_name, "sqlite")

    def test_now_sql(self):
        self.assertEqual(self.store._adapter.now_sql(), "datetime('now')")

    def test_date_trunc_day(self):
        result = self.store._adapter.date_trunc_sql("day", "timestamp")
        self.assertEqual(result, "DATE(timestamp)")

    def test_date_trunc_hour(self):
        result = self.store._adapter.date_trunc_sql("hour", "timestamp")
        self.assertIn("strftime", result)

    def test_date_diff_sql(self):
        result = self.store._adapter.date_diff_sql("timestamp", 30)
        self.assertEqual(result, "timestamp >= DATE('now', '-30 days')")

    def test_auto_id_type(self):
        self.assertIn("AUTOINCREMENT", self.store._adapter.auto_id_type())

    def test_timestamp_type(self):
        self.assertEqual(self.store._adapter.timestamp_type(), "TEXT")

    def test_supports_returning(self):
        # SQLite >= 3.35 supports RETURNING
        self.assertIsInstance(self.store._adapter.supports_returning, bool)

    def test_now_sql_is_valid(self):
        """Verify now_sql() produces valid SQL."""
        conn = self.store._adapter.connect()
        row = conn.execute(f"SELECT {self.store._adapter.now_sql()}").fetchone()
        self.assertIsNotNone(row[0])

    def test_date_diff_sql_is_valid(self):
        """Verify date_diff_sql() produces valid SQL in a WHERE clause."""
        conn = self.store._adapter.connect()
        expr = self.store._adapter.date_diff_sql("datetime('now')", 7)
        row = conn.execute(f"SELECT CASE WHEN {expr} THEN 1 ELSE 0 END").fetchone()
        self.assertEqual(row[0], 1)


class TestSQLiteAdapterWriteLock(StoreTestCase):
    """Test SQLiteAdapter write lock."""

    def test_write_lock_is_reentrant_safe(self):
        """write_lock() should not deadlock when called once."""
        with self.store._adapter.write_lock():
            conn = self.store._adapter.connect()
            conn.execute("SELECT 1")

    def test_store_lock_is_adapter_lock(self):
        """store._lock should be the adapter's lock property."""
        self.assertIs(self.store._lock, self.store._adapter.lock)


class TestSQLiteAdapterClose(StoreTestCase):
    """Test SQLiteAdapter close."""

    def test_close_clears_connection(self):
        self.store._adapter.connect()
        self.assertIsNotNone(getattr(self.store._adapter._local, "conn", None))
        self.store._adapter.close()
        self.assertIsNone(getattr(self.store._adapter._local, "conn", None))


class TestStoreAdapterIntegration(StoreTestCase):
    """Test AnalyticsStore delegates to adapter correctly."""

    def test_store_has_adapter(self):
        self.assertIsInstance(self.store._adapter, SQLiteAdapter)

    def test_store_connect_delegates_to_adapter(self):
        store_conn = self.store._connect()
        adapter_conn = self.store._adapter.connect()
        self.assertIs(store_conn, adapter_conn)

    def test_adapter_db_path_accessible(self):
        self.assertTrue(self.store._adapter._db_path.endswith(".db"))

    def test_store_accepts_custom_adapter(self):
        """AnalyticsStore can be constructed with an explicit adapter."""
        from lumen_argus.analytics.store import AnalyticsStore

        adapter = SQLiteAdapter(os.path.join(self.tmpdir, "custom.db"))
        store = AnalyticsStore(adapter=adapter)
        self.assertIs(store._adapter, adapter)
        # Verify it's functional
        conn = store._connect()
        row = conn.execute("SELECT COUNT(*) FROM findings").fetchone()
        self.assertEqual(row[0], 0)


class TestDatabaseAdapterABC(StoreTestCase):
    """Test DatabaseAdapter ABC cannot be instantiated."""

    def test_cannot_instantiate_abc(self):
        with self.assertRaises(TypeError):
            DatabaseAdapter()
