"""Tests for the SQLite + FTS5 database layer."""

import os
import tempfile

import pytest

# Override DB path before importing db module
os.environ["LOGSTREAM_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")

from src.db import (
    close_db,
    delete_old_logs,
    get_db_size_bytes,
    get_log_context,
    get_logs_after,
    get_services,
    init_db,
    insert_log,
    insert_logs_batch,
    search_logs,
    get_latest_log_id,
    reset_conn,
)


@pytest.fixture(autouse=True)
def setup_db(tmp_path):
    """Create a fresh DB for each test."""
    db_path = str(tmp_path / "test.db")
    from src import config
    config.settings.db_path = db_path
    close_db()
    reset_conn()
    init_db()
    yield
    close_db()
    reset_conn()


class TestInsertAndSearch:
    def test_insert_single(self):
        insert_log("dispatcher", "info", "2025-02-21T10:00:00+00:00", "hello world", "{}", "trace-1")
        results = search_logs()
        assert len(results) == 1
        assert results[0]["service"] == "dispatcher"
        assert results[0]["message"] == "hello world"
        assert results[0]["trace_id"] == "trace-1"

    def test_insert_batch(self):
        entries = [
            {"service": "dispatcher", "level": "info", "timestamp": f"2025-02-21T10:0{i}:00+00:00",
             "trace_id": None, "message": f"message {i}", "raw": "{}"}
            for i in range(10)
        ]
        insert_logs_batch(entries)
        results = search_logs(limit=20)
        assert len(results) == 10

    def test_fts5_search(self):
        insert_log("dispatcher", "info", "2025-02-21T10:00:00+00:00", "pipeline started", "{}")
        insert_log("einbroch", "error", "2025-02-21T10:01:00+00:00", "tool call failed", "{}")
        results = search_logs(q="pipeline")
        assert len(results) == 1
        assert results[0]["message"] == "pipeline started"

    def test_filter_by_service(self):
        insert_log("dispatcher", "info", "2025-02-21T10:00:00+00:00", "msg1", "{}")
        insert_log("einbroch", "info", "2025-02-21T10:01:00+00:00", "msg2", "{}")
        results = search_logs(service="einbroch")
        assert len(results) == 1
        assert results[0]["service"] == "einbroch"

    def test_filter_by_level(self):
        insert_log("dispatcher", "info", "2025-02-21T10:00:00+00:00", "ok", "{}")
        insert_log("dispatcher", "error", "2025-02-21T10:01:00+00:00", "fail", "{}")
        results = search_logs(level="error")
        assert len(results) == 1
        assert results[0]["message"] == "fail"

    def test_filter_by_time_range(self):
        insert_log("s", "info", "2025-02-21T08:00:00+00:00", "early", "{}")
        insert_log("s", "info", "2025-02-21T12:00:00+00:00", "midday", "{}")
        insert_log("s", "info", "2025-02-21T18:00:00+00:00", "evening", "{}")
        results = search_logs(from_ts="2025-02-21T10:00:00+00:00", to_ts="2025-02-21T14:00:00+00:00")
        assert len(results) == 1
        assert results[0]["message"] == "midday"

    def test_filter_by_trace_id(self):
        insert_log("s", "info", "2025-02-21T10:00:00+00:00", "msg1", "{}", "trace-a")
        insert_log("s", "info", "2025-02-21T10:01:00+00:00", "msg2", "{}", "trace-b")
        results = search_logs(trace_id="trace-a")
        assert len(results) == 1
        assert results[0]["trace_id"] == "trace-a"

    def test_pagination(self):
        for i in range(25):
            insert_log("s", "info", f"2025-02-21T10:{i:02d}:00+00:00", f"msg{i}", "{}")
        page1 = search_logs(limit=10, offset=0)
        page2 = search_logs(limit=10, offset=10)
        assert len(page1) == 10
        assert len(page2) == 10
        assert page1[0]["message"] != page2[0]["message"]

    def test_combined_filters(self):
        insert_log("dispatcher", "error", "2025-02-21T10:00:00+00:00", "pipeline failed", "{}", "t1")
        insert_log("dispatcher", "info", "2025-02-21T10:01:00+00:00", "pipeline ok", "{}", "t2")
        insert_log("einbroch", "error", "2025-02-21T10:02:00+00:00", "tool error", "{}", "t3")
        results = search_logs(service="dispatcher", level="error")
        assert len(results) == 1
        assert results[0]["trace_id"] == "t1"


class TestServices:
    def test_get_services(self):
        insert_log("dispatcher", "info", "2025-02-21T10:00:00+00:00", "msg", "{}")
        insert_log("einbroch", "info", "2025-02-21T10:01:00+00:00", "msg", "{}")
        insert_log("bifrost", "info", "2025-02-21T10:02:00+00:00", "msg", "{}")
        services = get_services()
        assert sorted(services) == ["bifrost", "dispatcher", "einbroch"]


class TestRetention:
    def test_delete_old_logs(self):
        insert_log("s", "info", "2025-01-01T10:00:00+00:00", "old", "{}")
        insert_log("s", "info", "2025-02-21T10:00:00+00:00", "new", "{}")
        deleted = delete_old_logs("2025-02-01T00:00:00+00:00")
        assert deleted == 1
        results = search_logs()
        assert len(results) == 1
        assert results[0]["message"] == "new"


class TestContext:
    def test_get_log_context(self):
        for i in range(20):
            insert_log("dispatcher", "info", f"2025-02-21T10:{i:02d}:00+00:00", f"line {i}", "{}")
        all_logs = search_logs(limit=100)
        mid_id = all_logs[10]["id"]
        context = get_log_context(mid_id, context_lines=6)
        assert len(context) > 0


class TestLiveTail:
    def test_get_logs_after(self):
        insert_log("s", "info", "2025-02-21T10:00:00+00:00", "msg1", "{}")
        insert_log("s", "info", "2025-02-21T10:01:00+00:00", "msg2", "{}")
        first_id = search_logs(limit=1, offset=1)[0]["id"]
        results = get_logs_after(first_id)
        assert len(results) == 1
        assert results[0]["message"] == "msg2"

    def test_get_latest_log_id_empty(self):
        assert get_latest_log_id() == 0

    def test_get_latest_log_id(self):
        insert_log("s", "info", "2025-02-21T10:00:00+00:00", "msg1", "{}")
        assert get_latest_log_id() > 0


class TestDbSize:
    def test_get_db_size(self):
        insert_log("s", "info", "2025-02-21T10:00:00+00:00", "msg", "{}")
        size = get_db_size_bytes()
        assert size > 0
