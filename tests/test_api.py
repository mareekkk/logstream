"""Tests for the Logstream REST API."""

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

# Set up test DB before imports
os.environ["LOGSTREAM_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test_api.db")
os.environ["LOGSTREAM_ADMIN_KEY"] = "test-secret-key"

from src.db import init_db, close_db, insert_log, reset_conn


@pytest.fixture(autouse=True)
def setup_db(tmp_path):
    db_path = str(tmp_path / "test_api.db")
    from src import config
    config.settings.db_path = db_path
    config.settings.admin_key = "test-secret-key"
    close_db()
    reset_conn()
    init_db()
    yield
    close_db()
    reset_conn()


@pytest.fixture
def client():
    from src.main import app
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def auth_headers():
    return {"x-admin-key": "test-secret-key"}


class TestHealthEndpoint:
    def test_health_no_auth_required(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "db_size_mb" in data

    def test_health_includes_config(self, client):
        resp = client.get("/health")
        data = resp.json()
        assert "retention_days" in data
        assert "max_db_size_mb" in data


class TestAuthMiddleware:
    def test_search_requires_auth(self, client):
        resp = client.get("/v1/logs/search")
        assert resp.status_code == 401

    def test_search_with_valid_key(self, client, auth_headers):
        resp = client.get("/v1/logs/search", headers=auth_headers)
        assert resp.status_code == 200

    def test_search_with_invalid_key(self, client):
        resp = client.get("/v1/logs/search", headers={"x-admin-key": "wrong"})
        assert resp.status_code == 401

    def test_services_requires_auth(self, client):
        resp = client.get("/v1/logs/services")
        assert resp.status_code == 401

    def test_context_requires_auth(self, client):
        resp = client.get("/v1/logs/1/context")
        assert resp.status_code == 401


class TestSearchEndpoint:
    def test_empty_search(self, client, auth_headers):
        resp = client.get("/v1/logs/search", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["entries"] == []
        assert data["count"] == 0

    def test_search_returns_results(self, client, auth_headers):
        insert_log("dispatcher", "info", "2025-02-21T10:00:00+00:00", "hello world", "{}")
        resp = client.get("/v1/logs/search", headers=auth_headers)
        data = resp.json()
        assert data["count"] == 1
        assert data["entries"][0]["message"] == "hello world"

    def test_fts_search(self, client, auth_headers):
        insert_log("dispatcher", "info", "2025-02-21T10:00:00+00:00", "pipeline started", "{}")
        insert_log("einbroch", "error", "2025-02-21T10:01:00+00:00", "tool failed", "{}")
        resp = client.get("/v1/logs/search?q=pipeline", headers=auth_headers)
        data = resp.json()
        assert data["count"] == 1

    def test_service_filter(self, client, auth_headers):
        insert_log("dispatcher", "info", "2025-02-21T10:00:00+00:00", "msg1", "{}")
        insert_log("einbroch", "info", "2025-02-21T10:01:00+00:00", "msg2", "{}")
        resp = client.get("/v1/logs/search?service=einbroch", headers=auth_headers)
        data = resp.json()
        assert data["count"] == 1
        assert data["entries"][0]["service"] == "einbroch"

    def test_level_filter(self, client, auth_headers):
        insert_log("s", "info", "2025-02-21T10:00:00+00:00", "ok", "{}")
        insert_log("s", "error", "2025-02-21T10:01:00+00:00", "fail", "{}")
        resp = client.get("/v1/logs/search?level=error", headers=auth_headers)
        data = resp.json()
        assert data["count"] == 1
        assert data["entries"][0]["level"] == "error"

    def test_trace_id_filter(self, client, auth_headers):
        insert_log("s", "info", "2025-02-21T10:00:00+00:00", "msg1", "{}", "abc-123")
        insert_log("s", "info", "2025-02-21T10:01:00+00:00", "msg2", "{}", "def-456")
        resp = client.get("/v1/logs/search?trace_id=abc-123", headers=auth_headers)
        data = resp.json()
        assert data["count"] == 1
        assert data["entries"][0]["trace_id"] == "abc-123"

    def test_time_range_filter(self, client, auth_headers):
        insert_log("s", "info", "2025-02-21T08:00:00+00:00", "early", "{}")
        insert_log("s", "info", "2025-02-21T12:00:00+00:00", "midday", "{}")
        resp = client.get(
            "/v1/logs/search?from=2025-02-21T10:00:00%2B00:00&to=2025-02-21T14:00:00%2B00:00",
            headers=auth_headers,
        )
        data = resp.json()
        assert data["count"] == 1

    def test_pagination(self, client, auth_headers):
        for i in range(25):
            insert_log("s", "info", f"2025-02-21T10:{i:02d}:00+00:00", f"msg{i}", "{}")
        resp = client.get("/v1/logs/search?limit=10&offset=0", headers=auth_headers)
        data = resp.json()
        assert data["count"] == 10
        assert data["limit"] == 10
        assert data["offset"] == 0


class TestServicesEndpoint:
    def test_returns_services(self, client, auth_headers):
        insert_log("dispatcher", "info", "2025-02-21T10:00:00+00:00", "msg", "{}")
        insert_log("einbroch", "info", "2025-02-21T10:01:00+00:00", "msg", "{}")
        resp = client.get("/v1/logs/services", headers=auth_headers)
        data = resp.json()
        assert sorted(data["services"]) == ["dispatcher", "einbroch"]


class TestContextEndpoint:
    def test_context_returns_surrounding_lines(self, client, auth_headers):
        for i in range(20):
            insert_log("dispatcher", "info", f"2025-02-21T10:{i:02d}:00+00:00", f"line {i}", "{}")
        resp = client.get("/v1/logs/search?limit=1", headers=auth_headers)
        log_id = resp.json()["entries"][0]["id"]
        resp = client.get(f"/v1/logs/{log_id}/context", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["entries"]) > 0

    def test_context_not_found(self, client, auth_headers):
        resp = client.get("/v1/logs/99999/context", headers=auth_headers)
        assert resp.status_code == 404
