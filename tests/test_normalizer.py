"""Tests for the log normalizer — all three schemas plus fallback."""

import json

from src.normalizer import normalize_log_line


class TestDispatcherStructlog:
    """Dispatcher uses structlog with event, log_level, ISO timestamp."""

    def test_basic_dispatcher_log(self):
        raw = json.dumps({
            "event": "request_received",
            "log_level": "info",
            "timestamp": "2025-02-21T10:00:00.123456+00:00",
            "trace_id": "abc-123",
        })
        result = normalize_log_line(raw, "dispatcher")
        assert result["service"] == "dispatcher"
        assert result["level"] == "info"
        assert result["message"] == "request_received"
        assert result["trace_id"] == "abc-123"
        assert result["timestamp"] == "2025-02-21T10:00:00.123456+00:00"

    def test_dispatcher_error(self):
        raw = json.dumps({
            "event": "pipeline_failed",
            "log_level": "error",
            "timestamp": "2025-02-21T10:01:00+00:00",
            "trace_id": "def-456",
        })
        result = normalize_log_line(raw, "dispatcher")
        assert result["level"] == "error"
        assert result["message"] == "pipeline_failed"

    def test_dispatcher_warning(self):
        raw = json.dumps({
            "event": "rate_limit_approaching",
            "log_level": "warning",
            "timestamp": "2025-02-21T10:02:00+00:00",
        })
        result = normalize_log_line(raw, "dispatcher")
        assert result["level"] == "warning"
        assert result["trace_id"] is None


class TestEinbrochStructlog:
    """Einbroch uses structlog with callsite info (filename, lineno)."""

    def test_basic_einbroch_log(self):
        raw = json.dumps({
            "event": "tool_call_authorized",
            "log_level": "info",
            "timestamp": "2025-02-21T10:00:00+00:00",
            "filename": "enforcement.py",
            "lineno": 42,
            "trace_id": "xyz-789",
        })
        result = normalize_log_line(raw, "einbroch")
        assert result["service"] == "einbroch"
        assert result["level"] == "info"
        assert result["message"] == "tool_call_authorized"
        assert result["trace_id"] == "xyz-789"

    def test_einbroch_firewall_entry(self):
        raw = json.dumps({
            "event": "dlp_scan_complete",
            "log_level": "info",
            "timestamp": "2025-02-21T10:00:00+00:00",
            "logging_strategy": "redacted",
            "payload_hash": "sha256:abc123",
        })
        result = normalize_log_line(raw, "einbroch")
        assert result["message"] == "dlp_scan_complete"
        assert result["level"] == "info"


class TestMemlinkPino:
    """Memlink uses Pino with msg, numeric level, Unix ms timestamp."""

    def test_basic_pino_log(self):
        raw = json.dumps({
            "msg": "fact created",
            "level": 30,
            "time": 1708506000123,
            "name": "memlink",
        })
        result = normalize_log_line(raw, "memlink-api")
        assert result["service"] == "memlink-api"
        assert result["level"] == "info"  # 30 = info
        assert result["message"] == "fact created"
        assert "2024-02-21" in result["timestamp"]

    def test_pino_error(self):
        raw = json.dumps({
            "msg": "database connection failed",
            "level": 50,
            "time": 1708506000999,
        })
        result = normalize_log_line(raw, "memlink-api")
        assert result["level"] == "error"

    def test_pino_warn(self):
        raw = json.dumps({
            "msg": "slow query detected",
            "level": 40,
            "time": 1708506000500,
        })
        result = normalize_log_line(raw, "memlink-api")
        assert result["level"] == "warn"

    def test_pino_fatal(self):
        raw = json.dumps({
            "msg": "unrecoverable error",
            "level": 60,
            "time": 1708506000000,
        })
        result = normalize_log_line(raw, "memlink-api")
        assert result["level"] == "fatal"

    def test_pino_debug(self):
        raw = json.dumps({
            "msg": "cache hit",
            "level": 20,
            "time": 1708506000000,
        })
        result = normalize_log_line(raw, "memlink-api")
        assert result["level"] == "debug"


class TestFallbackParsing:
    """Non-JSON log lines should be parsed with best-effort level detection."""

    def test_plain_text_info(self):
        result = normalize_log_line("Server started on port 3131", "memlink-api")
        assert result["level"] == "info"
        assert result["message"] == "Server started on port 3131"

    def test_plain_text_error(self):
        result = normalize_log_line("ERROR: connection refused", "dispatcher")
        assert result["level"] == "error"

    def test_plain_text_warning(self):
        result = normalize_log_line("WARN: deprecated function used", "bifrost")
        assert result["level"] == "warn"

    def test_plain_text_traceback(self):
        result = normalize_log_line("Traceback (most recent call last):", "einbroch")
        assert result["level"] == "error"

    def test_empty_line(self):
        result = normalize_log_line("", "test")
        assert result["message"] == ""
        assert result["level"] == "info"

    def test_whitespace_only(self):
        result = normalize_log_line("   \n  ", "test")
        assert result["message"] == ""


class TestTraceIdExtraction:
    """Test trace_id extraction from various field names."""

    def test_trace_id_field(self):
        raw = json.dumps({"event": "test", "trace_id": "abc"})
        assert normalize_log_line(raw, "s")["trace_id"] == "abc"

    def test_request_id_field(self):
        raw = json.dumps({"event": "test", "request_id": "def"})
        assert normalize_log_line(raw, "s")["trace_id"] == "def"

    def test_traceId_camelcase(self):
        raw = json.dumps({"event": "test", "traceId": "ghi"})
        assert normalize_log_line(raw, "s")["trace_id"] == "ghi"

    def test_no_trace_id(self):
        raw = json.dumps({"event": "test"})
        assert normalize_log_line(raw, "s")["trace_id"] is None
