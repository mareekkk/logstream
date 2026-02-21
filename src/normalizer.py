"""Log normalizer — handles three distinct log schemas.

Dispatcher (structlog): event field, log_level string, ISO timestamp
Einbroch (structlog):   event field, log_level string, ISO timestamp, callsite info
Memlink (Pino):         msg field, numeric level (10-60), Unix ms timestamp
"""

import json
from datetime import datetime, timezone
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)

# Pino numeric level → string level mapping
PINO_LEVELS = {
    10: "trace",
    20: "debug",
    30: "info",
    40: "warn",
    50: "error",
    60: "fatal",
}


def _parse_pino_level(level_value) -> str:
    """Convert Pino numeric level to string."""
    if isinstance(level_value, int):
        return PINO_LEVELS.get(level_value, "info")
    if isinstance(level_value, str):
        return level_value.lower()
    return "info"


def _unix_ms_to_iso(ts) -> Optional[str]:
    """Convert Unix milliseconds timestamp to ISO 8601."""
    try:
        if isinstance(ts, (int, float)):
            dt = datetime.fromtimestamp(ts / 1000.0, tz=timezone.utc)
            return dt.isoformat()
    except (ValueError, OSError, OverflowError):
        pass
    return None


def _extract_trace_id(data: dict) -> Optional[str]:
    """Extract trace ID from various field names."""
    for key in ("trace_id", "traceId", "request_id", "requestId", "x_trace_id"):
        val = data.get(key)
        if val:
            return str(val)
    return None


def _extract_message(data: dict) -> str:
    """Extract message from structlog 'event' or Pino 'msg' field."""
    for key in ("event", "msg", "message"):
        val = data.get(key)
        if val:
            return str(val)
    return json.dumps(data)


def _extract_level(data: dict) -> str:
    """Extract and normalize log level from various schemas."""
    # structlog: log_level as string
    level = data.get("log_level")
    if isinstance(level, str):
        return level.lower()

    # Pino: level as int
    level = data.get("level")
    if isinstance(level, int):
        return _parse_pino_level(level)
    if isinstance(level, str):
        return level.lower()

    # stdlib: levelname
    level = data.get("levelname")
    if isinstance(level, str):
        return level.lower()

    return "info"


def _extract_timestamp(data: dict) -> str:
    """Extract and normalize timestamp."""
    # structlog: ISO 8601 string in 'timestamp'
    ts = data.get("timestamp")
    if isinstance(ts, str):
        return ts

    # Pino: Unix ms in 'time'
    ts = data.get("time")
    if isinstance(ts, (int, float)):
        iso = _unix_ms_to_iso(ts)
        if iso:
            return iso

    # Fallback: current time
    return datetime.now(tz=timezone.utc).isoformat()


def normalize_log_line(raw_line: str, service: str) -> dict:
    """Parse and normalize a single log line into a standard format.

    Returns a dict with keys: service, level, timestamp, trace_id, message, raw
    """
    raw_line = raw_line.strip()
    if not raw_line:
        return {
            "service": service,
            "level": "info",
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "trace_id": None,
            "message": "",
            "raw": raw_line,
        }

    # Try JSON parse first
    try:
        data = json.loads(raw_line)
        if isinstance(data, dict):
            return {
                "service": service,
                "level": _extract_level(data),
                "timestamp": _extract_timestamp(data),
                "trace_id": _extract_trace_id(data),
                "message": _extract_message(data),
                "raw": raw_line,
            }
    except (json.JSONDecodeError, ValueError):
        pass

    # Fallback: plain text — try to detect level from common prefixes
    level = "info"
    lower = raw_line.lower()
    if "error" in lower or "traceback" in lower or "exception" in lower:
        level = "error"
    elif "warn" in lower:
        level = "warn"
    elif "debug" in lower:
        level = "debug"

    return {
        "service": service,
        "level": level,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "trace_id": None,
        "message": raw_line,
        "raw": raw_line,
    }
