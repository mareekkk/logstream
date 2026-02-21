"""SQLite + FTS5 database layer for Logstream."""

import os
import sqlite3
import threading
from typing import Optional

import structlog

from .config import settings

logger = structlog.get_logger(__name__)

_local = threading.local()
_write_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    service    TEXT    NOT NULL,
    level      TEXT    NOT NULL DEFAULT 'info',
    timestamp  TEXT    NOT NULL,
    trace_id   TEXT,
    message    TEXT    NOT NULL,
    raw        TEXT
);

CREATE INDEX IF NOT EXISTS idx_logs_service   ON logs(service);
CREATE INDEX IF NOT EXISTS idx_logs_level     ON logs(level);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_trace_id  ON logs(trace_id);

CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5(
    message,
    content=logs,
    content_rowid=id
);

-- Triggers to keep FTS5 in sync with the logs table
CREATE TRIGGER IF NOT EXISTS logs_ai AFTER INSERT ON logs BEGIN
    INSERT INTO logs_fts(rowid, message) VALUES (new.id, new.message);
END;

CREATE TRIGGER IF NOT EXISTS logs_ad AFTER DELETE ON logs BEGIN
    INSERT INTO logs_fts(logs_fts, rowid, message) VALUES ('delete', old.id, old.message);
END;
"""


def _get_conn() -> sqlite3.Connection:
    """Get a thread-local SQLite connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        os.makedirs(os.path.dirname(settings.db_path), exist_ok=True)
        conn = sqlite3.connect(settings.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        _local.conn = conn
    return _local.conn


def init_db():
    """Create tables and FTS5 index if they don't exist."""
    conn = _get_conn()
    conn.executescript(SCHEMA)
    conn.commit()
    logger.info("db_initialized", path=settings.db_path)


def close_db():
    """Close the thread-local connection."""
    if hasattr(_local, "conn") and _local.conn is not None:
        _local.conn.close()
        _local.conn = None


def insert_log(
    service: str,
    level: str,
    timestamp: str,
    message: str,
    raw: str,
    trace_id: Optional[str] = None,
):
    """Insert a single log entry. Thread-safe via write lock."""
    with _write_lock:
        conn = _get_conn()
        conn.execute(
            "INSERT INTO logs (service, level, timestamp, trace_id, message, raw) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (service, level, timestamp, message, raw, trace_id),
        )
        conn.commit()


def insert_logs_batch(entries: list[dict]):
    """Insert multiple log entries in a single transaction."""
    if not entries:
        return
    with _write_lock:
        conn = _get_conn()
        conn.executemany(
            "INSERT INTO logs (service, level, timestamp, trace_id, message, raw) "
            "VALUES (:service, :level, :timestamp, :trace_id, :message, :raw)",
            entries,
        )
        conn.commit()


def search_logs(
    q: Optional[str] = None,
    service: Optional[str] = None,
    level: Optional[str] = None,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
    trace_id: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """Search logs with optional FTS5 query and filters."""
    conn = _get_conn()
    conditions = []
    params: list = []

    if q:
        conditions.append(
            "logs.id IN (SELECT rowid FROM logs_fts WHERE logs_fts MATCH ?)"
        )
        params.append(q)
    if service:
        conditions.append("logs.service = ?")
        params.append(service)
    if level:
        conditions.append("logs.level = ?")
        params.append(level)
    if from_ts:
        conditions.append("logs.timestamp >= ?")
        params.append(from_ts)
    if to_ts:
        conditions.append("logs.timestamp <= ?")
        params.append(to_ts)
    if trace_id:
        conditions.append("logs.trace_id = ?")
        params.append(trace_id)

    where = " AND ".join(conditions) if conditions else "1=1"
    query = (
        f"SELECT id, service, level, timestamp, trace_id, message, raw "
        f"FROM logs WHERE {where} "
        f"ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    )
    params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def get_log_context(log_id: int, context_lines: int = 20) -> list[dict]:
    """Get surrounding log lines for a given log entry."""
    conn = _get_conn()
    # First get the target log's timestamp and service
    target = conn.execute(
        "SELECT service, timestamp FROM logs WHERE id = ?", (log_id,)
    ).fetchone()
    if not target:
        return []

    service = target["service"]
    timestamp = target["timestamp"]

    # Get lines around this timestamp for the same service
    rows = conn.execute(
        "SELECT id, service, level, timestamp, trace_id, message, raw FROM logs "
        "WHERE service = ? AND timestamp >= ("
        "  SELECT timestamp FROM logs WHERE service = ? "
        "  AND timestamp <= ? ORDER BY timestamp DESC LIMIT 1 OFFSET ?"
        ") AND timestamp <= ("
        "  SELECT timestamp FROM logs WHERE service = ? "
        "  AND timestamp >= ? ORDER BY timestamp ASC LIMIT 1 OFFSET ?"
        ") ORDER BY timestamp ASC",
        (service, service, timestamp, context_lines // 2,
         service, timestamp, context_lines // 2),
    ).fetchall()
    return [dict(row) for row in rows]


def get_services() -> list[str]:
    """Return distinct service names from the logs table."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT DISTINCT service FROM logs ORDER BY service"
    ).fetchall()
    return [row["service"] for row in rows]


def get_db_size_bytes() -> int:
    """Return the SQLite database file size in bytes."""
    try:
        return os.path.getsize(settings.db_path)
    except OSError:
        return 0


def delete_old_logs(before_timestamp: str) -> int:
    """Delete logs older than the given timestamp. Returns count deleted."""
    with _write_lock:
        conn = _get_conn()
        cursor = conn.execute(
            "DELETE FROM logs WHERE timestamp < ?", (before_timestamp,)
        )
        deleted = cursor.rowcount
        if deleted > 0:
            # Rebuild FTS5 index after bulk delete
            conn.execute("INSERT INTO logs_fts(logs_fts) VALUES ('rebuild')")
        conn.commit()
        return deleted


def get_latest_log_id() -> int:
    """Return the highest log id, or 0 if empty."""
    conn = _get_conn()
    row = conn.execute("SELECT MAX(id) as max_id FROM logs").fetchone()
    return row["max_id"] or 0 if row else 0


def get_logs_after(after_id: int, limit: int = 50) -> list[dict]:
    """Get log entries with id > after_id (for live tail)."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT id, service, level, timestamp, trace_id, message, raw "
        "FROM logs WHERE id > ? ORDER BY id ASC LIMIT ?",
        (after_id, limit),
    ).fetchall()
    return [dict(row) for row in rows]
