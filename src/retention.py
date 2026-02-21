"""Log retention and cleanup — configurable window with max_db_size safeguard."""

import asyncio
from datetime import datetime, timedelta, timezone

import structlog

from .config import settings
from .db import delete_old_logs, get_db_size_bytes

logger = structlog.get_logger(__name__)

_running = True


async def start_retention_loop():
    """Periodically clean up old logs based on retention policy."""
    global _running
    _running = True
    logger.info(
        "retention_loop_started",
        retention_days=settings.log_retention_days,
        max_db_size_mb=settings.max_db_size_mb,
        interval_seconds=settings.retention_check_interval_seconds,
    )

    while _running:
        try:
            _run_cleanup()
        except Exception as e:
            logger.error("retention_error", error=str(e))

        await asyncio.sleep(settings.retention_check_interval_seconds)


def _run_cleanup():
    """Execute one retention cleanup cycle."""
    # Time-based retention
    cutoff = datetime.now(tz=timezone.utc) - timedelta(
        days=settings.log_retention_days
    )
    cutoff_str = cutoff.isoformat()
    deleted = delete_old_logs(cutoff_str)
    if deleted > 0:
        logger.info("retention_cleanup", deleted=deleted, before=cutoff_str)

    # Size-based safeguard
    db_size = get_db_size_bytes()
    max_bytes = settings.max_db_size_mb * 1024 * 1024
    if db_size > max_bytes:
        logger.warning(
            "db_size_exceeded",
            current_mb=db_size / (1024 * 1024),
            max_mb=settings.max_db_size_mb,
        )
        # Aggressively purge: delete oldest 25% by reducing retention
        aggressive_cutoff = datetime.now(tz=timezone.utc) - timedelta(
            days=max(1, settings.log_retention_days * 3 // 4)
        )
        extra_deleted = delete_old_logs(aggressive_cutoff.isoformat())
        logger.info("retention_aggressive_purge", deleted=extra_deleted)


def stop_retention_loop():
    """Signal the retention loop to stop."""
    global _running
    _running = False
