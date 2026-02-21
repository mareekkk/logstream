"""Logstream REST API — search, context, services list, SSE live tail, health."""

import asyncio
import json
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

from .config import settings
from .collector import subscribe, unsubscribe
from .db import get_db_size_bytes, get_log_context, get_services, search_logs

logger = structlog.get_logger(__name__)

router = APIRouter()


def verify_admin_key(request: Request):
    """Validate X-Admin-Key header against configured secret."""
    if not settings.admin_key:
        # No key configured — allow all (dev mode)
        return
    key = request.headers.get("x-admin-key", "")
    if key != settings.admin_key:
        raise HTTPException(status_code=401, detail="Invalid admin key")


# ---------------------------------------------------------------------------
# Health check (no auth required)
# ---------------------------------------------------------------------------


@router.get("/health")
async def health():
    """Health check endpoint — returns service status and DB size."""
    db_size = get_db_size_bytes()
    return {
        "status": "healthy",
        "db_size_bytes": db_size,
        "db_size_mb": round(db_size / (1024 * 1024), 2),
        "max_db_size_mb": settings.max_db_size_mb,
        "retention_days": settings.log_retention_days,
    }


# ---------------------------------------------------------------------------
# Search API
# ---------------------------------------------------------------------------


@router.get("/v1/logs/search", dependencies=[Depends(verify_admin_key)])
async def search(
    q: Optional[str] = Query(None, description="Full-text search query"),
    service: Optional[str] = Query(None, description="Filter by service name"),
    level: Optional[str] = Query(None, description="Filter by log level"),
    from_ts: Optional[str] = Query(None, alias="from", description="Start timestamp (ISO 8601)"),
    to_ts: Optional[str] = Query(None, alias="to", description="End timestamp (ISO 8601)"),
    trace_id: Optional[str] = Query(None, description="Filter by trace ID"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Search logs with FTS5 full-text search and filters."""
    results = search_logs(
        q=q,
        service=service,
        level=level,
        from_ts=from_ts,
        to_ts=to_ts,
        trace_id=trace_id,
        limit=limit,
        offset=offset,
    )
    return {"entries": results, "count": len(results), "limit": limit, "offset": offset}


# ---------------------------------------------------------------------------
# Context (surrounding lines)
# ---------------------------------------------------------------------------


@router.get("/v1/logs/{log_id}/context", dependencies=[Depends(verify_admin_key)])
async def context(log_id: int, lines: int = Query(20, ge=1, le=200)):
    """Get surrounding log lines for a given log entry."""
    results = get_log_context(log_id, context_lines=lines)
    if not results:
        raise HTTPException(status_code=404, detail="Log entry not found")
    return {"entries": results, "target_id": log_id}


# ---------------------------------------------------------------------------
# Services list
# ---------------------------------------------------------------------------


@router.get("/v1/logs/services", dependencies=[Depends(verify_admin_key)])
async def services():
    """Return distinct service names found in the logs."""
    return {"services": get_services()}


# ---------------------------------------------------------------------------
# SSE Live tail
# ---------------------------------------------------------------------------


@router.get("/v1/logs/stream", dependencies=[Depends(verify_admin_key)])
async def stream(
    request: Request,
    service: Optional[str] = Query(None),
    level: Optional[str] = Query(None),
):
    """Server-Sent Events endpoint for live log tailing.

    Optional query params to filter the stream by service and/or level.
    Rate-limited to ~50 lines/sec.
    """

    async def event_generator():
        queue = subscribe()
        try:
            while True:
                if await request.is_disconnected():
                    break

                try:
                    entry = await asyncio.wait_for(queue.get(), timeout=30.0)
                except asyncio.TimeoutError:
                    # Send keepalive comment
                    yield {"comment": "keepalive"}
                    continue

                # Apply filters
                if service and entry.get("service") != service:
                    continue
                if level and entry.get("level") != level:
                    continue

                yield {"data": json.dumps(entry), "event": "log"}

                # Rate limiting: brief sleep to cap throughput
                await asyncio.sleep(1.0 / settings.sse_max_lines_per_second)

        finally:
            unsubscribe(queue)

    return EventSourceResponse(event_generator())
