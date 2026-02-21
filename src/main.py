"""Logstream — centralized log collector and search service for PronterLabs."""

import asyncio
import logging
import sys

import structlog
from fastapi import FastAPI
from contextlib import asynccontextmanager

from .config import settings
from .db import init_db, close_db
from .collector import start_collector, stop_collector
from .retention import start_retention_loop, stop_retention_loop
from .api import router


def configure_logging():
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
    )
    handler = logging.StreamHandler(sys.stdout)
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.INFO)


configure_logging()
logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("logstream_starting", db_path=settings.db_path)
    init_db()
    collector_task = asyncio.create_task(start_collector())
    retention_task = asyncio.create_task(start_retention_loop())
    yield
    stop_collector()
    stop_retention_loop()
    collector_task.cancel()
    retention_task.cancel()
    try:
        await collector_task
    except asyncio.CancelledError:
        pass
    try:
        await retention_task
    except asyncio.CancelledError:
        pass
    close_db()
    logger.info("logstream_stopped")


app = FastAPI(
    title="Logstream",
    description="Centralized log collector and search for PronterLabs",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(router)
