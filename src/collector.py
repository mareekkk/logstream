"""Docker log collector daemon.

Tails logs from all running containers via the Docker socket API.
Normalizes, scrubs, and stores entries in SQLite.
"""

import asyncio
import threading
from datetime import datetime, timezone
from typing import Optional

import docker
import structlog

from .config import settings
from .db import insert_logs_batch
from .normalizer import normalize_log_line
from .scrubber import scrub_entry

logger = structlog.get_logger(__name__)

_stop_event = threading.Event()
_collector_threads: list[threading.Thread] = []
_monitor_running = False


def _get_service_name(container) -> str:
    """Extract a human-readable service name from a container.

    Prefers Docker Compose service label, falls back to container name.
    """
    labels = container.labels or {}
    # Docker Compose v2 label
    service = labels.get("com.docker.compose.service")
    if service:
        return service
    # Fallback: container name (strip leading /)
    name = container.name or container.short_id
    return name.lstrip("/")


def _tail_container(container, since: Optional[datetime] = None):
    """Tail a single container's logs in a background thread.

    Reads log lines, normalizes them, scrubs secrets, and writes
    to SQLite in batches.
    """
    service = _get_service_name(container)
    logger.info("collector_tailing", service=service, container_id=container.short_id)

    batch: list[dict] = []
    batch_size = 50
    flush_interval = 2.0  # seconds
    last_flush = asyncio.get_event_loop().time() if False else 0

    try:
        kwargs = {"stream": True, "follow": True, "timestamps": True}
        if since:
            kwargs["since"] = since

        for line_bytes in container.logs(**kwargs):
            if _stop_event.is_set():
                break

            try:
                line = line_bytes.decode("utf-8", errors="replace").strip()
            except Exception:
                continue

            if not line:
                continue

            # Docker prepends timestamps like "2025-02-21T10:00:00.123Z message"
            # Strip Docker's timestamp prefix if present (we parse our own from JSON)
            docker_ts = None
            if len(line) > 30 and line[0].isdigit() and "T" in line[:30]:
                space_idx = line.find(" ")
                if space_idx > 0:
                    docker_ts = line[:space_idx]
                    line = line[space_idx + 1:]

            entry = normalize_log_line(line, service)

            # Use Docker's timestamp as fallback if normalizer used current time
            if docker_ts and entry["timestamp"] == normalize_log_line("", service)["timestamp"]:
                entry["timestamp"] = docker_ts

            entry = scrub_entry(entry)
            batch.append(entry)

            if len(batch) >= batch_size:
                insert_logs_batch(batch)
                # Notify live tail subscribers
                _notify_subscribers(batch)
                batch = []

        # Flush remaining
        if batch:
            insert_logs_batch(batch)
            _notify_subscribers(batch)

    except Exception as e:
        if not _stop_event.is_set():
            logger.error("collector_error", service=service, error=str(e))


# Live tail subscriber system
_subscribers: list[asyncio.Queue] = []
_sub_lock = threading.Lock()


def subscribe() -> asyncio.Queue:
    """Subscribe to live log entries. Returns an asyncio.Queue."""
    q: asyncio.Queue = asyncio.Queue(maxsize=1000)
    with _sub_lock:
        _subscribers.append(q)
    return q


def unsubscribe(q: asyncio.Queue):
    """Remove a subscriber queue."""
    with _sub_lock:
        try:
            _subscribers.remove(q)
        except ValueError:
            pass


def _notify_subscribers(entries: list[dict]):
    """Push new entries to all live tail subscribers."""
    with _sub_lock:
        dead = []
        for q in _subscribers:
            for entry in entries:
                try:
                    q.put_nowait(entry)
                except asyncio.QueueFull:
                    # Drop oldest to make room
                    try:
                        q.get_nowait()
                        q.put_nowait(entry)
                    except (asyncio.QueueEmpty, asyncio.QueueFull):
                        pass
                except Exception:
                    dead.append(q)
                    break
        for q in dead:
            try:
                _subscribers.remove(q)
            except ValueError:
                pass


def _monitor_containers():
    """Monitor Docker for container start/stop events and manage tailers."""
    global _monitor_running
    _monitor_running = True

    try:
        client = docker.from_env()
    except docker.errors.DockerException as e:
        logger.error("docker_connect_failed", error=str(e))
        return

    active: dict[str, threading.Thread] = {}
    self_id = None

    # Try to detect our own container ID to skip self
    try:
        import socket
        self_hostname = socket.gethostname()
    except Exception:
        self_hostname = None

    while not _stop_event.is_set():
        try:
            containers = client.containers.list()
            current_ids = set()

            for container in containers:
                cid = container.id
                current_ids.add(cid)

                # Skip self
                if self_hostname and container.short_id in (self_hostname or ""):
                    self_id = cid
                    continue
                if cid == self_id:
                    continue

                # Skip if already tailing
                if cid in active and active[cid].is_alive():
                    continue

                # Start tailing this container
                since = datetime.now(tz=timezone.utc)
                t = threading.Thread(
                    target=_tail_container,
                    args=(container, since),
                    daemon=True,
                    name=f"tail-{_get_service_name(container)}",
                )
                t.start()
                active[cid] = t
                _collector_threads.append(t)

            # Clean up dead threads for removed containers
            for cid in list(active.keys()):
                if cid not in current_ids:
                    logger.info(
                        "collector_container_removed",
                        container_id=cid[:12],
                    )
                    del active[cid]

        except Exception as e:
            if not _stop_event.is_set():
                logger.error("monitor_error", error=str(e))

        # Check for new containers every 10 seconds
        _stop_event.wait(timeout=10)

    _monitor_running = False


async def start_collector():
    """Start the container monitor in a background thread."""
    logger.info("collector_starting")
    t = threading.Thread(target=_monitor_containers, daemon=True, name="container-monitor")
    t.start()
    _collector_threads.append(t)

    # Keep the async task alive until stop
    while not _stop_event.is_set():
        await asyncio.sleep(1)


def stop_collector():
    """Signal all collector threads to stop."""
    logger.info("collector_stopping")
    _stop_event.set()
