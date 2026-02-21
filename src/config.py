"""Logstream configuration via environment variables."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Auth
    admin_key: str = ""

    # Storage
    db_path: str = "/data/logstream.db"

    # Retention
    log_retention_days: int = 7
    max_db_size_mb: int = 2048  # 2 GB default cap
    retention_check_interval_seconds: int = 3600  # 1 hour

    # Collector
    collector_restart_delay_seconds: int = 5

    # SSE rate limiting
    sse_max_lines_per_second: int = 50

    # Scrubber
    extra_scrub_patterns: str = ""  # comma-separated extra regex patterns

    model_config = {"env_prefix": "LOGSTREAM_"}


settings = Settings()
