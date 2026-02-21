"""INV-006 compliant secret scrubbing pipeline.

Scrubs secrets from log lines BEFORE writing to SQLite.
Patterns derived from Einbroch's DLP engine (einbroch/src/firewall/dlp_engine.py).

Respects Einbroch's upstream redaction: entries with logging_strategy
"redacted" or "partial" skip re-scrubbing to avoid mangling.
"""

import json
import re
from typing import Optional

import structlog

from .config import settings

logger = structlog.get_logger(__name__)

# Patterns modeled after Einbroch's DLP lightweight tier
SCRUB_PATTERNS: list[tuple[str, re.Pattern]] = [
    # API keys
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("stripe_key", re.compile(r"sk_(live|test)_[A-Za-z0-9]{20,}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    # Bearer tokens
    ("bearer_token", re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.]{20,}", re.I)),
    # JWT signatures (three-part dot-separated base64)
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    # Connection strings
    ("connection_string", re.compile(
        r"(postgres|mysql|mongodb|redis|amqp)://[^\s\"']{10,}", re.I
    )),
    # Generic key=value secrets
    ("api_key_assignment", re.compile(
        r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?", re.I
    )),
    ("password_assignment", re.compile(
        r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?", re.I
    )),
    ("secret_assignment", re.compile(
        r"(?:secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?", re.I
    )),
    # AWS credentials
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    # Private keys
    ("private_key", re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----")),
]

# Extra patterns from config
_extra_compiled: list[tuple[str, re.Pattern]] = []


def _load_extra_patterns():
    """Load extra scrub patterns from environment variable."""
    global _extra_compiled
    if settings.extra_scrub_patterns:
        for i, pattern_str in enumerate(settings.extra_scrub_patterns.split(",")):
            pattern_str = pattern_str.strip()
            if pattern_str:
                try:
                    _extra_compiled.append(
                        (f"custom_{i}", re.compile(pattern_str))
                    )
                except re.error as e:
                    logger.warning("invalid_scrub_pattern", pattern=pattern_str, error=str(e))


_load_extra_patterns()


def _should_skip_scrubbing(raw: str) -> bool:
    """Check if this entry has already been scrubbed by Einbroch's DLP.

    Einbroch's FirewallLogEntry includes a logging_strategy field.
    If it's "redacted" or "partial", the upstream DLP already handled scrubbing.
    """
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            strategy = data.get("logging_strategy", "")
            if strategy in ("redacted", "partial"):
                return True
    except (json.JSONDecodeError, ValueError):
        pass
    return False


def scrub(text: str, raw: Optional[str] = None) -> str:
    """Scrub secrets from a text string.

    Args:
        text: The message text to scrub
        raw: The raw log line (used to check logging_strategy)

    Returns:
        Scrubbed text with secrets replaced by [REDACTED]
    """
    if raw and _should_skip_scrubbing(raw):
        return text

    scrubbed = False
    result = text

    for name, pattern in SCRUB_PATTERNS + _extra_compiled:
        match = pattern.search(result)
        if match:
            scrubbed = True
            # Special case for Bearer: keep the "Bearer " prefix
            if name == "bearer_token":
                result = pattern.sub(r"\1[REDACTED]", result)
            else:
                result = pattern.sub("[REDACTED]", result)

    if scrubbed:
        logger.debug("secrets_scrubbed", original_length=len(text), scrubbed_length=len(result))

    return result


def scrub_entry(entry: dict) -> dict:
    """Scrub secrets from a normalized log entry (message and raw fields)."""
    raw = entry.get("raw")

    if raw and _should_skip_scrubbing(raw):
        return entry

    entry["message"] = scrub(entry["message"], raw)
    if raw:
        entry["raw"] = scrub(raw, raw)

    return entry
