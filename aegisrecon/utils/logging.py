"""Logging configuration for AegisRecon.

Logs are always written to stderr so that stdout remains clean for piped data.
Secrets are never logged: log messages must be constructed from untrusted data
using structured fields, and :func:`scrub` redacts known sensitive patterns as
a final safety net.
"""

from __future__ import annotations

import logging
import re
import sys

_LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s | %(message)s"

# Sensitive patterns redacted from any message before it hits the wire.
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(api[_-]?key|token|secret|password|passwd|auth)\s*[=:]\s*([^\s&,]+)", re.IGNORECASE
        ),
        r"\1=***REDACTED***",
    ),
    (re.compile(r"(bearer|basic)\s+\S+", re.IGNORECASE), r"\1 ***REDACTED***"),
    (re.compile(r"(?i)https?://([^:\s/@]+):([^@\s/]+)@"), r"https://\1:***REDACTED***@"),
]


def scrub(message: str) -> str:
    """Redact common secret patterns from a log message."""
    redacted = message
    for pattern, replacement in _SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


class _RedactingHandler(logging.StreamHandler):
    """StreamHandler that scrubs sensitive patterns from formatted output."""

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        record.msg = scrub(message)
        record.args = ()
        return super().format(record)


def setup_logging(level: str = "INFO", debug: bool = False) -> None:
    """Configure the root AegisRecon logger.

    Args:
        level: One of DEBUG/INFO/WARNING/ERROR.
        debug: Shortcut to set DEBUG level.
    """
    effective = "DEBUG" if debug else level.upper()
    root = logging.getLogger("aegisrecon")
    root.setLevel(effective)

    if root.handlers:
        root.handlers.clear()

    handler = _RedactingHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    root.addHandler(handler)

    # Keep third-party loggers quiet unless we are in debug mode.
    for noisy in ("httpx", "httpcore", "urllib3", "sqlalchemy.engine"):
        third = logging.getLogger(noisy)
        third.setLevel(logging.DEBUG if debug else logging.WARNING)

    root.debug("logging initialised at %s level", effective)


__all__ = ["setup_logging", "scrub"]
