"""Retry and backoff helpers.

All external calls in AegisRecon (HTTP, DNS, external binaries) are wrapped
with retry logic so transient failures do not kill a long-running scan.
"""

from __future__ import annotations

import functools
import logging
import random
import time
from typing import Any, Callable, TypeVar

from aegisrecon.exceptions import AegisReconError

logger = logging.getLogger("aegisrecon.utils.retry")

T = TypeVar("T")


def retry(
    attempts: int = 3,
    base_delay: float = 0.5,
    max_delay: float = 8.0,
    backoff_factor: float = 2.0,
    exceptions: tuple[type[Exception], ...] = (AegisReconError, OSError, TimeoutError),
    logger_: logging.Logger | None = None,
):
    """Decorator that retries a callable with exponential backoff and jitter.

    Args:
        attempts: Maximum number of attempts including the first.
        base_delay: Initial sleep in seconds.
        max_delay: Upper bound on sleep in seconds.
        backoff_factor: Multiplier applied to the delay each attempt.
        exceptions: Exception types that trigger a retry.
        logger_: Logger to emit warnings through.

    Returns:
        The wrapped callable.
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            log = logger_ or logger
            delay = base_delay
            for attempt in range(1, attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:  # type: ignore[misc]
                    if attempt >= attempts:
                        raise
                    sleep = min(max_delay, delay * (backoff_factor ** (attempt - 1)))
                    sleep = sleep * (0.5 + random.random() * 0.5)  # jitter
                    log.warning(
                        "%s failed (attempt %d/%d): %s; retrying in %.1fs",
                        getattr(func, "__name__", func),
                        attempt,
                        attempts,
                        exc,
                        sleep,
                    )
                    time.sleep(sleep)
            raise AssertionError("unreachable")  # pragma: no cover

        return wrapper

    return decorator


__all__ = ["retry"]
