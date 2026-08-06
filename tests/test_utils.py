"""Tests for retry/backoff and logging scrubbing."""

from __future__ import annotations

import time

import pytest

from aegisrecon.utils.logging import scrub, setup_logging
from aegisrecon.utils.retry import retry


def test_retry_succeeds_on_second_attempt(monkeypatch) -> None:
    attempts = {"n": 0}

    @retry(attempts=3, base_delay=0.01)
    def flaky():
        attempts["n"] += 1
        if attempts["n"] < 2:
            raise TimeoutError("transient")
        return "ok"

    monkeypatch.setattr(time, "sleep", lambda _s: None)
    assert flaky() == "ok"
    assert attempts["n"] == 2


def test_retry_exhausts_and_reraises(monkeypatch) -> None:
    attempts = {"n": 0}

    @retry(attempts=2, base_delay=0.01)
    def always_fails():
        attempts["n"] += 1
        raise TimeoutError("nope")

    monkeypatch.setattr(time, "sleep", lambda _s: None)
    with pytest.raises(TimeoutError):
        always_fails()
    assert attempts["n"] == 2


def test_retry_does_not_catch_other_errors(monkeypatch) -> None:
    @retry(attempts=2, base_delay=0.01, exceptions=(TimeoutError,))
    def type_error():
        raise ValueError("not retryable")

    monkeypatch.setattr(time, "sleep", lambda _s: None)
    with pytest.raises(ValueError):
        type_error()


def test_scrub_redacts_common_secrets() -> None:
    assert "key=***REDACTED***" in scrub("api_key=supersecret&x=1")
    assert scrub("Authorization: Bearer abcdef123") == "Authorization: Bearer ***REDACTED***"
    assert "***REDACTED***" in scrub("https://user:password@example.com/path")
    assert scrub("plain message with no secrets") == "plain message with no secrets"


def test_setup_logging_clears_handlers(caplog) -> None:
    setup_logging(level="DEBUG")
    import logging

    logger = logging.getLogger("aegisrecon")
    assert logger.level == logging.DEBUG
    assert len(logger.handlers) == 1
