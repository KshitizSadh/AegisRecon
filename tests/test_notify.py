"""Tests for the notification plugins and dispatcher."""

from __future__ import annotations

import httpx
import pytest

from aegisrecon.exceptions import AegisReconError
from aegisrecon.notify import (
    ConsoleNotifier,
    DiscordNotifier,
    NotifierDispatcher,
    NotifierNotFoundError,
    SlackNotifier,
    available_notifiers,
    build_notifier,
)

PAYLOAD = {"title": "T", "program": "p", "message": "m"}


def test_console_notifier_emits(capsys) -> None:
    assert ConsoleNotifier().send(PAYLOAD) is True
    captured = capsys.readouterr().err
    assert "T" in captured


def test_slack_notifier_posts_success(monkeypatch) -> None:
    monkeypatch.setattr("httpx.Client", mockitoa())
    assert SlackNotifier(webhook_url="https://hooks.slack.com/services/T/B/X").send(PAYLOAD) is True


def test_slack_notifier_returns_false_on_error(monkeypatch) -> None:
    monkeypatch.setattr("httpx.Client", mock_client_that_raises())
    assert SlackNotifier(webhook_url="https://hooks.slack.com/services/T/B/X").send(PAYLOAD) is False


def test_discord_notifier_posts_success(monkeypatch) -> None:
    monkeypatch.setattr("httpx.Client", mockitoa())
    assert DiscordNotifier(webhook_url="https://discord.com/api/webhooks/x").send(PAYLOAD) is True


def test_available_notifiers_includes_builtins() -> None:
    names = available_notifiers()
    assert {"console", "slack", "discord"} <= set(names)


def test_build_notifier_returns_typed_instance() -> None:
    notifier = build_notifier("console")
    assert isinstance(notifier, ConsoleNotifier)


def test_build_unknown_notifier_raises() -> None:
    with pytest.raises(NotifierNotFoundError) as excinfo:
        build_notifier("does-not-exist")
    assert issubclass(NotifierNotFoundError, AegisReconError)
    assert "does-not-exist" in str(excinfo.value)


def test_dispatcher_isolates_failures() -> None:
    class _Good:
        name = "good"

        def send(self, payload) -> bool:  # noqa: ANN001
            return True

    class _Bad:
        name = "bad"

        def send(self, payload):  # noqa: ANN001
            raise RuntimeError("boom")

    summary = NotifierDispatcher([_Good(), _Bad()]).dispatch(PAYLOAD)
    assert summary == {"good": True, "bad": False}


def test_dispatcher_delivers_to_all() -> None:
    sent: list[str] = []

    class _Spy:
        name = "spy"

        def send(self, payload) -> bool:  # noqa: ANN001
            sent.append(payload["title"])
            return True

    NotifierDispatcher([_Spy(), _Spy()]).dispatch(PAYLOAD)
    assert sent == ["T", "T"]


def mockitoa():
    """Return a fake httpx.Client class whose instances post successfully."""

    class _Msg:
        def raise_for_status(self) -> None:  # noqa: ANN001
            pass

    class _Ctx:
        def __init__(self, *args, **kwargs):  # noqa: ANN001
            pass

        def __enter__(self) -> _Ctx:
            return self

        def __exit__(self, *args) -> None:  # noqa: ANN001
            pass

        def post(self, *a, **kw) -> _Msg:  # noqa: ANN001
            return _Msg()

    return _Ctx


def mock_client_that_raises():
    class _R:
        def raise_for_status(self) -> None:  # noqa: ANN001
            raise httpx.HTTPError("boom")

    class _Ctx:
        def __init__(self, *args, **kwargs):  # noqa: ANN001
            pass

        def __enter__(self) -> _Ctx:
            return self

        def __exit__(self, *args) -> None:  # noqa: ANN001
            pass

        def post(self, *a, **kw):  # noqa: ANN001
            return _R()

    return _Ctx
