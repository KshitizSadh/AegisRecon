"""Notification plugins and dispatcher.

Notifications are delivered through :class:`~aegisrecon.plugins.base.Notifier`
implementations. Built-ins cover console and webhooks (Slack / Discord); the
dispatcher resolves configured channels and fans a message out to each.

Messages are payload dicts; each notifier renders them to its own transport
format. Secrets are never included — callers must only submit safe summaries.
"""

from __future__ import annotations

import json
import logging
from typing import Any, cast

import httpx

from aegisrecon.exceptions import AegisReconError
from aegisrecon.plugins.base import Notifier

logger = logging.getLogger("aegisrecon.notify")


class ConsoleNotifier(Notifier):
    """Sends notifications to the local console (useful for local runs / tests)."""

    name = "console"
    version = "1.0.0"
    author = "AegisRecon Contributors"
    description = "Print notifications to the console"

    @classmethod
    def create(cls, **kwargs: Any) -> ConsoleNotifier:
        return cls()

    def send(self, payload: dict) -> bool:
        import sys

        sys.stderr.write(f"[notify] {json.dumps(payload, sort_keys=True)}\n")
        return True


class SlackNotifier(Notifier):
    """Pushes notifications to a Slack Incoming Webhook."""

    name = "slack"
    version = "1.0.0"
    author = "AegisRecon Contributors"
    description = "Send notifications to a Slack incoming webhook"

    def __init__(self, webhook_url: str, timeout: float = 10.0) -> None:
        self.webhook_url = webhook_url
        self.timeout = timeout

    @classmethod
    def create(cls, **kwargs: Any) -> SlackNotifier:
        return cls(webhook_url=kwargs["webhook_url"], timeout=kwargs.get("timeout", 10.0))

    def send(self, payload: dict) -> bool:
        body = {
            "text": (
                f"{payload.get('title', 'AegisRecon notification')}\n"
                f"*Program*: {payload.get('program', 'n/a')}\n"
                f"*Message*: {payload.get('message', '')}"
            )
        }
        try:
            with httpx.Client(timeout=httpx.Timeout(self.timeout)) as client:
                response = client.post(self.webhook_url, json=body)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            logger.warning("slack notification failed: %s", exc)
            return False
        return True


class DiscordNotifier(Notifier):
    """Pushes notifications to a Discord webhook."""

    name = "discord"
    version = "1.0.0"
    author = "AegisRecon Contributors"
    description = "Send notifications to a Discord webhook"

    def __init__(self, webhook_url: str, timeout: float = 10.0) -> None:
        self.webhook_url = webhook_url
        self.timeout = timeout

    @classmethod
    def create(cls, **kwargs: Any) -> DiscordNotifier:
        return cls(webhook_url=kwargs["webhook_url"], timeout=kwargs.get("timeout", 10.0))

    def send(self, payload: dict) -> bool:
        body = {
            "content": (
                f"**{payload.get('title', 'AegisRecon notification')}**\n"
                f"{payload.get('program', 'n/a')} — {payload.get('message', '')}"
            )
        }
        try:
            with httpx.Client(timeout=httpx.Timeout(self.timeout)) as client:
                response = client.post(self.webhook_url, json=body)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            logger.warning("discord notification failed: %s", exc)
            return False
        return True


_NOTIFIER_REGISTRY: dict[str, type[Notifier]] = {
    ConsoleNotifier.name: ConsoleNotifier,
    SlackNotifier.name: SlackNotifier,
    DiscordNotifier.name: DiscordNotifier,
}


def available_notifiers() -> list[str]:
    """Return the names of registered notifier plugins."""
    return sorted(_NOTIFIER_REGISTRY)


def build_notifier(name: str, **kwargs: Any) -> Notifier:
    """Instantiate a registered notifier by name.

    Raises:
        NotifierNotFoundError: When the name is unregistered.
    """
    try:
        plugin = _NOTIFIER_REGISTRY[name]
    except KeyError as exc:
        raise NotifierNotFoundError(name) from exc
    notifier = cast(Notifier, plugin.create(**kwargs))
    return notifier


class NotifierNotFoundError(AegisReconError):
    """Raised when an unknown notifier is requested."""


class NotifierDispatcher:
    """Fans a payload out to every configured notifier."""

    def __init__(self, notifiers: list[Notifier]) -> None:
        self.notifiers = notifiers

    def dispatch(self, payload: dict) -> dict[str, bool]:
        """Send *payload* to all notifiers; returns name -> success map."""
        summary: dict[str, bool] = {}
        for notifier in self.notifiers:
            try:
                summary[notifier.name] = notifier.send(payload)
            except Exception as exc:  # noqa: BLE001 - one notifier must not break others
                logger.warning("notifier %s raised %s", notifier.name, exc)
                summary[notifier.name] = False
        return summary


__all__ = [
    "ConsoleNotifier",
    "SlackNotifier",
    "DiscordNotifier",
    "NotifierDispatcher",
    "NotifierNotFoundError",
    "available_notifiers",
    "build_notifier",
]
