"""Plugin ecosystem foundations.

AegisRecon is plugin driven. Third-party packages can extend the framework
without modifying core code by inheriting from one of the abstract base
classes below and registering their implementation.
"""

from __future__ import annotations

import abc


class Plugin(abc.ABC):
    """Base class shared by every plugin.

    Attributes:
        name: Canonical plugin name used for registration and display.
        version: Semantic version of the plugin.
        author: Author/owner identifier.
        description: One-line summary shown in ``aegisrecon plugins list``.
    """

    name: str = "unnamed"
    version: str = "0.1.0"
    author: str = ""
    description: str = ""

    @classmethod
    @abc.abstractmethod
    def create(cls, **kwargs: object) -> Plugin:
        """Instantiate the plugin with resolved runtime options."""

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"<{self.__class__.__name__} name={self.name!r} v{self.version}>"


class ReconProvider(Plugin):
    """A source that discovers candidate subdomains/hostnames for a domain."""

    @abc.abstractmethod
    def query(self, domain: str) -> list[str]:
        """Return discovered hostnames for the given root domain.

        Providers must return normalized, de-duplicated hostnames. Raising
        :class:`aegisrecon.exceptions.ReconError` signals a transient failure
        that the engine may retry.
        """


class Scanner(Plugin):
    """A module that inspects an asset and returns resource records."""

    @abc.abstractmethod
    def scan(self, asset) -> list:
        """Run against one asset and return discovered resource records."""


class Notifier(Plugin):
    """A delivery channel for findings and notifications."""

    @abc.abstractmethod
    def send(self, payload: dict) -> bool:
        """Deliver *payload* and return True on success."""


class Exporter(Plugin):
    """Writes domain records to an external destination (file, API...)."""

    @abc.abstractmethod
    def export(self, records: list, destination: str) -> None:
        """Export records to an external destination."""


__all__ = ["Plugin", "ReconProvider", "Scanner", "Notifier", "Exporter"]
