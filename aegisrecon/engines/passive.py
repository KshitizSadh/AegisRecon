"""Passive intelligence providers.

Passive discovery never sends traffic to the target infrastructure. The
current built-in provider queries Certificate Transparency (CT) logs through
crt.sh, surfacing certificates that were issued for a domain — a rich source
of otherwise hidden subdomains.

Additional providers (SecurityTrails, Censys, HackerTarget, passive DNS APIs)
are designed to plug in through :class:`aegisrecon.plugins.base.ReconProvider`.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from aegisrecon.exceptions import ReconError
from aegisrecon.plugins.base import ReconProvider
from aegisrecon.utils.retry import retry
from aegisrecon.utils.validators import is_valid_hostname, normalize_hostname

logger = logging.getLogger("aegisrecon.engines.passive")

CRTSH_API = "https://crt.sh/?q=%25.{domain}&output=json"


class CertificateTransparencyProvider(ReconProvider):
    """Discover subdomains from public Certificate Transparency logs via crt.sh."""

    name = "crtsh"
    version = "1.0.0"
    author = "AegisRecon Contributors"
    description = "Certificate Transparency log search via crt.sh"

    def __init__(self, client: httpx.Client | None = None, timeout: float = 20.0, user_agent: str = "AegisRecon") -> None:
        self.client = client or httpx.Client(
            headers={"User-Agent": user_agent},
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
        )
        self.timeout = timeout

    @classmethod
    def create(cls, **kwargs: Any) -> "CertificateTransparencyProvider":
        return cls(**kwargs)

    @retry(attempts=3, logger_=logger)
    def query(self, domain: str) -> list[str]:
        """Return normalized subdomains discovered for *domain*.

        Raises:
            ReconError: When crt.sh is unreachable or returns unusable data.
        """
        url = CRTSH_API.format(domain=domain)
        try:
            response = self.client.get(url)
            response.raise_for_status()
            payload: Any = response.json()
        except (httpx.HTTPError, json.JSONDecodeError, ValueError) as exc:
            raise ReconError(f"crt.sh query failed for {domain}: {exc}") from exc

        if not isinstance(payload, list):
            raise ReconError(f"crt.sh returned an unexpected payload for {domain}")

        found: set[str] = set()
        for entry in payload:
            name = entry.get("name_value") or entry.get("common_name") or ""
            for candidate in _split_names(name):
                normalized = normalize_hostname(candidate)
                if is_valid_hostname(normalized) and _under(normalized, domain):
                    found.add(normalized)

        logger.debug("crt.sh returned %d subdomains for %s", len(found), domain)
        return sorted(found)

    def close(self) -> None:
        """Release the underlying HTTP client."""
        if self.client is not None:
            self.client.close()


def _split_names(name: str) -> list[str]:
    """Split a certificate name field (newline or comma separated)."""
    parts: list[str] = []
    for line in name.replace("\n", ",").split(","):
        candidate = line.strip().rstrip(".")
        if candidate:
            parts.append(candidate)
    return parts


def _under(hostname: str, root: str) -> bool:
    """Return True when *hostname* equals *root* or lives under it."""
    root = root.rstrip(".")
    return hostname == root or hostname.endswith(f".{root}")


__all__ = ["CertificateTransparencyProvider", "CRTSH_API"]
