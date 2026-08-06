"""ProjectDiscovery subfinder integration.

``subfinder`` is the industry-standard passive subdomain enumerator. AegisRecon
wraps it as a :class:`~aegisrecon.plugins.base.ReconProvider` so its output
flows through the same scope-filtered persistence path as every other source.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from typing import Any

from aegisrecon.exceptions import ReconError, ToolNotFoundError
from aegisrecon.plugins.base import ReconProvider
from aegisrecon.utils.retry import retry
from aegisrecon.utils.validators import is_valid_hostname, normalize_hostname

logger = logging.getLogger("aegisrecon.engines.subfinder")


class SubfinderProvider(ReconProvider):
    """Passive subdomain enumeration via ProjectDiscovery subfinder."""

    name = "subfinder"
    version = "1.0.0"
    author = "AegisRecon Contributors"
    description = "Passive subdomain enumeration via ProjectDiscovery subfinder"

    def __init__(self, binary: str = "subfinder", timeout: float = 300.0) -> None:
        resolved = shutil.which(binary)
        if resolved is None:
            raise ToolNotFoundError(
                f"subfinder binary {binary!r} was not found on PATH. "
                "Install it from https://github.com/projectdiscovery/subfinder/releases "
                "or set AEGISRECON_SUBFINDER_BIN."
            )
        self.binary_path = resolved
        self.timeout = timeout

    @classmethod
    def create(cls, **kwargs: Any) -> SubfinderProvider:
        return cls(**kwargs)

    @retry(attempts=2, logger_=logger, exceptions=(subprocess.CalledProcessError,))
    def query(self, domain: str) -> list[str]:
        """Return normalized subdomains discovered for *domain*.

        Raises:
            ReconError: When subfinder exits abnormally.
        """
        command = [self.binary_path, "-d", domain, "-silent"]
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ReconError(f"subfinder timed out for {domain}: {exc}") from exc

        if proc.returncode != 0:
            raise ReconError(f"subfinder failed for {domain}: {proc.stderr.strip()[:500]}")

        found: set[str] = set()
        for line in proc.stdout.splitlines():
            candidate = normalize_hostname(line)
            if is_valid_hostname(candidate):
                found.add(candidate)

        logger.debug("subfinder returned %d subdomains for %s", len(found), domain)
        return sorted(found)

    def close(self) -> None:
        """No persistent resources to release (kept for provider interface)."""


__all__ = ["SubfinderProvider"]
