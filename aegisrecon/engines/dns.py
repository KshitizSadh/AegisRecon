"""DNS resolution engine.

Resolves hostnames into the records AegisRecon stores: A/AAAA addresses,
CNAME aliases and additional record types. Resolution is performed in parallel
with bounded concurrency so large asset sets resolve quickly without
overwhelming resolvers.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import dns.resolver

from aegisrecon.core.models import DnsRecordType
from aegisrecon.exceptions import ResolutionError
from aegisrecon.utils.validators import normalize_hostname

logger = logging.getLogger("aegisrecon.engines.dns")

_RECORD_TYPES = (DnsRecordType.A, DnsRecordType.AAAA, DnsRecordType.CNAME)


@dataclass(frozen=True)
class Resolution:
    """The resolved records for a single hostname."""

    hostname: str
    addresses: tuple[str, ...] = field(default_factory=tuple)
    cname: str | None = None
    records: dict[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def is_resolved(self) -> bool:
        """True when at least one address or CNAME was found."""
        return bool(self.addresses or self.cname)


class DnsResolver:
    """Performs parallel DNS lookups with bounded concurrency."""

    def __init__(self, concurrency: int = 50, timeout: float = 5.0) -> None:
        self.concurrency = max(1, concurrency)
        self.timeout = timeout

    def resolve(self, hostname: str) -> Resolution:
        """Resolve a single hostname into a :class:`Resolution`."""
        target = normalize_hostname(hostname)
        addresses: list[str] = []
        cname: str | None = None
        records: dict[str, tuple[str, ...]] = {}

        for record_type in _RECORD_TYPES:
            try:
                answer = dns.resolver.resolve(target, record_type.value, lifetime=self.timeout)
                values = [
                    str(record.target if record_type == DnsRecordType.CNAME else record.address)
                    .rstrip(".")
                    .lower()
                    for record in answer
                ]
            except dns.resolver.NoAnswer:
                values = []
            except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as exc:
                raise ResolutionError(f"no {record_type.value} record for {target}: {exc}") from exc
            except (dns.exception.Timeout, dns.resolver.LifetimeTimeout) as exc:
                raise ResolutionError(
                    f"resolution timed out for {target} ({record_type.value}): {exc}"
                ) from exc

            records[record_type.value] = tuple(values)
            if record_type == DnsRecordType.CNAME:
                cname = values[0] if values else None
            else:
                addresses.extend(values)

        return Resolution(
            hostname=target, addresses=tuple(sorted(set(addresses))), cname=cname, records=records
        )

    def resolve_many(self, hostnames: list[str]) -> dict[str, Resolution]:
        """Resolve many hostnames in parallel.

        Failures (NXDOMAIN, timeouts) are recorded in :data:`self.errors` and
        do not abort the batch.
        """
        results: dict[str, Resolution] = {}
        failures: list[str] = []

        def _one(hostname: str) -> Resolution:
            try:
                return self.resolve(hostname)
            except ResolutionError as exc:
                logger.debug("resolution failed for %s: %s", hostname, exc)
                failures.append(hostname)
                return Resolution(hostname=hostname)

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = {pool.submit(_one, h): h for h in hostnames}
            for future in as_completed(futures):
                resolution = future.result()
                results[resolution.hostname] = resolution

        self.errors = failures
        logger.debug("resolved %d/%d hostnames", len(results) - len(failures), len(hostnames))
        return results


__all__ = ["DnsResolver", "Resolution"]
