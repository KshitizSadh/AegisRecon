"""DNS resolution backed by ProjectDiscovery ``dnsx``.

``dnsx`` performs bulk, highly-concurrent DNS resolution in Go, which is
substantially faster than per-host dnspython lookups for large hostname sets.
AegisRecon shells out to ``dnsx`` when it is available and falls back to the
pure-Python :class:`aegisrecon.engines.dns.DnsResolver` otherwise, so the same
:class:`Resolution` shape is always produced.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field

from aegisrecon.engines.dns import Resolution
from aegisrecon.exceptions import ResolutionError

logger = logging.getLogger("aegisrecon.engines.dnsx")

_RECORD_TYPES = ("A", "AAAA", "CNAME")


@dataclass
class DnsxResolver:
    """Bulk DNS resolver that delegates to the Go ``dnsx`` binary."""

    binary: str = "dnsx"
    concurrency: int = 50
    timeout: float = 30.0

    errors: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._path = shutil.which(self.binary)

    @property
    def available(self) -> bool:
        """True when the ``dnsx`` binary is present on PATH."""
        return self._path is not None

    def resolve_many(self, hostnames: list[str]) -> dict[str, Resolution]:
        """Resolve *hostnames* in bulk via a single ``dnsx`` invocation.

        Failures are recorded in :data:`self.errors` and never abort the batch.
        """
        if not hostnames:
            return {}
        if not self.available:
            raise ResolutionError(f"dnsx binary {self.binary!r} not found on PATH")

        binary = self._path
        assert binary is not None  # guaranteed by available
        payload = "\n".join(dict.fromkeys(hostnames))
        command = [
            binary,
            "-a",
            "-aaaa",
            "-cname",
            "-silent",
            "-json",
            "-t",
            str(max(1, self.concurrency)),
        ]
        try:
            proc = subprocess.run(
                command,
                input=payload,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ResolutionError(f"dnsx timed out after {self.timeout}s") from exc

        results: dict[str, Resolution] = {h: Resolution(hostname=h) for h in hostnames}
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("dnsx returned non-JSON line: %r", line)
                continue
            host = str(entry.get("host", "")).strip().lower()
            if not host:
                continue
            records: dict[str, tuple[str, ...]] = {}
            addresses: list[str] = []
            cname: str | None = None
            for record_type in _RECORD_TYPES:
                values = entry.get(record_type) or entry.get(record_type.lower()) or []
                values = tuple(str(v).rstrip(".").lower() for v in values if str(v).strip())
                records[record_type] = values
                if record_type == "CNAME":
                    cname = values[0] if values else None
                else:
                    addresses.extend(values)
            results[host] = Resolution(
                hostname=host,
                addresses=tuple(sorted(set(addresses))),
                cname=cname,
                records=records,
            )

        if proc.returncode != 0 and not results:
            raise ResolutionError(
                f"dnsx exited {proc.returncode}: {proc.stderr.strip()[:500]}"
            )
        if proc.returncode != 0:
            self.errors.append(proc.stderr.strip()[:500])

        logger.debug(
            "dnsx resolved %d/%d hostnames", sum(1 for r in results.values() if r.is_resolved), len(hostnames)
        )
        return results

    def resolve(self, hostname: str) -> Resolution:
        """Resolve a single hostname (batch of one via dnsx)."""
        return self.resolve_many([hostname]).get(hostname, Resolution(hostname=hostname))


__all__ = ["DnsxResolver"]
