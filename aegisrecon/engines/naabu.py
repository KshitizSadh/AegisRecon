"""Port discovery via ProjectDiscovery naabu.

``naabu`` performs fast TCP/UDP port discovery. AegisRecon runs it against
in-scope hosts (or their resolved IPs) and persists open ports.

Only authorized program assets are ever handed to naabu — the same scope gate
that guards every other active step.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field

from aegisrecon.core.database import Database
from aegisrecon.core.models import Port
from aegisrecon.core.repositories import AssetRepository, PortRepository
from aegisrecon.exceptions import EngineError, ToolNotFoundError, tool_not_found_message
from aegisrecon.utils.retry import retry

logger = logging.getLogger("aegisrecon.engines.naabu")

DEFAULT_PORTS = "80,443,3000,8000,8080,8443,8888,9000,9001,9090,3306,5432,6379,27017"


@dataclass(frozen=True)
class PortFinding:
    """A parsed naabu result line."""

    host: str
    port: int
    protocol: str = "tcp"
    service: str = ""


@dataclass
class PortScanResult:
    """Statistics for a port scan pass."""

    program_id: str
    hosts: int = 0
    open_ports: int = 0
    new_ports: int = 0
    errors: list[str] = field(default_factory=list)


class NaabuScanner:
    """Wraps the ProjectDiscovery naabu binary."""

    def __init__(self, binary: str = "naabu") -> None:
        resolved = shutil.which(binary)
        if resolved is None:
            raise ToolNotFoundError(
                tool_not_found_message(
                    binary, "AEGISRECON_NAABU_BIN", "github.com/projectdiscovery/naabu"
                )
            )
        self.binary_path = resolved

    @retry(attempts=2, logger_=logger, exceptions=(subprocess.CalledProcessError,))
    def _run(self, hosts: list[str], ports: str) -> str:
        command = [
            self.binary_path,
            "-host",
            ",".join(hosts),
            "-p",
            ports,
            "-silent",
            "-json",
        ]
        proc = subprocess.run(command, capture_output=True, text=True, timeout=900, check=False)
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, command, stderr=proc.stderr)
        return proc.stdout or ""

    def scan(self, hosts: list[str], ports: str = DEFAULT_PORTS) -> list[PortFinding]:
        """Scan *hosts* for open ports and return parsed findings."""
        if not hosts:
            return []
        findings: list[PortFinding] = []
        for line in self._run(hosts, ports).splitlines():
            parsed = self._parse(line)
            if parsed is not None:
                findings.append(parsed)
        return findings

    @staticmethod
    def _parse(line: str) -> PortFinding | None:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            return None
        host = str(payload.get("host") or payload.get("ip") or "").strip()
        port = payload.get("port")
        if not host or not isinstance(port, int):
            return None
        return PortFinding(
            host=host,
            port=port,
            protocol=str(payload.get("protocol", "tcp")),
            service=str(payload.get("service", "")),
        )


class PortEngine:
    """Scans program assets for open ports and persists the results."""

    def __init__(self, database: Database, binary: str = "naabu", ports: str = DEFAULT_PORTS) -> None:
        self.database = database
        self.scanner = NaabuScanner(binary=binary)
        self.ports = ports

    def run(self, program_id: str, hostnames: list[str] | None = None) -> PortScanResult:
        """Scan a program's in-scope assets (or an explicit hostname list)."""
        if hostnames is None:
            with self.database.session() as session:
                hostnames = AssetRepository(session).list_names(program_id)
                session.close()

        result = PortScanResult(program_id=program_id)
        if not hostnames:
            return result

        try:
            findings = self.scanner.scan(hostnames, ports=self.ports)
        except subprocess.CalledProcessError as exc:
            raise EngineError(f"naabu failed: {exc.stderr or exc}") from exc

        result.hosts = len(hostnames)
        result.open_ports = len(findings)
        self._persist(program_id, findings, result)
        return result

    def _persist(self, program_id: str, findings: list[PortFinding], result: PortScanResult) -> None:
        with self.database.session() as session:
            assets = AssetRepository(session)
            ports = PortRepository(session)

            for finding in findings:
                asset = assets.get_by_name(program_id, finding.host)
                if asset is None:
                    result.errors.append(finding.host)
                    continue
                if ports.exists(asset.id, finding.port, finding.protocol):
                    continue
                ports.create(
                    Port(
                        asset_id=asset.id,
                        port=finding.port,
                        protocol=finding.protocol,
                        service=finding.service,
                        source="naabu",
                    )
                )
                result.new_ports += 1

            session.commit()


__all__ = ["NaabuScanner", "PortEngine", "PortFinding", "PortScanResult", "DEFAULT_PORTS"]
