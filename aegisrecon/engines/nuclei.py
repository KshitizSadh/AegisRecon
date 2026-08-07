"""Vulnerability scanning via ProjectDiscovery nuclei.

``nuclei`` is the industry-standard fast template-based vulnerability scanner
written in Go. AegisRecon runs it against in-scope endpoints and persists the
matches as :class:`Finding` records so they flow into the same triage and
reporting pipeline as every other result.

Only authorized program assets are ever handed to nuclei — the same scope gate
that guards every other active step.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field

from aegisrecon.core.database import Database
from aegisrecon.core.models import Finding, FindingSeverity, FindingStatus
from aegisrecon.core.repositories import AssetRepository, FindingRepository
from aegisrecon.exceptions import EngineError, ToolNotFoundError, tool_not_found_message
from aegisrecon.utils.retry import retry

logger = logging.getLogger("aegisrecon.engines.nuclei")

SEVERITY_MAP = {
    "info": FindingSeverity.INFO,
    "low": FindingSeverity.LOW,
    "medium": FindingSeverity.MEDIUM,
    "high": FindingSeverity.HIGH,
    "critical": FindingSeverity.CRITICAL,
}


@dataclass(frozen=True)
class NucleiFinding:
    """A parsed nuclei result line."""

    host: str
    template_id: str
    name: str
    severity: str = "info"
    matcher_name: str = ""
    info: dict = field(default_factory=dict)


@dataclass
class NucleiScanResult:
    """Statistics for a nuclei scan pass."""

    program_id: str
    targets: int = 0
    matched: int = 0
    new_findings: int = 0
    errors: list[str] = field(default_factory=list)


class NucleiScanner:
    """Wraps the ProjectDiscovery nuclei binary."""

    def __init__(
        self,
        binary: str = "nuclei",
        severity: str = "low,medium,high,critical",
        tags: str = "",
    ) -> None:
        resolved = shutil.which(binary)
        if resolved is None:
            raise ToolNotFoundError(
                tool_not_found_message(
                    binary, "AEGISRECON_NUCLEI_BIN", "github.com/projectdiscovery/nuclei"
                )
            )
        self.binary_path = resolved
        self.severity = severity
        self.tags = tags

    @retry(attempts=2, logger_=logger, exceptions=(subprocess.CalledProcessError,))
    def _run(self, urls: list[str]) -> str:
        command = [
            self.binary_path,
            "-u",
            ",".join(urls),
            "-json",
            "-silent",
            "-severity",
            self.severity,
        ]
        if self.tags:
            command += ["-tags", self.tags]
        proc = subprocess.run(command, capture_output=True, text=True, timeout=1800, check=False)
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, command, stderr=proc.stderr)
        return proc.stdout or ""

    def scan(self, urls: list[str]) -> list[NucleiFinding]:
        """Scan *urls* and return parsed findings."""
        if not urls:
            return []
        findings: list[NucleiFinding] = []
        for line in self._run(urls).splitlines():
            parsed = self._parse(line)
            if parsed is not None:
                findings.append(parsed)
        return findings

    @staticmethod
    def _parse(line: str) -> NucleiFinding | None:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            return None
        host = str(payload.get("host") or "").strip()
        template_id = str(payload.get("template-id") or "").strip()
        name = str(payload.get("info", {}).get("name") or template_id or "nuclei match")
        severity = str(payload.get("info", {}).get("severity") or "info").lower()
        matcher_name = str(payload.get("matcher-name") or "")
        info = payload.get("info") or {}
        return NucleiFinding(
            host=host,
            template_id=template_id,
            name=name,
            severity=severity,
            matcher_name=matcher_name,
            info=info,
        )


class NucleiEngine:
    """Runs nuclei over a program's endpoints and persists findings."""

    def __init__(
        self,
        database: Database,
        binary: str = "nuclei",
        severity: str = "low,medium,high,critical",
        tags: str = "",
    ) -> None:
        self.database = database
        self.scanner = NucleiScanner(binary=binary, severity=severity, tags=tags)

    def run(self, program_id: str) -> NucleiScanResult:
        """Scan every live endpoint in the program and persist matches."""
        with self.database.session() as session:
            urls = self._collect_endpoints(session, program_id)
            session.close()

        result = NucleiScanResult(program_id=program_id, targets=len(urls))
        if not urls:
            return result

        try:
            findings = self.scanner.scan(urls)
        except subprocess.CalledProcessError as exc:
            raise EngineError(f"nuclei failed: {exc.stderr or exc}") from exc

        result.matched = len(findings)
        self._persist(program_id, findings, result)
        return result

    @staticmethod
    def _collect_endpoints(session, program_id: str) -> list[str]:
        """Return the live URL set for the program, deduplicated."""
        from aegisrecon.core.repositories import EndpointRepository

        seen: set[str] = set()
        urls: list[str] = []
        for endpoint in EndpointRepository(session).list_for_program(program_id):
            if endpoint.url not in seen:
                seen.add(endpoint.url)
                urls.append(endpoint.url)
        return urls

    def _persist(
        self, program_id: str, findings: list[NucleiFinding], result: NucleiScanResult
    ) -> None:
        with self.database.session() as session:
            assets = AssetRepository(session)
            repo = FindingRepository(session)

            for finding in findings:
                asset = assets.get_by_name(program_id, finding.host) or self._match_asset(
                    assets, program_id, finding.host
                )
                asset_id = asset.id if asset is not None else None

                description = f"nuclei template {finding.template_id}"
                if finding.matcher_name:
                    description += f" ({finding.matcher_name})"
                record = Finding(
                    program_id=program_id,
                    asset_id=asset_id,
                    title=finding.name,
                    severity=SEVERITY_MAP.get(finding.severity, FindingSeverity.INFO),
                    status=FindingStatus.OPEN,
                    description=description,
                    evidence={
                        "template_id": finding.template_id,
                        "matcher_name": finding.matcher_name,
                        "nuclei_info": finding.info,
                    },
                    references=[],
                )
                repo.create(record)
                result.new_findings += 1

            session.commit()

    @staticmethod
    def _match_asset(assets, program_id: str, host: str):
        """Best-effort: try a bare hostname, then any asset whose name is a hostname."""

        candidate = host
        if candidate.startswith("http://"):
            candidate = candidate[len("http://") :]
        elif candidate.startswith("https://"):
            candidate = candidate[len("https://") :]
        candidate = candidate.split("/", 1)[0]

        asset = assets.get_by_name(program_id, candidate)
        if asset is not None:
            return asset
        for existing in assets.list(program_id=program_id):
            if existing.name.endswith("." + candidate) or candidate.endswith("." + existing.name):
                return existing
        return None


__all__ = ["NucleiScanner", "NucleiEngine", "NucleiFinding", "NucleiScanResult"]
