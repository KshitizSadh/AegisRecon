"""HTTP probing engine.

Runs ProjectDiscovery httpx against in-scope assets and persists the results:
endpoints (URL + metadata), technologies, and query-string parameters.

The engine is scope-aware by construction: it only ever probes hostnames that
were already validated and stored as program assets.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlparse

from aegisrecon.core.database import Database
from aegisrecon.core.models import (
    Asset,
    Endpoint,
    Parameter,
    Technology,
    utcnow,
)
from aegisrecon.core.repositories import (
    AssetRepository,
    EndpointRepository,
    ParameterRepository,
    TechnologyRepository,
)
from aegisrecon.engines.httpx import HttpxProber, ProbingResult

logger = logging.getLogger("aegisrecon.engines.probe")

DEFAULT_FLAGS = [
    "-status-code",
    "-title",
    "-tech-detect",
    "-content-type",
    "-web-server",
    "-follow-redirects",
]


@dataclass
class ProbeResult:
    """Statistics for a single HTTP probe pass."""

    program_id: str
    probed: int = 0
    endpoints: int = 0
    new_endpoints: int = 0
    technologies: int = 0
    parameters: int = 0
    errors: list[str] = field(default_factory=list)


class ProbeEngine:
    """Discovers and persists endpoints, technologies and parameters."""

    def __init__(self, database: Database, binary: str = "httpx") -> None:
        self.database = database
        self.prober = HttpxProber(binary=binary)

    def run(self, program_id: str, hostnames: list[str] | None = None) -> ProbeResult:
        """Probe a program's assets (or an explicit hostname list)."""
        if hostnames is None:
            with self.database.session() as session:
                hostnames = AssetRepository(session).list_names(program_id)
                session.close()

        if not hostnames:
            raise ValueError(f"no assets to probe for program {program_id}")

        result = ProbeResult(program_id=program_id)
        results = self.prober.probe(hostnames, extra_flags=DEFAULT_FLAGS)
        result.probed = len(results)
        self._persist(program_id, results, result)
        return result

    def _persist(self, program_id: str, results: list[ProbingResult], result: ProbeResult) -> None:
        seen_at = utcnow()
        with self.database.session() as session:
            assets = AssetRepository(session)
            endpoints = EndpointRepository(session)
            techs = TechnologyRepository(session)
            params = ParameterRepository(session)

            for item in results:
                asset = self._find_asset(assets, program_id, item.url)
                if asset is None:
                    result.errors.append(item.url)
                    continue

                endpoint = self._store_endpoint(endpoints, asset.id, item, seen_at, result)
                self._store_technologies(techs, asset.id, item.technologies, result)
                self._store_parameters(params, asset.id, endpoint.id, item.url, result)

            session.commit()
        logger.info(
            "probe: %d endpoints (%d new), %d technologies, %d parameters for %s",
            result.endpoints,
            result.new_endpoints,
            result.technologies,
            result.parameters,
            program_id,
        )

    @staticmethod
    def _find_asset(assets: AssetRepository, program_id: str, url: str) -> Asset | None:
        """Resolve the asset that owns a probed URL."""
        try:
            host = urlparse(url).netloc.split(":")[0].lower()
        except ValueError:
            return None
        if not host:
            return None
        return assets.get_by_name(program_id, host)

    def _store_endpoint(
        self,
        endpoints: EndpointRepository,
        asset_id: str,
        item: ProbingResult,
        seen_at,
        result: ProbeResult,
    ) -> Endpoint:
        if endpoints.exists(asset_id, item.url):
            existing = next((e for e in endpoints.list(asset_id=asset_id) if e.url == item.url), None)
            if existing is not None:
                return existing

        endpoint = endpoints.create(
            Endpoint(
                asset_id=asset_id,
                url=item.url,
                status_code=item.status_code,
                title=item.title,
                content_type=item.content_type,
                source="httpx",
            )
        )
        result.endpoints += 1
        result.new_endpoints += 1
        return endpoint

    def _store_technologies(
        self, techs: TechnologyRepository, asset_id: str, technologies: tuple[str, ...], result: ProbeResult
    ) -> None:
        for name in technologies:
            if techs.exists(asset_id, name):
                continue
            techs.create(Technology(asset_id=asset_id, name=name, category="fingerprint"))
            result.technologies += 1

    def _store_parameters(
        self,
        params: ParameterRepository,
        asset_id: str,
        endpoint_id: str,
        url: str,
        result: ProbeResult,
    ) -> None:
        parsed = urlparse(url)
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            if not name or params.exists(endpoint_id, name):
                continue
            params.create(
                Parameter(
                    asset_id=asset_id,
                    endpoint_id=endpoint_id,
                    name=name,
                    location="query",
                    value_example=value[:4096],
                    source="probe",
                )
            )
            result.parameters += 1


__all__ = ["ProbeEngine", "ProbeResult"]
