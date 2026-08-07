"""Recon orchestration engine.

:class:`ReconEngine` is the conductor that drives an end-to-end discovery pass
for a program:

    scope load -> passive discovery -> scope filtering -> DNS resolution ->
    persistence

Every discovered hostname passes through the program's :class:`ScopeValidator`
before anything is stored. Nothing outside the authorized scope ever reaches
the database or an active probe.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from aegisrecon.core.database import Database
from aegisrecon.core.models import (
    Asset,
    AssetKind,
    DnsRecord,
    DnsRecordType,
    IpRecord,
    Program,
    utcnow,
)
from aegisrecon.core.repositories import (
    AssetAliasRepository,
    AssetRepository,
    DnsRecordRepository,
    IpRecordRepository,
    ProgramRepository,
    ScopeRepository,
)
from aegisrecon.core.scope import ScopeValidator
from aegisrecon.engines.checkpoint import Checkpoint, CheckpointStore
from aegisrecon.engines.dns import DnsResolver
from aegisrecon.engines.passive import CertificateTransparencyProvider
from aegisrecon.engines.subfinder import SubfinderProvider
from aegisrecon.exceptions import EngineError, ReconError, StorageError
from aegisrecon.utils.validators import is_valid_domain, normalize_hostname

logger = logging.getLogger("aegisrecon.engines.recon")

PASSIVE_SOURCES = {
    "crtsh": CertificateTransparencyProvider,
    "subfinder": SubfinderProvider,
}


@dataclass
class ReconResult:
    """Statistics for a single recon pass."""

    program_id: str
    discovered: int = 0
    in_scope: int = 0
    resolved: int = 0
    new_assets: int = 0
    updated_assets: int = 0
    dns_records: int = 0
    ip_records: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.discovered


class ReconEngine:
    """Runs passive discovery, resolution and persistence for a program."""

    def __init__(
        self,
        database: Database,
        dns_concurrency: int = 50,
        enable_ct_logs: bool = True,
        ct_timeout: float = 20.0,
    ) -> None:
        self.database = database
        self.dns_concurrency = dns_concurrency
        self.enable_ct_logs = enable_ct_logs
        self.ct_timeout = ct_timeout

    # -- public API ------------------------------------------------------
    def run(
        self,
        program_id: str,
        sources: list[str] | None = None,
        resume: bool = False,
    ) -> ReconResult:
        """Execute a full discovery pass for *program_id*.

        Args:
            resume: When True, continue from a previously saved checkpoint
                instead of walking every passive source/root from scratch.

        Raises:
            EntityNotFoundError: When the program does not exist.
            ReconError: When no authorized in-scope root domains exist.
        """
        with self.database.session() as session:
            program = ProgramRepository(session).get(program_id)
            entries = ScopeRepository(session).list_for_program(program_id)
            session.close()

        validator = ScopeValidator(entries)
        roots = self._root_domains(program, validator)

        result = ReconResult(program_id=program_id)
        enabled_sources = sources or self._default_sources()

        store = CheckpointStore(self.database.path.parent)
        ckpt = store.load(program_id) if resume else Checkpoint()
        ckpt.program_id = program_id

        candidate_hostnames: set[str] = set(ckpt.hostnames)
        resumed = 0
        for source in enabled_sources:
            provider = self._open_provider(source)
            try:
                for root in roots:
                    if ckpt.is_done(source, root):
                        resumed += 1
                        continue
                    found = self._collect_root(provider, root)
                    result.discovered += len(found)
                    candidate_hostnames.update(found)
                    ckpt.hostnames = candidate_hostnames
                    ckpt.mark_done(source, root)
                    self._persist_checkpoint(store, ckpt)
            finally:
                if provider is not None:
                    provider.close()

        if resumed:
            logger.info("recon resumed: %d (source, root) units skipped", resumed)

        allowed = [h for h in candidate_hostnames if validator.is_allowed(h)]
        result.in_scope = len(allowed)
        logger.info(
            "recon for %s: %d candidates, %d in scope",
            program.name,
            result.discovered,
            result.in_scope,
        )

        self._persist(program_id, allowed, result)
        if allowed:
            store.clear(program_id)
        return result

    def ingest(self, program_id: str, hostnames: list[str]) -> ReconResult:
        """Persist externally-supplied hostnames after scope validation."""
        with self.database.session() as session:
            entries = ScopeRepository(session).list_for_program(program_id)
            session.close()

        validator = ScopeValidator(entries)
        result = ReconResult(program_id=program_id)
        allowed = [h for h in hostnames if validator.is_allowed(h)]
        result.discovered = len(hostnames)
        result.in_scope = len(allowed)
        self._persist(program_id, allowed, result)
        return result

    # -- internals ---------------------------------------------------------
    def _default_sources(self) -> list[str]:
        sources: list[str] = []
        if self.enable_ct_logs:
            sources.append("crtsh")
        return sources

    def _open_provider(self, source: str):
        """Return a provider instance for *source*, or ``None`` when unavailable."""
        provider_class = PASSIVE_SOURCES.get(source)
        if provider_class is None:
            raise ReconError(
                f"unknown passive source {source!r}; available: {sorted(PASSIVE_SOURCES)}"
            )
        try:
            return provider_class.create(timeout=self.ct_timeout)  # type: ignore[attr-defined]
        except EngineError as exc:
            logger.warning("source %s unavailable: %s", source, exc)
            return None

    def _collect_root(self, provider, root: str) -> set[str]:
        """Query a single provider for one root domain, tolerating failures."""
        found: set[str] = set()
        if provider is None:
            return found
        try:
            found.update(provider.query(root))
        except ReconError as exc:
            logger.warning("passive source failed for %s: %s", root, exc)
        return found

    def _persist_checkpoint(self, store: CheckpointStore, ckpt: Checkpoint) -> None:
        try:
            store.save(ckpt)
        except StorageError as exc:
            logger.warning("could not save checkpoint: %s", exc)

    def _root_domains(self, program: Program, validator: ScopeValidator) -> list[str]:
        """Derive authorized root domains from include wildcard/exact rules."""
        roots: list[str] = []
        for rule in validator.include_rules:
            value = rule.entry.value
            if value.startswith("*."):
                value = value[2:]
            if is_valid_domain(value):
                roots.append(value)
        roots = sorted(set(roots))
        if not roots:
            raise ReconError(
                f"program {program.name!r} has no in-scope root domains; "
                "add a wildcard or exact scope rule first"
            )
        return roots

    def _persist(self, program_id: str, hostnames: list[str], result: ReconResult) -> None:
        """Resolve and store in-scope hostnames and their records."""
        if not hostnames:
            logger.info("nothing to persist for program %s", program_id)
            return

        resolver = DnsResolver(concurrency=self.dns_concurrency)
        resolutions = resolver.resolve_many(hostnames)
        result.errors.extend(resolver.errors)
        result.resolved = sum(1 for r in resolutions.values() if r.is_resolved)

        seen_at = utcnow()
        with self.database.session() as session:
            assets = AssetRepository(session)
            aliases = AssetAliasRepository(session)
            dns_records = DnsRecordRepository(session)
            ip_records = IpRecordRepository(session)

            for hostname, resolution in resolutions.items():
                normalized = normalize_hostname(hostname)
                existing = assets.get_by_name(program_id, normalized)
                if existing is None:
                    alias = aliases.get_by_name(program_id, normalized)
                    if alias is not None:
                        existing = assets.get(alias.asset_id)

                if existing is None:
                    asset = assets.create(
                        Asset(
                            program_id=program_id,
                            name=hostname,
                            kind=AssetKind.SUBDOMAIN if "." in hostname else AssetKind.HOSTNAME,
                            source="recon",
                            last_seen_at=seen_at,
                        )
                    )
                    result.new_assets += 1
                else:
                    asset = existing
                    assets.update(asset.id, last_seen_at=seen_at, source="recon")
                    result.updated_assets += 1

                self._store_dns(session, asset.id, resolution, dns_records, ip_records, result)

            session.commit()
        logger.info(
            "persisted %d new + %d updated assets (%d dns, %d ip records)",
            result.new_assets,
            result.updated_assets,
            result.dns_records,
            result.ip_records,
        )

    def _store_dns(
        self, session, asset_id: str, resolution, dns_records, ip_records, result
    ) -> None:
        for record_type, values in resolution.records.items():
            if not values:
                continue
            rtype = DnsRecordType(record_type)
            for value in values:
                if not dns_records.exists(asset_id, rtype.value, value):
                    dns_records.create(
                        DnsRecord(
                            asset_id=asset_id, record_type=rtype, value=value, source="resolver"
                        )
                    )
                    result.dns_records += 1
                if rtype in (DnsRecordType.A, DnsRecordType.AAAA) and not ip_records.exists(
                    asset_id, value
                ):
                    ip_records.create(IpRecord(asset_id=asset_id, address=value, source="resolver"))
                    result.ip_records += 1


__all__ = ["ReconEngine", "ReconResult"]
