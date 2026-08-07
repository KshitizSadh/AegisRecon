"""Asset deduplication and canonical-name resolution.

:class:`DedupEngine` finds duplicate assets for a program and merges them into
a single canonical survivor:

    * **Exact canonical collapse** — names that differ only by case, trailing
      dots or IDN/punycode spelling share one canonical key and are merged.
    * **``www.`` folding** — a ``www.``-prefixed host may be folded into the
      apex asset. By default this happens only when the two hosts share a
      resolved IP set (evidence-based, safe). ``--www-strip`` turns it into a
      pure name heuristic.

When merging, every child record (endpoints, DNS, IPs, ports, technologies,
files, parameters, findings, secrets, snapshots) is re-parented to the
survivor; rows that would collide with an existing survivor row are dropped.
The losing asset's name is registered as an alias of the survivor so future
discoveries resolve to the canonical asset.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select

from aegisrecon.core.database import Database
from aegisrecon.core.db_models import (
    AssetAliasORM,
    AssetFileORM,
    AssetORM,
    DnsRecordORM,
    EndpointORM,
    FindingORM,
    IpRecordORM,
    ParameterORM,
    PortORM,
    SecretORM,
    SnapshotORM,
    TechnologyORM,
)
from aegisrecon.core.models import Asset, new_uuid
from aegisrecon.core.repositories import AssetRepository
from aegisrecon.utils.validators import canonical_key, normalize_hostname, strip_www_prefix

logger = logging.getLogger("aegisrecon.engines.dedup")


@dataclass
class DedupReport:
    """Statistics for a deduplication pass."""

    program_id: str
    candidates: int = 0
    merged: int = 0
    reparented: int = 0
    deleted_duplicates: int = 0
    aliases_registered: int = 0
    dry_run: bool = False
    merged_pairs: list[tuple[str, str]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.candidates


class DedupEngine:
    """Finds and merges duplicate assets belonging to a program."""

    def __init__(self, database: Database) -> None:
        self.database = database

    # -- public API ------------------------------------------------------
    def run(
        self, program_id: str, dry_run: bool = False, www_strip: bool = False
    ) -> DedupReport:
        """Deduplicate assets for *program_id*.

        Args:
            dry_run: Report what would be merged without mutating the store.
            www_strip: Merge ``www.``-prefixed hosts by name even when no
                shared IP evidence exists.
        """
        report = DedupReport(program_id=program_id, dry_run=dry_run)
        with self.database.session() as session:
            assets = AssetRepository(session).list(program_id=program_id)
            if not assets:
                return report
            pairs = self._build_pairs(session, assets, www_strip)
            report.candidates = len(pairs)
            for survivor, loser in pairs:
                if not dry_run:
                    self._merge(session, survivor, loser, report)
                report.merged += 1
                report.merged_pairs.append((loser.name, survivor.name))
            if not dry_run:
                session.commit()
        return report

    # -- pairing -----------------------------------------------------------
    def _build_pairs(
        self, session, assets: list[Asset], www_strip: bool
    ) -> list[tuple[Asset, Asset]]:
        """Return ``(survivor, loser)`` pairs to merge, loser ids unique."""
        by_key: dict[str, list[Asset]] = {}
        for asset in assets:
            by_key.setdefault(canonical_key(asset.name), []).append(asset)

        loser_to_survivor: dict[str, Asset] = {}
        for group in by_key.values():
            if len(group) < 2:
                continue
            survivor = self._choose_survivor(group)
            for asset in group:
                if asset.id != survivor.id:
                    loser_to_survivor[asset.id] = survivor

        loser_to_survivor.update(self._www_folding(session, assets, loser_to_survivor, www_strip))

        asset_by_id = {asset.id: asset for asset in assets}
        return [
            (survivor, asset_by_id[loser_id])
            for loser_id, survivor in loser_to_survivor.items()
        ]

    def _www_folding(
        self, session, assets: list[Asset], existing: dict[str, Asset], www_strip: bool
    ) -> dict[str, Asset]:
        """Fold ``www.``-prefixed assets into their apex counterpart."""
        by_key: dict[str, Asset] = {}
        for asset in assets:
            by_key.setdefault(canonical_key(asset.name), asset)

        evidence = self._ip_sets(session, [a.id for a in assets])
        folded: dict[str, Asset] = {}
        for asset in assets:
            if asset.id in existing:
                continue
            stripped = strip_www_prefix(asset.name)
            if stripped == asset.name:
                continue
            parent = by_key.get(canonical_key(stripped))
            if parent is None or parent.id == asset.id:
                continue
            if www_strip or self._shares_ips(evidence, asset.id, parent.id):
                folded[asset.id] = parent
        return folded

    @staticmethod
    def _choose_survivor(group: list[Asset]) -> Asset:
        """Pick the canonical asset: prefer non-``www.``, shorter, then oldest."""

        def rank(asset: Asset) -> tuple[int, int, datetime]:
            stripped = strip_www_prefix(asset.name) == asset.name
            return (0 if stripped else 1, len(asset.name), asset.created_at)

        return min(group, key=rank)

    # -- evidence ----------------------------------------------------------
    def _ip_sets(self, session, asset_ids: list[str]) -> dict[str, set[str]]:
        if not asset_ids:
            return {}
        rows = session.execute(
            select(IpRecordORM.asset_id, IpRecordORM.address).where(
                IpRecordORM.asset_id.in_(asset_ids)
            )
        ).all()
        sets: dict[str, set[str]] = {}
        for asset_id, address in rows:
            sets.setdefault(asset_id, set()).add(address)
        return sets

    @staticmethod
    def _shares_ips(evidence: dict[str, set[str]], left: str, right: str) -> bool:
        return bool(evidence.get(left, set()) & evidence.get(right, set()))

    # -- merging ------------------------------------------------------------
    def _merge(self, session, survivor: Asset, loser: Asset, report: DedupReport) -> None:
        """Re-parent every child row of *loser* onto *survivor*."""
        survivor_id, loser_id = survivor.id, loser.id

        moved_endpoints: set[str] = set()
        deleted_endpoints: set[str] = set()

        for row in session.scalars(
            select(EndpointORM).where(EndpointORM.asset_id == loser_id)
        ).all():
            if self._exists(
                session, EndpointORM, survivor_id, EndpointORM.url, row.url
            ):
                session.delete(row)
                deleted_endpoints.add(row.id)
                report.deleted_duplicates += 1
            else:
                row.asset_id = survivor_id
                moved_endpoints.add(row.id)
                report.reparented += 1

        for orm, uniques in (
            (DnsRecordORM, (DnsRecordORM.record_type, DnsRecordORM.value)),
            (IpRecordORM, (IpRecordORM.address,)),
            (PortORM, (PortORM.port, PortORM.protocol)),
            (TechnologyORM, (TechnologyORM.name,)),
        ):
            for row in session.scalars(
                select(orm).where(orm.asset_id == loser_id)
            ).all():
                clauses = [orm.asset_id == survivor_id]
                clauses.extend(c == getattr(row, c.name) for c in uniques)
                existing = session.scalars(select(orm.id).where(*clauses)).first()
                if existing is not None:
                    session.delete(row)
                    report.deleted_duplicates += 1
                else:
                    row.asset_id = survivor_id
                    report.reparented += 1

        for row in session.scalars(
            select(AssetFileORM).where(AssetFileORM.asset_id == loser_id)
        ).all():
            existing = session.scalars(
                select(AssetFileORM.id).where(
                    AssetFileORM.asset_id == survivor_id, AssetFileORM.url == row.url
                )
            ).first()
            if existing is not None:
                session.delete(row)
                report.deleted_duplicates += 1
            else:
                row.asset_id = survivor_id
                report.reparented += 1

        for row in session.scalars(
            select(ParameterORM).where(ParameterORM.asset_id == loser_id)
        ).all():
            if row.endpoint_id in deleted_endpoints:
                session.delete(row)
                report.deleted_duplicates += 1
            else:
                row.asset_id = survivor_id
                report.reparented += 1

        for row in session.scalars(
            select(FindingORM).where(FindingORM.asset_id == loser_id)
        ).all():
            row.asset_id = survivor_id
            report.reparented += 1

        for row in session.scalars(
            select(SecretORM).where(SecretORM.asset_id == loser_id)
        ).all():
            existing = session.scalars(
                select(SecretORM.id).where(
                    SecretORM.asset_id == survivor_id,
                    SecretORM.kind == row.kind,
                    SecretORM.value == row.value,
                )
            ).first()
            if existing is not None:
                session.delete(row)
                report.deleted_duplicates += 1
            else:
                row.asset_id = survivor_id
                report.reparented += 1

        for row in session.scalars(
            select(SnapshotORM).where(SnapshotORM.entity_id == loser_id)
        ).all():
            row.entity_id = survivor_id
            report.reparented += 1

        existing_alias = session.scalars(
            select(AssetAliasORM.id).where(
                AssetAliasORM.program_id == survivor.program_id,
                AssetAliasORM.name == normalize_hostname(loser.name),
            )
        ).first()
        if existing_alias is None:
            session.add(
                AssetAliasORM(
                    id=new_uuid(),
                    program_id=survivor.program_id,
                    asset_id=survivor_id,
                    name=normalize_hostname(loser.name),
                )
            )
            report.aliases_registered += 1

        row = session.get(AssetORM, loser_id)
        if row is not None:
            session.delete(row)

    @staticmethod
    def _exists(session, orm, survivor_id: str, column, value: Any) -> bool:
        return (
            session.scalars(
                select(orm.id).where(orm.asset_id == survivor_id, column == value)
            ).first()
            is not None
        )


__all__ = ["DedupEngine", "DedupReport"]
