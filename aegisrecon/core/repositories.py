"""Repository layer mapping domain models to ORM rows.

Each repository is responsible for exactly one entity type. A generic base
provides the CRUD primitives; subclasses add domain-specific queries. All
methods accept and return Pydantic domain models, never ORM rows.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, TypeVar

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegisrecon.core.db_models import (
    AssetORM,
    DnsRecordORM,
    EndpointORM,
    FindingORM,
    IpRecordORM,
    ProgramORM,
    ReportORM,
    ScopeEntryORM,
    TechnologyORM,
)
from aegisrecon.core.models import (
    Asset,
    DnsRecord,
    Endpoint,
    Finding,
    IpRecord,
    Program,
    Report,
    ScopeEntry,
    Technology,
)
from aegisrecon.exceptions import EntityNotFoundError
from aegisrecon.utils.validators import normalize_hostname

M = TypeVar("M")
R = TypeVar("R")


def _iso(value: Any) -> Any:
    """Serialize a datetime into ISO 8601 string for Pydantic consumption."""
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


class BaseRepository(Generic[M, R]):
    """Generic CRUD repository over a SQLAlchemy session."""

    orm: type[R]
    domain: type[M]

    def __init__(self, session: Session) -> None:
        self.session = session

    # -- mapping -------------------------------------------------------
    def _to_domain(self, row: R) -> M:
        data = {
            column.name: getattr(row, column.name)
            for column in row.__table__.columns
        }
        data = {k: _iso(v) for k, v in data.items()}
        return self.domain.model_validate(data)

    def _from_domain(self, model: M) -> R:
        row = self.orm(**model.model_dump(mode="python"))
        return row

    # -- primitives ------------------------------------------------------
    def create(self, model: M) -> M:
        row = self._from_domain(model)
        self.session.add(row)
        return model

    def get(self, entity_id: str) -> M:
        row = self.session.get(self.orm, entity_id)
        if row is None:
            raise EntityNotFoundError(f"{self.domain.__name__} with id {entity_id!r} not found")
        return self._to_domain(row)

    def list(self, **filters: Any) -> list[M]:
        stmt = select(self.orm)
        for key, value in filters.items():
            if value is not None:
                stmt = stmt.where(getattr(self.orm, key) == value)
        stmt = stmt.order_by(getattr(self.orm, "created_at"))
        rows = self.session.scalars(stmt).all()
        return [self._to_domain(row) for row in rows]

    def update(self, entity_id: str, **fields: Any) -> M:
        row = self.session.get(self.orm, entity_id)
        if row is None:
            raise EntityNotFoundError(f"{self.domain.__name__} with id {entity_id!r} not found")
        for key, value in fields.items():
            setattr(row, key, value)
        self.session.flush()
        return self._to_domain(row)

    def delete(self, entity_id: str) -> None:
        row = self.session.get(self.orm, entity_id)
        if row is None:
            raise EntityNotFoundError(f"{self.domain.__name__} with id {entity_id!r} not found")
        self.session.delete(row)

    def count(self, **filters: Any) -> int:
        stmt = select(self.orm.id)
        for key, value in filters.items():
            if value is not None:
                stmt = stmt.where(getattr(self.orm, key) == value)
        return len(self.session.execute(stmt).all())


class ProgramRepository(BaseRepository[Program, ProgramORM]):
    orm = ProgramORM
    domain = Program

    def get_by_name(self, name: str) -> Program | None:
        row = self.session.scalars(select(ProgramORM).where(ProgramORM.name == name)).first()
        return self._to_domain(row) if row else None


class ScopeRepository(BaseRepository[ScopeEntry, ScopeEntryORM]):
    orm = ScopeEntryORM
    domain = ScopeEntry

    def list_for_program(self, program_id: str) -> list[ScopeEntry]:
        return self.list(program_id=program_id)


class AssetRepository(BaseRepository[Asset, AssetORM]):
    orm = AssetORM
    domain = Asset

    def get_by_name(self, program_id: str, name: str) -> Asset | None:
        row = self.session.scalars(
            select(AssetORM).where(AssetORM.program_id == program_id, AssetORM.name == name)
        ).first()
        return self._to_domain(row) if row else None

    def get_or_create(self, program_id: str, name: str, **fields: Any) -> Asset:
        normalized = normalize_hostname(name)
        existing = self.get_by_name(program_id, normalized)
        if existing is not None:
            return existing
        asset = Asset(program_id=program_id, name=normalized, **fields)
        self.create(asset)
        return asset

    def list_names(self, program_id: str) -> list[str]:
        stmt = select(AssetORM.name).where(AssetORM.program_id == program_id)
        return list(self.session.scalars(stmt).all())

    def touch(self, entity_id: str) -> Asset:
        """Mark an asset as seen now and return it."""
        row = self.session.get(AssetORM, entity_id)
        if row is None:
            raise EntityNotFoundError(f"Asset with id {entity_id!r} not found")
        from aegisrecon.core.models import utcnow
        row.last_seen_at = utcnow()
        self.session.flush()
        return self._to_domain(row)


class DnsRecordRepository(BaseRepository[DnsRecord, DnsRecordORM]):
    orm = DnsRecordORM
    domain = DnsRecord

    def exists(self, asset_id: str, record_type: str, value: str) -> bool:
        stmt = select(DnsRecordORM.id).where(
            DnsRecordORM.asset_id == asset_id,
            DnsRecordORM.record_type == record_type,
            DnsRecordORM.value == value,
        )
        return self.session.scalar(stmt) is not None


class IpRecordRepository(BaseRepository[IpRecord, IpRecordORM]):
    orm = IpRecordORM
    domain = IpRecord

    def exists(self, asset_id: str, address: str) -> bool:
        stmt = select(IpRecordORM.id).where(
            IpRecordORM.asset_id == asset_id,
            IpRecordORM.address == address,
        )
        return self.session.scalar(stmt) is not None


class EndpointRepository(BaseRepository[Endpoint, EndpointORM]):
    orm = EndpointORM
    domain = Endpoint

    def exists(self, asset_id: str, url: str) -> bool:
        stmt = select(EndpointORM.id).where(
            EndpointORM.asset_id == asset_id,
            EndpointORM.url == url,
        )
        return self.session.scalar(stmt) is not None


class TechnologyRepository(BaseRepository[Technology, TechnologyORM]):
    orm = TechnologyORM
    domain = Technology

    def exists(self, asset_id: str, name: str) -> bool:
        stmt = select(TechnologyORM.id).where(
            TechnologyORM.asset_id == asset_id,
            TechnologyORM.name == name,
        )
        return self.session.scalar(stmt) is not None


class FindingRepository(BaseRepository[Finding, FindingORM]):
    orm = FindingORM
    domain = Finding


class ReportRepository(BaseRepository[Report, ReportORM]):
    orm = ReportORM
    domain = Report


__all__ = [
    "BaseRepository",
    "ProgramRepository",
    "ScopeRepository",
    "AssetRepository",
    "DnsRecordRepository",
    "IpRecordRepository",
    "EndpointRepository",
    "TechnologyRepository",
    "FindingRepository",
    "ReportRepository",
]
