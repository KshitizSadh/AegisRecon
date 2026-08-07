"""Repository layer mapping domain models to ORM rows.

Each repository is responsible for exactly one entity type. A generic base
provides the CRUD primitives; subclasses add domain-specific queries. All
methods accept and return Pydantic domain models, never ORM rows.
"""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegisrecon.core.db_models import (
    AssetAliasORM,
    AssetFileORM,
    AssetORM,
    Base,
    CollaboratorORM,
    DnsRecordORM,
    EndpointORM,
    FindingORM,
    IpRecordORM,
    ParameterORM,
    PortORM,
    ProgramORM,
    ReportORM,
    ScheduledJobORM,
    ScopeEntryORM,
    SecretORM,
    SnapshotORM,
    TechnologyORM,
)
from aegisrecon.core.models import (
    Asset,
    AssetAlias,
    AssetFile,
    Collaborator,
    DnsRecord,
    Endpoint,
    Finding,
    IpRecord,
    Parameter,
    Port,
    Program,
    Report,
    ScheduledJob,
    ScopeEntry,
    Secret,
    Snapshot,
    Technology,
    utcnow,
)
from aegisrecon.exceptions import EntityNotFoundError
from aegisrecon.utils.validators import normalize_hostname

M = TypeVar("M", bound=BaseModel)
R = TypeVar("R", bound=Base)


def _iso(value: Any) -> Any:
    """Serialize a datetime into ISO 8601 string for Pydantic consumption."""
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


def _as_utc(value):
    """Normalize a possibly-naive datetime to an aware UTC datetime."""
    from datetime import timezone

    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class BaseRepository(Generic[M, R]):
    """Generic CRUD repository over a SQLAlchemy session."""

    orm: type[R]
    domain: type[M]

    def __init__(self, session: Session) -> None:
        self.session = session

    # -- mapping -------------------------------------------------------
    def _to_domain(self, row: R) -> M:
        data = {column.name: getattr(row, column.name) for column in row.__table__.columns}
        data = {k: _iso(v) for k, v in data.items()}
        return self.domain.model_validate(data)  # type: ignore[return-value]

    def _from_domain(self, model: M) -> R:
        return self.orm(**model.model_dump(mode="python"))

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
        stmt = stmt.order_by(getattr(self.orm, "created_at"))  # noqa: B009 - generic ORM type
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
        stmt = select(getattr(self.orm, "id"))  # noqa: B009 - generic ORM type
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
        alias = AssetAliasRepository(self.session).get_by_name(program_id, normalized)
        if alias is not None:
            return self.get(alias.asset_id)
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
        row.last_seen_at = utcnow()
        self.session.flush()
        return self._to_domain(row)


class AssetAliasRepository(BaseRepository[AssetAlias, AssetAliasORM]):
    orm = AssetAliasORM
    domain = AssetAlias

    def get_by_name(self, program_id: str, name: str) -> AssetAlias | None:
        row = self.session.scalars(
            select(AssetAliasORM).where(
                AssetAliasORM.program_id == program_id,
                AssetAliasORM.name == normalize_hostname(name),
            )
        ).first()
        return self._to_domain(row) if row else None

    def register(self, asset: Asset, name: str) -> AssetAlias | None:
        """Register *name* as an alias of *asset*, returning the created row.

        Returns ``None`` when the alias already resolves to the same asset.
        """
        normalized = normalize_hostname(name)
        existing = self.get_by_name(asset.program_id, normalized)
        if existing is not None:
            return None
        alias = AssetAlias(
            program_id=asset.program_id, asset_id=asset.id, name=normalized
        )
        self.create(alias)
        return alias


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

    def get_by_url(self, asset_id: str, url: str) -> Endpoint | None:
        row = self.session.scalars(
            select(EndpointORM).where(EndpointORM.asset_id == asset_id, EndpointORM.url == url)
        ).first()
        return self._to_domain(row) if row else None

    def list_for_program(self, program_id: str) -> list[Endpoint]:
        stmt = (
            select(EndpointORM)
            .join(AssetORM, AssetORM.id == EndpointORM.asset_id)
            .where(AssetORM.program_id == program_id)
        )
        rows = self.session.scalars(stmt).all()
        return [self._to_domain(row) for row in rows]


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


class PortRepository(BaseRepository[Port, PortORM]):
    orm = PortORM
    domain = Port

    def exists(self, asset_id: str, port: int, protocol: str = "tcp") -> bool:
        stmt = select(PortORM.id).where(
            PortORM.asset_id == asset_id,
            PortORM.port == port,
            PortORM.protocol == protocol,
        )
        return self.session.scalar(stmt) is not None


class ParameterRepository(BaseRepository[Parameter, ParameterORM]):
    orm = ParameterORM
    domain = Parameter

    def exists(self, endpoint_id: str, name: str) -> bool:
        stmt = select(ParameterORM.id).where(
            ParameterORM.endpoint_id == endpoint_id,
            ParameterORM.name == name,
        )
        return self.session.scalar(stmt) is not None


class AssetFileRepository(BaseRepository[AssetFile, AssetFileORM]):
    orm = AssetFileORM
    domain = AssetFile

    def get_by_url(self, asset_id: str, url: str) -> AssetFile | None:
        row = self.session.scalars(
            select(AssetFileORM).where(AssetFileORM.asset_id == asset_id, AssetFileORM.url == url)
        ).first()
        return self._to_domain(row) if row else None

    def get_by_path(self, asset_id: str, path: str) -> AssetFile | None:
        row = self.session.scalars(
            select(AssetFileORM).where(AssetFileORM.asset_id == asset_id, AssetFileORM.path == path)
        ).first()
        return self._to_domain(row) if row else None

    def list_for_program(self, program_id: str) -> list[AssetFile]:
        stmt = (
            select(AssetFileORM)
            .join(AssetORM, AssetORM.id == AssetFileORM.asset_id)
            .where(AssetORM.program_id == program_id)
        )
        rows = self.session.scalars(stmt).all()
        return [self._to_domain(row) for row in rows]


class SecretRepository(BaseRepository[Secret, SecretORM]):
    orm = SecretORM
    domain = Secret

    def exists(self, program_id: str, asset_id: str, kind: str, value: str) -> bool:
        stmt = select(SecretORM.id).where(
            SecretORM.program_id == program_id,
            SecretORM.asset_id == asset_id,
            SecretORM.kind == kind,
            SecretORM.value == value,
        )
        return self.session.scalar(stmt) is not None


class SnapshotRepository(BaseRepository[Snapshot, SnapshotORM]):
    orm = SnapshotORM
    domain = Snapshot

    def latest(self, entity_type: str, entity_id: str) -> Snapshot | None:
        stmt = (
            select(SnapshotORM)
            .where(SnapshotORM.entity_type == entity_type, SnapshotORM.entity_id == entity_id)
            .order_by(SnapshotORM.created_at.desc())
        )
        row = self.session.scalars(stmt).first()
        return self._to_domain(row) if row else None

    def history(self, entity_type: str, entity_id: str, limit: int = 50) -> list[Snapshot]:
        stmt = (
            select(SnapshotORM)
            .where(SnapshotORM.entity_type == entity_type, SnapshotORM.entity_id == entity_id)
            .order_by(SnapshotORM.created_at.desc())
            .limit(limit)
        )
        rows = self.session.scalars(stmt).all()
        return [self._to_domain(row) for row in rows]


class ScheduledJobRepository(BaseRepository[ScheduledJob, ScheduledJobORM]):
    orm = ScheduledJobORM
    domain = ScheduledJob

    def get_by_name(self, program_id: str, name: str) -> ScheduledJob | None:
        row = self.session.scalars(
            select(ScheduledJobORM).where(
                ScheduledJobORM.program_id == program_id, ScheduledJobORM.name == name
            )
        ).first()
        return self._to_domain(row) if row else None

    def list_enabled_due(self, now) -> list[ScheduledJob]:
        """Return enabled jobs whose interval has elapsed since their last run."""
        rows = self.session.scalars(
            select(ScheduledJobORM).where(ScheduledJobORM.enabled.is_(True))
        ).all()
        due: list[ScheduledJob] = []
        for row in rows:
            job = self._to_domain(row)
            last_run = _as_utc(job.last_run_at)
            elapsed = (now - last_run).total_seconds() if last_run else float("inf")
            if elapsed >= job.interval_seconds:
                due.append(job)
        return due

    def list_enabled(self) -> list[ScheduledJob]:
        """Return all enabled jobs."""
        rows = self.session.scalars(
            select(ScheduledJobORM).where(ScheduledJobORM.enabled.is_(True))
        ).all()
        return [self._to_domain(row) for row in rows]


class CollaboratorRepository(BaseRepository[Collaborator, CollaboratorORM]):
    orm = CollaboratorORM
    domain = Collaborator

    def get_for_program(self, program_id: str, email: str) -> Collaborator | None:
        row = self.session.scalars(
            select(CollaboratorORM).where(
                CollaboratorORM.program_id == program_id,
                CollaboratorORM.email == email.lower().strip(),
            )
        ).first()
        return self._to_domain(row) if row else None

    def list_for_program(self, program_id: str) -> list[Collaborator]:
        return self.list(program_id=program_id)


__all__ = [
    "BaseRepository",
    "ProgramRepository",
    "ScopeRepository",
    "AssetRepository",
    "AssetAliasRepository",
    "DnsRecordRepository",
    "IpRecordRepository",
    "EndpointRepository",
    "TechnologyRepository",
    "FindingRepository",
    "ReportRepository",
    "PortRepository",
    "ParameterRepository",
    "AssetFileRepository",
    "SecretRepository",
    "SnapshotRepository",
    "ScheduledJobRepository",
    "CollaboratorRepository",
]
