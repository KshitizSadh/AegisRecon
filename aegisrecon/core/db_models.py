"""SQLAlchemy ORM schema for AegisRecon.

These classes mirror the domain models in :mod:`aegisrecon.core.models`. They
are intentionally a thin persistence mapping; all business rules and
validation live in the Pydantic domain layer.

Conventions:
    * Every table uses a string UUID primary key.
    * ``created_at`` / ``updated_at`` are managed on insert/update via defaults.
    * ``program_id`` and ``asset_id`` foreign keys are unconstrained by design
      (soft references) so historical records survive program removal until an
      explicit purge.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def _utcnow() -> datetime:
    """Return timezone-aware UTC now (SQLite stores naive, ignores tz)."""
    return datetime.now(timezone.utc)


class ProgramORM(Base):
    __tablename__ = "programs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    organization: Mapped[str] = mapped_column(String(255), default="")
    owner: Mapped[str] = mapped_column(String(255), default="")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class ScopeEntryORM(Base):
    __tablename__ = "scope_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    program_id: Mapped[str] = mapped_column(String(36), ForeignKey("programs.id"), index=True)
    value: Mapped[str] = mapped_column(String(2048), index=True)
    kind: Mapped[str] = mapped_column(String(16))
    action: Mapped[str] = mapped_column(String(16))
    note: Mapped[str] = mapped_column(String(1000), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class AssetORM(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    program_id: Mapped[str] = mapped_column(String(36), ForeignKey("programs.id"), index=True)
    name: Mapped[str] = mapped_column(String(2048), index=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    source: Mapped[str] = mapped_column(String(255), default="manual")
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class DnsRecordORM(Base):
    __tablename__ = "dns_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), index=True)
    record_type: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(2048))
    ttl: Mapped[int] = mapped_column(Integer, default=0)
    source: Mapped[str] = mapped_column(String(255), default="resolver")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class IpRecordORM(Base):
    __tablename__ = "ip_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), index=True)
    address: Mapped[str] = mapped_column(String(45), index=True)
    source: Mapped[str] = mapped_column(String(255), default="resolver")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class EndpointORM(Base):
    __tablename__ = "endpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), index=True)
    url: Mapped[str] = mapped_column(Text, index=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str] = mapped_column(String(2048), default="")
    content_type: Mapped[str] = mapped_column(String(255), default="")
    source: Mapped[str] = mapped_column(String(255), default="httpx")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class TechnologyORM(Base):
    __tablename__ = "technologies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    version: Mapped[str] = mapped_column(String(255), default="")
    category: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class FindingORM(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    program_id: Mapped[str] = mapped_column(String(36), ForeignKey("programs.id"), index=True)
    asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id"), nullable=True, index=True
    )
    title: Mapped[str] = mapped_column(String(2048), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    references: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class ReportORM(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    program_id: Mapped[str] = mapped_column(String(36), ForeignKey("programs.id"), index=True)
    title: Mapped[str] = mapped_column(String(2048))
    format: Mapped[str] = mapped_column(String(32), default="json")
    path: Mapped[str] = mapped_column(String(2048), default="")
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


__all__ = [
    "Base",
    "ProgramORM",
    "ScopeEntryORM",
    "AssetORM",
    "DnsRecordORM",
    "IpRecordORM",
    "EndpointORM",
    "TechnologyORM",
    "FindingORM",
    "ReportORM",
]
