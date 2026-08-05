"""Domain models for AegisRecon.

These Pydantic models define the canonical shapes of every entity that flows
through the framework. They are validated on construction, kept independent of
the persistence layer, and can be (de)serialized to and from JSON without any
SQL knowledge. The database layer translates these into relational rows.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def new_uuid() -> str:
    """Return a fresh UUID4 string."""
    return str(uuid.uuid4())


def utcnow() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


class Resource(BaseModel):
    """Base model shared by every persisted entity."""

    model_config = ConfigDict(validate_assignment=True, use_enum_values=True)

    id: str = Field(default_factory=new_uuid, description="Universally unique identifier")
    created_at: datetime = Field(default_factory=utcnow, description="Creation timestamp (UTC)")
    updated_at: datetime = Field(default_factory=utcnow, description="Last modification timestamp (UTC)")

    def touch(self) -> None:
        """Mark the entity as modified at the current time."""
        self.updated_at = utcnow()


class ScopeKind(str, enum.Enum):
    """How a scope entry is matched against a target."""

    EXACT = "exact"
    WILDCARD = "wildcard"
    REGEX = "regex"


class ScopeAction(str, enum.Enum):
    """Whether a scope entry includes or excludes a target."""

    INCLUDE = "include"
    EXCLUDE = "exclude"


class AssetKind(str, enum.Enum):
    """Classification of a discovered asset."""

    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    HOSTNAME = "hostname"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    URL = "url"


class FindingSeverity(str, enum.Enum):
    """Severity ranking, aligned with the CVSS/bug-bounty convention."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, enum.Enum):
    """Lifecycle status of a finding."""

    OPEN = "open"
    TRIAGED = "triaged"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"


class DnsRecordType(str, enum.Enum):
    """Supported DNS record types."""

    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    SOA = "SOA"


class Program(Resource):
    """An authorized engagement: the top-level scope container."""

    name: str = Field(min_length=1, max_length=255, description="Human readable program name")
    description: str = Field(default="", max_length=4000, description="Optional program description")
    organization: str = Field(default="", max_length=255, description="Owning organization")
    owner: str = Field(default="", max_length=255, description="Responsible researcher/team")
    tags: list[str] = Field(default_factory=list, description="Free-form tags for grouping/filtering")
    enabled: bool = Field(default=True, description="Whether the program is active")

    @field_validator("tags")
    @classmethod
    def _normalise_tags(cls, value: list[str]) -> list[str]:
        return sorted({t.strip().lower() for t in value if t.strip()})


class ScopeEntry(Resource):
    """A single authorized scope rule belonging to a program."""

    program_id: str = Field(description="Owning program identifier")
    value: str = Field(min_length=1, max_length=2048, description="Hostname, domain or pattern")
    kind: ScopeKind = Field(default=ScopeKind.EXACT, description="How the value is matched")
    action: ScopeAction = Field(default=ScopeAction.INCLUDE, description="Include or exclude rule")
    note: str = Field(default="", max_length=1000, description="Optional justification / source")

    @field_validator("value")
    @classmethod
    def _normalise_value(cls, value: str) -> str:
        return value.strip().rstrip(".").lower()


class Asset(Resource):
    """A discovered asset that belongs to an authorized program."""

    program_id: str = Field(description="Owning program identifier")
    name: str = Field(min_length=1, max_length=2048, description="Canonical asset name")
    kind: AssetKind = Field(default=AssetKind.HOSTNAME, description="Classification of the asset")
    source: str = Field(default="manual", max_length=255, description="Where the asset was discovered from")
    last_seen_at: datetime = Field(default_factory=utcnow, description="Last time the asset was observed")
    tags: list[str] = Field(default_factory=list, description="Free-form tags")

    @field_validator("name")
    @classmethod
    def _normalise_name(cls, value: str) -> str:
        return value.strip().rstrip(".").lower()

    @field_validator("tags")
    @classmethod
    def _normalise_tags(cls, value: list[str]) -> list[str]:
        return sorted({t.strip().lower() for t in value if t.strip()})


class DnsRecord(Resource):
    """A single DNS record observed for an asset."""

    asset_id: str = Field(description="Owning asset identifier")
    record_type: DnsRecordType = Field(description="DNS record type")
    value: str = Field(description="Record payload (IP, hostname, text)")
    ttl: int = Field(default=0, ge=0, description="Record time-to-live in seconds")
    source: str = Field(default="resolver", max_length=255, description="Discovery source")

    @field_validator("value")
    @classmethod
    def _normalise_value(cls, value: str) -> str:
        return value.strip().lower()


class IpRecord(Resource):
    """An IP address that backs one or more assets."""

    asset_id: str = Field(description="Owning asset identifier")
    address: str = Field(description="IPv4 or IPv6 address")
    source: str = Field(default="resolver", max_length=255, description="Discovery source")

    @field_validator("address")
    @classmethod
    def _validate_address(cls, value: str) -> str:
        candidate = value.strip().lower()
        parsed = ip_address(candidate)
        if isinstance(parsed, (IPv4Address, IPv6Address)):
            return str(parsed)
        raise ValueError(f"invalid IP address: {value!r}")


class Endpoint(Resource):
    """A concrete URL discovered on an asset."""

    asset_id: str = Field(description="Owning asset identifier")
    url: str = Field(description="Full URL including scheme, host, path and query")
    status_code: int | None = Field(default=None, description="HTTP response status code")
    title: str = Field(default="", max_length=2048, description="Response page title")
    content_type: str = Field(default="", max_length=255, description="HTTP Content-Type header")
    source: str = Field(default="httpx", max_length=255, description="Discovery source")

    @field_validator("url")
    @classmethod
    def _normalise_url(cls, value: str) -> str:
        candidate = value.strip()
        if "://" not in candidate:
            raise ValueError(f"URL must include a scheme: {value!r}")
        return candidate


class Technology(Resource):
    """A technology/product fingerprinted on an asset."""

    asset_id: str = Field(description="Owning asset identifier")
    name: str = Field(min_length=1, max_length=255, description="Technology name")
    version: str = Field(default="", max_length=255, description="Detected version")
    category: str = Field(default="", max_length=255, description="Category (server, framework, cdn...)")

    @field_validator("name", "category")
    @classmethod
    def _normalise_text(cls, value: str) -> str:
        return value.strip().lower()


class Finding(Resource):
    """A potential vulnerability observed during an engagement."""

    program_id: str = Field(description="Owning program identifier")
    asset_id: str | None = Field(default=None, description="Affected asset (if applicable)")
    title: str = Field(min_length=1, max_length=2048, description="Short finding title")
    severity: FindingSeverity = Field(default=FindingSeverity.INFO, description="Estimated severity")
    status: FindingStatus = Field(default=FindingStatus.OPEN, description="Lifecycle status")
    description: str = Field(default="", description="Full technical description")
    evidence: dict[str, Any] = Field(default_factory=dict, description="Supporting evidence")
    references: list[str] = Field(default_factory=list, description="External references")

    @field_validator("title")
    @classmethod
    def _normalise_title(cls, value: str) -> str:
        return value.strip()

    @field_validator("references")
    @classmethod
    def _normalise_references(cls, value: list[str]) -> list[str]:
        return [v.strip() for v in value if v.strip()]


class Report(Resource):
    """A generated deliverable for a program."""

    program_id: str = Field(description="Owning program identifier")
    title: str = Field(min_length=1, max_length=2048, description="Report title")
    format: str = Field(default="json", max_length=32, description="Output format")
    path: str = Field(default="", max_length=2048, description="Location of the generated file")
    summary: dict[str, Any] = Field(default_factory=dict, description="Aggregate statistics")

    @field_validator("title")
    @classmethod
    def _normalise_title(cls, value: str) -> str:
        return value.strip()


class ProgramSummary(BaseModel):
    """Aggregate statistics computed over a program's assets."""

    model_config = ConfigDict(validate_assignment=True)

    program_id: str = Field(description="Owning program identifier")
    total_assets: int = Field(default=0, ge=0)
    total_subdomains: int = Field(default=0, ge=0)
    total_ips: int = Field(default=0, ge=0)
    total_endpoints: int = Field(default=0, ge=0)
    total_technologies: int = Field(default=0, ge=0)
    total_findings: int = Field(default=0, ge=0)
    by_kind: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)


__all__ = [
    "Program",
    "ScopeEntry",
    "ScopeKind",
    "ScopeAction",
    "Asset",
    "AssetKind",
    "DnsRecord",
    "DnsRecordType",
    "IpRecord",
    "Endpoint",
    "Technology",
    "Finding",
    "FindingSeverity",
    "FindingStatus",
    "Report",
    "ProgramSummary",
    "Resource",
    "new_uuid",
    "utcnow",
]
