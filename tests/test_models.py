"""Unit tests for domain models."""

from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from aegisrecon.core.models import (
    Asset,
    AssetKind,
    DnsRecord,
    DnsRecordType,
    Endpoint,
    Finding,
    FindingSeverity,
    FindingStatus,
    IpRecord,
    Program,
    ScopeEntry,
)


def test_program_normalizes_tags_and_names() -> None:
    program = Program(name="  Acme  ", tags=["High", "high", "  A", ""])
    assert program.name == "  Acme  "  # name is not normalized; tags are
    assert program.tags == ["a", "high"]


def test_asset_normalizes_name_and_tags() -> None:
    asset = Asset(program_id="p", name=" WWW.Example.COM. ", tags=["X", "x"])
    assert asset.name == "www.example.com"
    assert asset.tags == ["x"]


def test_asset_kind_default() -> None:
    asset = Asset(program_id="p", name="example.com")
    assert asset.kind == AssetKind.HOSTNAME


def test_ip_record_validates_addresses() -> None:
    ip4 = IpRecord(asset_id="a", address=" 8.8.8.8 ")
    assert ip4.address == "8.8.8.8"
    IpRecord(asset_id="a", address="2001:db8::1")
    with pytest.raises(ValidationError):
        IpRecord(asset_id="a", address="not-an-ip")


def test_endpoint_requires_scheme() -> None:
    Endpoint(asset_id="a", url="https://example.com/x")
    with pytest.raises(ValidationError):
        Endpoint(asset_id="a", url="example.com/x")


def test_dns_record_type_enum() -> None:
    record = DnsRecord(asset_id="a", record_type=DnsRecordType.A, value="1.2.3.4")
    assert record.record_type == "A"


def test_finding_defaults() -> None:
    finding = Finding(program_id="p", title="Test")
    assert finding.severity == FindingSeverity.INFO
    assert finding.status == FindingStatus.OPEN
    assert finding.evidence == {}


def test_resource_has_uuids_and_timestamps() -> None:
    asset = Asset(program_id="p", name="a.example.com")
    assert len(asset.id) == 36
    assert isinstance(asset.created_at, datetime)
    assert asset.updated_at >= asset.created_at


def test_scope_entry_normalizes_value() -> None:
    entry = ScopeEntry(program_id="p", value="  *.Example.COM. ")
    assert entry.value == "*.example.com"


def test_created_at_settable() -> None:
    from datetime import timezone

    stamp = datetime(2020, 1, 1, tzinfo=timezone.utc)
    asset = Asset(program_id="p", name="a.com", created_at=stamp)
    assert asset.created_at == stamp
