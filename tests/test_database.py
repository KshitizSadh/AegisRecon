"""Repository round-trip and database tests."""

from __future__ import annotations

import pytest

from aegisrecon.core.models import (
    Asset,
    AssetKind,
    DnsRecord,
    DnsRecordType,
    Endpoint,
    Finding,
    FindingSeverity,
    IpRecord,
    Report,
    ScopeEntry,
    Technology,
)
from aegisrecon.core.repositories import (
    AssetRepository,
    DnsRecordRepository,
    EndpointRepository,
    FindingRepository,
    IpRecordRepository,
    ProgramRepository,
    ReportRepository,
    ScopeRepository,
    TechnologyRepository,
)
from aegisrecon.exceptions import EntityNotFoundError


def test_program_crud_roundtrip(database, program) -> None:
    with database.session() as session:
        repo = ProgramRepository(session)
        fetched = repo.get(program.id)
        assert fetched.name == program.name
        assert fetched.id == program.id

        repo.update(program.id, organization="New Org")
        session.commit()
        updated = repo.get(program.id)
        assert updated.organization == "New Org"
        session.close()

    with database.session() as session:
        repo = ProgramRepository(session)
        by_name = repo.get_by_name("Test Program")
        assert by_name is not None and by_name.organization == "New Org"


def test_program_delete_not_found(database, program) -> None:
    with database.session() as session:
        with pytest.raises(EntityNotFoundError):
            ProgramRepository(session).delete("does-not-exist")


def test_scope_repository_filter(database, program) -> None:
    with database.session() as session:
        repo = ScopeRepository(session)
        for value in ["*.example.com", "example.com"]:
            repo.create(ScopeEntry(program_id=program.id, value=value, kind="wildcard" if "*" in value else "exact"))
        session.commit()
        rules = repo.list_for_program(program.id)
        session.close()
    assert len(rules) == 2


def test_asset_get_or_create_dedupes(database, program) -> None:
    with database.session() as session:
        repo = AssetRepository(session)
        first = repo.get_or_create(program.id, "www.example.com", kind=AssetKind.SUBDOMAIN, source="test")
        second = repo.get_or_create(program.id, "WWW.Example.COM", kind=AssetKind.SUBDOMAIN, source="test")
        session.commit()
        names = repo.list_names(program.id)
        session.close()
    assert first.id == second.id
    assert names == ["www.example.com"]


def test_related_records_persist(database, program) -> None:
    with database.session() as session:
        assets = AssetRepository(session)
        asset = assets.create(Asset(program_id=program.id, name="app.example.com", kind=AssetKind.SUBDOMAIN))
        DnsRecordRepository(session).create(DnsRecord(asset_id=asset.id, record_type=DnsRecordType.A, value="1.2.3.4"))
        DnsRecordRepository(session).create(DnsRecord(asset_id=asset.id, record_type=DnsRecordType.AAAA, value="::1"))
        IpRecordRepository(session).create(IpRecord(asset_id=asset.id, address="1.2.3.4"))
        EndpointRepository(session).create(Endpoint(asset_id=asset.id, url="https://app.example.com/", status_code=200))
        TechnologyRepository(session).create(Technology(asset_id=asset.id, name="nginx"))
        FindingRepository(session).create(Finding(program_id=program.id, asset_id=asset.id, title="XSS", severity=FindingSeverity.HIGH))
        a = DnsRecordRepository(session).list(asset_id=asset.id)
        ips = IpRecordRepository(session).list(asset_id=asset.id)
        endpoints = EndpointRepository(session).list(asset_id=asset.id)
        techs = TechnologyRepository(session).list(asset_id=asset.id)
        findings = FindingRepository(session).list(program_id=program.id)
        session.close()
    assert len(a) == 2
    assert len(ips) == 1
    assert len(endpoints) == 1
    assert len(techs) == 1
    assert len(findings) == 1


def test_exists_helpers(database, program) -> None:
    with database.session() as session:
        assets = AssetRepository(session)
        asset = assets.create(Asset(program_id=program.id, name="a.example.com"))
        dns = DnsRecordRepository(session)
        dns.create(DnsRecord(asset_id=asset.id, record_type=DnsRecordType.A, value="1.2.3.4"))
        session.commit()
        assert dns.exists(asset.id, "A", "1.2.3.4") is True
        assert dns.exists(asset.id, "A", "9.9.9.9") is False


def test_database_context_manager(tmp_path) -> None:
    from aegisrecon.core.database import Database

    with Database(tmp_path / "cm.db") as db:
        assert db.path.exists()


def test_report_repository(database, program) -> None:
    with database.session() as session:
        repo = ReportRepository(session)
        report = repo.create(Report(program_id=program.id, title="T", format="json", path="/tmp/x.json"))
        session.commit()
        assert repo.get(report.id).title == "T"