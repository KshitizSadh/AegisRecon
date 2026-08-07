"""Tests for asset deduplication, aliasing and canonical-name resolution."""

from __future__ import annotations

from aegisrecon.core.database import Database
from aegisrecon.core.models import (
    Asset,
    AssetKind,
    DnsRecord,
    DnsRecordType,
    Endpoint,
    IpRecord,
)
from aegisrecon.core.repositories import (
    AssetAliasRepository,
    AssetRepository,
    DnsRecordRepository,
    EndpointRepository,
    IpRecordRepository,
)
from aegisrecon.engines.dedup import DedupEngine
from aegisrecon.utils.validators import canonical_key, strip_www_prefix


def _add_asset(database: Database, program_id: str, name: str) -> Asset:
    with database.session() as session:
        asset = Asset(
            program_id=program_id,
            name=name,
            kind=AssetKind.SUBDOMAIN if "." in name else AssetKind.HOSTNAME,
            source="test",
        )
        AssetRepository(session).create(asset)
        session.commit()
        return asset


def _asset_names(database: Database, program_id: str) -> list[str]:
    with database.session() as session:
        assets = AssetRepository(session).list(program_id=program_id)
        session.close()
        return [a.name for a in assets]


def test_canonical_key_idn_collapse():
    assert canonical_key("Fußball.de") == canonical_key("xn--fuball-cta.de")
    assert canonical_key(" EXAMPLE.COM. ") == canonical_key("example.com")
    assert canonical_key("www.example.com") != canonical_key("example.com")


def test_strip_www_prefix():
    assert strip_www_prefix("www.example.com") == "example.com"
    assert strip_www_prefix("example.com") == "example.com"
    assert strip_www_prefix("Www.Example.COM.") == "example.com"


def test_asset_alias_registration_and_lookup(database, scoped_program) -> None:
    asset = _add_asset(database, scoped_program.id, "example.com")
    with database.session() as session:
        AssetAliasRepository(session).register(asset, "Example.Com.")
        session.commit()
    with database.session() as session:
        alias = AssetAliasRepository(session).get_by_name(scoped_program.id, "example.com.")
        assert alias is not None and alias.asset_id == asset.id
        session.close()


def test_get_or_create_routes_through_alias(database, scoped_program) -> None:
    canonical = _add_asset(database, scoped_program.id, "example.com")
    with database.session() as session:
        AssetAliasRepository(session).register(canonical, "Example.com.")
        session.commit()
    with database.session() as session:
        resolved = AssetRepository(session).get_or_create(scoped_program.id, "example.com.")
        session.commit()
        session.close()
    assert resolved.id == canonical.id


def test_dedup_collapses_case_and_idn_variants(database, scoped_program) -> None:
    _add_asset(database, scoped_program.id, "Example.com")
    _add_asset(database, scoped_program.id, "example.com")
    report = DedupEngine(database).run(scoped_program.id)
    assert report.candidates == 1
    assert report.merged == 1
    assert len(_asset_names(database, scoped_program.id)) == 1


def test_dedup_www_requires_evidence(database, scoped_program) -> None:
    apex = _add_asset(database, scoped_program.id, "example.com")
    www = _add_asset(database, scoped_program.id, "www.example.com")
    # no shared IP evidence -> www must NOT fold by default
    report = DedupEngine(database).run(scoped_program.id)
    assert report.candidates == 0
    with database.session() as session:
        IpRecordRepository(session).create(IpRecord(asset_id=apex.id, address="10.0.0.5"))
        IpRecordRepository(session).create(IpRecord(asset_id=www.id, address="10.0.0.5"))
        session.commit()
    report = DedupEngine(database).run(scoped_program.id)
    assert report.candidates == 1


def test_dedup_www_strip_heuristic(database, scoped_program) -> None:
    _add_asset(database, scoped_program.id, "example.com")
    _add_asset(database, scoped_program.id, "www.example.com")
    report = DedupEngine(database).run(scoped_program.id, www_strip=True)
    assert report.candidates == 1


def test_dedup_reparents_child_and_registers_alias(database, scoped_program) -> None:
    canonical = _add_asset(database, scoped_program.id, "example.com")
    dup = _add_asset(database, scoped_program.id, "EXAMPLE.COM")
    with database.session() as session:
        EndpointRepository(session).create(
            Endpoint(asset_id=dup.id, url="https://EXAMPLE.COM/")
        )
        DnsRecordRepository(session).create(
            DnsRecord(asset_id=dup.id, record_type=DnsRecordType.A, value="10.0.0.1")
        )
        session.commit()
    report = DedupEngine(database).run(scoped_program.id)
    assert report.merged == 1
    with database.session() as session:
        eps = EndpointRepository(session).get_by_url(canonical.id, "https://EXAMPLE.COM/")
        assert eps is not None
        alias = AssetAliasRepository(session).get_by_name(scoped_program.id, "example.com")
        assert alias is not None and alias.asset_id == canonical.id
        session.close()


def test_dedup_dry_run_is_noop(database, scoped_program) -> None:
    _add_asset(database, scoped_program.id, "Example.com")
    _add_asset(database, scoped_program.id, "example.com")
    report = DedupEngine(database).run(scoped_program.id, dry_run=True)
    assert report.dry_run and report.candidates == 1
    assert len(_asset_names(database, scoped_program.id)) == 2  # unchanged
