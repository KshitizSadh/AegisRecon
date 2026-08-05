"""Integration tests for the recon engine (providers mocked, DB real)."""

from __future__ import annotations

import pytest

from aegisrecon.core.models import AssetKind
from aegisrecon.core.repositories import AssetRepository, DnsRecordRepository, IpRecordRepository
from aegisrecon.engines import recon as recon_module
from aegisrecon.engines.dns import Resolution
from aegisrecon.exceptions import ReconError


class _FakeProvider:
    discovered: dict[str, list[str]] = {"example.com": ["www.example.com", "api.example.com", "outofscope.org"]}

    @classmethod
    def create(cls, **kwargs):
        return cls()

    def query(self, domain: str) -> list[str]:
        return self.discovered.get(domain, [])

    def close(self):
        return None


class _FakeResolver:
    def __init__(self, *args, **kwargs):
        self.errors = []

    def resolve_many(self, hostnames):
        return {
            h: Resolution(
                hostname=h,
                addresses=("1.2.3.4",) if h != "api.example.com" else (),
                records={"A": ("1.2.3.4",) if h != "api.example.com" else (), "AAAA": (), "CNAME": ()},
            )
            for h in hostnames
        }


def test_run_discovers_resolves_and_persists(monkeypatch, database, scoped_program) -> None:
    monkeypatch.setattr(recon_module, "PASSIVE_SOURCES", {"crtsh": _FakeProvider})
    monkeypatch.setattr(recon_module, "DnsResolver", _FakeResolver)

    engine = recon_module.ReconEngine(database, enable_ct_logs=True)
    result = engine.run(scoped_program.id, sources=["crtsh"])

    assert result.discovered == 3
    assert result.in_scope == 2  # mail/outofscope.org filtered
    assert result.new_assets == 2

    with database.session() as session:
        assets = AssetRepository(session).list(program_id=scoped_program.id)
        kinds = {a.kind for a in assets}
        session.close()
    assert {a.name for a in assets} == {"www.example.com", "api.example.com"}
    assert AssetKind.SUBDOMAIN in kinds


def test_second_run_updates_not_recreates(monkeypatch, database, scoped_program) -> None:
    monkeypatch.setattr(recon_module, "PASSIVE_SOURCES", {"crtsh": _FakeProvider})
    monkeypatch.setattr(recon_module, "DnsResolver", _FakeResolver)
    engine = recon_module.ReconEngine(database, enable_ct_logs=True)
    engine.run(scoped_program.id, sources=["crtsh"])
    second = engine.run(scoped_program.id, sources=["crtsh"])

    assert second.new_assets == 0
    assert second.updated_assets == 2

    with database.session() as session:
        dns = DnsRecordRepository(session).list()
        ips = IpRecordRepository(session).list()
        session.close()
    assert len(dns) == 1
    assert len(ips) == 1


def test_run_requires_root_domains(database, program) -> None:
    engine = recon_module.ReconEngine(database, enable_ct_logs=True)
    with pytest.raises(ReconError):
        engine.run(program.id, sources=[])


def test_ingest_respects_scope(monkeypatch, database, scoped_program) -> None:
    monkeypatch.setattr(recon_module, "DnsResolver", _FakeResolver)
    engine = recon_module.ReconEngine(database)
    result = engine.ingest(scoped_program.id, ["ok.example.com", "evil.org", "api.example.com"])
    assert result.in_scope == 2
    assert result.discovered == 3