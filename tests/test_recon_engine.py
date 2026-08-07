"""Integration tests for the recon engine (providers mocked, DB real)."""

from __future__ import annotations

import json

import pytest
from conftest import add_scope

from aegisrecon.core.models import AssetKind
from aegisrecon.core.repositories import AssetRepository, DnsRecordRepository, IpRecordRepository
from aegisrecon.engines import recon as recon_module
from aegisrecon.engines.dns import Resolution
from aegisrecon.exceptions import ReconError


class _FakeProvider:
    discovered: dict[str, list[str]] = {
        "example.com": ["www.example.com", "api.example.com", "outofscope.org"]
    }

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
                records={
                    "A": ("1.2.3.4",) if h != "api.example.com" else (),
                    "AAAA": (),
                    "CNAME": (),
                },
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


def test_resume_skips_completed_roots(monkeypatch, database, scoped_program) -> None:
    add_scope(database, scoped_program.id, "*.example.org", wildcard=True)

    calls: list[str] = []

    class Provider:
        discovered = {
            "example.com": ["api.example.com"],
            "example.org": ["www.example.org"],
        }

        @classmethod
        def create(cls, **kwargs):
            return cls()

        def query(self, domain: str) -> list[str]:
            calls.append(domain)
            return self.discovered.get(domain, [])

        def close(self):
            return None

    monkeypatch.setattr(recon_module, "PASSIVE_SOURCES", {"fake": Provider})
    monkeypatch.setattr(recon_module, "DnsResolver", _FakeResolver)

    # Simulate an interrupted scan where example.com was already completed.
    cp_dir = database.path.parent / "checkpoints"
    cp_dir.mkdir(parents=True, exist_ok=True)
    checkpoint = cp_dir / f"{scoped_program.id}.json"
    checkpoint.write_text(
        json.dumps(
            {
                "version": 1,
                "program_id": scoped_program.id,
                "sources_done": {"fake": ["example.com"]},
                "hostnames": ["api.example.com"],
            }
        ),
        encoding="utf-8",
    )

    engine = recon_module.ReconEngine(database, enable_ct_logs=True)
    result = engine.run(scoped_program.id, sources=["fake"], resume=True)

    assert calls == ["example.org"]  # completed root was skipped
    assert result.in_scope == 2
    names = _persisted_names(database)
    assert {"api.example.com", "www.example.org"} <= names
    assert not checkpoint.exists()  # checkpoint cleared after completion


def _persisted_names(database) -> set[str]:
    with database.session() as session:
        assets = AssetRepository(session).list()
        session.close()
    return {a.name for a in assets}


def test_provider_timeout_applied_only_to_crtsh(database) -> None:
    """ct_timeout must not leak into providers with their own timeouts."""

    seen: dict[str, dict] = {}

    class RecordingProvider:
        @classmethod
        def create(cls, **kwargs):
            seen[cls.__name__] = kwargs
            return _FakeProvider()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(recon_module, "PASSIVE_SOURCES", {"crtsh": RecordingProvider})
    engine = recon_module.ReconEngine(database, enable_ct_logs=True, ct_timeout=20.0)
    try:
        engine._open_provider("crtsh")
    finally:
        monkeypatch.undo()
    assert seen["RecordingProvider"] == {"timeout": 20.0}


def test_subfinder_provider_uses_own_default_timeout(database, monkeypatch) -> None:
    """Subfinder must keep its own (long) timeout, not the CT timeout."""

    captured: dict = {}

    class CapturingProvider:
        @classmethod
        def create(cls, **kwargs):
            captured.update(kwargs)
            return _FakeProvider()

    monkeypatch.setattr(recon_module, "PASSIVE_SOURCES", {"subfinder": CapturingProvider})
    engine = recon_module.ReconEngine(database, enable_ct_logs=True, ct_timeout=20.0)
    engine._open_provider("subfinder")

    assert captured == {}  # no timeout kwarg forced
