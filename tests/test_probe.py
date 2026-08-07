"""Tests for the HTTP probing engine (tool mocked)."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from aegisrecon.core.database import Database
from aegisrecon.core.models import Program
from aegisrecon.core.repositories import AssetRepository, EndpointRepository, ParameterRepository
from aegisrecon.engines.probe import ProbeEngine


@pytest.fixture(autouse=True)
def _fake_httpx(monkeypatch) -> None:
    monkeypatch.setattr(
        "aegisrecon.engines.httpx._find_go_binary", lambda name: "/usr/local/bin/httpx"
    )


@dataclass
class _FakeProbeResult:
    url: str
    status_code: int | None = None
    title: str = ""
    content_type: str = ""
    technologies: tuple[str, ...] = ()


def _seed_assets(database: Database, program: Program) -> None:
    with database.session() as session:
        AssetRepository(session).get_or_create(program.id, "app.example.com")
        session.commit()


def test_probe_persists_endpoints_and_parameters(database: Database, program: Program, monkeypatch) -> None:
    _seed_assets(database, program)
    results = [
        _FakeProbeResult(
            url="https://app.example.com/?utm=1&id=42",
            status_code=200,
            title="App",
            content_type="text/html",
            technologies=("React",),
        )
    ]

    engine = ProbeEngine(database, binary="httpx")
    engine.prober.probe = lambda hosts, extra_flags=None: results  # type: ignore[method-assign]
    outcome = engine.run(program.id)

    assert outcome.endpoints == 1
    assert outcome.new_endpoints == 1
    assert outcome.technologies == 1
    assert outcome.parameters == 2

    with database.session() as session:
        endpoints = EndpointRepository(session).list_for_program(program.id)
        params = ParameterRepository(session).list()
        session.close()
    assert len(endpoints) == 1
    assert endpoints[0].status_code == 200
    assert any(p.name == "id" for p in params)


def test_probe_skips_out_of_scope_host(database: Database, program: Program, monkeypatch) -> None:
    _seed_assets(database, program)
    results = [_FakeProbeResult(url="https://evil.example.net/", status_code=200)]

    engine = ProbeEngine(database, binary="httpx")
    engine.prober.probe = lambda hosts, extra_flags=None: results  # type: ignore[method-assign]
    outcome = engine.run(program.id)

    assert outcome.endpoints == 0
    assert outcome.errors == ["https://evil.example.net/"]


def test_probe_requires_assets(database: Database, program: Program, monkeypatch) -> None:
    engine = ProbeEngine(database, binary="httpx")
    engine.prober.probe = lambda hosts, extra_flags=None: []  # type: ignore[method-assign]
    with pytest.raises(ValueError):
        engine.run(program.id)
