"""Tests for the naabu port scanner and engine."""

from __future__ import annotations

import json

import pytest

from aegisrecon.core.database import Database
from aegisrecon.core.models import Program
from aegisrecon.core.repositories import AssetRepository, PortRepository
from aegisrecon.engines.naabu import NaabuScanner, PortEngine, PortFinding
from aegisrecon.exceptions import ToolNotFoundError

DEFAULT_PORTS = PortEngine.__init__.__defaults__[-1]


@pytest.fixture(autouse=True)
def _fake_naabu(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/naabu")


class _FakeProc:
    returncode = 0
    stdout = ""
    stderr = ""


def _run_with_stdout(stdout: str):
    def fake_run(*args, **kwargs):  # noqa: ANN001
        proc = _FakeProc()
        proc.stdout = stdout
        return proc

    return fake_run


def _naabu_line(host: str = "app.example.com", port: int = 443, protocol: str = "tcp", service: str = "https") -> str:
    return json.dumps({"host": host, "port": port, "protocol": protocol, "service": service})


def test_parse_valid_line() -> None:
    finding = NaabuScanner._parse(_naabu_line())
    assert finding is not None
    assert finding.host == "app.example.com"
    assert finding.port == 443
    assert finding.protocol == "tcp"
    assert finding.service == "https"


def test_parse_invalid_line_returns_none() -> None:
    assert NaabuScanner._parse("not json") is None
    assert NaabuScanner._parse(json.dumps({"host": "x"})) is None
    assert NaabuScanner._parse(json.dumps({"port": 443})) is None


def test_scan_parses_multiple_lines(monkeypatch) -> None:
    stdout = _naabu_line() + "\n" + _naabu_line("app.example.com", 8443)
    monkeypatch.setattr("subprocess.run", _run_with_stdout(stdout))
    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/naabu")
    findings = NaabuScanner(binary="naabu").scan(["app.example.com"])
    assert len(findings) == 2


def test_scan_skips_bad_lines(monkeypatch) -> None:
    stdout = "bad\n" + json.dumps({"port": 443}) + "\n" + _naabu_line()
    monkeypatch.setattr("subprocess.run", _run_with_stdout(stdout))
    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/naabu")
    findings = NaabuScanner(binary="naabu").scan(["app.example.com"])
    assert len(findings) == 1


def test_scan_empty_hosts_returns_empty(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/naabu")
    assert NaabuScanner(binary="naabu").scan([]) == []


def test_missing_binary_raises(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(ToolNotFoundError):
        NaabuScanner(binary="does-not-exist")


def _seed_asset(database: Database, program: Program) -> str:
    with database.session() as session:
        asset = AssetRepository(session).get_or_create(program.id, "app.example.com")
        session.commit()
        return asset.id


def test_engine_persists_valid_ports(database: Database, program: Program, monkeypatch) -> None:
    asset_id = _seed_asset(database, program)
    findings = [PortFinding(host="app.example.com", port=443, protocol="tcp", service="https")]

    engine = PortEngine(database, binary="naabu")
    engine.scanner.scan = lambda hosts, ports=DEFAULT_PORTS: findings  # type: ignore[method-assign]
    outcome = engine.run(program.id)

    assert outcome.open_ports == 1
    assert outcome.new_ports == 1
    with database.session() as session:
        ports = PortRepository(session).list(asset_id=asset_id, protocol="tcp")
        session.close()
    assert len(ports) == 1
    assert ports[0].port == 443


def test_engine_skips_unknown_host(database: Database, program: Program, monkeypatch) -> None:
    _seed_asset(database, program)
    findings = [PortFinding(host="not-in-scope.example.net", port=443)]

    engine = PortEngine(database, binary="naabu")
    engine.scanner.scan = lambda hosts, ports=DEFAULT_PORTS: findings  # type: ignore[method-assign]
    outcome = engine.run(program.id)
    assert outcome.new_ports == 0
    assert outcome.errors == ["not-in-scope.example.net"]
