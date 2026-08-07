"""Tests for the nuclei vulnerability scanning engine."""

from __future__ import annotations

from aegisrecon.core.models import FindingSeverity
from aegisrecon.engines.nuclei import SEVERITY_MAP, NucleiScanner


def test_parse_valid_json_line():
    line = (
        '{"host":"https://api.example.com/x","template-id":"cve-2020-0001",'
        '"info":{"name":"Example CVE","severity":"high"},'
        '"matcher-name":"body-match","matched-at":"https://api.example.com/x"}'
    )
    finding = NucleiScanner._parse(line)
    assert finding is not None
    assert finding.host == "https://api.example.com/x"
    assert finding.template_id == "cve-2020-0001"
    assert finding.name == "Example CVE"
    assert finding.severity == "high"
    assert finding.matcher_name == "body-match"


def test_parse_garbage_line_is_skipped():
    assert NucleiScanner._parse("not-json") is None


def test_parse_missing_info_defaults():
    line = '{"host":"https://x.test/","template-id":"tech-detect"}'
    finding = NucleiScanner._parse(line)
    assert finding is not None
    assert finding.severity == "info"
    assert finding.name == "tech-detect"
    assert finding.info == {}


def test_severity_map_covers_nuclei_severities():
    for sev in ("info", "low", "medium", "high", "critical"):
        assert SEVERITY_MAP[sev] in FindingSeverity
    assert SEVERITY_MAP["medium"] == FindingSeverity.MEDIUM


def test_engine_persists_findings(monkeypatch, database, scoped_program) -> None:
    from aegisrecon.core.models import Asset, Endpoint
    from aegisrecon.core.repositories import (
        AssetRepository,
        EndpointRepository,
        FindingRepository,
    )
    from aegisrecon.engines.nuclei import NucleiEngine

    with database.session() as session:
        asset = Asset(program_id=scoped_program.id, name="api.example.com")
        AssetRepository(session).create(asset)
        EndpointRepository(session).create(
            Endpoint(asset_id=asset.id, url="https://api.example.com/")
        )
        session.commit()
        session.close()

    class _FakeScanner:
        def __init__(self, *args, **kwargs):
            pass

        def scan(self, urls):
            return [
                NucleiFindingFixture(
                    host="api.example.com",
                    template_id="xss-test",
                    name="Reflected XSS",
                    severity="high",
                    matcher_name="body-1",
                    info={"name": "Reflected XSS"},
                )
            ]

    monkeypatch.setattr(
        "aegisrecon.engines.nuclei.NucleiScanner.__init__", lambda *a, **k: None
    )
    engine = NucleiEngine(database)
    engine.scanner = _FakeScanner()

    result = engine.run(scoped_program.id)

    assert result.targets == 1
    assert result.matched == 1
    assert result.new_findings == 1

    with database.session() as session:
        findings = FindingRepository(session).list(program_id=scoped_program.id)
        session.close()
    assert len(findings) == 1
    assert findings[0].title == "Reflected XSS"
    assert findings[0].severity == FindingSeverity.HIGH
    assert findings[0].evidence["template_id"] == "xss-test"


class NucleiFindingFixture:
    def __init__(self, host, template_id, name, severity, matcher_name, info):
        self.host = host
        self.template_id = template_id
        self.name = name
        self.severity = severity
        self.matcher_name = matcher_name
        self.info = info
