"""Tests for JSON report generation."""

from __future__ import annotations

import json

from aegisrecon.core.models import Asset, AssetKind, DnsRecord, DnsRecordType, Finding, FindingSeverity, IpRecord
from aegisrecon.core.repositories import AssetRepository, DnsRecordRepository, FindingRepository, IpRecordRepository
from aegisrecon.reporting.json_report import build_payload, generate_json_report, REPORT_SCHEMA_VERSION


def _seed(database, program) -> None:
    with database.session() as session:
        assets = AssetRepository(session)
        asset = assets.create(Asset(program_id=program.id, name="www.example.com", kind=AssetKind.SUBDOMAIN))
        DnsRecordRepository(session).create(DnsRecord(asset_id=asset.id, record_type=DnsRecordType.A, value="1.2.3.4"))
        IpRecordRepository(session).create(IpRecord(asset_id=asset.id, address="1.2.3.4"))
        FindingRepository(session).create(
            Finding(program_id=program.id, asset_id=asset.id, title="Reflected XSS", severity=FindingSeverity.HIGH)
        )
        FindingRepository(session).create(
            Finding(program_id=program.id, asset_id=asset.id, title="Info leak", severity=FindingSeverity.INFO)
        )
        session.commit()
        session.close()


def test_build_payload_contains_program_assets_and_summary(database, scoped_program) -> None:
    _seed(database, scoped_program)
    payload = build_payload(database, scoped_program.id)
    assert payload["schema_version"] == REPORT_SCHEMA_VERSION
    assert payload["program"]["name"] == scoped_program.name
    assert len(payload["assets"]) == 1
    assert payload["assets"][0]["dns_records"][0]["value"] == "1.2.3.4"
    assert payload["summary"]["total_assets"] == 1
    assert payload["summary"]["total_ips"] == 1
    assert payload["summary"]["total_findings"] == 2
    assert payload["summary"]["by_severity"]["high"] == 1


def test_generate_writes_file_and_persists_report(database, scoped_program, data_dir) -> None:
    _seed(database, scoped_program)
    report = generate_json_report(database, scoped_program.id, data_dir / "reports", title="Weekly")
    assert report.path.endswith(".json")
    assert report.title == "Weekly"
    assert report.format == "json"

    written = json.loads(open(report.path, encoding="utf-8").read())
    assert written["summary"]["total_findings"] == 2