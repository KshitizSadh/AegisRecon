"""JSON report generation.

The JSON exporter produces a machine-readable engagement deliverable
containing the program, its scope, all assets with their DNS/IP/endpoint
records, technologies, findings, and aggregate statistics. The schema is
stable and versioned for downstream tooling.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from aegisrecon.core.database import Database
from aegisrecon.core.models import Report
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
from aegisrecon.exceptions import ReportError
from aegisrecon.utils.fs import unique_output_path

logger = logging.getLogger("aegisrecon.reporting.json_report")

REPORT_SCHEMA_VERSION = "1.0.0"


def generate_json_report(database: Database, program_id: str, output_dir: Path, title: str | None = None) -> Report:
    """Generate and persist a JSON report for a program.

    Raises:
        EntityNotFoundError: When the program does not exist.
        ReportError: When the report file cannot be written.
    """
    payload = build_payload(database, program_id)
    effective_title = title or payload["program"]["name"]

    try:
        path = unique_output_path(output_dir, stem=f"{effective_title}-report", suffix=".json")
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"cannot write report to {output_dir}: {exc}") from exc

    with database.session() as session:
        repo = ReportRepository(session)
        report = repo.create(
            Report(
                program_id=program_id,
                title=effective_title,
                format="json",
                path=str(path),
                summary=payload["summary"],
            )
        )
        session.commit()
        report = repo.get(report.id)
        session.close()

    logger.info("report written to %s (%d bytes)", path, path.stat().st_size)
    return report


def build_payload(database: Database, program_id: str) -> dict[str, Any]:
    """Build the full report dictionary for a program (no file I/O)."""
    with database.session() as session:
        program = ProgramRepository(session).get(program_id)
        scope_entries = ScopeRepository(session).list_for_program(program_id)
        assets = AssetRepository(session).list(program_id=program_id)
        findings = FindingRepository(session).list(program_id=program_id)

        asset_rows: list[dict[str, Any]] = []
        asset_repo = AssetRepository(session)
        for asset in assets:
            asset_rows.append(
                {
                    **asset.model_dump(mode="json"),
                    "dns_records": [
                        r.model_dump(mode="json")
                        for r in DnsRecordRepository(session).list(asset_id=asset.id)
                    ],
                    "ips": [r.model_dump(mode="json") for r in IpRecordRepository(session).list(asset_id=asset.id)],
                    "endpoints": [
                        e.model_dump(mode="json") for e in EndpointRepository(session).list(asset_id=asset.id)
                    ],
                    "technologies": [
                        t.model_dump(mode="json") for t in TechnologyRepository(session).list(asset_id=asset.id)
                    ],
                }
            )
        session.close()

    summary = _summarize(payload_assets=asset_rows, findings=[f.model_dump(mode="json") for f in findings])
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "program": program.model_dump(mode="json"),
        "scope": [e.model_dump(mode="json") for e in scope_entries],
        "assets": asset_rows,
        "findings": [f.model_dump(mode="json") for f in findings],
        "summary": summary,
    }


def _summarize(payload_assets: list[dict[str, Any]], findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute aggregate statistics over report data."""
    by_kind: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    total_ips = total_endpoints = total_technologies = 0

    for asset in payload_assets:
        kind = asset.get("kind", "unknown")
        by_kind[kind] = by_kind.get(kind, 0) + 1
        total_ips += len(asset.get("ips", []))
        total_endpoints += len(asset.get("endpoints", []))
        total_technologies += len(asset.get("technologies", []))

    for finding in findings:
        severity = finding.get("severity", "info")
        by_severity[severity] = by_severity.get(severity, 0) + 1

    return {
        "total_assets": len(payload_assets),
        "total_ips": total_ips,
        "total_endpoints": total_endpoints,
        "total_technologies": total_technologies,
        "total_findings": len(findings),
        "by_kind": by_kind,
        "by_severity": by_severity,
    }


__all__ = ["generate_json_report", "build_payload", "REPORT_SCHEMA_VERSION"]
