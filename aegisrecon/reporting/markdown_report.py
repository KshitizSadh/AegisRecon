"""Markdown executive report generator.

Renders a human-readable engagement summary in Markdown: program context,
scope, an executive snapshot (asset / endpoint / finding counts), the open
finding backlog ordered by severity, and a listing of notable assets. The
output is persisted as a ``Report`` record alongside the JSON deliverable so
reports can be shared without tooling.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from aegisrecon.core.database import Database
from aegisrecon.core.models import Report
from aegisrecon.core.repositories import ReportRepository
from aegisrecon.exceptions import ReportError
from aegisrecon.reporting.json_report import build_payload
from aegisrecon.utils.fs import unique_output_path

logger = logging.getLogger("aegisrecon.reporting.markdown_report")

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def generate_markdown_report(
    database: Database, program_id: str, output_dir: Path, title: str | None = None
) -> Report:
    """Generate and persist a Markdown report for a program."""
    payload = build_payload(database, program_id)
    effective_title = title or payload["program"]["name"]
    rendered = render_markdown(payload, title=effective_title)

    try:
        path = unique_output_path(output_dir, stem=f"{effective_title}-summary", suffix=".md")
        path.write_text(rendered, encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"cannot write report to {output_dir}: {exc}") from exc

    with database.session() as session:
        repo = ReportRepository(session)
        report = repo.create(
            Report(
                program_id=program_id,
                title=effective_title,
                format="markdown",
                path=str(path),
                summary=payload["summary"],
            )
        )
        session.commit()
        report = repo.get(report.id)
        session.close()

    logger.info("markdown report written to %s", path)
    return report


def render_markdown(payload: dict, title: str | None = None) -> str:
    """Render an executive summary document from a report payload."""
    program = payload["program"]
    summary = payload["summary"]
    generated = payload.get("generated_at", datetime.now(timezone.utc).isoformat())

    lines: list[str] = [
        f"# {title or program['name']} — Engagement Summary",
        "",
        f"*Generated at {generated}*",
        "",
        "## Program",
        "",
        f"- **Name**: {program.get('name', '')}",
        f"- **Organization**: {program.get('organization', '') or '—'}",
        f"- **Owner**: {program.get('owner', '') or '—'}",
        "",
        "## Executive snapshot",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
        f"| Assets | {summary['total_assets']} |",
        f"| IPs | {summary['total_ips']} |",
        f"| Endpoints | {summary['total_endpoints']} |",
        f"| Technologies | {summary['total_technologies']} |",
        f"| Findings | {summary['total_findings']} |",
        "",
    ]

    if summary.get("by_kind"):
        lines += [
            "## Asset breakdown",
            "",
            "| Kind | Count |",
            "| --- | ---: |",
        ]
        lines += [f"| {kind} | {count} |" for kind, count in sorted(summary["by_kind"].items())]
        lines.append("")

    findings = payload.get("findings", [])
    open_findings = [
        f
        for f in findings
        if f.get("status", "open") not in {"fixed", "false_positive"}
    ]
    lines += [
        "## Open findings",
        "",
    ]
    if not open_findings:
        lines += ["_No open findings. Good posture._", ""]
    else:
        lines += [
            "| Severity | Title | Status |",
            "| --- | --- | --- |",
        ]
        ordered = sorted(
            open_findings,
            key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "info"), 9),
        )
        lines += [
            f"| {f.get('severity', 'info').upper()} | {f.get('title', '')} | {f.get('status', '')} |"
            for f in ordered
        ]
        lines.append("")

    lines += ["## Scope", ""]
    scope = payload.get("scope", [])
    if scope:
        lines += ["| Rule | Kind | Action |", "| --- | --- | --- |"]
        lines += [
            f"| {entry.get('value', '')} | {entry.get('kind', '')} | {entry.get('action', '')} |"
            for entry in scope
        ]
    else:
        lines += ["_No scope rules defined._"]
    lines.append("")

    lines += ["## Manual-testing suggestions", ""]
    try:
        from aegisrecon.suggestions import generate_suggestions

        suggestions = generate_suggestions(payload)
    except Exception:  # pragma: no cover - defensive: suggestions must never break a report
        suggestions = []
    if not suggestions:
        lines += ["_No suggestions generated — collect more data with `probe run`, `harvest js`, "
                  "`ports scan`._", ""]
    else:
        lines += ["| Risk | Category | Suggestion |", "| --- | --- | --- |"]
        lines += [
            f"| {s.risk.upper()} | {s.category} | {s.title} |" for s in suggestions
        ]
        lines.append("")

    return "\n".join(lines)


__all__ = ["generate_markdown_report", "render_markdown"]
