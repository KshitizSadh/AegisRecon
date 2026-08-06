"""Monitoring and change-detection engine.

Takes periodic snapshots of a program's assets and endpoints, then diffs them
against the previous snapshot to surface changes (new endpoints, status code
changes, title changes, removed endpoints). Snapshots are immutable historical
records; change reports are stored as findings so they flow into the same
triage pipeline as everything else.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from aegisrecon.core.database import Database
from aegisrecon.core.models import Finding, FindingSeverity, FindingStatus, Snapshot, utcnow
from aegisrecon.core.repositories import (
    EndpointRepository,
    FindingRepository,
    SnapshotRepository,
)

logger = logging.getLogger("aegisrecon.engines.monitor")

SNAPSHOT_ENTITY = "endpoint"


@dataclass(frozen=True)
class Change:
    """A single observed change between two snapshots."""

    endpoint_id: str
    url: str
    field: str
    before: Any
    after: Any

    def describe(self) -> str:
        return f"{self.field}: {self.before!r} -> {self.after!r}"


@dataclass
class MonitorResult:
    """Statistics for a monitor pass."""

    program_id: str
    snapshots_taken: int = 0
    endpoints_seen: int = 0
    changes: int = 0
    findings_created: int = 0
    diffs: list[Change] = field(default_factory=list)


class MonitorEngine:
    """Snapshots endpoint state and detects change across passes."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def run(self, program_id: str) -> MonitorResult:
        """Capture a snapshot and compare it against the previous one."""
        result = MonitorResult(program_id=program_id)

        with self.database.session() as session:
            snapshots = SnapshotRepository(session)
            endpoints = EndpointRepository(session)
            findings = FindingRepository(session)

            previous = snapshots.latest(SNAPSHOT_ENTITY, program_id)
            current = self._capture(endpoints.list_for_program(program_id))
            result.snapshots_taken = len(current)
            result.endpoints_seen = len(current)

            snapshot = self._build_snapshot(program_id, current)
            snapshots.create(snapshot)

            if previous is not None:
                for change in _diff(previous.data, current):
                    result.changes += 1
                    result.diffs.append(change)
                    if self._record_finding(findings, program_id, change):
                        result.findings_created += 1

            session.commit()
            session.flush()

        logger.info("monitor: %d changes observed for %s", result.changes, program_id)
        return result

    @staticmethod
    def _capture(endpoints) -> dict[str, dict[str, Any]]:
        """Build a stable state map keyed by endpoint URL."""
        state: dict[str, dict[str, Any]] = {}
        for endpoint in endpoints:
            state[endpoint.url] = {
                "status_code": endpoint.status_code,
                "title": endpoint.title,
                "content_type": endpoint.content_type,
            }
        return state

    @staticmethod
    def _build_snapshot(program_id: str, state: dict[str, dict[str, Any]]) -> Snapshot:
        data = state
        checksum = hashlib.sha256(
            json.dumps(data, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        return Snapshot(
            program_id=program_id,
            entity_type=SNAPSHOT_ENTITY,
            entity_id=program_id,
            label=f"endpoint state at {utcnow().isoformat()}",
            data=data,
            checksum=checksum,
        )

    @staticmethod
    def _record_finding(findings: FindingRepository, program_id: str, change: Change) -> bool:
        title = f"Change detected: {change.url} — {change.field}"
        existing = [
            f
            for f in findings.list(program_id=program_id)
            if f.title == title and f.status == FindingStatus.OPEN
        ]
        if existing:
            return False
        findings.create(
            Finding(
                program_id=program_id,
                title=title,
                severity=FindingSeverity.INFO,
                status=FindingStatus.OPEN,
                description=f"{change.describe()} observed between monitoring passes.",
                evidence={"endpoint_id": change.endpoint_id, "url": change.url},
            )
        )
        return True


def _diff(previous: dict[str, dict[str, Any]], current: dict[str, dict[str, Any]]) -> list[Change]:
    """Compute field-level changes between two endpoint state maps."""
    changes: list[Change] = []

    for url, state in current.items():
        prev_state = previous.get(url)
        if prev_state is None:
            changes.append(Change(endpoint_id="", url=url, field="added", before=None, after=state))
            continue
        for field_name, after in state.items():
            before = prev_state.get(field_name)
            if before != after:
                changes.append(
                    Change(endpoint_id="", url=url, field=field_name, before=before, after=after)
                )

    for url in previous:
        if url not in current:
            changes.append(Change(endpoint_id="", url=url, field="removed", before=previous[url], after=None))

    return changes


__all__ = ["MonitorEngine", "MonitorResult", "Change"]
