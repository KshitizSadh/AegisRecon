"""Tests for the monitoring / change-detection engine."""

from __future__ import annotations

from aegisrecon.core.database import Database
from aegisrecon.core.models import Endpoint, Program
from aegisrecon.core.repositories import AssetRepository, EndpointRepository, SnapshotRepository
from aegisrecon.engines.monitor import Change, MonitorEngine, _diff


def _seed_asset(database: Database, program: Program) -> str:
    with database.session() as session:
        asset = AssetRepository(session).get_or_create(program.id, "app.example.com")
        session.commit()
        return asset.id


def _seed_endpoint(database: Database, asset_id: str, url: str, status_code: int, title: str = "") -> None:
    with database.session() as session:
        EndpointRepository(session).create(
            Endpoint(
                asset_id=asset_id,
                url=url,
                status_code=status_code,
                title=title,
                content_type="text/html",
                source="httpx",
            )
        )
        session.commit()


def _seed_all(database: Database, program: Program) -> tuple[str, str]:
    asset_id = _seed_asset(database, program)
    url = "https://app.example.com/"
    _seed_endpoint(database, asset_id, url, 200, title="Home")
    return asset_id, url


def test_first_run_captures_snapshot_no_changes(database: Database, program: Program) -> None:
    _seed_all(database, program)
    result = MonitorEngine(database).run(program.id)
    assert result.snapshots_taken == 1
    assert result.changes == 0
    assert result.findings_created == 0

    with database.session() as session:
        count = len(SnapshotRepository(session).list(entity_type="endpoint", entity_id=program.id))
        session.close()
    assert count == 1


def test_second_run_detects_change_and_creates_finding(database: Database, program: Program) -> None:
    asset_id, url = _seed_all(database, program)
    MonitorEngine(database).run(program.id)

    _seed_endpoint(database, asset_id, url, 404, title="Not Found")
    result = MonitorEngine(database).run(program.id)

    assert result.changes >= 1
    assert result.findings_created >= 1
    assert any(c.field in {"status_code", "title"} for c in result.diffs)


def test_same_state_produces_no_findings(database: Database, program: Program) -> None:
    _seed_all(database, program)
    MonitorEngine(database).run(program.id)
    result = MonitorEngine(database).run(program.id)
    assert result.changes == 0
    assert result.findings_created == 0


def test_added_endpoint_detected(database: Database, program: Program) -> None:
    asset_id, _ = _seed_all(database, program)
    MonitorEngine(database).run(program.id)
    _seed_endpoint(database, asset_id, "https://app.example.com/admin", 200)
    result = MonitorEngine(database).run(program.id)
    assert any(c.field == "added" for c in result.diffs)


def test_removed_endpoint_detected(database: Database, program: Program) -> None:
    asset_id, url = _seed_all(database, program)
    MonitorEngine(database).run(program.id)
    with database.session() as session:
        endpoint = EndpointRepository(session).list_for_program(program.id)[0]
        EndpointRepository(session).delete(endpoint.id)
        session.commit()
    result = MonitorEngine(database).run(program.id)
    assert any(c.field == "removed" for c in result.diffs)


def test_diff_is_pure_function() -> None:
    previous = {"https://a.example.com/": {"status_code": 200, "title": "A", "content_type": "text/html"}}
    current = {"https://a.example.com/": {"status_code": 301, "title": "A", "content_type": "text/html"}}
    changes = _diff(previous, current)
    assert len(changes) == 1
    assert isinstance(changes[0], Change)
    assert changes[0].field == "status_code"
    assert changes[0].before == 200
    assert changes[0].after == 301
