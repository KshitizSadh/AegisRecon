"""Tests for the scheduler."""

from __future__ import annotations

from datetime import datetime, timezone

from aegisrecon.core.database import Database
from aegisrecon.core.models import Program, ScheduledJob
from aegisrecon.core.repositories import ScheduledJobRepository
from aegisrecon.scheduler import VALID_WORKFLOWS, Scheduler


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _add_job(database: Database, program: Program, *, workflow: str = "monitor", name: str = "nightly") -> ScheduledJob:
    job = ScheduledJob(program_id=program.id, name=name, workflow=workflow, interval_seconds=3600)
    with database.session() as session:
        ScheduledJobRepository(session).create(job)
        session.commit()
        session.close()
    return job


def test_valid_workflows() -> None:
    assert set(VALID_WORKFLOWS) == {"probe", "monitor", "secrets", "ports", "harvest"}


def test_due_job_runs_monitor(database: Database, program: Program, monkeypatch) -> None:
    _add_job(database, program, workflow="monitor")
    calls: list[str] = []

    def fake_run(program_id):  # noqa: ANN001
        calls.append(program_id)

    monkeypatch.setattr("aegisrecon.scheduler.MonitorEngine", _FakeEngine(fake_run))
    report = Scheduler(database).run_due(now=_now())

    assert report.jobs_evaluated == 1
    assert report.jobs_due == 1
    assert report.completed == 1
    assert calls == [program.id]

    with database.session() as session:
        job = ScheduledJobRepository(session).get_by_name(program.id, "nightly")
        session.close()
    assert job is not None
    assert job.run_count == 1
    assert job.last_status == "ok"


def test_not_due_job_skipped(database: Database, program: Program) -> None:
    _add_job(database, program, workflow="monitor")
    with database.session() as session:
        repo = ScheduledJobRepository(session)
        job = repo.get_by_name(program.id, "nightly")
        repo.update(job.id, last_run_at=_now(), run_count=1)
        session.commit()
        session.close()

    report = Scheduler(database).run_due(now=_now())
    assert report.jobs_evaluated == 1
    assert report.jobs_due == 0
    assert report.completed == 0


def test_disabled_job_not_run(database: Database, program: Program) -> None:
    _add_job(database, program, workflow="monitor")
    with database.session() as session:
        repo = ScheduledJobRepository(session)
        job = repo.get_by_name(program.id, "nightly")
        repo.update(job.id, enabled=False)
        session.commit()
        session.close()
    report = Scheduler(database).run_due(now=_now())
    assert report.jobs_due == 0


def test_failed_job_isolated(database: Database, program: Program, monkeypatch) -> None:
    _add_job(database, program, workflow="monitor")

    class _Broken:
        def __init__(self, *a, **k):  # noqa: ANN001
            pass

        def run(self, program_id):  # noqa: ANN001
            raise RuntimeError("boom")

    monkeypatch.setattr("aegisrecon.scheduler.MonitorEngine", _Broken)
    report = Scheduler(database).run_due(now=_now())

    assert report.completed == 0
    assert report.failed == {"nightly": "boom"}

    with database.session() as session:
        job = ScheduledJobRepository(session).get_by_name(program.id, "nightly")
        session.close()
    assert job is not None
    assert job.last_status == "failed"


class _FakeEngine:
    def __init__(self, fn) -> None:  # noqa: ANN001
        self._fn = fn

    def __call__(self, database, binary=None, output_root=None, ports=None):  # noqa: ANN001
        return self

    def run(self, program_id):  # noqa: ANN001
        self._fn(program_id)
        return None
