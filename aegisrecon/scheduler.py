"""Scheduler for recurring workflows.

Persists :class:`~aegisrecon.core.models.ScheduledJob` definitions and runs any
job that is due. Each workflow maps to a concrete engine invocation; a single
``run_due()`` call executes every enabled job whose interval has elapsed since
its previous run, so it can be driven from ``cron`` or a long-lived process.

Runs are lightweight: the underlying engines deduplicate against already-stored
records, so re-running a workflow never duplicates data.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from aegisrecon.core.database import Database
from aegisrecon.core.models import ScheduledJob, utcnow
from aegisrecon.core.repositories import ScheduledJobRepository
from aegisrecon.engines.js import JsHarvestEngine
from aegisrecon.engines.monitor import MonitorEngine
from aegisrecon.engines.naabu import PortEngine
from aegisrecon.engines.probe import ProbeEngine
from aegisrecon.engines.secretscan import SecretEngine

logger = logging.getLogger("aegisrecon.scheduler")

VALID_WORKFLOWS = ("probe", "monitor", "secrets", "ports", "harvest")


@dataclass
class ScheduledRunReport:
    """Summary of one scheduler invocation."""

    jobs_evaluated: int = 0
    jobs_due: int = 0
    completed: int = 0
    failed: dict[str, str] = field(default_factory=dict)
    results: dict[str, str] = field(default_factory=dict)


class Scheduler:
    """Executes due scheduled workflows for registered programs."""

    def __init__(self, database: Database, *, binary: dict[str, str] | None = None) -> None:
        self.database = database
        self.binary = binary or {}

    def run_due(self, now=None) -> ScheduledRunReport:
        """Run every enabled job whose interval has elapsed."""
        now = now or utcnow()
        jobs = self._evaluate_jobs(now)
        report = ScheduledRunReport(
            jobs_evaluated=len(self._enabled_jobs()),
            jobs_due=len(jobs),
        )

        for job in jobs:
            try:
                detail = self._run_workflow(job.workflow, job.program_id)
            except Exception as exc:  # noqa: BLE001 - one failed job must not stall the sweep
                report.failed[job.name] = str(exc)
                logger.warning("scheduled job %s failed: %s", job.name, exc)
                self._finish(job.id, "failed")
                continue
            report.completed += 1
            report.results[job.name] = detail
            self._finish(job.id, "ok")

        logger.info("scheduler: %d/%d due jobs completed", report.completed, report.jobs_due)
        return report

    def _enabled_jobs(self) -> list[ScheduledJob]:
        with self.database.session() as session:
            jobs = ScheduledJobRepository(session).list_enabled()
            session.close()
        return jobs

    def _evaluate_jobs(self, now) -> list[ScheduledJob]:
        with self.database.session() as session:
            jobs = ScheduledJobRepository(session).list_enabled_due(now)
            session.close()
        return jobs

    def _run_workflow(self, workflow: str, program_id: str) -> str:
        if workflow == "probe":
            ProbeEngine(self.database, binary=self.binary.get("httpx", "httpx")).run(program_id)
            return "probe"
        if workflow == "monitor":
            MonitorEngine(self.database).run(program_id)
            return "monitor"
        if workflow == "secrets":
            SecretEngine(self.database).run(program_id)
            return "secrets"
        if workflow == "ports":
            PortEngine(self.database, binary=self.binary.get("naabu", "naabu")).run(program_id)
            return "ports"
        if workflow == "harvest":
            JsHarvestEngine(self.database, binary=self.binary.get("katana", "katana")).run(program_id)
            return "harvest"
        raise ValueError(f"unknown workflow {workflow!r}")

    def _finish(self, job_id: str, status: str) -> None:
        with self.database.session() as session:
            repo = ScheduledJobRepository(session)
            job = repo.get(job_id)
            repo.update(
                job_id,
                last_run_at=utcnow(),
                last_status=status,
                run_count=job.run_count + 1,
            )
            session.commit()
            session.close()


__all__ = ["Scheduler", "ScheduledRunReport", "VALID_WORKFLOWS"]
