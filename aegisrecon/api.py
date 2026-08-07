"""REST API for AegisRecon.

A thin FastAPI wrapper over the core domain and repositories. It is read-first
by default: listing and reporting are always available, while state-changing
operations (run recon, triage a finding, manage scope) require a program role
that meets the operation's minimum, resolved from the ``X-Aegis-Email`` header
against the program's collaborator registry (see :mod:`aegisrecon.auth`).

The app is built on demand so the extra dependencies (``fastapi``, ``uvicorn``)
are only required when the API is actually used.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from aegisrecon.auth import AccessDeniedError, require_role
from aegisrecon.config import AegisSettings
from aegisrecon.core.database import Database
from aegisrecon.core.models import CollaboratorRole
from aegisrecon.core.repositories import (
    AssetRepository,
    CollaboratorRepository,
    FindingRepository,
    ProgramRepository,
    ScopeRepository,
)
from aegisrecon.engines.recon import ReconEngine
from aegisrecon.exceptions import EntityNotFoundError, ReconError
from aegisrecon.reporting.json_report import build_payload
from aegisrecon.suggestions import generate_suggestions


def _deny(exc: AccessDeniedError) -> HTTPException:
    return HTTPException(status_code=403, detail=str(exc))


class ProgramCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    organization: str = Field(default="")
    owner: str = Field(default="")
    description: str = Field(default="")


class ScopeBody(BaseModel):
    value: str
    wildcard: bool = False


class StatusBody(BaseModel):
    status: str


class ReconBody(BaseModel):
    sources: list[str] = Field(default_factory=list)
    resume: bool = False


class CollaboratorBody(BaseModel):
    email: str
    role: str = "viewer"


def create_app(db: Database, settings: AegisSettings | None = None) -> FastAPI:
    """Build and configure the FastAPI application bound to *db*."""
    app = FastAPI(title="AegisRecon API", version="1.0.0")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "database": str(db.path)}

    # -- programs ----------------------------------------------------------
    @app.get("/programs")
    def list_programs() -> list[dict[str, Any]]:
        with db.session() as session:
            rows = [p.model_dump(mode="json") for p in ProgramRepository(session).list()]
            session.close()
        return rows

    @app.post("/programs", status_code=status.HTTP_201_CREATED)
    def create_program(
        body: ProgramCreate, x_aegis_email: str | None = Header(None)
    ) -> dict[str, Any]:
        from aegisrecon.core.models import Program

        if not x_aegis_email:
            raise HTTPException(status_code=403, detail="X-Aegis-Email header required")
        data = body.model_dump()
        data["owner"] = data["owner"] or x_aegis_email
        program = Program(**data)
        with db.session() as session:
            ProgramRepository(session).create(program)
            session.commit()
            session.close()
        return program.model_dump(mode="json")

    @app.get("/programs/{program_id}")
    def get_program(program_id: str) -> dict[str, Any]:
        try:
            with db.session() as session:
                program = ProgramRepository(session).get(program_id)
                payload = build_payload(db, program_id)
                session.close()
        except EntityNotFoundError:
            raise HTTPException(status_code=404, detail=f"program {program_id} not found") from None
        return {"program": program.model_dump(mode="json"), "summary": payload["summary"]}

    # -- collaborators -------------------------------------------------------
    @app.get("/programs/{program_id}/collaborators")
    def list_collaborators(
        program_id: str, x_aegis_email: str | None = Header(None)
    ) -> list[dict[str, Any]]:
        try:
            require_role(db, program_id, x_aegis_email, CollaboratorRole.VIEWER)
        except AccessDeniedError as exc:
            raise _deny(exc) from None
        with db.session() as session:
            rows = [
                c.model_dump(mode="json")
                for c in CollaboratorRepository(session).list_for_program(program_id)
            ]
            session.close()
        return rows

    @app.post("/programs/{program_id}/collaborators", status_code=status.HTTP_201_CREATED)
    def add_collaborator(
        program_id: str,
        body: CollaboratorBody,
        x_aegis_email: str | None = Header(None),
    ) -> dict[str, Any]:
        from aegisrecon.core.models import Collaborator, CollaboratorRole

        try:
            role = CollaboratorRole(body.role)
            require_role(db, program_id, x_aegis_email or "", CollaboratorRole.ADMIN)
        except ValueError:
            raise HTTPException(status_code=422, detail=f"invalid role: {body.role}") from None
        except AccessDeniedError as exc:
            raise _deny(exc) from None

        with db.session() as session:
            repo = CollaboratorRepository(session)
            existing = repo.get_for_program(program_id, body.email)
            if existing is not None:
                collab = repo.update(existing.id, role=role)
            else:
                collab = Collaborator(
                    program_id=program_id,
                    email=body.email,
                    role=role,
                    invited_by=x_aegis_email or "",
                )
                repo.create(collab)
            session.commit()
            session.close()
        return collab.model_dump(mode="json")

    @app.delete("/programs/{program_id}/collaborators/{email}")
    def remove_collaborator(
        program_id: str, email: str, x_aegis_email: str | None = Header(None)
    ) -> dict[str, Any]:
        try:
            require_role(db, program_id, x_aegis_email, CollaboratorRole.ADMIN)
        except AccessDeniedError as exc:
            raise _deny(exc) from None
        with db.session() as session:
            repo = CollaboratorRepository(session)
            collab = repo.get_for_program(program_id, email)
            if collab is None:
                session.close()
                raise HTTPException(status_code=404, detail=f"collaborator {email} not found")
            repo.delete(collab.id)
            session.commit()
            session.close()
        return {"removed": email}

    # -- scope -------------------------------------------------------------
    @app.get("/programs/{program_id}/scope")
    def list_scope(program_id: str) -> list[dict[str, Any]]:
        with db.session() as session:
            rows = [
                s.model_dump(mode="json")
                for s in ScopeRepository(session).list_for_program(program_id)
            ]
            session.close()
        return rows

    @app.post("/programs/{program_id}/scope", status_code=status.HTTP_201_CREATED)
    def add_scope(
        program_id: str,
        body: ScopeBody,
        x_aegis_email: str | None = Header(None),
    ) -> dict[str, Any]:
        try:
            require_role(db, program_id, x_aegis_email, CollaboratorRole.ADMIN)
        except AccessDeniedError as exc:
            raise _deny(exc) from None
        from aegisrecon.core.models import ScopeAction, ScopeEntry, ScopeKind

        entry = ScopeEntry(
            program_id=program_id,
            value=body.value,
            kind=ScopeKind.WILDCARD if body.wildcard else ScopeKind.EXACT,
            action=ScopeAction.INCLUDE,
        )
        with db.session() as session:
            repo = ScopeRepository(session)
            repo.create(entry)
            session.commit()
            session.close()
        return entry.model_dump(mode="json")

    # -- assets / recon -----------------------------------------------------
    @app.get("/programs/{program_id}/assets")
    def list_assets(
        program_id: str, kind: str | None = Query(None)
    ) -> list[dict[str, Any]]:
        with db.session() as session:
            rows = [
                a.model_dump(mode="json")
                for a in AssetRepository(session).list(program_id=program_id, kind=kind)
            ]
            session.close()
        return rows

    @app.post("/programs/{program_id}/recon/run")
    def run_recon(
        program_id: str,
        body: ReconBody,
        x_aegis_email: str | None = Header(None),
    ) -> dict[str, Any]:
        try:
            require_role(db, program_id, x_aegis_email, CollaboratorRole.MEMBER)
        except AccessDeniedError as exc:
            raise _deny(exc) from None
        effective = settings if settings is not None else AegisSettings()
        engine = ReconEngine(
            db,
            dns_concurrency=effective.dns_concurrency,
            enable_ct_logs=effective.enable_ct_logs,
            ct_timeout=effective.ct_logs_timeout,
        )
        try:
            result = engine.run(program_id, sources=body.sources or None, resume=body.resume)
        except ReconError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
        return _asdict(result)

    # -- findings ------------------------------------------------------------
    @app.get("/programs/{program_id}/findings")
    def list_findings(
        program_id: str, status_: str | None = Query(None, alias="status")
    ) -> list[dict[str, Any]]:
        with db.session() as session:
            rows = [
                f.model_dump(mode="json")
                for f in FindingRepository(session).list(program_id=program_id, status=status_)
            ]
            session.close()
        return rows

    @app.patch("/findings/{finding_id}/status")
    def set_finding_status(
        finding_id: str,
        body: StatusBody,
        x_aegis_email: str | None = Header(None),
    ) -> dict[str, Any]:
        try:
            with db.session() as session:
                finding = FindingRepository(session).get(finding_id)
                require_role(db, finding.program_id, x_aegis_email, CollaboratorRole.MEMBER)
                finding = FindingRepository(session).update(finding_id, status=body.status)
                session.commit()
                session.close()
        except EntityNotFoundError:
            raise HTTPException(status_code=404, detail=f"finding {finding_id} not found") from None
        except AccessDeniedError as exc:
            raise _deny(exc) from None
        return finding.model_dump(mode="json")

    # -- reports / suggestions ----------------------------------------------
    @app.get("/programs/{program_id}/report")
    def program_report(program_id: str) -> dict[str, Any]:
        return build_payload(db, program_id)

    @app.get("/programs/{program_id}/dashboard", response_class=HTMLResponse)
    def program_dashboard(program_id: str) -> HTMLResponse:
        try:
            payload = build_payload(db, program_id)
        except EntityNotFoundError:
            raise HTTPException(status_code=404, detail=f"program {program_id} not found") from None
        from aegisrecon.reporting.dashboard import render_dashboard

        return HTMLResponse(render_dashboard(payload))

    @app.get("/programs/{program_id}/suggestions")
    def program_suggestions(program_id: str) -> list[dict[str, Any]]:
        payload = build_payload(db, program_id)
        suggestions = generate_suggestions(payload)
        return [s.__dict__ for s in suggestions]

    return app


def _asdict(result: Any) -> dict[str, Any]:
    return {
        "program_id": result.program_id,
        "discovered": result.discovered,
        "in_scope": result.in_scope,
        "resolved": result.resolved,
        "new_assets": result.new_assets,
        "updated_assets": result.updated_assets,
        "dns_records": result.dns_records,
        "ip_records": result.ip_records,
        "errors": result.errors,
    }


__all__ = ["create_app"]
