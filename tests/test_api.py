"""Tests for the REST API (skipped when FastAPI is unavailable)."""

from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from aegisrecon.api import create_app  # noqa: E402


def _seed(database) -> str:
    from aegisrecon.core.models import (
        Collaborator,
        CollaboratorRole,
        Program,
        ScopeEntry,
        ScopeKind,
    )
    from aegisrecon.core.repositories import (
        CollaboratorRepository,
        ProgramRepository,
        ScopeRepository,
    )

    with database.session() as session:
        program = Program(name="API Lab", owner="owner@example.com")
        ProgramRepository(session).create(program)
        session.commit()
        session.close()

    with database.session() as session:
        ScopeRepository(session).create(
            ScopeEntry(program_id=program.id, value="*.example.com", kind=ScopeKind.WILDCARD)
        )
        CollaboratorRepository(session).create(
            Collaborator(
                program_id=program.id,
                email="admin@example.com",
                role=CollaboratorRole.ADMIN,
            )
        )
        session.commit()
        session.close()
    return program.id


def _client(database):
    return TestClient(create_app(database))


def _admin_headers():
    return {"X-Aegis-Email": "admin@example.com"}


def _owner_headers():
    return {"X-Aegis-Email": "owner@example.com"}


def test_health(database) -> None:
    resp = _client(database).get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_program_lifecycle(database) -> None:
    client = _client(database)
    pid = _seed(database)

    listing = client.get("/programs")
    assert listing.status_code == 200
    assert any(p["id"] == pid for p in listing.json())

    detail = client.get(f"/programs/{pid}")
    assert detail.status_code == 200
    assert detail.json()["summary"]["total_assets"] == 0


def test_scope_read(database) -> None:
    client = _client(database)
    pid = _seed(database)
    resp = client.get(f"/programs/{pid}/scope")
    assert resp.status_code == 200
    assert resp.json()[0]["value"] == "*.example.com"


def test_assets_and_report(database) -> None:
    client = _client(database)
    pid = _seed(database)
    assert client.get(f"/programs/{pid}/assets").json() == []
    report = client.get(f"/programs/{pid}/report")
    assert report.status_code == 200
    assert report.json()["program"]["name"] == "API Lab"


def test_suggestions_endpoint(database) -> None:
    client = _client(database)
    pid = _seed(database)
    resp = client.get(f"/programs/{pid}/suggestions")
    assert resp.status_code == 200
    assert resp.json() == []


def test_dashboard_endpoint(database) -> None:
    client = _client(database)
    pid = _seed(database)
    resp = client.get(f"/programs/{pid}/dashboard")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert "<html" in resp.text


def test_scope_write_requires_admin(database) -> None:
    client = _client(database)
    pid = _seed(database)

    resp = client.post(
        f"/programs/{pid}/scope",
        json={"value": "api.example.com"},
        headers={"X-Aegis-Email": "viewer@example.com"},
    )
    assert resp.status_code == 403

    resp = client.post(
        f"/programs/{pid}/scope",
        json={"value": "api.example.com"},
        headers=_admin_headers(),
    )
    assert resp.status_code == 201


def test_finding_status_update_requires_member(database) -> None:
    from aegisrecon.core.models import Finding
    from aegisrecon.core.repositories import FindingRepository

    pid = _seed(database)
    with database.session() as session:
        finding = Finding(program_id=pid, title="t", severity="info")
        FindingRepository(session).create(finding)
        session.commit()
        fid = finding.id
        session.close()

    client = _client(database)
    assert (
        client.patch(
            f"/findings/{fid}/status",
            json={"status": "accepted"},
            headers={"X-Aegis-Email": "viewer@example.com"},
        ).status_code
        == 403
    )
    ok = client.patch(
        f"/findings/{fid}/status",
        json={"status": "accepted"},
        headers=_admin_headers(),
    )
    assert ok.status_code == 200
    assert ok.json()["status"] == "accepted"


def test_collaborator_crud(database) -> None:
    client = _client(database)
    pid = _seed(database)

    listing = client.get(f"/programs/{pid}/collaborators", headers=_admin_headers())
    assert listing.status_code == 200
    assert len(listing.json()) == 1

    added = client.post(
        f"/programs/{pid}/collaborators",
        json={"email": "new@example.com", "role": "member"},
        headers=_admin_headers(),
    )
    assert added.status_code == 201
    assert added.json()["role"] == "member"

    denied = client.post(
        f"/programs/{pid}/collaborators",
        json={"email": "x@example.com", "role": "member"},
        headers={"X-Aegis-Email": "new@example.com"},
    )
    assert denied.status_code == 403

    removed = client.delete(
        f"/programs/{pid}/collaborators/new@example.com", headers=_admin_headers()
    )
    assert removed.status_code == 200
    assert removed.json()["removed"] == "new@example.com"


def test_create_program_requires_email(database) -> None:
    client = _client(database)
    resp = client.post("/programs", json={"name": "No owner"})
    assert resp.status_code == 403

    resp = client.post(
        "/programs", json={"name": "With owner"}, headers=_owner_headers()
    )
    assert resp.status_code == 201
    assert resp.json()["owner"] == "owner@example.com"


def test_unknown_program_404(database) -> None:
    resp = _client(database).get("/programs/missing")
    assert resp.status_code == 404
