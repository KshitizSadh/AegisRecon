"""Tests for program-level authorization."""

from __future__ import annotations

import pytest

from aegisrecon.auth import AccessDeniedError, can, require_role, resolve_role
from aegisrecon.core.models import Collaborator, CollaboratorRole
from aegisrecon.core.repositories import CollaboratorRepository


def test_can_rank_hierarchy():
    assert can(CollaboratorRole.VIEWER, CollaboratorRole.VIEWER)
    assert can(CollaboratorRole.ADMIN, CollaboratorRole.MEMBER)
    assert can(CollaboratorRole.OWNER, CollaboratorRole.ADMIN)
    assert not can(CollaboratorRole.MEMBER, CollaboratorRole.ADMIN)
    assert not can(CollaboratorRole.VIEWER, CollaboratorRole.MEMBER)
    assert can("admin", CollaboratorRole.MEMBER)


def test_program_owner_is_implicit_owner(database, program):
    with database.session() as session:
        from aegisrecon.core.repositories import ProgramRepository

        ProgramRepository(session).update(program.id, owner="boss@example.com")
        session.commit()
        session.close()
    role = resolve_role(database, program.id, "boss@example.com")
    assert role == CollaboratorRole.OWNER


def test_unknown_user_defaults_to_viewer(database, program):
    assert resolve_role(database, program.id, "nobody@example.com") == CollaboratorRole.VIEWER


def test_stored_collaborator_role_is_used(database, program):
    with database.session() as session:
        repo = CollaboratorRepository(session)
        repo.create(
            Collaborator(
                program_id=program.id,
                email="member@example.com",
                role=CollaboratorRole.MEMBER,
            )
        )
        session.commit()
        session.close()
    assert (
        resolve_role(database, program.id, "member@example.com") == CollaboratorRole.MEMBER
    )


def test_require_role_raises_when_insufficient(database, program):
    with pytest.raises(AccessDeniedError):
        require_role(database, program.id, "nobody@example.com", CollaboratorRole.MEMBER)


def test_require_role_passes_when_sufficient(database, program):
    with database.session() as session:
        from aegisrecon.core.repositories import ProgramRepository

        ProgramRepository(session).update(program.id, owner="admin@example.com")
        session.commit()
        session.close()
    require_role(database, program.id, "admin@example.com", CollaboratorRole.ADMIN)
