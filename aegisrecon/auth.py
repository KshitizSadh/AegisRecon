"""Program-level authorization for AegisRecon.

Roles are a simple hierarchy: viewer < member < admin < owner. Authorization
checks resolve a user's role for a program and compare it against a required
minimum. The program's ``owner`` field is treated as an implicit owner; named
collaborators come from the ``collaborators`` table.
"""

from __future__ import annotations

from typing import Any

from aegisrecon.core.models import ROLE_RANK, Collaborator, CollaboratorRole
from aegisrecon.core.repositories import CollaboratorRepository, ProgramRepository


class AccessDeniedError(Exception):
    """Raised when a user lacks the required role for a program."""


def resolve_role(db: Any, program_id: str, email: str | None) -> CollaboratorRole:
    """Return the effective role of *email* for *program_id*.

    The program's ``owner`` field (if it matches) outranks everything; otherwise
    the stored collaborator role applies, defaulting to ``viewer``.
    """
    email_key = (email or "").strip().lower()
    with db.session() as session:
        program = ProgramRepository(session).get(program_id)
        owner = (program.owner or "").strip().lower()
        collaborator = CollaboratorRepository(session).get_for_program(program_id, email_key)
        session.close()

    if owner and owner == email_key:
        return CollaboratorRole.OWNER
    if collaborator is not None:
        role = collaborator.role
        if isinstance(role, str):
            role = CollaboratorRole(role)
        return role
    return CollaboratorRole.VIEWER


def require_role(
    db: Any, program_id: str, email: str | None, minimum: CollaboratorRole
) -> None:
    """Raise :class:`AccessDeniedError` unless *email* meets *minimum*."""
    role = resolve_role(db, program_id, email)
    if ROLE_RANK[role] < ROLE_RANK[minimum]:
        raise AccessDeniedError(
            f"{email or '<anonymous>'} requires {minimum.value} on {program_id} (has {role.value})"
        )


def can(role: CollaboratorRole | str, minimum: CollaboratorRole) -> bool:
    """Compare a role against a required minimum without a database."""
    if isinstance(role, str):
        role = CollaboratorRole(role)
    return ROLE_RANK[role] >= ROLE_RANK[minimum]


__all__ = ["AccessDeniedError", "resolve_role", "require_role", "can", "Collaborator", "CollaboratorRole"]
