"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegisrecon.config import AegisSettings
from aegisrecon.core.database import Database
from aegisrecon.core.models import Program, ScopeAction, ScopeEntry, ScopeKind
from aegisrecon.core.repositories import ProgramRepository, ScopeRepository


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    return tmp_path / "state"


@pytest.fixture
def settings(data_dir: Path) -> AegisSettings:
    cfg = AegisSettings(data_dir=data_dir)
    cfg.prepare()
    return cfg


@pytest.fixture
def database(data_dir: Path) -> Database:
    db = Database(data_dir / "test.db")
    db.create_schema()
    yield db
    db.close()


@pytest.fixture
def program(database: Database) -> Program:
    prog = Program(name="Test Program", organization="Test Org", owner="tester")
    with database.session() as session:
        ProgramRepository(session).create(prog)
        session.commit()
        created = ProgramRepository(session).get(prog.id)
        session.close()
    return created


def add_scope(
    database: Database,
    program_id: str,
    value: str,
    *,
    wildcard: bool = False,
    exclude: bool = False,
) -> ScopeEntry:
    """Helper to add a scope rule in a committed transaction."""
    kind = ScopeKind.WILDCARD if wildcard else ScopeKind.EXACT
    value = value if wildcard else value
    entry = ScopeEntry(
        program_id=program_id,
        value=value,
        kind=kind,
        action=ScopeAction.EXCLUDE if exclude else ScopeAction.INCLUDE,
    )
    with database.session() as session:
        ScopeRepository(session).create(entry)
        session.commit()
        created = ScopeRepository(session).get(entry.id)
        session.close()
    return created


@pytest.fixture
def scoped_program(database: Database, program: Program) -> Program:
    """A program with ``*.example.com`` in scope."""
    add_scope(database, program.id, "*.example.com", wildcard=True)
    return program


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: touches the real network (off by default)")
