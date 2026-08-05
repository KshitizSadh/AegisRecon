"""SQLite-backed persistence layer for AegisRecon.

The :class:`Database` owns the engine, the session factory, and schema
creation. It is deliberately small: business logic lives in repositories and
services on top of it, so the store can be swapped or tested independently.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from aegisrecon.core.db_models import Base
from aegisrecon.exceptions import StorageError

logger = logging.getLogger("aegisrecon.core.database")


def _set_sqlite_pragmas(dbapi_connection, _connection_record) -> None:  # pragma: no cover - trivial
    """Tune SQLite for concurrent, correct, WAL-mode access."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=30000")
    cursor.close()


class Database:
    """Owns the SQLAlchemy engine and session lifecycle for a SQLite store."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.engine: Engine = create_engine(
            f"sqlite:///{self.path}",
            echo=False,
            future=True,
        )
        event.listen(self.engine, "connect", _set_sqlite_pragmas)
        self._session_factory = sessionmaker(bind=self.engine, expire_on_commit=False, class_=Session)

    def create_schema(self) -> None:
        """Create all tables that do not yet exist."""
        try:
            Base.metadata.create_all(self.engine)
        except Exception as exc:  # pragma: no cover - environment dependent
            raise StorageError(f"failed to create schema in {self.path}: {exc}") from exc
        logger.debug("schema ready at %s", self.path)

    def session(self) -> Session:
        """Return a new ORM session bound to this store."""
        return self._session_factory()

    def iter_session(self) -> Iterator[Session]:
        """Context-manager style iterator yielding a session and closing it.

        Usage::

            for session in database.iter_session():
                with session.begin():
                    session.add(row)
        """
        session = self.session()
        try:
            yield session
        finally:
            session.close()

    def close(self) -> None:
        """Dispose of the underlying engine and any pooled connections."""
        self.engine.dispose()

    def __enter__(self) -> "Database":
        self.create_schema()
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


__all__ = ["Database"]
