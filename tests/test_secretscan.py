"""Tests for the secret scan engine persistence."""

from __future__ import annotations

from aegisrecon.core.database import Database
from aegisrecon.core.models import AssetFile, Program
from aegisrecon.core.repositories import AssetFileRepository, AssetRepository, SecretRepository
from aegisrecon.engines.secretscan import SecretEngine


def _seed_program_with_asset(database: Database, program: Program) -> str:
    with database.session() as session:
        asset = AssetRepository(session).get_or_create(program.id, "app.example.com")
        session.commit()
        return asset.id


def test_engine_persists_detected_secrets(database: Database, program: Program) -> None:
    asset_id = _seed_program_with_asset(database, program)

    with database.session() as session:
        AssetFileRepository(session).create(
            AssetFile(
                asset_id=asset_id,
                url="https://app.example.com/app.js",
                kind="javascript",
                hash="h1",
                size=1,
                content='var key = "AKIAIOSFODNN7EXAMPLE";',
            )
        )
        session.commit()

    result = SecretEngine(database).run(program.id)

    assert result.files_checked == 1
    assert result.new_secrets >= 1
    assert any(kind == "aws_access_key_id" for kind in result.by_kind)

    with database.session() as session:
        secrets = SecretRepository(session).list(program_id=program.id)
        session.close()
    assert any(s.kind == "aws_access_key_id" for s in secrets)


def test_engine_does_not_duplicate_secrets(database: Database, program: Program) -> None:
    asset_id = _seed_program_with_asset(database, program)
    with database.session() as session:
        AssetFileRepository(session).create(
            AssetFile(
                asset_id=asset_id,
                url="https://app.example.com/app.js",
                kind="javascript",
                hash="h1",
                size=1,
                content='key = "AKIAIOSFODNN7EXAMPLE"',
            )
        )
        session.commit()

    first = SecretEngine(database).run(program.id)
    second = SecretEngine(database).run(program.id)

    assert first.new_secrets >= 1
    assert second.new_secrets == 0


def test_engine_ignores_empty_files(database: Database, program: Program) -> None:
    asset_id = _seed_program_with_asset(database, program)
    with database.session() as session:
        AssetFileRepository(session).create(
            AssetFile(
                asset_id=asset_id,
                url="https://app.example.com/empty.js",
                kind="javascript",
                hash="h2",
                size=0,
                content="",
            )
        )
        session.commit()

    result = SecretEngine(database).run(program.id)
    assert result.files_checked == 0
    assert result.new_secrets == 0
