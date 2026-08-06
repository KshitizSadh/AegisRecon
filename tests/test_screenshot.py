"""Tests for the screenshot capture engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegisrecon.core.database import Database
from aegisrecon.core.models import Endpoint, Program
from aegisrecon.core.repositories import AssetFileRepository, AssetRepository, EndpointRepository
from aegisrecon.engines.screenshot import ScreenshotEngine
from aegisrecon.exceptions import ToolNotFoundError


@pytest.fixture(autouse=True)
def _fake_httpx(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/httpx")


def _seed_endpoint(database: Database, program: Program, url: str) -> None:
    with database.session() as session:
        asset = AssetRepository(session).get_or_create(program.id, "app.example.com")
        EndpointRepository(session).create(
            Endpoint(asset_id=asset.id, url=url, status_code=200, content_type="text/html")
        )
        session.commit()


def test_missing_binary_raises(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(ToolNotFoundError):
        ScreenshotEngine(Database(":memory:"), binary="nope")


def test_find_renders_filters_extensions(tmp_path: Path) -> None:
    (tmp_path / "a.png").write_bytes(b"x")
    (tmp_path / "b.txt").write_bytes(b"x")
    (tmp_path / "c.jpg").write_bytes(b"x")
    renders = ScreenshotEngine._find_renders(tmp_path)
    assert sorted(p.name for p in renders) == ["a.png", "c.jpg"]


def test_run_moves_renders_and_persists(database: Database, program: Program, tmp_path: Path) -> None:
    url = "https://app.example.com/"
    _seed_endpoint(database, program, url)
    engine = ScreenshotEngine(database, binary="httpx", output_root=tmp_path)

    def _fake_invoke(url, store):  # noqa: ANN001
        (store / "render.png").write_bytes(b"\x89PNG-fake")

    engine._invoke_httpx = _fake_invoke  # type: ignore[method-assign]

    result = engine.run(program.id)

    assert result.endpoints_attempted == 1
    assert result.new_files == 1
    with database.session() as session:
        files = AssetFileRepository(session).list_for_program(program.id)
        session.close()
    assert len(files) == 1
    assert files[0].kind == "screenshot"
    assert files[0].path
    assert Path(files[0].path).exists()
    assert not Path(files[0].path).parent.parent.joinpath(".tmp").exists()


def test_run_dedupes_on_second_pass(database: Database, program: Program, tmp_path: Path) -> None:
    url = "https://app.example.com/"
    _seed_endpoint(database, program, url)
    engine = ScreenshotEngine(database, binary="httpx", output_root=tmp_path)

    def _fake_invoke(url, store):  # noqa: ANN001
        (store / "render.png").write_bytes(b"\x89PNG-fake")

    engine._invoke_httpx = _fake_invoke  # type: ignore[method-assign]

    first = engine.run(program.id)
    second = engine.run(program.id)

    assert first.new_files == 1
    assert second.new_files == 0
    assert second.skipped >= 1
