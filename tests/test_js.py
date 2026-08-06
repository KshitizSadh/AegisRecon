"""Tests for the JavaScript harvesting engine (tool mocked)."""

from __future__ import annotations

import pytest

from aegisrecon.core.database import Database
from aegisrecon.core.models import Program
from aegisrecon.core.repositories import AssetFileRepository, AssetRepository
from aegisrecon.engines.js import HarvestedFile, JsHarvestEngine


@pytest.fixture(autouse=True)
def _fake_katana(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/katana")


def _seeds(urls: list[str], text: str, digest: str) -> list[HarvestedFile]:
    return [HarvestedFile(url=u, content=text, hash=digest, size=len(text)) for u in urls]


def _seed_assets(database: Database, program: Program) -> None:
    with database.session() as session:
        AssetRepository(session).get_or_create(program.id, "app.example.com")
        session.commit()


def test_run_persists_new_files(database: Database, program: Program, monkeypatch) -> None:
    _seed_assets(database, program)
    url = "https://app.example.com/app.js"
    engine = JsHarvestEngine(database, binary="katana")
    engine.crawler.crawl_js = lambda targets: [url]  # type: ignore[method-assign]
    monkeypatch.setattr(engine, "_download", lambda urls: _seeds(urls, "var a=1;", "h1"))

    result = engine.run(program.id)

    assert result.candidates == 1
    assert result.fetched == 1
    assert result.new_files == 1
    with database.session() as session:
        files = AssetFileRepository(session).list_for_program(program.id)
        session.close()
    assert len(files) == 1
    assert files[0].url == url


def test_run_unchanged_hash_counts_unchanged(database: Database, program: Program, monkeypatch) -> None:
    _seed_assets(database, program)
    url = "https://app.example.com/app.js"
    engine = JsHarvestEngine(database, binary="katana")
    engine.crawler.crawl_js = lambda targets: [url]  # type: ignore[method-assign]
    monkeypatch.setattr(engine, "_download", lambda urls: _seeds(urls, "var a=1;", "h1"))

    first = engine.run(program.id)
    second = engine.run(program.id)

    assert first.new_files == 1
    assert second.unchanged == 1
    assert second.new_files == 0


def test_run_skips_out_of_scope_host(database: Database, program: Program, monkeypatch) -> None:
    _seed_assets(database, program)
    engine = JsHarvestEngine(database, binary="katana")
    engine.crawler.crawl_js = lambda targets: ["https://evil.example.net/app.js"]  # type: ignore[method-assign]
    monkeypatch.setattr(engine, "_download", lambda urls: _seeds(urls, "x", "h"))

    result = engine.run(program.id)

    assert result.errors == ["https://evil.example.net/app.js"]
    with database.session() as session:
        files = AssetFileRepository(session).list_for_program(program.id)
        session.close()
    assert len(files) == 0


def test_run_no_hosts_is_noop(database: Database, program: Program) -> None:
    engine = JsHarvestEngine(database, binary="katana")
    result = engine.run(program.id, hostnames=[])
    assert result.candidates == 0
    assert result.fetched == 0
