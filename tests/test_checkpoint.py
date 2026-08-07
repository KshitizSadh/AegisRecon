"""Tests for resumable, checkpointed reconnaissance scans."""

from __future__ import annotations

import json
from typing import Any

from aegisrecon.engines.checkpoint import Checkpoint, CheckpointStore


class _FakeProvider:
    """Provider that returns a deterministic set per caller-supplied map."""

    name = "fake"

    def __init__(self, results: dict[str, list[str]]) -> None:
        self.results = results
        self.closed = False

    @classmethod
    def create(cls, **kwargs: Any) -> _FakeProvider:
        return cls(kwargs.get("results", {}))

    def query(self, root: str) -> list[str]:
        return self.results.get(root, [])

    def close(self) -> None:
        self.closed = True


def _write_cp(tmp_path, data: dict) -> None:
    p = tmp_path / "checkpoints" / f"{data['program_id']}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data), encoding="utf-8")


def test_checkpoint_roundtrip(tmp_path) -> None:
    store = CheckpointStore(tmp_path)
    ckpt = Checkpoint()
    ckpt.program_id = "p1"
    ckpt.hostnames = {"a.example.com", "b.example.com"}
    ckpt.mark_done("crtsh", "example.com")
    store.save(ckpt)

    loaded = store.load("p1")
    assert loaded.hostnames == {"a.example.com", "b.example.com"}
    assert loaded.is_done("crtsh", "example.com")
    assert not loaded.is_done("crtsh", "other.com")


def test_checkpoint_missing_returns_empty(tmp_path) -> None:
    store = CheckpointStore(tmp_path)
    loaded = store.load("nope")
    assert loaded.hostnames == set()


def test_checkpoint_corrupt_returns_empty(tmp_path) -> None:
    p = tmp_path / "checkpoints"
    p.mkdir(parents=True, exist_ok=True)
    (p / "bad.json").write_text("{not json", encoding="utf-8")
    store = CheckpointStore(tmp_path)
    loaded = store.load("bad")
    assert loaded.hostnames == set()


def test_checkpoint_clear(tmp_path) -> None:
    store = CheckpointStore(tmp_path)
    ckpt = Checkpoint()
    ckpt.program_id = "p1"
    ckpt.mark_done("crtsh", "example.com")
    store.save(ckpt)
    store.clear("p1")
    assert store.load("p1").sources_done == {}
    assert not store.load("p1").hostnames


def test_checkpoint_is_done_tracks_roots(tmp_path) -> None:
    ckpt = Checkpoint()
    ckpt.mark_done("crtsh", "a.com")
    ckpt.mark_done("crtsh", "a.com")
    assert ckpt.sources_done["crtsh"] == ["a.com"]
    assert not ckpt.is_done("subfinder", "a.com")
