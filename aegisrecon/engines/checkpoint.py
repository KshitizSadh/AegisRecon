"""Persistent scan checkpoints for resumable reconnaissance.

:class:`CheckpointStore` records, per program, which passive-discovery
``(source, root)`` pairs have already been completed and the set of hostnames
collected so far. When a scan is interrupted (Ctrl+C, network cut, crash), a
subsequent run with ``--resume`` picks up exactly where it left off instead of
re-walking every source from scratch.

Checkpoints are plain JSON snapshots under the data directory and never contain
anything sensitive. A completed run clears its checkpoint.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from aegisrecon.exceptions import StorageError

logger = logging.getLogger("aegisrecon.engines.checkpoint")


def _serializable(data: set[str]) -> list[str]:
    return sorted(data)


class Checkpoint:
    """An in-memory view of a scan's saved progress."""

    version = 1

    def __init__(self) -> None:
        self.program_id: str = ""
        self.sources_done: dict[str, list[str]] = {}  # source -> roots completed
        self.hostnames: set[str] = set()

    def is_done(self, source: str, root: str) -> bool:
        return root in self.sources_done.get(source, [])

    def mark_done(self, source: str, root: str) -> None:
        done = self.sources_done.setdefault(source, [])
        if root not in done:
            done.append(root)

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "program_id": self.program_id,
            "sources_done": self.sources_done,
            "hostnames": _serializable(self.hostnames),
        }

    @classmethod
    def from_dict(cls, data: dict) -> Checkpoint:
        ckpt = cls()
        ckpt.program_id = str(data.get("program_id", ""))
        out: dict[str, list[str]] = {}
        for source, roots in (data.get("sources_done") or {}).items():
            out[str(source)] = [str(r) for r in roots]
        ckpt.sources_done = out
        ckpt.hostnames = {str(h) for h in (data.get("hostnames") or [])}
        return ckpt


class CheckpointStore:
    """Loads and persists :class:`Checkpoint` snapshots to JSON files."""

    def __init__(self, data_dir: Path) -> None:
        self.directory = Path(data_dir) / "checkpoints"
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path(self, program_id: str) -> Path:
        safe = program_id
        for char in "<>:\"/\\|?*":
            safe = safe.replace(char, "_")
        return self.directory / f"{safe}.json"

    def load(self, program_id: str) -> Checkpoint:
        path = self._path(program_id)
        if not path.exists():
            return Checkpoint()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("discarding unreadable checkpoint %s: %s", path, exc)
            return Checkpoint()
        ckpt = Checkpoint.from_dict(data)
        ckpt.program_id = program_id
        return ckpt

    def save(self, ckpt: Checkpoint) -> None:
        path = self._path(ckpt.program_id)
        try:
            path.write_text(
                json.dumps(ckpt.to_dict(), indent=2), encoding="utf-8"
            )
        except OSError as exc:
            raise StorageError(f"cannot write checkpoint {path}: {exc}") from exc

    def clear(self, program_id: str) -> None:
        path = self._path(program_id)
        try:
            if path.exists():
                path.unlink()
        except OSError as exc:
            logger.warning("cannot clear checkpoint %s: %s", path, exc)


__all__ = ["Checkpoint", "CheckpointStore"]
