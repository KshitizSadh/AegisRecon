"""Filesystem helpers with a security focus.

Path handling in AegisRecon must never allow traversal or writes outside
intended directories. These helpers centralize safe path resolution.
"""

from __future__ import annotations

import re
from pathlib import Path

from aegisrecon.core.models import new_uuid


def safe_child(base: Path, name: str) -> Path:
    """Join ``base`` and ``name`` and guarantee the result stays under base.

    Raises :class:`ValueError` on directory traversal attempts.
    """
    base_resolved = base.resolve()
    candidate = (base_resolved / name).resolve()
    if not candidate.is_relative_to(base_resolved):
        raise ValueError(f"path escape attempted: {name!r}")
    return candidate


def unique_output_path(directory: Path, stem: str, suffix: str = ".json") -> Path:
    """Return a collision-free output path ``stem-uuid.suffix`` under directory."""
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    filename = f"{_slug(stem)}-{new_uuid()[:8]}{suffix}"
    return directory / filename


def _slug(value: str) -> str:
    """Coerce a string into a safe file stem."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-")
    return cleaned or "output"


def ensure_dir(path: Path) -> Path:
    """Create a directory tree and return the resolved path."""
    resolved = path.expanduser().resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def mtime(path: Path) -> str:
    """Return the ISO-8601 modification time of a path, or empty string."""
    from datetime import datetime, timezone

    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
    except OSError:
        return ""


__all__ = ["safe_child", "unique_output_path", "ensure_dir", "mtime"]
