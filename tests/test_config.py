"""Tests for filesystem and config helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegisrecon.config import AegisSettings, default_data_dir
from aegisrecon.exceptions import ConfigError
from aegisrecon.utils.fs import ensure_dir, safe_child, unique_output_path


def test_safe_child_allows_within_base(tmp_path: Path) -> None:
    base = tmp_path / "state"
    base.mkdir()
    result = safe_child(base, "sub/child.txt")
    assert result == (base.resolve() / "sub" / "child.txt")


def test_safe_child_rejects_traversal(tmp_path: Path) -> None:
    base = tmp_path / "state"
    base.mkdir()
    with pytest.raises(ValueError):
        safe_child(base, "../escape.txt")


def test_unique_output_path_generates_collision_free(tmp_path: Path) -> None:
    first = unique_output_path(tmp_path, "My Program")
    second = unique_output_path(tmp_path, "My Program")
    assert first != second
    assert first.suffix == ".json"
    assert "My-Program" in first.name
    assert first.exists() is False  # path is reserved but not created


def test_ensure_dir_creates(tmp_path: Path) -> None:
    target = tmp_path / "a" / "b"
    resolved = ensure_dir(target)
    assert resolved.is_dir()


def test_settings_environment_overrides(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AEGISRECON_DATA_DIR", str(tmp_path / "envstate"))
    settings = AegisSettings()
    assert settings.data_dir == tmp_path / "envstate"


def test_settings_database_path_resolution(tmp_path: Path) -> None:
    settings = AegisSettings(data_dir=tmp_path / "x")
    assert settings.database_path == (tmp_path / "x" / "aegisrecon.db").resolve()
    settings.db_path = tmp_path / "other.db"
    assert settings.database_path == (tmp_path / "other.db").resolve()


def test_settings_prepare_creates_dirs(tmp_path: Path) -> None:
    settings = AegisSettings(data_dir=tmp_path / "state")
    settings.prepare()
    assert settings.data_dir.is_dir()
    assert settings.reports_path.is_dir()


def test_settings_rejects_bad_state_file() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        AegisSettings(state_file="notjson.txt")


def test_settings_require_tool_resolution(monkeypatch) -> None:
    settings = AegisSettings()
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/python" if name == "httpx" else None)
    assert settings.require_tool("httpx") == "/usr/bin/python"


def test_settings_require_tool_missing(monkeypatch) -> None:
    settings = AegisSettings()
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(ConfigError):
        settings.require_tool("subfinder")


def test_default_data_dir_respects_env(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AEGISRECON_DATA_DIR", str(tmp_path / "d"))
    assert default_data_dir() == tmp_path / "d"


def test_utcnow_is_timezone_aware() -> None:
    from aegisrecon.core.models import utcnow

    assert utcnow().tzinfo is not None
