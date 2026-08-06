"""CLI end-to-end tests using the Typer CliRunner."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from aegisrecon.cli import app

runner = CliRunner()


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "aegisrecon" in result.output


def test_init_creates_state(data_dir: Path) -> None:
    result = runner.invoke(app, ["--data-dir", str(data_dir), "init"])
    assert result.exit_code == 0, result.output
    assert data_dir.is_dir()
    assert (data_dir / "aegisrecon.db").exists()


def test_program_create_and_list(data_dir: Path) -> None:
    runner.invoke(app, ["--data-dir", str(data_dir), "init"])
    created = runner.invoke(
        app,
        [
            "--data-dir",
            str(data_dir),
            "program",
            "create",
            "Acme",
            "--org",
            "Acme Inc",
            "--tag",
            "a,b",
        ],
    )
    assert created.exit_code == 0, created.output
    assert "Created program" in created.output

    listed = runner.invoke(app, ["--data-dir", str(data_dir), "program", "list"])
    assert listed.exit_code == 0
    assert "Acme" in listed.output


def test_program_show_unknown(data_dir: Path) -> None:
    runner.invoke(app, ["--data-dir", str(data_dir), "init"])
    result = runner.invoke(app, ["--data-dir", str(data_dir), "program", "show", "missing"])
    assert result.exit_code != 0


def test_scope_add_and_list(data_dir: Path) -> None:
    runner.invoke(app, ["--data-dir", str(data_dir), "init"])
    runner.invoke(app, ["--data-dir", str(data_dir), "program", "create", "Acme"])
    added = runner.invoke(
        app, ["--data-dir", str(data_dir), "scope", "add", "Acme", "example.com", "--wildcard"]
    )
    assert added.exit_code == 0, added.output
    assert "*.example.com" in added.output


def test_config_show(data_dir: Path) -> None:
    result = runner.invoke(app, ["--data-dir", str(data_dir), "config", "show"])
    assert result.exit_code == 0
    assert "Scope enforcement" in result.output


def test_report_json_no_program(data_dir: Path) -> None:
    result = runner.invoke(app, ["--data-dir", str(data_dir), "report", "json", "ghost"])
    assert result.exit_code != 0
