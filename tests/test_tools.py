"""Tests for the `tools` group (install/check external binaries)."""

from __future__ import annotations

import os

from typer.testing import CliRunner

from aegisrecon.cli import app
from aegisrecon.cli_groups import TOOL_MODULES, _tool_available

runner = CliRunner()


def test_tool_modules_cover_binaries_used() -> None:
    assert "httpx" in TOOL_MODULES
    assert "katana" in TOOL_MODULES
    assert "nuclei" in TOOL_MODULES
    assert "subfinder" in TOOL_MODULES
    assert "naabu" in TOOL_MODULES
    assert "gitleaks" in TOOL_MODULES


def test_tool_available_resolves_from_path(tmp_path, monkeypatch) -> None:
    ext = ".exe" if os.name == "nt" else ""
    binary = tmp_path / f"katana{ext}"
    binary.write_bytes(b"fake binary\n")
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    assert _tool_available("katana") is not None
    assert _tool_available("katana").lower() == str(binary).lower()


def test_tool_available_missing(monkeypatch) -> None:
    monkeypatch.setenv("PATH", os.path.sep + "nonexistent-dir-xyz")
    assert _tool_available("no-such-tool-abc") is None


def test_tools_list_shows_missing(monkeypatch) -> None:
    monkeypatch.setenv("PATH", os.path.sep + "nonexistent-dir-xyz")
    result = runner.invoke(app, ["tools", "list"])
    assert result.exit_code == 0
    assert "httpx" in result.stderr
    assert "Missing" in result.stderr


def test_tools_install_requires_go(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: None if name == "go" else "/bin/true")
    result = runner.invoke(app, ["tools", "install"])
    assert result.exit_code == 1
    assert "Go not found" in result.stderr


def test_tools_install_unknown_tool() -> None:
    result = runner.invoke(app, ["tools", "install", "not-a-real-tool"])
    assert result.exit_code != 0
    assert "unknown tool" in result.stderr.lower()


def test_tools_install_success_path(monkeypatch) -> None:
    # go exists; subprocess.run is faked to succeed; binaries resolve after.
    fake_paths = {name: f"/usr/bin/{name}" for name in TOOL_MODULES}
    monkeypatch.setattr(
        "shutil.which", lambda name: "/usr/bin/go" if name == "go" else fake_paths.get(name)
    )
    calls: list[list[str]] = []

    class _Ok:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(command, **kwargs):
        calls.append(command)
        return _Ok()

    monkeypatch.setattr("subprocess.run", fake_run)
    result = runner.invoke(app, ["tools", "install"])
    assert result.exit_code == 0
    assert "Installed httpx" in result.stderr
    assert len(calls) == len(TOOL_MODULES)
    assert calls[0][0] == "go"
