"""Tests for the subfinder provider wrapper."""

from __future__ import annotations

import subprocess

import pytest

from aegisrecon.engines.subfinder import SubfinderProvider
from aegisrecon.exceptions import ReconError, ToolNotFoundError


class _FakeProc:
    returncode = 0
    stdout = ""
    stderr = ""


@pytest.fixture(autouse=True)
def _fake_subfinder(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/subfinder")


def test_query_returns_normalized_subdomains(monkeypatch) -> None:
    proc = _FakeProc()
    proc.stdout = "www.example.com\nSub.Example.COM.\nnot_a_host\n"

    def fake_run(command, **kwargs):  # noqa: ANN001
        return proc

    monkeypatch.setattr("subprocess.run", fake_run)
    result = SubfinderProvider(binary="subfinder").query("example.com")
    assert result == ["sub.example.com", "www.example.com"]


def test_query_returns_empty_when_no_output(monkeypatch) -> None:
    def fake_run(command, **kwargs):  # noqa: ANN001
        return _FakeProc()

    monkeypatch.setattr("subprocess.run", fake_run)
    assert SubfinderProvider(binary="subfinder").query("example.com") == []


def test_query_raises_on_nonzero_exit(monkeypatch) -> None:
    proc = _FakeProc()
    proc.returncode = 1
    proc.stderr = "no sources configured"

    def fake_run(command, **kwargs):  # noqa: ANN001
        return proc

    monkeypatch.setattr("subprocess.run", fake_run)
    with pytest.raises(ReconError):
        SubfinderProvider(binary="subfinder").query("example.com")


def test_query_raises_on_timeout(monkeypatch) -> None:
    def fake_run(command, **kwargs):  # noqa: ANN001
        raise subprocess.TimeoutExpired(cmd=command, timeout=1)

    monkeypatch.setattr("subprocess.run", fake_run)
    with pytest.raises(ReconError):
        SubfinderProvider(binary="subfinder").query("example.com")


def test_missing_binary_raises(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(ToolNotFoundError):
        SubfinderProvider(binary="does-not-exist")
