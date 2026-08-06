"""Tests for the ProjectDiscovery httpx wrapper."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from aegisrecon.engines.httpx import HttpxProber
from aegisrecon.exceptions import ToolNotFoundError


def _fake_line() -> str:
    return json.dumps(
        {
            "url": "https://www.example.com/",
            "status_code": 200,
            "title": "Example Domain",
            "content_type": "text/html",
            "webserver": "ECS",
            "tech": ["Amazon Web Services", "HTTP/3"],
            "ip": "93.184.216.34",
        }
    )


def test_parse_full_record() -> None:
    result = HttpxProber._parse(_fake_line())
    assert result.url == "https://www.example.com/"
    assert result.status_code == 200
    assert result.title == "Example Domain"
    assert result.content_type == "text/html"
    assert result.web_server == "ECS"
    assert result.technologies == ("Amazon Web Services", "HTTP/3")
    assert result.raw["ip"] == "93.184.216.34"


def test_parse_unparseable_line() -> None:
    result = HttpxProber._parse("not json at all")
    assert result.url == "not json at all"
    assert result.status_code is None
    assert result.technologies == ()


def test_parse_handles_missing_fields() -> None:
    result = HttpxProber._parse(json.dumps({"url": "http://x.example.com/"}))
    assert result.title == ""
    assert result.status_code is None


def test_probe_uses_binary_and_target_file(tmp_path: Path, monkeypatch) -> None:
    calls: dict = {}

    class _FakeProc:
        returncode = 0
        stdout = _fake_line() + "\n"
        stderr = ""

    def fake_run(command, **kwargs):
        calls["command"] = command
        calls["target_file"] = Path(command[command.index("-l") + 1])
        return _FakeProc()

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/httpx")

    prober = HttpxProber(binary="httpx")
    results = prober.probe(["www.example.com"])

    assert len(results) == 1
    assert results[0].status_code == 200
    assert "-json" in calls["command"]
    # the temp target file is cleaned up
    assert not calls["target_file"].exists()


def test_probe_returns_empty_for_no_targets(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/httpx")
    prober = HttpxProber(binary="httpx")
    assert prober.probe([]) == []


def test_missing_binary_raises(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(ToolNotFoundError):
        HttpxProber(binary="does-not-exist-binary")


def test_probe_retries_then_raises(tmp_path: Path, monkeypatch) -> None:
    class _FailingProc:
        returncode = 1
        stdout = ""
        stderr = "boom"

    def fake_run(command, **kwargs):
        return _FailingProc()

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/httpx")

    prober = HttpxProber(binary="httpx")
    with pytest.raises(subprocess.CalledProcessError):
        prober.probe(["www.example.com"])
