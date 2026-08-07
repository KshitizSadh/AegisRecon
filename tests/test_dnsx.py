"""Tests for the dnsx-based bulk DNS resolver."""

from __future__ import annotations

import pytest

from aegisrecon.engines.dnsx import DnsxResolver
from aegisrecon.exceptions import ResolutionError


def test_unavailable_binary_raises(monkeypatch) -> None:
    resolver = DnsxResolver(binary="definitely-not-a-real-binary")
    monkeypatch.setattr(resolver, "_path", None)
    assert not resolver.available
    with pytest.raises(ResolutionError):
        resolver.resolve_many(["example.com"])


def test_empty_input_returns_empty(monkeypatch) -> None:
    resolver = DnsxResolver(binary="fakednsx")
    monkeypatch.setattr(resolver, "_path", "/fake/dnsx")
    assert resolver.resolve_many([]) == {}


def test_parses_dnsx_json_lines(monkeypatch) -> None:
    fake_run = _StubRunner(
        stdout=(
            '{"host":"www.example.com","a":["1.2.3.4"],"aaaa":["::1"],"cname":["cdn.example.com"]}\n'
            '{"host":"plain.example.com","a":["5.6.7.8"]}\n'
            '{"host":"nx.example.com","a":[]}\n'
        )
    )
    resolver = DnsxResolver(binary="fakednsx")
    monkeypatch.setattr(resolver, "_path", "/fake/dnsx")
    monkeypatch.setattr("aegisrecon.engines.dnsx.subprocess.run", fake_run)

    results = resolver.resolve_many(
        ["www.example.com", "plain.example.com", "nx.example.com"]
    )

    www = results["www.example.com"]
    assert www.addresses == ("1.2.3.4", "::1")
    assert www.cname == "cdn.example.com"
    assert www.is_resolved

    plain = results["plain.example.com"]
    assert plain.addresses == ("5.6.7.8",)
    assert plain.is_resolved

    assert not results["nx.example.com"].is_resolved


def test_missing_hosts_default_to_unresolved(monkeypatch) -> None:
    fake_run = _StubRunner(stdout='{"host":"www.example.com","a":["1.2.3.4"]}\n')
    resolver = DnsxResolver(binary="fakednsx")
    monkeypatch.setattr(resolver, "_path", "/fake/dnsx")
    monkeypatch.setattr("aegisrecon.engines.dnsx.subprocess.run", fake_run)

    results = resolver.resolve_many(["www.example.com", "missing.example.com"])
    assert results["www.example.com"].is_resolved
    assert not results["missing.example.com"].is_resolved


class _StubProc:
    stdout: str
    stderr: str
    returncode: int = 0

    def __init__(self, stdout: str, stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class _StubRunner:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self._proc = _StubProc(stdout, stderr, returncode)

    def __call__(self, *args, **kwargs) -> _StubProc:
        return self._proc
