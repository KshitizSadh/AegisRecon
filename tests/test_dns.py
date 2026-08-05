"""Tests for the DNS resolution engine (mocked resolver)."""

from __future__ import annotations

import dns.resolver
import pytest

from aegisrecon.core.models import DnsRecordType
from aegisrecon.engines.dns import DnsResolver, Resolution
from aegisrecon.exceptions import ResolutionError

_HOSTS = {
    "www.example.com": {DnsRecordType.A: ["93.184.216.34"], DnsRecordType.AAAA: [], DnsRecordType.CNAME: []},
    "alias.example.com": {DnsRecordType.A: ["10.0.0.1"], DnsRecordType.AAAA: [], DnsRecordType.CNAME: ["www.example.com"]},
    "missing.example.com": {},
}


class _FakeAnswer:
    def __init__(self, values: list[str], cname: bool = False):
        self._values = values
        self._cname = cname

    def __iter__(self):
        for value in self._values:
            if self._cname:
                yield _FakeName(value)
            else:
                yield _FakeAddr(value)

    def __len__(self) -> int:
        return len(self._values)


class _FakeAddr:
    def __init__(self, value: str) -> None:
        self.address = value


class _FakeName:
    def __init__(self, value: str) -> None:
        self.target = dns.name.from_text(value)


def _fake_resolve(hostname: str, record_type: str, lifetime: float):
    records = _HOSTS.get(hostname, {})
    rtype = DnsRecordType(record_type)
    values = records.get(rtype, [])
    if rtype == DnsRecordType.AAAA and hostname == "missing.example.com":
        raise dns.resolver.NoNameservers()
    if not values:
        raise dns.resolver.NoAnswer()
    return _FakeAnswer(values, cname=(rtype == DnsRecordType.CNAME))


def test_resolve_single_host(monkeypatch) -> None:
    monkeypatch.setattr(dns.resolver, "resolve", _fake_resolve)
    resolver = DnsResolver(concurrency=2)
    resolution = resolver.resolve("www.example.com")
    assert resolution.addresses == ("93.184.216.34",)
    assert resolution.cname is None
    assert resolution.is_resolved


def test_resolve_cname(monkeypatch) -> None:
    monkeypatch.setattr(dns.resolver, "resolve", _fake_resolve)
    resolution = DnsResolver(concurrency=2).resolve("alias.example.com")
    assert resolution.cname == "www.example.com"
    assert "10.0.0.1" in resolution.addresses


def test_resolve_nxdomain_raises(monkeypatch) -> None:
    monkeypatch.setattr(dns.resolver, "resolve", _fake_resolve)
    with pytest.raises(ResolutionError):
        DnsResolver(concurrency=2).resolve("missing.example.com")


def test_resolve_many_collects_failures(monkeypatch) -> None:
    monkeypatch.setattr(dns.resolver, "resolve", _fake_resolve)
    resolver = DnsResolver(concurrency=2)
    results = resolver.resolve_many(["www.example.com", "missing.example.com"])
    assert "www.example.com" in results
    assert results["www.example.com"].is_resolved
    assert "missing.example.com" in resolver.errors


def test_resolution_defaults() -> None:
    r = Resolution(hostname="x.example.com")
    assert r.addresses == ()
    assert r.cname is None
    assert not r.is_resolved