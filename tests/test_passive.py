"""Tests for the passive CT-log discovery provider (mocked HTTP)."""

from __future__ import annotations

import httpx
import pytest

from aegisrecon.engines.passive import CertificateTransparencyProvider, _split_names, _under
from aegisrecon.exceptions import ReconError


def _make_response(
    status_code: int = 200, content: object = None, url: str = "https://crt.sh/"
) -> httpx.Response:
    from httpx import Request

    resp = (
        httpx.Response(status_code, json=content)
        if content is not None
        else httpx.Response(status_code)
    )
    resp.request = Request("GET", url)
    return resp


def _crt_response(*name_values: str) -> httpx.Response:
    payload = [{"name_value": v} for v in name_values]
    return _make_response(200, payload)


def test_query_returns_normalized_subdomains(monkeypatch) -> None:
    def fake_get(self, url, **kwargs):
        return _crt_response(
            "www.example.com\nmail.example.com", "ftp.example.com", "www.example.com"
        )

    monkeypatch.setattr(httpx.Client, "get", fake_get)
    provider = CertificateTransparencyProvider()
    try:
        result = provider.query("example.com")
    finally:
        provider.close()
    assert result == ["ftp.example.com", "mail.example.com", "www.example.com"]


def test_query_filters_outside_domain(monkeypatch) -> None:
    def fake_get(self, url, **kwargs):
        return _crt_response("evil.org", "www.example.com", "example.com")

    monkeypatch.setattr(httpx.Client, "get", fake_get)
    provider = CertificateTransparencyProvider()
    try:
        result = provider.query("example.com")
    finally:
        provider.close()
    assert result == ["example.com", "www.example.com"]


def test_query_raises_on_http_error(monkeypatch) -> None:
    def fake_get(self, url, **kwargs):
        return _make_response(500)

    monkeypatch.setattr(httpx.Client, "get", fake_get)
    monkeypatch.setattr("aegisrecon.utils.retry.time.sleep", lambda _s: None)
    provider = CertificateTransparencyProvider()
    try:
        with pytest.raises(ReconError):
            provider.query("example.com")
    finally:
        provider.close()


def test_query_raises_on_invalid_payload(monkeypatch) -> None:
    def fake_get(self, url, **kwargs):
        return _make_response(200, "not json")

    monkeypatch.setattr(httpx.Client, "get", fake_get)
    monkeypatch.setattr("aegisrecon.utils.retry.time.sleep", lambda _s: None)
    provider = CertificateTransparencyProvider()
    try:
        with pytest.raises(ReconError):
            provider.query("example.com")
    finally:
        provider.close()


def test_query_handles_non_list_json(monkeypatch) -> None:
    def fake_get(self, url, **kwargs):
        return _make_response(200, {"error": "nope"})

    monkeypatch.setattr(httpx.Client, "get", fake_get)
    monkeypatch.setattr("aegisrecon.utils.retry.time.sleep", lambda _s: None)
    provider = CertificateTransparencyProvider()
    try:
        with pytest.raises(ReconError):
            provider.query("example.com")
    finally:
        provider.close()


def test_split_names() -> None:
    assert _split_names("a.com\nb.com,c.com") == ["a.com", "b.com", "c.com"]
    assert _split_names("") == []


def test_under() -> None:
    assert _under("www.example.com", "example.com")
    assert _under("example.com", "example.com")
    assert not _under("example.org", "example.com")
    assert not _under("notexample.com", "example.com")
