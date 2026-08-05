"""Unit tests for validation helpers."""

from __future__ import annotations

import pytest

from aegisrecon.utils.validators import (
    is_valid_domain,
    is_valid_hostname,
    is_valid_ip,
    is_valid_url,
    is_valid_wildcard,
    normalize_hostname,
    normalize_list,
)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("example.com", True),
        ("www.example.com", True),
        ("a-1.b-2.co.uk", True),
        ("localhost", True),
        ("example.com.", False),
        ("-example.com", False),
        ("example-.com", False),
        ("exa mple.com", False),
        ("a" * 254, False),
        ("xn--fiqs8s.example", True),
    ],
)
def test_is_valid_hostname(value: str, expected: bool) -> None:
    assert is_valid_hostname(value) is expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("example.com", True),
        ("sub.example.co.uk", True),
        ("example", False),
        ("example.t", False),
        ("localhost", False),
    ],
)
def test_is_valid_domain(value: str, expected: bool) -> None:
    assert is_valid_domain(value) is expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("*.example.com", True),
        ("example.com", False),
        ("**.example.com", False),
        ("*.*.example.com", False),
        ("*", False),
    ],
)
def test_is_valid_wildcard(value: str, expected: bool) -> None:
    assert is_valid_wildcard(value) is expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("192.168.1.1", True),
        ("::1", True),
        ("2001:db8::ff00:42:8329", True),
        ("999.1.1.1", False),
        ("example.com", False),
    ],
)
def test_is_valid_ip(value: str, expected: bool) -> None:
    assert is_valid_ip(value) is expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("https://example.com/path?q=1", True),
        ("http://example.com", True),
        ("ftp://example.com", False),
        ("example.com", False),
    ],
)
def test_is_valid_url(value: str, expected: bool) -> None:
    assert is_valid_url(value) is expected


def test_normalize_hostname() -> None:
    assert normalize_hostname("  Example.COM.  ") == "example.com"


def test_normalize_list_dedupes_and_filters() -> None:
    result = normalize_list(["b.org", "a.com", "A.com", "  ", None])
    assert result == ["a.com", "b.org"]
    assert normalize_list([]) == []
    assert normalize_list(None) == []