"""Shared validation and normalization helpers.

Everything here is pure and side-effect free so it can be unit tested in
isolation and reused across every layer of the framework.
"""

from __future__ import annotations

import re

# Roughly RFC 1035 compliant hostname: labels of 1-63 chars, letters/digits/hyphen.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

_TLD_RE = re.compile(r"^[a-zA-Z]{2,63}$")


def is_valid_hostname(value: str) -> bool:
    """Return True when *value* looks like a valid absolute hostname.

    Strict by design: fully-qualified trailing dots are rejected. Callers that
    accept user input should normalize with :func:`normalize_hostname` first.
    """
    candidate = value.strip().lower()
    if not candidate or len(candidate) > 253:
        return False
    if candidate in {"localhost"}:
        return True
    return bool(_HOSTNAME_RE.fullmatch(candidate))


def is_valid_domain(value: str) -> bool:
    """Return True when *value* is a valid registrable-style domain.

    This is intentionally lenient: it requires at least two labels and a
    plausible TLD. Actual registrability is decided elsewhere.
    """
    candidate = value.strip().rstrip(".").lower()
    if not is_valid_hostname(candidate):
        return False
    parts = candidate.split(".")
    if len(parts) < 2:
        return False
    return bool(_TLD_RE.fullmatch(parts[-1]))


def is_valid_wildcard(value: str) -> bool:
    """Return True when *value* is a wildcard pattern such as ``*.example.com``.

    Only a single leading ``*.`` is accepted; ``*`` must not appear anywhere
    else in the pattern.
    """
    candidate = value.strip().rstrip(".").lower()
    if not candidate.startswith("*."):
        return False
    rest = candidate[2:]
    if "*" in rest or not rest:
        return False
    return is_valid_hostname(rest)


def is_valid_ip(value: str) -> bool:
    """Return True when *value* parses as IPv4 or IPv6."""
    from ipaddress import ip_address

    try:
        ip_address(value.strip())
    except ValueError:
        return False
    return True


def is_valid_url(value: str) -> bool:
    """Return True when *value* has an http(s) scheme and a host."""
    from urllib.parse import urlparse

    candidate = value.strip()
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def normalize_hostname(value: str) -> str:
    """Lowercase, strip whitespace and trailing dots from a hostname."""
    return value.strip().rstrip(".").lower()


def normalize_list(values: list[str] | None) -> list[str]:
    """Normalize a list of raw strings, dropping empty entries and duplicates.

    The result is deterministic (sorted) and never contains ``None``.
    """
    if not values:
        return []
    return sorted({v.strip().lower() for v in values if v and v.strip()})


__all__ = [
    "is_valid_hostname",
    "is_valid_domain",
    "is_valid_wildcard",
    "is_valid_ip",
    "is_valid_url",
    "normalize_hostname",
    "normalize_list",
]
