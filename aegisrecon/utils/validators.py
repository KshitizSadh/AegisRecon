"""Shared validation and normalization helpers.

Everything here is pure and side-effect free so it can be unit tested in
isolation and reused across every layer of the framework.
"""

from __future__ import annotations

import re

# Roughly RFC 1035 compliant hostname: labels of 1-63 chars, letters/digits/hyphen.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

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


def strip_www_prefix(value: str) -> str:
    """Return *value* without a leading ``www.`` label, if present."""
    candidate = normalize_hostname(value)
    if candidate.startswith("www."):
        return candidate[4:]
    return candidate


def _idna_alabel(value: str) -> str:
    """Encode a hostname to its ASCII A-label (punycode) form.

    Prefers the ``idna`` package (IDNA 2008 / UTS-46, which correctly folds
    characters such as ``ß``). Falls back to :mod:`encodings` IDNA 2003 when the
    package is unavailable and passes ASCII/plain text through untouched.
    """
    try:
        import idna  # type: ignore[import-not-found]

        return idna.encode(value, uts46=True).decode("ascii")
    except Exception:  # noqa: BLE001 - fall back for unusual input/installations
        value = value.encode("idna").decode("ascii")
        return value


def canonical_key(value: str) -> str:
    """Map a hostname to a canonical key that collapses cosmetic variants.

    Rules applied (idempotent, pure):
        * strip surrounding whitespace and trailing dots
        * lowercase
        * encode IDN spellings to their ASCII *punycode* form, so ``fußball.de``
          and ``xn--fuball-cta.de`` collide into a single key

    ``www.`` is intentionally **not** stripped here: the apex and ``www`` host
    are frequently distinct systems. Use :func:`strip_www_prefix` explicitly
    when a www-merge is desired, and only when backed by evidence.
    """
    candidate = normalize_hostname(value)
    try:
        return _idna_alabel(candidate)
    except UnicodeError:
        return candidate


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
    "strip_www_prefix",
    "canonical_key",
    "normalize_list",
]
