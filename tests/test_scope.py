"""Unit tests for the scope validator."""

from __future__ import annotations

import pytest

from aegisrecon.core.models import ScopeAction, ScopeEntry, ScopeKind
from aegisrecon.core.scope import ScopeValidator


def _entry(value: str, kind: ScopeKind = ScopeKind.EXACT, action: ScopeAction = ScopeAction.INCLUDE) -> ScopeEntry:
    return ScopeEntry(program_id="p1", value=value, kind=kind, action=action)


def test_wildcard_matches_apex_and_subdomains() -> None:
    validator = ScopeValidator([_entry("*.example.com", kind=ScopeKind.WILDCARD)])
    assert validator.is_allowed("example.com")
    assert validator.is_allowed("www.example.com")
    assert validator.is_allowed("a.b.example.com")
    assert not validator.is_allowed("other.com")
    assert not validator.is_allowed("example.org")


def test_exact_match() -> None:
    validator = ScopeValidator([_entry("www.example.com")])
    assert validator.is_allowed("www.example.com")
    assert not validator.is_allowed("example.com")
    assert not validator.is_allowed("mail.example.com")


def test_exclude_overrides_include() -> None:
    validator = ScopeValidator(
        [
            _entry("*.example.com", kind=ScopeKind.WILDCARD),
            _entry("secret.example.com", action=ScopeAction.EXCLUDE),
        ]
    )
    assert validator.is_allowed("www.example.com")
    assert not validator.is_allowed("secret.example.com")


def test_regex_match() -> None:
    validator = ScopeValidator([_entry(r"^(api|admin)\.example\.com$", kind=ScopeKind.REGEX)])
    assert validator.is_allowed("api.example.com")
    assert validator.is_allowed("admin.example.com")
    assert not validator.is_allowed("www.example.com")


def test_deny_by_default_when_no_scope() -> None:
    validator = ScopeValidator([])
    assert not validator.has_scope
    assert not validator.is_allowed("example.com")


def test_reject_reason_is_informative() -> None:
    excluded = ScopeValidator([_entry("*.example.com", kind=ScopeKind.WILDCARD), _entry("x.example.com", action=ScopeAction.EXCLUDE)])
    assert "excluded" in excluded.reject_reason("x.example.com")

    none = ScopeValidator([])
    assert "no in-scope" in none.reject_reason("example.com")

    allowed = ScopeValidator([_entry("*.example.com", kind=ScopeKind.WILDCARD)])
    assert allowed.reject_reason("www.example.com") is None


def test_filter_yields_in_scope_only() -> None:
    validator = ScopeValidator([_entry("*.example.com", kind=ScopeKind.WILDCARD)])
    result = list(validator.filter(iter(["www.example.com", "evil.com", "api.example.com"])))
    assert result == ["www.example.com", "api.example.com"]


def test_assert_names_scope() -> None:
    validator = ScopeValidator([_entry("*.example.com", kind=ScopeKind.WILDCARD)])
    assert len(validator) == 1


def test_invalid_regex_raises() -> None:
    with pytest.raises(ValueError):
        ScopeValidator([_entry("(unclosed", kind=ScopeKind.REGEX)])