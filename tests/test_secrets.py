"""Tests for the pure secret detector."""

from __future__ import annotations

from aegisrecon.engines.secrets import scan, shannon_entropy


def test_shannon_entropy_basics() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") > 1.5
    assert shannon_entropy("a" * 100) < shannon_entropy("aBcD0_-9" * 10)


def test_detects_aws_key() -> None:
    content = 'const awsKey = "AKIAIOSFODNN7EXAMPLE";'
    candidates = scan(content)
    kinds = {c.kind for c in candidates}
    assert "aws_access_key_id" in kinds
    matched = next(c for c in candidates if c.kind == "aws_access_key_id")
    assert matched.value == "AKIAIOSFODNN7EXAMPLE"


def test_detects_private_key_block() -> None:
    content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAK\n-----END RSA PRIVATE KEY-----"
    candidates = scan(content)
    assert any(c.kind == "private_key_block" for c in candidates)


def test_detects_github_token() -> None:
    content = "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    candidates = scan(content)
    assert any(c.kind == "github_token" for c in candidates)


def test_blocklist_values_are_skipped() -> None:
    content = 'password = "example"'
    assert scan(content) == []


def test_low_entropy_generic_assignment_rejected() -> None:
    content = 'api_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
    assert all(c.kind != "generic_secret_assignment" for c in scan(content))


def test_min_entropy_threshold_filters() -> None:
    content = 'secret = "AKIAIOSFODNN7EXAMPLE"'
    assert scan(content, min_entropy=8.0) == []


def test_empty_content() -> None:
    assert scan("") == []
    assert scan(None) == []  # type: ignore[arg-type]


def test_entropy_is_bounded() -> None:
    for candidate in scan("aws=AKIAIOSFODNN7EXAMPLE slack=xoxb-12345678901234567890"):
        assert 0.0 <= candidate.entropy <= 8.0
