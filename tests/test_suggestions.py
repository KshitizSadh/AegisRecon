"""Tests for the manual-testing suggestions engine."""

from __future__ import annotations

from aegisrecon.suggestions import generate_suggestions


def _payload(**overrides) -> dict:
    base = {
        "schema_version": "1.0.0",
        "generated_at": "2026-08-07T00:00:00Z",
        "program": {"name": "Acme"},
        "scope": [],
        "assets": [],
        "findings": [],
        "summary": {},
    }
    base.update(overrides)
    return base


def test_empty_engagement_yields_no_suggestions():
    assert generate_suggestions(_payload()) == []


def test_spring_actuator_suggestion():
    payload = _payload(
        assets=[
            {
                "name": "api.acme.test",
                "technologies": [{"name": "Spring Boot", "version": "3.2"}],
                "endpoints": [{"url": "https://api.acme.test/actuator/env"}],
                "ports": [],
            }
        ]
    )
    suggestions = generate_suggestions(payload)
    assert any("Spring" in s.title for s in suggestions)


def test_openapi_docs_suggestion():
    payload = _payload(
        assets=[
            {
                "name": "api.acme.test",
                "technologies": [],
                "endpoints": [{"url": "https://api.acme.test/openapi.json"}],
                "ports": [],
            }
        ]
    )
    suggestions = generate_suggestions(payload)
    assert any("API specification" in s.title for s in suggestions)


def test_database_port_suggestion():
    payload = _payload(
        assets=[
            {
                "name": "db.acme.test",
                "technologies": [],
                "endpoints": [],
                "ports": [{"port": 3306, "protocol": "tcp", "service": "mysql"}],
            }
        ]
    )
    suggestions = generate_suggestions(payload)
    assert any("Database" in s.title for s in suggestions)


def test_secret_finding_raises_high_risk():
    payload = _payload(
        assets=[],
        findings=[
            {
                "title": "AWS key",
                "severity": "high",
                "status": "open",
                "kind": "aws_access_key_id",
                "location": "https://cdn.acme.test/app.js",
            }
        ],
    )
    suggestions = generate_suggestions(payload)
    assert suggestions and suggestions[0].risk == "high"
    assert any("Review leaked credentials" in s.title for s in suggestions)


def test_suggestions_are_ranked_high_first():
    payload = _payload(
        assets=[
            {
                "name": "x.acme.test",
                "technologies": [{"name": "Spring Boot"}],
                "endpoints": [{"url": "https://x.acme.test/openapi.json"}],
                "ports": [{"port": 9200, "protocol": "tcp", "service": "elasticsearch"}],
            }
        ],
        findings=[],
    )
    suggestions = generate_suggestions(payload)
    risks = [s.risk for s in suggestions]
    assert risks == sorted(risks, key={"high": 0, "medium": 1, "low": 2}.get)


def test_fixed_findings_are_ignored():
    payload = _payload(
        assets=[],
        findings=[
            {
                "title": "AWS key",
                "severity": "high",
                "status": "fixed",
                "kind": "aws_access_key_id",
                "location": "app.js",
            }
        ],
    )
    assert generate_suggestions(payload) == []
