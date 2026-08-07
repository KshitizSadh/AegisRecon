"""Tests for the static HTML dashboard renderer."""

from __future__ import annotations

from aegisrecon.reporting.dashboard import render_dashboard


def _payload(**overrides) -> dict:
    base = {
        "schema_version": "1.0.0",
        "generated_at": "2026-08-07T00:00:00Z",
        "program": {"name": "Acme <&>\""},
        "scope": [],
        "assets": [],
        "findings": [],
        "summary": {
            "total_assets": 0,
            "total_ips": 0,
            "total_endpoints": 0,
            "total_technologies": 0,
            "total_findings": 0,
            "by_kind": {},
            "by_severity": {},
        },
    }
    base.update(overrides)
    return base


def test_empty_payload_renders():
    doc = render_dashboard(_payload())
    assert doc.startswith("<!doctype html>")
    assert "</html>" in doc
    assert "No assets discovered" in doc
    assert "No findings" in doc


def test_lenient_escapes_unsafe_program_name():
    doc = render_dashboard(_payload())
    assert "<  " not in doc and '="' not in doc.split('</h1>')[0]


def test_findings_are_included():
    payload = _payload(
        findings=[
            {
                "title": "SQLi possible",
                "severity": "high",
                "kind": "sqli",
                "status": "open",
                "location": "https://a.test/x",
            }
        ],
        summary={"total_findings": 1, "by_severity": {"high": 1}},
    )
    doc = render_dashboard(payload)
    assert "<span class='tag' style='background:#ff7a45'>high</span>" in doc
    assert "SQLi possible" in doc


def test_assets_table_present_with_technologies():
    payload = _payload(
        assets=[
            {
                "name": "api.test",
                "kind": "domain",
                "ips": [{"address": "1.2.3.4"}],
                "endpoints": [{"url": "https://api.test"}],
                "technologies": [{"name": "nginx"}],
            }
        ],
        summary={"total_assets": 1, "by_severity": {}},
    )
    doc = render_dashboard(payload)
    assert "api.test" in doc
    assert "nginx" in doc
