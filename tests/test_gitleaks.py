"""Tests for the gitleaks-based secret scanner."""

from __future__ import annotations

from aegisrecon.engines.gitleaks import GitleaksScanner


def test_parse_empty_output_returns_empty():
    assert GitleaksScanner._parse("") == []
    assert GitleaksScanner._parse("[]") == []
    assert GitleaksScanner._parse("not-json") == []


def test_parse_valid_json_rows():
    output = (
        '[{"RuleID":"aws-access-token","Description":"AWS","File":"src/app.js",'
        '"Secret":"AKIAEXAMPLE","StartLine":12,"Entropy":3.5},'
        '{"Rule":"github-token","File":"keys.txt","Secret":"ghp_abc"}]'
    )
    findings = GitleaksScanner._parse(output)
    assert len(findings) == 2
    first = findings[0]
    assert first.rule_id == "aws-access-token"
    assert first.file == "src/app.js"
    assert first.secret == "AKIAEXAMPLE"
    assert first.line == 12
    assert first.entropy == 3.5
    assert findings[1].rule_id == "github-token"
    assert findings[1].line == 0
