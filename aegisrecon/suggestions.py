"""Context-aware manual-testing suggestions (heuristic, non-AI).

:func:`generate_suggestions` inspects an engagement's technologies, endpoints,
exposed ports and open findings, then emits deterministic, checklist-style hints
a professional tester can follow up on. It is guidance only — never an
automated exploit — and is driven entirely by rules that ship with the
framework.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_RISK_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass
class Suggestion:
    """A single manual-testing hint with supporting evidence."""

    title: str
    risk: str  # high | medium | low | info
    category: str
    detail: str
    evidence: list[str] = field(default_factory=list)


def _tech(assets: list[dict[str, Any]], needles: list[str]) -> list[str]:
    out: list[str] = []
    for asset in assets:
        for t in asset.get("technologies", []):
            name = (t.get("name") or "").lower()
            if any(n in name for n in needles) and name not in out:
                out.append(name)
    return out


def _paths(assets: list[dict[str, Any]], needles: list[str]) -> list[str]:
    out: list[str] = []
    for asset in assets:
        for e in asset.get("endpoints", []):
            url = (e.get("url") or "").lower()
            if any(n in url for n in needles) and url not in out:
                out.append(url)
    return out


def _ports(assets: list[dict[str, Any]], mapping: dict[int, str]) -> list[str]:
    out: list[str] = []
    seen: set[tuple[int, str]] = set()
    for asset in assets:
        for p in asset.get("ports", []):
            port = p.get("port")
            if port in mapping and (port, mapping[port]) not in seen:
                seen.add((port, mapping[port]))
                out.append(f"{port}/{mapping[port]}")
    return out


def _open_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        f
        for f in payload.get("findings", [])
        if f.get("status", "open") not in {"fixed", "false_positive"}
    ]


def generate_suggestions(payload: dict[str, Any]) -> list[Suggestion]:
    """Compute manual-testing suggestions from a report payload."""
    assets = payload.get("assets", [])
    out: list[Suggestion] = []

    # --- Frameworks / platforms ------------------------------------------
    spring = _tech(assets, ["spring"])
    if spring:
        out.append(
            Suggestion(
                title="Spring Boot / Actuator exposure",
                risk="medium",
                category="web",
                detail=(
                    "Spring Actuator endpoints can leak environment, heap dumps and sensitive "
                    "properties. Enumerate /actuator, /actuator/env, /actuator/beans and verify "
                    "whether management endpoints require authentication."
                ),
                evidence=spring,
            )
        )
    wordpress = _tech(assets, ["wordpress"])
    if wordpress:
        out.append(
            Suggestion(
                title="WordPress hardening checklist",
                risk="medium",
                category="cms",
                detail=(
                    "Check /wp-login.php for user enumeration, /wp-json/wp/v2/users for account "
                    "disclosure, outdated plugins/themes, and whether xmlrpc.php is exposed."
                ),
                evidence=wordpress,
            )
        )
    php = _tech(assets, ["php"])
    if php:
        out.append(
            Suggestion(
                title="PHP misconfiguration review",
                risk="medium",
                category="web",
                detail=(
                    "Look for phpinfo() pages, LFI/RFI opportunities in file parameters and "
                    "exposed source files; confirm the scope permits follow-up testing."
                ),
                evidence=php,
            )
        )

    # --- API surface -----------------------------------------------------
    graphql = _tech(assets, ["graphql"]) or _paths(assets, ["/graphql"])
    if graphql:
        out.append(
            Suggestion(
                title="GraphQL API review",
                risk="medium",
                category="api",
                detail=(
                    "Confirm introspection is disabled in production, and check for "
                    "over-permissive queries, batching (DoS) and field-level authorization gaps."
                ),
                evidence=graphql,
            )
        )
    api_docs = _paths(assets, ["/swagger", "/api-docs", "/openapi.json", "/swagger-ui"])
    if api_docs:
        out.append(
            Suggestion(
                title="Exposed API specification",
                risk="low",
                category="api",
                detail=(
                    "A discoverable API specification leaks the endpoint surface. Verify "
                    "whether it changes behavior when accessed unauthenticated."
                ),
                evidence=api_docs,
            )
        )

    # --- Secrets ---------------------------------------------------------
    secret_findings = [
        f for f in _open_findings(payload) if f.get("kind", "").startswith(("aws", "google", "github", "slack"))
    ]
    if secret_findings:
        out.append(
            Suggestion(
                title="Review leaked credentials",
                risk="high",
                category="secrets",
                detail=(
                    "Stored secrets need human review. Confirm whether the value is still live "
                    "in responses, rotate or report it through the program's disclosure path — "
                    "never validate against third-party services."
                ),
                evidence=[f"{f.get('kind', '')}: {f.get('location', '')}" for f in secret_findings],
            )
        )

    # --- Services / network ---------------------------------------------
    smb = _ports(assets, {139: "netbios-ssn", 445: "microsoft-ds"})
    if smb:
        out.append(
            Suggestion(
                title="SMB share enumeration",
                risk="medium",
                category="network",
                detail=(
                    "Exposed SMB may allow null-session or anonymous share access. Enumerate "
                    "named shares only within authorized scope."
                ),
                evidence=smb,
            )
        )
    db = _ports(assets, {3306: "mysql", 5432: "postgresql", 1433: "mssql", 27017: "mongod", 6379: "redis"})
    if db:
        out.append(
            Suggestion(
                title="Database service exposure",
                risk="high",
                category="network",
                detail=(
                    "A database port appears reachable. Verify it is not bound to a public "
                    "interface and whether it requires authentication — never brute-force."
                ),
                evidence=db,
            )
        )
    elastic = _ports(assets, {9200: "elasticsearch"})
    if elastic:
        out.append(
            Suggestion(
                title="Elasticsearch exposure",
                risk="high",
                category="network",
                detail=(
                    "An Elasticsearch port is exposed. Confirm whether the cluster allows "
                    "unauthenticated access and whether indices hold sensitive data."
                ),
                evidence=elastic,
            )
        )

    return sorted(out, key=lambda s: _RISK_ORDER.get(s.risk.lower(), 4))


__all__ = ["Suggestion", "generate_suggestions"]
