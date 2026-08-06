# Changelog

All notable changes to AegisRecon are documented here. This project follows
[Semantic Versioning](https://semver.org/). The format is based on
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Initial project scaffolding: `pyproject.toml`, package layout, `Makefile`,
  `.gitignore`.
- Domain model layer (Pydantic): Program, ScopeEntry, Asset, DnsRecord,
  IpRecord, Endpoint, Technology, Finding, Report.
- Configuration layer (`AegisSettings`) with environment-variable overrides.
- SQLite persistence via SQLAlchemy: full ORM schema, session management,
  repository layer with generic CRUD and domain-specific queries.
- Scope validator with exact / wildcard / regex rules and deny-by-default
  enforcement.
- Recon engine: passive Certificate Transparency discovery (crt.sh) with
  retry/backoff, parallel DNS resolution, scope-filtered persistence.
- ProjectDiscovery `httpx` integration for HTTP probing with JSONL parsing.
- Versioned JSON report generator.
- Rich/Typer CLI: `init`, `program`, `scope`, `recon`, `report`, `config`.
- Plugin base classes: `Plugin`, `ReconProvider`, `Scanner`, `Notifier`, `Exporter`.
- Utility modules: validation helpers, redacting logger, retry decorator,
  safe filesystem helpers.
- Test suite (107 tests) with mocked external dependencies and coverage config.
- Documentation: README, ARCHITECTURE, INSTALL (Kali-focused), CONTRIBUTING,
  SECURITY, CODE_OF_CONDUCT, ROADMAP.

## [0.1.0] - 2026-08-05
- First working end-to-end pipeline: init → program → scope → recon → report.
- License: Apache-2.0.