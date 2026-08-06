# Roadmap

AegisRecon is built incrementally. Every feature must answer one question:
*"Would this actually help a professional bug bounty hunter every single day?"*
If not, we do not build it.

Legend: 🟢 done · 🟡 in progress · ⚪ planned

## Phase 1 — Foundation (current)

- 🟢 Modular package + plugin base classes
- 🟢 Program & scope management
- 🟢 Scope validation with deny-by-default enforcement
- 🟢 SQLite asset database (assets, DNS, IPs, endpoints, findings)
- 🟢 Passive subdomain discovery (Certificate Transparency)
- 🟢 Parallel DNS resolution
- 🟢 JSON reporting
- 🟢 Rich/Typer CLI
- 🟢 ProjectDiscovery `httpx` probing → endpoint + tech + parameter ingestion
- 🟢 `subfinder` passive enumeration integration
- 🟢 Asset `list` CLI command

## Phase 2 — Attack-surface intelligence

- 🟢 Endpoint discovery + parameter extraction
- 🟢 JavaScript file harvesting and secret detection (entropy-based + regex)
- 🟢 Technology fingerprinting ingestion (from `httpx -tech-detect`)
- 🟢 Screenshot pipeline (`httpx -screenshot` capture)
- 🟢 Port discovery integration (projectdiscovery `naabu`)
- 🟡 Asset deduplication, aliasing and canonical-name resolution

## Phase 3 — Monitoring & automation

- 🟢 Change detection / diff scanning across assets and endpoints
- 🟢 Historical tracking (snapshots + `snapshot`/`history` queries)
- 🟢 Scheduled runs (`schedule add` / `schedule run`, cron-friendly)
- 🟢 Notifications (Slack, Discord, console) via `Notifier` plugins
- 🟡 Resumable, checkpointed scans

## Phase 4 — Analysis & AI assistance

- 🟢 Finding triage queue (`finding list` / `finding set-status`)
- 🟢 Executive summaries and report templating (`report markdown`)
- ⚪ AI-assisted triage (severity estimation, dedup, grouping) — never verdicts
- ⚪ Context-aware suggestions for manual testing

## Phase 5 — Platform

- ⚪ REST API
- ⚪ Dashboard (attack-surface graph, tech breakdown, timelines, dark mode)
- ⚪ Team collaboration (shared programs, roles)
- ⚪ Plugin registry / install flow
- 🟢 Packaging: Docker, docker-compose, DevContainer

## Always

- 🟢 Documentation kept excellent and current
- 🟢 Tests maintained for every module
- 🟢 Ethical-use guardrails: authorized scope only

*See [CHANGELOG.md](CHANGELOG.md) for what shipped, and open an issue to propose
a roadmap item.*