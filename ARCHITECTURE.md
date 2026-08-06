# AegisRecon Architecture

This document describes the design of AegisRecon: its principles, module
layout, data flow, and the interfaces that keep it modular and extensible.

## Design principles

1. **Simple over clever.** Readable, obvious code wins.
2. **Small, single-responsibility modules.** No god classes, no circular imports.
3. **Reliability over speed.** Retries, resumability, transactional writes.
4. **Scope enforcement layered everywhere.** Safety is not a single choke point
   but a guarantee.

## High-level data flow

```
                    ┌─────────────────────────────────────────────┐
                    │                    CLI                      │
                    │          (Typer + Rich, cli.py)             │
                    └───────────────────┬─────────────────────────┘
                                        │
                    ┌───────────────────▼─────────────────────────┐
                    │               Config (AegisSettings)        │
                    └───────────────────┬─────────────────────────┘
                                        │
                    ┌───────────────────▼─────────────────────────┐
                    │              ReconEngine                    │
                    └───────────────────┬─────────────────────────┘
                                        │
      ┌───────────────┬─────────────────┼─────────────────┐
      ▼               ▼                 ▼                 ▼
 Passive       DNS Resolver      Scope Validator     http - probe
 providers      (engines/dns)     (core/scope)        (engines/httpx)
 (engines/passive)    │                 │                 │
      │               │                 │                 │
      └───────────────┴───────┬─────────┴─────────────────┘
                              │  (only in-scope assets flow down)
                              ▼
                    ┌─────────────────────────────────────────────┐
                    │         Repository layer (core)             │
                    │         Pydantic ⇄ SQLAlchemy rows           │
                    └───────────────────┬─────────────────────────┘
                                        ▼
                    ┌─────────────────────────────────────────────┐
                    │        SQLite store (Database)              │
                    └───────────────────┬─────────────────────────┘
                                        ▼
                    ┌─────────────────────────────────────────────┐
                    │             Reporting (JSON)                │
                    └─────────────────────────────────────────────┘
```

## Module layout

```
aegisrecon/
├── cli.py                  # Typer app wiring + shared context
├── cli_groups.py           # command groups (program/scope/recon/report/config/…)
├── config.py               # AegisSettings (env-aware, typed)
├── exceptions.py           # explicit exception hierarchy
├── notify.py               # notifier plugins + dispatcher (console/slack/discord)
├── core/
│   ├── models.py           # Pydantic domain models (validate everywhere)
│   ├── db_models.py        # SQLAlchemy ORM schema
│   ├── database.py         # engine/session lifecycle, SQLite pragmas
│   ├── repositories.py     # repository layer (domain ⇄ ORM)
│   ├── scope.py            # ScopeValidator + compiled scope rules
│   └── __init__.py
├── engines/
│   ├── passive.py          # CT-log subdomain discovery (crt.sh)
│   ├── subfinder.py        # ProjectDiscovery subfinder passive enumeration
│   ├── dns.py              # parallel DNS resolution
│   ├── httpx.py            # ProjectDiscovery httpx integration
│   ├── probe.py            # HTTP probing: endpoints, tech, parameters
│   ├── naabu.py            # ProjectDiscovery naabu port scanning
│   ├── js.py               # katana JS harvesting + download/hash/storage
│   ├── secrets.py          # pure regex + entropy secret detector
│   ├── secretscan.py       # secret scan orchestration + persistence
│   ├── screenshot.py       # httpx -screenshot capture + on-disk storage
│   ├── monitor.py          # snapshots + change detection → findings
│   └── recon.py            # recon orchestrator
├── scheduler.py            # recurring workflow runner (due-based)
├── reporting/
│   ├── json_report.py      # versioned JSON report generator
│   └── markdown_report.py  # executive Markdown summary generator
├── plugins/
│   └── base.py             # plugin abstract base classes
└── utils/
    ├── validators.py       # pure validation helpers
    ├── console.py          # Rich console (stderr)
    ├── logging.py          # scrubbed, stderr-bound logging
    ├── retry.py            # retry/backoff/jitter decorator
    └── fs.py               # safe path helpers
```

## Separation of concerns

### Domain models (`core/models.py`)
Pydantic models are the single source of truth for entity shape. They validate
on construction and normalize input (hostnames, tags, IPs). They know nothing
about SQL. Their string-dumped JSON is the wire format for reports.

### ORM schema (`core/db_models.py`)
A thin, 1:1 persistence mirror of the domain models. No business logic lives
here. Each table uses a string-UUID PK plus `created_at`/`updated_at`.

### Repositories (`core/repositories.py`)
The translation boundary. A generic `BaseRepository` provides CRUD over a
session; subclasses add domain queries (e.g. `AssetRepository.get_or_create`,
`DnsRecordRepository.exists`). Callers pass and receive Pydantic models, never
rows.

### Scope (`core/scope.py`)
Compiled rules (exact / wildcard / regex) with deny-by-default semantics:
exclude > include. Used by the recon engine before any persistence or probing.

### Engines (`engines/`)
Stateless-ish workers that produce or transform data:
- `passive.py` / `subfinder.py` — `ReconProvider`s returning hostnames.
- `dns.py` — resolves hostnames into `Resolution` records in parallel.
- `httpx.py` — shells out to ProjectDiscovery `httpx`, parses JSONL.
- `probe.py` — persists endpoints, technologies and parameters for in-scope assets.
- `naabu.py` — parses `naabu` JSON output and persists open ports.
- `js.py` — harvests JS URLs via `katana`, downloads bodies, hashes and stores them.
- `secrets.py` — pure regex + Shannon-entropy detector (side-effect free).
- `secretscan.py` — runs the detector over stored files and persists `Secret` records.
- `screenshot.py` — drives `httpx -screenshot`, moves renders to disk, records them.
- `monitor.py` — immutable snapshots + field-level diffing surfaced as findings.
- `recon.py` — orchestrates discovery → filtering → resolution → persistence.

### Scheduler (`scheduler.py`)
`ScheduledJob` definitions persist in SQLite; `Scheduler.run_due()` executes every
enabled job whose interval has elapsed, delegating to the appropriate engine and
recording `last_run_at` / `last_status` / `run_count` on each job.

### Plugins (`plugins/base.py`)
Abstract base classes (`Plugin`, `ReconProvider`, `Scanner`, `Notifier`,
`Exporter`) define the extension contract. Third parties implement these and
register them; the core never special-cases a plugin.

## Interfaces

Engines and repositories communicate through explicit, typed interfaces:

| Boundary | Input | Output |
| --- | --- | --- |
| `ReconProvider.query(domain)` | root domain `str` | `list[str]` hostnames |
| `DnsResolver.resolve_many(hosts)` | `list[str]` | `dict[str, Resolution]` |
| `ScopeValidator.is_allowed(host)` | hostname `str` | `bool` |
| `BaseRepository.create/get/list/…` | Pydantic model / id | Pydantic model(s) |
| `generate_json_report(db, program_id, dir)` | db + program | `Report` + file |

## Safety & confidentiality

- **Scope deny-by-default.** No include rule ⇒ nothing is stored.
- **Passive-first.** Discovery begins with Certificate Transparency data, which
  never contacts the target.
- **Secrets never logged.** A redacting handler scrubs keys/tokens/passwords
  from every log line before emission.
- **stdout stays clean.** All logs and Rich UI go to stderr so piped output is
  parseable.
- **No exploitability.** The framework has no functionality to execute attacks.

## Testing strategy

| Layer | Coverage |
| --- | --- |
| Validators | table-driven unit tests |
| Models | Pydantic validation tests |
| Scope | matching/priority/case tests |
| Repositories | SQLite round-trip tests |
| Engines | mocked network (httpx/dns/crt.sh) |
| Reporting | shape + persistence assertions |
| CLI | Typer `CliRunner` end-to-end |

External calls are mocked so the suite is deterministic and offline.

## Extensibility notes

To add a passive source, implement `ReconProvider` and register it in
`engines/recon.py:PASSIVE_SOURCES`. To add a scanner or exporter, implement the
corresponding base class. The recon engine, persistence and reporting are
source-agnostic and will consume results through the established interfaces.