# Changelog

All notable changes to AegisRecon are documented here. This project follows
[Semantic Versioning](https://semver.org/). The format is based on
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- **New domain entities**: `Port`, `Parameter`, `AssetFile`, `Secret`, `Snapshot`
  (Pydantic models, ORM tables, and repositories with `exists` / `latest` /
  `history`, plus program-scoped joins for endpoints and asset files).
- **Secret detection engine** (`engines/secrets.py`): pure, side-effect-free
  regex + Shannon-entropy detector with a blocklist of known placeholder values.
- **Secret scan engine** (`engines/secretscan.py`): runs the detector over
  harvested files and persists conservative, unverified `Secret` records.
- **HTTP probing engine** (`engines/probe.py`): wraps ProjectDiscovery `httpx`
  and persists endpoints, technologies and query parameters, scope-gated.
- **Port scanner** (`engines/naabu.py`): wraps ProjectDiscovery `naabu`,
  parses JSON output, persists open ports for in-scope assets.
- **JavaScript harvester** (`engines/js.py`): wraps `katana` + follows with
  httpx to download, hash and store JS files for secret scanning.
- **Subfinder provider** (`engines/subfinder.py`): passive subdomain
  enumeration wired into the recon passive-source registry.
- **Monitoring engine** (`engines/monitor.py`): immutable snapshots +
  field-level change detection surfaced as lifecycle findings.
- **Screenshot engine** (`engines/screenshot.py`): captures renders of live
  endpoints via `httpx -screenshot`, stores PNGs on disk, records `AssetFile`
  (kind `screenshot`) entries; `AssetFile` gains an optional on-disk `path`.
- **Scheduler** (`scheduler.py`): persistent `ScheduledJob` definitions
  (workflow + interval) with due-based execution driven by `schedule run`.
- **Markdown executive report** (`reporting/markdown_report.py`): human-readable
  engagement summary with executive snapshot and open-finding backlog.
- **Notification plugins** (`notify.py`): console, Slack and Discord notifiers
  behind a `Notifier`-based dispatcher that isolates per-channel failures.
- **New CLI groups**: `probe run`, `harvest js`, `secrets scan`/`list`,
  `ports scan`, `monitor run`, `screenshot run`, `asset list`,
  `finding list`/`set-status`, `notify list`/`test`, `schedule add`/`list`/`run`,
  `report markdown`. `recon run` now supports `subfinder` as a passive source.
- Config keys `naabu_bin`, `katana_bin` and `screenshot_dir`.
- **Asset deduplication / canonical names** (`engines/dedup.py`): `canonical_key`
  collapses case, trailing-dot and IDN/punycode spellings; a new `AssetAlias`
  entity routes variant hostnames to a canonical asset on ingest. New commands:
  `asset list --show-aliases`, `asset alias add`, `asset dedup [--dry-run]
  [--www-strip]` (evidence-based `www.` folding by default, with orphan
  child-record re-parenting and duplicate collision handling).
- **Resumable scans** (`engines/checkpoint.py`): SQLite-backed-free JSON
  checkpoints persist per-`(source, root)` discovery progress and the hostname
  set; `recon run --resume` continues an interrupted scan and clears the
  checkpoint on completion.
- **Manual-testing suggestions** (`suggestions.py`): non-AI heuristic engine that
  reads the report payload (ports, technologies, findings, endpoints) and emits
  ranked, context-aware testing ideas (Spring Actuator, GraphQL/Swagger exposure,
  DB/SMB/Elasticsearch listeners, leaked credentials). New `suggest run
  [--category]` command; JSON payload now carries per-asset `ports`.
- **Static dashboard** (`reporting/dashboard.py`): `report dashboard` renders a
  self-contained, deterministic dark-mode HTML page (stat cards, severity grid,
  findings, assets + technologies) with no external dependencies or network.
- **REST API** (`api.py`): FastAPI app exposed via `api serve --host --port`.
  Read-first endpoints for programs/scope/assets/findings plus reports,
  dashboards and suggestions; state-changing actions (run recon, triage, manage
  scope) require a program role from the `X-Aegis-Email` header. Ships as the
  optional `[api]` extra (fastapi, uvicorn).
- **Team collaboration**: `Collaborator` entity/repo with a `viewer` < `member`
  < `admin` < `owner` hierarchy (`auth.py`). Program `owner` is implicit owner.
  New `collab add/list/remove` commands and role-guarded API routes.
- **Plugin registry / install** (`plugins/registry.py`, `plugins/scaffold.py`):
  discovers plugins via the `aegisrecon.plugins` entry-point group and the
  `AEGISRECON_PLUGIN_PATH` local directory; `plugin list`, `plugin scaffold`
  (emits importable package + pyproject entry point), and `plugin install`
  (pip-installs and verifies the entry point loads).
- Expanded test suite: +214 tests total, covering suggestions, dashboard, API,
  auth and the plugin registry/scaffold.
- **Global options fix**: `--debug`, `-v/--verbose` and `--data-dir` are now
  accepted anywhere on the command line (`AegisTyperGroup` hoists them before
  subcommand parsing).

## [0.1.0] - 2026-08-05
- First working end-to-end pipeline: init → program → scope → recon → report.
- License: Apache-2.0.