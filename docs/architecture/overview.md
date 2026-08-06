# Architecture Overview

This page summarizes how AegisRecon is organized and how a discovery pass flows
through it. The canonical design document is [ARCHITECTURE.md](../../ARCHITECTURE.md).

## Layers

1. **CLI** (`aegisrecon/cli.py`, `aegisrecon/cli_groups.py`) — command surface,
   context wiring, Rich output.
2. **Config** (`aegisrecon/config.py`) — typed, environment-aware settings.
3. **Core** (`aegisrecon/core/`) — domain models, ORM schema, database,
   repositories, scope validation.
4. **Engines** (`aegisrecon/engines/`) — passive providers, DNS resolution,
   ProjectDiscovery `httpx`, recon orchestrator.
5. **Reporting** (`aegisrecon/reporting/`) — report generators.
6. **Plugins** (`aegisrecon/plugins/`) — extension contracts.
7. **Utils** (`aegisrecon/utils/`) — validation, logging, retry, filesystem,
   console.

## A recon pass, step by step

1. Load the program and its scope entries.
2. Build a `ScopeValidator` from the entries.
3. Derive authorized root domains from include rules.
4. Query passive providers (e.g. crt.sh) for candidate hostnames.
5. Filter candidates through the validator (deny-by-default).
6. Resolve surviving hostnames in parallel.
7. Persist assets, DNS records and IPs transactionally.
8. Optionally hand live assets to `httpx` for HTTP probing.

## Extension model

- **New passive source** → implement `ReconProvider`, register in
  `engines/recon.py:PASSIVE_SOURCES`.
- **New scanner** → implement `Scanner`.
- **New notification channel** → implement `Notifier`.
- **New exporter** → implement `Exporter`.

See [plugins.md](plugins.md).
