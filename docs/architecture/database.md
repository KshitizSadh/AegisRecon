# Database Schema

AegisRecon stores all state in a single SQLite database (WAL mode). The schema
is defined in `aegisrecon/core/db_models.py` and mirrors the Pydantic domain
models in `aegisrecon/core/models.py`.

## Conventions

- Every table has a string **UUID** primary key.
- Every table has `created_at` and `updated_at` timestamps.
- Foreign keys are **soft references** — we store the parent UUID but do not
  cascade-delete, so historical data survives until an explicit purge.
- Enum-like fields (kind, action, severity, record type) are stored as strings.

## Entities

| Table | Purpose | Key fields |
| --- | --- | --- |
| `programs` | Authorized engagement | name, organization, owner, tags, enabled |
| `scope_entries` | Authorization rules | program_id, value, kind, action, note |
| `assets` | Discovered hosts | program_id, name, kind, source, last_seen_at |
| `dns_records` | Resolved DNS data | asset_id, record_type, value, ttl |
| `ip_records` | Resolved addresses | asset_id, address |
| `endpoints` | Discovered URLs | asset_id, url, status_code, title |
| `technologies` | Fingerprinted products | asset_id, name, version, category |
| `findings` | Potential issues | program_id, asset_id, severity, status |
| `reports` | Generated deliverables | program_id, title, format, path |

## Relationships

```
programs 1──n scope_entries
programs 1──n assets 1──n dns_records / ip_records / endpoints / technologies
programs 1──n findings 1──1 assets (nullable)
programs 1──n reports
```

## Access

All reads/writes go through repositories in `aegisrecon/core/repositories.py`.
Repositories accept and return Pydantic models; SQL is isolated inside them.

## Migrations

For the alpha stage, schema is created idempotently with
`Base.metadata.create_all(engine)`. Before 1.0 we will add an Alembic-based
migration pipeline.