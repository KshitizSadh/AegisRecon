# Scope & Safety Model

AegisRecon is an *authorized-only* framework. Scope validation is the safety
gate that ensures nothing outside your authorized program is ever stored or
probed.

## Rule kinds

| Kind | Example | Matches |
| --- | --- | --- |
| `exact` | `www.example.com` | that exact hostname |
| `wildcard` | `*.example.com` | `example.com` and any subdomain depth |
| `regex` | `^(api\|admin)\.example\.com$` | full-hostname regex match |

## Actions

- **include** — authorizes a target.
- **exclude** — explicitly blocks a target (e.g. an out-of-scope subdomain).

## Resolution order (deny-first)

1. If an **exclude** rule matches → **out of scope**.
2. If an **include** rule matches → **in scope**.
3. Otherwise → **out of scope** (deny by default).

This ordering means an explicit exclusion always wins, and a program with no
include rules allows nothing at all.

## Enforcement points

- The recon engine filters discovered hostnames through a `ScopeValidator`
  before persistence.
- `recon ingest` validates externally-supplied hostnames before storing them.

## CLI

```bash
aegisrecon scope add Acme example.com --wildcard          # include *.example.com
aegisrecon scope add Acme admin.example.com --exclude     # exclude this host
aegisrecon scope list Acme
aegisrecon scope remove Acme *.example.com
```

## Configuration

- `AEGISRECON_REQUIRE_SCOPE` controls whether scope enforcement is on
  (default `true`). It is recommended to keep it enabled.