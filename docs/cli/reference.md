# CLI Reference

Global options: `--data-dir PATH`, `--debug`, `-v/--verbose`, `--version`.

## `aegisrecon init`

Create the state directory, database schema and defaults.

```bash
aegisrecon init
aegisrecon init --data-dir /path/to/state
```

## `aegisrecon program`

| Command | Example | Purpose |
| --- | --- | --- |
| `create` | `aegisrecon program create "Acme" --org "Acme Inc" --tag high,scope` | Create a program |
| `list` | `aegisrecon program list` | List all programs |
| `show` | `aegisrecon program show Acme` | Show a program and its scope summary |

Programs can be referenced by name or UUID.

## `aegisrecon scope`

| Command | Example | Purpose |
| --- | --- | --- |
| `add` | `aegisrecon scope add Acme example.com --wildcard` | Add an include rule |
| `add` | `aegisrecon scope add Acme admin.example.com --exclude` | Add an exclude rule |
| `add` | `aegisrecon scope add Acme "^(api\|dev)\.example\.com$" --regex` | Add a regex rule |
| `list` | `aegisrecon scope list Acme` | List rules |
| `remove` | `aegisrecon scope remove Acme *.example.com` | Remove a rule |

## `aegisrecon recon`

| Command | Example | Purpose |
| --- | --- | --- |
| `run` | `aegisrecon recon run Acme` | Passive discovery + DNS resolution |
| `run` | `aegisrecon recon run Acme --source crtsh --dns-concurrency 100` | Tune sources/concurrency |
| `ingest` | `aegisrecon recon ingest Acme hosts.txt` | Import hostnames from a file |

`recon run` never contacts the target — discovery is passive, and results are
filtered through program scope before being stored.

## `aegisrecon report`

| Command | Example | Purpose |
| --- | --- | --- |
| `json` | `aegisrecon report json Acme --title "Weekly"` | Generate a JSON report |
| `markdown` | `aegisrecon report markdown Acme` | Generate an executive summary |
| `dashboard` | `aegisrecon report dashboard Acme` | Generate a self-contained dark-mode HTML dashboard |

Reports are written to `<data-dir>/reports/` and recorded in the database.

## `aegisrecon suggest`

| Command | Example | Purpose |
| --- | --- | --- |
| `run` | `aegisrecon suggest run Acme` | Context-aware manual-testing suggestions |
| `run` | `aegisrecon suggest run Acme --category secrets` | Filter by category |

## `aegisrecon collab`

| Command | Example | Purpose |
| --- | --- | --- |
| `add` | `aegisrecon collab add Acme alice@x.com --role member` | Grant access |
| `list` | `aegisrecon collab list Acme` | List collaborators |
| `remove` | `aegisrecon collab remove Acme alice@x.com` | Revoke access |

Roles ascend `viewer` → `member` → `admin` → `owner`; the program `owner` is the
implicit owner.

## `aegisrecon plugin`

| Command | Example | Purpose |
| --- | --- | --- |
| `list` | `aegisrecon plugin list` | Discover entry-point + local plugins |
| `scaffold` | `aegisrecon plugin scaffold my-notifier --kind Notifier` | Emit a plugin skeleton |
| `install` | `aegisrecon plugin install my-notifier` | pip-install + verify entry point |

## `aegisrecon api`

| Command | Example | Purpose |
| --- | --- | --- |
| `serve` | `aegisrecon api serve --host 0.0.0.0 --port 8000` | Run the REST API + dashboard |

Requires the optional `[api]` extra (`pip install -e ".[api]"`). Interactive
docs at `/docs`; the HTML dashboard is served per program at
`/programs/{id}/dashboard`. State-changing endpoints are role-guarded via the
`X-Aegis-Email` header.

## `aegisrecon vuln`

| Command | Example | Purpose |
| --- | --- | --- |
| `run` | `aegisrecon vuln run Acme` | Scan endpoints with ProjectDiscovery `nuclei` |
| `run` | `aegisrecon vuln run Acme --severity high,critical --tags cve` | Filter templates |

Matches are persisted as findings (same triage/report pipeline).

## `aegisrecon secrets`

| Command | Example | Purpose |
| --- | --- | --- |
| `scan` | `aegisrecon secrets scan Acme` | Scan harvested file bodies with the built-in detector |
| `scan-repo` | `aegisrecon secrets scan-repo Acme ./repo` | Scan a git repo / dir with the Go `gitleaks` binary |
| `list` | `aegisrecon secrets list Acme` | List detected secrets |

## `aegisrecon config`

| Command | Purpose |
| --- | --- |
| `show` | Print effective configuration |

## `aegisrecon tools`

| Command | Example | Purpose |
| --- | --- | --- |
| `list` | `aegisrecon tools list` | Show each external binary and whether it's on PATH |
| `install` | `aegisrecon tools install` | Install all ProjectDiscovery + gitleaks binaries via Go |
| `install` | `aegisrecon tools install httpx katana` | Install specific binaries |

`tools install` requires Go on PATH; binaries land in `~/go/bin` (add it to PATH).

## Piping & scripting

UI, logs and progress bars go to **stderr**; only machine-readable data is
written to **stdout**. Example:

```bash
aegisrecon --data-dir /state program list > programs.txt
```