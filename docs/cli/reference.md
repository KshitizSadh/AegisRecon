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

Reports are written to `<data-dir>/reports/` and recorded in the database.

## `aegisrecon config`

| Command | Purpose |
| --- | --- |
| `show` | Print effective configuration |

## Piping & scripting

UI, logs and progress bars go to **stderr**; only machine-readable data is
written to **stdout**. Example:

```bash
aegisrecon --data-dir /state program list > programs.txt
```