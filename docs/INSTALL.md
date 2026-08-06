# Installing and testing AegisRecon on Kali Linux

AegisRecon is designed to run on Kali Linux, Ubuntu, Debian, Parrot OS, Windows WSL and macOS. This guide focuses on Kali, the primary development environment.

## Prerequisites

- Python 3.10+
- `git`
- Optional: `go` (only needed to install ProjectDiscovery tools used for active probing)

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git golang
```

## 1. Get the code

```bash
git clone <your-repo-url> ~/AegisRecon
cd ~/AegisRecon
```

Prefer a git clone over a folder copy so you stay in sync with upstream.

## 2. Create an isolated environment

Kali's system Python is externally managed. Always use a virtualenv.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e ".[dev]"
```

The `dev` extra pulls in `pytest`, `pytest-cov`, `ruff`, `mypy`, and `pre-commit`.

## 3. Run the test suite

```bash
pytest                       # full suite with coverage
pytest -q                    # quiet, fast
pytest tests/test_scope.py   # a single module
pytest -k "scope or recon"   # filter by keyword
```

All tests are offline — external calls (crt.sh, DNS, httpx) are mocked — so the suite runs anywhere.

## 4. Install ProjectDiscovery tools (optional, for active probing)

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/cmd/subfinder@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Add Go's bin directory to PATH
export PATH="$PATH:$HOME/go/bin"
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
```

Each tool is optional and maps to one command group:

| Tool | Used by | Missing binary message |
| --- | --- | --- |
| `httpx` | `probe run` | `AEGISRECON_HTTPX_BIN` |
| `subfinder` | `recon run --source subfinder` | `AEGISRECON_SUBFINDER_BIN` |
| `naabu` | `ports scan` | `AEGISRECON_NAABU_BIN` |
| `katana` | `harvest js` | `AEGISRECON_KATANA_BIN` |

AegisRecon discovers these binaries automatically via `PATH`, or you can point at them explicitly:

```bash
export AEGISRECON_HTTPX_BIN=/root/go/bin/httpx
```

## 5. End-to-end smoke test

Run everything against a throwaway data directory using an in-scope domain you control:

```bash
export AEGISRECON_DATA_DIR=~/aegisrecon-lab

aegisrecon init
aegisrecon program create "My Lab" --org "me" --description "authorized testing only"
aegisrecon scope add "My Lab" example.com --wildcard
aegisrecon recon run "My Lab" --debug
aegisrecon probe run "My Lab"
aegisrecon harvest js "My Lab"
aegisrecon secrets scan "My Lab"
aegisrecon ports scan "My Lab"
aegisrecon monitor run "My Lab"
aegisrecon schedule add "My Lab" nightly monitor --every 24
aegisrecon schedule run
aegisrecon finding list "My Lab"
aegisrecon report markdown "My Lab"
aegisrecon report json "My Lab"
aegisrecon config show
```

Expected flow:

1. `init` creates `~/aegisrecon-lab` and the SQLite schema.
2. `recon run` queries Certificate Transparency logs passively, filters results through scope, resolves DNS, and stores assets.
3. `report json` writes a versioned JSON deliverable to `~/aegisrecon-lab/reports/`.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `External tool 'httpx' was not found` | `go install .../httpx@latest` or set `AEGISRECON_HTTPX_BIN`. |
| `naabu` / `katana` not found | Install them (see step 4) or set `AEGISRECON_NAABU_BIN` / `AEGISRECON_KATANA_BIN`. |
| `command not found: aegisrecon` | Activate the venv: `source .venv/bin/activate`, or run `python -m aegisrecon`. |
| `externally-managed-environment` error | You skipped the venv; use `python3 -m venv .venv`. |
| DNS timeouts in `recon run` | Ensure outbound UDP/53 works; increase concurrency via `--dns-concurrency`. |
| `crt.sh` throttling | Wait and re-run; AegisRecon retries transient failures automatically. |

## Authorized-use reminder

AegisRecon enforces program scope before anything is stored or probed. Only ever add domains to scope that you are explicitly authorized to test.
