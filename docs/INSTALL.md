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

## 4. Install ProjectDiscovery tools (optional, for active HTTP probing)

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/cmd/subfinder@latest

# Add Go's bin directory to PATH
export PATH="$PATH:$HOME/go/bin"
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
```

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
| `command not found: aegisrecon` | Activate the venv: `source .venv/bin/activate`, or run `python -m aegisrecon`. |
| `externally-managed-environment` error | You skipped the venv; use `python3 -m venv .venv`. |
| DNS timeouts in `recon run` | Ensure outbound UDP/53 works; increase concurrency via `--dns-concurrency`. |
| `crt.sh` throttling | Wait and re-run; AegisRecon retries transient failures automatically. |

## Authorized-use reminder

AegisRecon enforces program scope before anything is stored or probed. Only ever add domains to scope that you are explicitly authorized to test.
