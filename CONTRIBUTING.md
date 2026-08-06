# Contributing to AegisRecon

Thank you for helping make AegisRecon a mature open-source security framework.
Please read the [Code of Conduct](CODE_OF_CONDUCT.md) and this guide before
opening issues or pull requests.

## Project principles

The standards we hold ourselves to are those of ProjectDiscovery, Nmap, nuclei,
httpx, and TruffleHog:

- **Simple over clever** — readable, obvious code.
- **Reliable over fast** — retries, transactional writes, no silent failures.
- **Production quality** — no placeholders, no TODOs, no pseudo-code in the tree.
- **Documented** — every module has a README, and new features update docs.
- **Tested** — every module has unit + integration coverage; CI must stay green.

## Code of conduct

Be respectful and constructive. Harassment of any kind is unacceptable.

## Development setup

```bash
git clone <your-fork>
cd AegisRecon
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Recommended tools: `ruff` (lint/format), `mypy` (types), `pytest` (tests),
`pre-commit` (hooks).

## Branching & PR workflow

1. Fork the repo and create a branch: `git checkout -b feature/your-change`.
2. Make your change with tests and docs.
3. Run the full check suite (below).
4. Open a pull request describing the motivation and the change.

Base all work on the latest `main`. Keep PRs focused: one logical change each.

## The check suite

Run everything before pushing:

```bash
ruff check aegisrecon tests      # lint
ruff format --check aegisrecon tests  # formatting
mypy aegisrecon                  # type checking
pytest                           # tests + coverage
pre-commit run --all-files       # hooks (if configured)
```

Or use the Make target: `make check` (lint + test).

## Where things live

| Concern | Location |
| --- | --- |
| Domain models | `aegisrecon/core/models.py` |
| ORM schema | `aegisrecon/core/db_models.py` |
| Repositories | `aegisrecon/core/repositories.py` |
| Scope validation | `aegisrecon/core/scope.py` |
| Engines | `aegisrecon/engines/` |
| Reporting | `aegisrecon/reporting/` |
| Plugins | `aegisrecon/plugins/base.py` |
| CLI | `aegisrecon/cli.py`, `aegisrecon/cli_groups.py` |

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full picture.

## Writing tests

- Put tests in `tests/test_<module>.py`.
- **Never require the network.** Mock `httpx`, DNS, and external binaries.
- Use fixtures from `tests/conftest.py` (in-memory SQLite, sample scope).
- Aim for meaningful assertions, not just coverage numbers.

## Reporting bugs

Open an issue with:

- A minimal, reproducible example.
- Expected vs. actual behavior.
- Environment (OS, Python version, AegisRecon version).

## Security vulnerabilities

Do **not** open a public issue for security problems. Follow the process in
[SECURITY.md](SECURITY.md).

## Licensing

By contributing you agree that your contributions are licensed under the
Apache-2.0 terms (see [LICENSE](LICENSE)).