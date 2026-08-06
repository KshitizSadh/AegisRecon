# Plugin Development

AegisRecon is plugin-driven. Extending it should never require modifying core
code.

## Base classes (`aegisrecon/plugins/base.py`)

| Base class | Contract |
| --- | --- |
| `Plugin` | name, version, author, description, `create(**kwargs)` |
| `ReconProvider` | `query(domain) -> list[str]` (normalized hostnames) |
| `Scanner` | `scan(asset) -> list` (resource records) |
| `Notifier` | `send(payload: dict) -> bool` |
| `Exporter` | `export(records, destination)` |

Every plugin:

- Inherits from the relevant base class.
- Declares `name`, `version`, `author`, `description`.
- Implements the abstract methods.
- Is instantiated via the `create(**kwargs)` classmethod with resolved options.

## Example: a passive source

```python
from aegisrecon.plugins import ReconProvider
from aegisrecon.exceptions import ReconError


class MySource(ReconProvider):
    name = "mysource"
    version = "1.0.0"
    author = "you"
    description = "Queries my passive API"

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    @classmethod
    def create(cls, **kwargs) -> "MySource":
        return cls(api_key=kwargs["api_key"])

    def query(self, domain: str) -> list[str]:
        # ... call the API, return a list of normalized hostnames
        return ["api.example.com", "www.example.com"]
```

## Registering

Register built-in passive sources in `aegisrecon/engines/recon.py`:

```python
PASSIVE_SOURCES = {
    "crtsh": CertificateTransparencyProvider,
    "mysource": MySource,
}
```

The recon engine then discovers them by name:

```bash
aegisrecon recon run Acme --source crtsh,mysource
```

## Guidelines

- Return normalized, de-duplicated data (use `aegisrecon.utils.validators`).
- Raise `ReconError` for transient failures — the engine retries with backoff.
- Never log API keys or tokens. Read secrets from environment variables or the
  settings object; the logger scrubs known patterns as a safety net.
- Keep network access bounded and parallelizable.