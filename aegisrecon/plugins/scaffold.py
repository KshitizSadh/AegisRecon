"""Plugin scaffolding.

``aegisrecon plugin scaffold`` emits a minimal, importable plugin package that
exposes the correct entry point. The generated ``pyproject.toml`` registers the
``aegisrecon.plugins`` entry point group so ``aegisrecon plugin list`` picks it
up after ``pip install -e``.
"""

from __future__ import annotations

import re
from pathlib import Path

_VALID_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]*$")

KIND_BASES = {
    "ReconProvider": "from aegisrecon.plugins.base import ReconProvider\n",
    "Scanner": "from aegisrecon.plugins.base import Scanner\n",
    "Notifier": "from aegisrecon.plugins.base import Notifier\n",
    "Exporter": "from aegisrecon.plugins.base import Exporter\n",
}

KIND_METHOD = {
    "ReconProvider": (
        "    def query(self, domain: str) -> list[str]:\n"
        "        \"\"\"Return discovered hostnames for the root domain.\"\"\"\n"
        "        return [domain]\n"
    ),
    "Scanner": (
        "    def scan(self, asset):\n"
        "        \"\"\"Run against one asset and return resource records.\"\"\"\n"
        "        return []\n"
    ),
    "Notifier": (
        "    def send(self, payload: dict) -> bool:\n"
        "        \"\"\"Deliver payload and return True on success.\"\"\"\n"
        "        return True\n"
    ),
    "Exporter": (
        "    def export(self, records: list, destination: str) -> None:\n"
        "        \"\"\"Export records to an external destination.\"\"\"\n"
        "        raise NotImplementedError\n"
    ),
}


def scaffold_plugin(
    target: Path, *, name: str, kind: str = "Notifier", author: str = ""
) -> Path:
    """Write a plugin skeleton into *target* and return the created directory."""
    if not _VALID_NAME.match(name):
        raise ValueError(f"invalid plugin name {name!r}: use lowercase letters, digits, - or _")
    if kind not in KIND_BASES:
        raise ValueError(f"invalid kind {kind!r}: choose {', '.join(sorted(KIND_BASES))}")

    target = Path(target)
    package_dir = target / name.replace("-", "_")
    package_dir.mkdir(parents=True, exist_ok=True)

    base_import = KIND_BASES[kind].strip()
    method = KIND_METHOD[kind]

    (package_dir / "__init__.py").write_text(
        _pyproject_placeholder(package_dir.name), encoding="utf-8"
    )
    (package_dir / "plugin.py").write_text(
        _plugin_source(name, base_import, method, author, kind), encoding="utf-8"
    )
    (target / "pyproject.toml").write_text(
        _pyproject(name, kind, author, package_dir.name), encoding="utf-8"
    )
    (target / "README.md").write_text(
        f"# {name}\n\nAegisRecon {kind.lower()} plugin scaffolded by `aegisrecon plugin scaffold`.\n",
        encoding="utf-8",
    )
    return target


def _plugin_source(name: str, base_import: str, method: str, author: str, kind: str) -> str:
    class_name = "".join(part.capitalize() for part in name.replace("-", "_").split("_"))
    base_class = base_import.split(" import ")[-1]
    return f'''"""{name} AegisRecon plugin."""

from __future__ import annotations

{base_import}


class {class_name}({base_class}):
    name = "{name}"
    version = "0.1.0"
    author = "{author}"
    description = "AegisRecon {kind} plugin"

    @classmethod
    def create(cls, **kwargs):
        return cls(**kwargs)

{method}

plugin = {class_name}()
'''


def _pyproject_placeholder(package: str) -> str:
    return f'"""Plugin package: {package}."""\n'


def _pyproject(name: str, kind: str, author: str, package: str) -> str:
    entry_point_class = (
        f"{name.replace('-', '_')}.plugin:plugin"
    )
    author_line = f'    authors = [{{ name = "{author}" }}]\n' if author else ""
    return (
        "[build-system]\n"
        '    requires = ["setuptools>=68"]\n'
        '    build-backend = "setuptools.build_meta"\n\n'
        "[project]\n"
        f'    name = "{name}"\n'
        '    version = "0.1.0"\n'
        f'    description = "AegisRecon {kind.lower()} plugin"\n'
        f'{author_line}'
        f'    requires-python = ">=3.10"\n\n'
        "[project.entry-points.aegisrecon.plugins]\n"
        f'    {name} = "{entry_point_class}"\n'
    )


__all__ = ["scaffold_plugin"]
