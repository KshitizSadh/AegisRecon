"""Plugin registry and installation flow.

AegisRecon discovers third-party plugins through two mechanisms:

1. **Entry points** -- packages declaring the ``aegisrecon.plugins`` entry
   point group are auto-discovered on import (via :mod:`importlib.metadata`).
2. **Local plugins** -- directories registered with ``aegisrecon plugin add``
   are scanned for ``plugin.py`` files exporting a ``plugin`` attribute.

``plugin install`` pip-installs a distribution and then verifies that its entry
point resolves, so an invalid plugin never silently breaks the registry.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path

from aegisrecon.plugins.base import Plugin

ENTRY_POINT_GROUP = "aegisrecon.plugins"


class PluginError(Exception):
    """Raised when a plugin cannot be discovered, loaded or verified."""


@dataclass
class PluginInfo:
    """Resolved metadata for a discovered plugin."""

    name: str
    version: str = ""
    author: str = ""
    description: str = ""
    kind: str = "plugin"
    source: str = "entry_point"
    entry_point: str = ""
    module: str = ""

    @classmethod
    def from_plugin(cls, plugin: Plugin, source: str, module: str) -> PluginInfo:
        return cls(
            name=plugin.name,
            version=plugin.version,
            author=plugin.author,
            description=plugin.description,
            kind=type(plugin).__name__,
            source=source,
            module=module,
        )


@dataclass
class PluginRegistry:
    """Holds the plugin cache for a process."""

    installed: dict[str, PluginInfo] = field(default_factory=dict)
    modules: dict[str, str] = field(default_factory=dict)

    def discover(self) -> list[PluginInfo]:
        """Discover plugins from entry points and local plugin directories."""
        found: dict[str, PluginInfo] = {}

        for entry_point in metadata.entry_points(group=ENTRY_POINT_GROUP):
            try:
                plugin_cls = entry_point.load()
                module = entry_point.module
            except (ImportError, AttributeError) as exc:
                raise PluginError(f"cannot load entry point {entry_point}: {exc}") from exc
            plugin = self._instantiate(plugin_cls)
            info = PluginInfo.from_plugin(plugin, "entry_point", module)
            info.entry_point = entry_point.value
            found[info.name] = info

        for module_path in self._local_modules():
            try:
                module = self._import_module(module_path)
            except (ImportError, AttributeError) as exc:
                raise PluginError(f"cannot import plugin {module_path}: {exc}") from exc
            plugin = self._instantiate(module.plugin)
            info = PluginInfo.from_plugin(plugin, "local", module_path)
            found[info.name] = info
            self.modules[info.name] = module_path

        self.installed = found
        return sorted(found.values(), key=lambda p: p.name)

    def _local_modules(self) -> list[str]:
        """Return python module paths from the ``AEGISRECON_PLUGIN_PATH``."""
        import os

        path_env = os.environ.get("AEGISRECON_PLUGIN_PATH", "")
        modules: list[str] = []
        for raw in path_env.split(os.pathsep):
            if not raw:
                continue
            base = Path(raw).expanduser()
            for candidate in (base, base / "plugin.py"):
                if candidate.is_file():
                    modules.append(str(candidate))
                    break
        return modules

    def _import_module(self, path: str):
        spec = importlib.util.spec_from_file_location("aegisrecon_local_plugin", path)
        if spec is None or spec.loader is None:  # pragma: no cover - defensive
            raise PluginError(f"cannot build import spec for {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        if not hasattr(module, "plugin"):
            raise PluginError(f"{path} does not export a `plugin` attribute")
        return module

    @staticmethod
    def _instantiate(plugin_cls: type | object) -> Plugin:
        if not isinstance(plugin_cls, type):
            return plugin_cls  # type: ignore[return-value]
        if not issubclass(plugin_cls, Plugin):
            raise PluginError(f"{plugin_cls.__name__} does not inherit from Plugin")
        return plugin_cls.create()


def install_distribution(distribution: str, python: str = sys.executable) -> None:
    """Pip-install *distribution* and verify its AegisRecon entry point."""
    import subprocess

    proc = subprocess.run(
        [python, "-m", "pip", "install", "--quiet", distribution],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise PluginError(f"pip install failed: {proc.stderr.strip() or proc.stdout.strip()}")

    entry_points = list(metadata.entry_points(group=ENTRY_POINT_GROUP))
    matching = [
        ep for ep in entry_points if ep.value.split(":")[0] == distribution
    ]
    if not matching:
        raise PluginError(
            f"{distribution} installed but exposes no '{ENTRY_POINT_GROUP}' entry point"
        )
    ep = matching[0]
    try:
        ep.load()
    except (ImportError, AttributeError) as exc:
        raise PluginError(f"installed {distribution} entry point {ep} failed to load: {exc}") from exc


__all__ = ["PluginRegistry", "PluginInfo", "PluginError", "install_distribution", "ENTRY_POINT_GROUP"]
