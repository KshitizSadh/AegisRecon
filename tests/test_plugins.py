"""Tests for the plugin registry, scaffold, and install verification."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegisrecon.plugins.registry import PluginError, PluginRegistry
from aegisrecon.plugins.scaffold import scaffold_plugin


def test_scaffold_produces_importable_package(tmp_path: Path) -> None:
    target = tmp_path / "sample-notifier"
    created = scaffold_plugin(target, name="sample-notifier", kind="Notifier", author="alice")

    assert created == target
    assert (target / "pyproject.toml").is_file()
    plugin_src = (target / "sample_notifier" / "plugin.py").read_text(encoding="utf-8")
    assert "class SampleNotifier(Notifier):" in plugin_src
    assert "plugin = SampleNotifier()" in plugin_src
    pyproject = (target / "pyproject.toml").read_text(encoding="utf-8")
    assert "aegisrecon.plugins" in pyproject


def test_scaffold_rejects_bad_name(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        scaffold_plugin(tmp_path / "x", name="Bad Name!")
    with pytest.raises(ValueError):
        scaffold_plugin(tmp_path / "x", name="ok", kind="NotARealKind")


def test_registry_loads_scaffolded_plugin(tmp_path: Path, monkeypatch) -> None:
    scaffold_plugin(tmp_path / "plug", name="demo", kind="Scanner", author="bob")
    plugin_path = tmp_path / "plug" / "demo" / "plugin.py"
    monkeypatch.setenv("AEGISRECON_PLUGIN_PATH", str(plugin_path))

    infos = PluginRegistry().discover()
    assert any(i.name == "demo" and i.kind == "Demo" and i.source == "local" for i in infos)


def test_registry_rejects_module_without_plugin_attr(tmp_path: Path, monkeypatch) -> None:
    bad = tmp_path / "bad.py"
    bad.write_text("from __future__ import annotations\nVALUE = 1\n", encoding="utf-8")
    monkeypatch.setenv("AEGISRECON_PLUGIN_PATH", str(bad))
    with pytest.raises(PluginError):
        PluginRegistry().discover()


def test_registry_empty_environment(monkeypatch) -> None:
    monkeypatch.delenv("AEGISRECON_PLUGIN_PATH", raising=False)
    assert PluginRegistry().discover() == []
