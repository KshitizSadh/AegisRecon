"""AegisRecon command-line interface.

Built on Typer (Click) with a Rich-powered console. Interactive and status
output goes to stderr; only machine-readable data is ever written to stdout so
results can be piped safely.

Top-level layout::

    aegisrecon init config recon report program scope
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import typer
from rich.panel import Panel
from typer.core import TyperGroup

from aegisrecon import __version__
from aegisrecon.config import AegisSettings
from aegisrecon.core.database import Database
from aegisrecon.utils.console import console
from aegisrecon.utils.logging import setup_logging

# Global options that must be accepted anywhere on the command line, including
# after a subcommand (e.g. ``aegisrecon recon run "Lab" --debug``).
_GLOBAL_FLAGS = {"--debug", "-v", "--verbose"}
_GLOBAL_VALUE_OPTS = {"--data-dir"}


def _hoist_global_options(args: list[str]) -> list[str]:
    """Move global options to the front of *args* so the root callback sees them.

    Only the root group reorders; subcommand-local options keep their order.
    """
    front: list[str] = []
    rest: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in _GLOBAL_FLAGS:
            front.append(arg)
            i += 1
        elif arg.startswith("--data-dir=") or arg in _GLOBAL_VALUE_OPTS:
            front.append(arg)
            i += 1
            if arg in _GLOBAL_VALUE_OPTS and i < len(args):
                front.append(args[i])
                i += 1
        else:
            rest.append(arg)
            i += 1
    return front + rest


class AegisTyperGroup(TyperGroup):
    """Typer group that accepts global options before or after subcommands."""

    def parse_args(self, ctx, args):  # type: ignore[no-untyped-def]
        if ctx.parent is None:
            args = _hoist_global_options(list(args))
        return super().parse_args(ctx, args)


app = typer.Typer(
    name="aegisrecon",
    cls=AegisTyperGroup,
    help="Enterprise-grade Attack Surface Intelligence and Bug Bounty Automation Framework.",
    add_completion=True,
    no_args_is_help=True,
)


def load_settings(ctx: typer.Context) -> AegisSettings:
    """Resolve the shared settings object for an invocation."""
    if ctx.obj is None:
        ctx.obj = AegisSettings()
    return cast(AegisSettings, ctx.obj)


def load_database(settings: AegisSettings) -> Database:
    """Create and prepare the SQLite store from settings."""
    settings.prepare()
    db = Database(settings.database_path)
    db.create_schema()
    return db


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"aegisrecon {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version."
    ),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show verbose logging."),
    debug: bool = typer.Option(False, "--debug", help="Show debug logging."),
    data_dir: str | None = typer.Option(None, "--data-dir", help="Override the state directory."),
) -> None:
    """Entrypoint shared by every command.

    State lives in AEGISRECON_DATA_DIR or ~/.aegisrecon by default.
    """
    settings = load_settings(ctx)
    if debug:
        settings.debug = True
    if verbose or debug:
        settings.verbose = True
    if data_dir:
        settings.data_dir = Path(data_dir)
    setup_logging(debug=settings.debug)


@app.command("init")
def init(
    ctx: typer.Context,
    data_dir: str | None = typer.Option(None, "--data-dir", help="Explicit state directory."),
) -> None:
    """Create the state directory, database schema and defaults."""
    settings = load_settings(ctx)
    if data_dir:
        settings.data_dir = Path(data_dir)
    settings.prepare()
    db = load_database(settings)
    console.print(
        Panel.fit(
            f"[bold green]AegisRecon initialized[/]\n\n"
            f"  Data directory : [cyan]{settings.data_dir}[/]\n"
            f"  Database       : [cyan]{settings.database_path}[/]",
            title="init",
        )
    )
    db.close()


# Sub-command groups are registered at import time to keep this file minimal.
from aegisrecon.cli_groups import (  # noqa: E402, F401
    api_group,
    asset_group,
    collab_group,
    config_group,
    finding_group,
    harvest_group,
    monitor_group,
    notify_group,
    plugin_group,
    ports_group,
    probe_group,
    program_group,
    recon_group,
    report_group,
    schedule_group,
    scope_group,
    screenshot_group,
    secrets_group,
    suggest_group,
    tools_group,
    vuln_group,
)

app.add_typer(program_group, name="program", help="Manage engagement programs.")
app.add_typer(scope_group, name="scope", help="Manage program scope rules.")
app.add_typer(recon_group, name="recon", help="Run reconnaissance workflows.")
app.add_typer(report_group, name="report", help="Generate engagement reports.")
app.add_typer(config_group, name="config", help="Inspect runtime configuration.")
app.add_typer(probe_group, name="probe", help="Probe assets for live endpoints.")
app.add_typer(harvest_group, name="harvest", help="Harvest and store JavaScript files.")
app.add_typer(secrets_group, name="secrets", help="Detect and manage leaked secrets.")
app.add_typer(ports_group, name="ports", help="Discover open ports on assets.")
app.add_typer(vuln_group, name="vuln", help="Scan for vulnerabilities with ProjectDiscovery nuclei.")
app.add_typer(screenshot_group, name="screenshot", help="Capture screenshots of live endpoints.")
app.add_typer(monitor_group, name="monitor", help="Snapshot state and detect changes.")
app.add_typer(asset_group, name="asset", help="List and inspect discovered assets.")
app.add_typer(finding_group, name="finding", help="Query and triage findings.")
app.add_typer(notify_group, name="notify", help="Deliver notifications to external channels.")
app.add_typer(schedule_group, name="schedule", help="Manage recurring scheduled workflows.")
app.add_typer(suggest_group, name="suggest", help="Context-aware manual-testing suggestions.")
app.add_typer(api_group, name="api", help="Serve the REST API and dashboard.")
app.add_typer(collab_group, name="collab", help="Manage program collaborators and roles.")
app.add_typer(plugin_group, name="plugin", help="Discover, scaffold and install plugins.")
app.add_typer(
    tools_group, name="tools", help="Install and check the external binaries AegisRecon uses."
)

__all__ = ["app", "load_settings", "load_database"]
