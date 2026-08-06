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

from aegisrecon import __version__
from aegisrecon.config import AegisSettings
from aegisrecon.core.database import Database
from aegisrecon.utils.console import console
from aegisrecon.utils.logging import setup_logging

app = typer.Typer(
    name="aegisrecon",
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
    config_group,
    program_group,
    recon_group,
    report_group,
    scope_group,
)

app.add_typer(program_group, name="program", help="Manage engagement programs.")
app.add_typer(scope_group, name="scope", help="Manage program scope rules.")
app.add_typer(recon_group, name="recon", help="Run reconnaissance workflows.")
app.add_typer(report_group, name="report", help="Generate engagement reports.")
app.add_typer(config_group, name="config", help="Inspect runtime configuration.")

__all__ = ["app", "load_settings", "load_database"]
