"""CLI command implementations, grouped into Typer sub-applications.

Kept separate from :mod:`aegisrecon.cli` so the app wiring stays minimal and
each group reads as a self-contained module.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from aegisrecon.cli import load_database, load_settings
from aegisrecon.core.models import Program, ScopeAction, ScopeEntry, ScopeKind
from aegisrecon.core.repositories import (
    AssetRepository,
    FindingRepository,
    ProgramRepository,
    ScopeRepository,
)
from aegisrecon.engines.recon import ReconEngine
from aegisrecon.exceptions import EntityNotFoundError
from aegisrecon.reporting.json_report import generate_json_report
from aegisrecon.utils.console import console
from aegisrecon.utils.validators import is_valid_hostname, normalize_list, normalize_hostname

program_group = typer.Typer(help="Manage engagement programs.")
scope_group = typer.Typer(help="Manage program scope rules.")
report_group = typer.Typer(help="Generate engagement reports.")
config_group = typer.Typer(help="Inspect runtime configuration.")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _resolve_program(repo: ProgramRepository, value: str) -> Program:
    """Resolve a program by id or name."""
    try:
        return repo.get(value)
    except EntityNotFoundError:
        found = repo.get_by_name(value)
        if found is None:
            raise typer.BadParameter(f"program {value!r} not found (use `aegisrecon program list`)")
        return found


def _render_table(title: str, columns: list[str], rows: list[list[str]]) -> None:
    table = Table(title=title, show_lines=False, header_style="bold cyan")
    for column in columns:
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(*row)
    console.print(table)


# --------------------------------------------------------------------------- #
# `program` group
# --------------------------------------------------------------------------- #
@program_group.command("create")
def program_create(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Program name."),
    organization: str = typer.Option("", "--org", help="Owning organization."),
    owner: str = typer.Option("", "--owner", help="Responsible researcher/team."),
    description: str = typer.Option("", "--description", help="Program description."),
    tags: Optional[str] = typer.Option(None, "--tag", help="Comma-separated tags."),
) -> None:
    """Create a new engagement program."""
    settings = load_settings(ctx)
    db = load_database(settings)
    program = Program(name=name, organization=organization, owner=owner, description=description, tags=normalize_list(tags.split(",") if tags else None))
    with db.session() as session:
        ProgramRepository(session).create(program)
        session.commit()
        console.print(f"[green]Created program[/] [cyan]{program.name}[/] (id: {program.id})")


@program_group.command("list")
def program_list(ctx: typer.Context) -> None:
    """List all programs."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        programs = ProgramRepository(session).list()
        session.close()
    if not programs:
        console.print("[yellow]No programs yet. Create one with `aegisrecon program create`.[/]")
        return
    rows = [[p.name, p.id, p.organization, ",".join(p.tags), "yes" if p.enabled else "no"] for p in programs]
    _render_table("Programs", ["Name", "ID", "Organization", "Tags", "Enabled"], rows)


@program_group.command("show")
def program_show(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
) -> None:
    """Show a program and its scope summary."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        repo = ProgramRepository(session)
        found = _resolve_program(repo, program)
        scopes = ScopeRepository(session).list_for_program(found.id)
        assets = AssetRepository(session).count(program_id=found.id)
        findings = FindingRepository(session).count(program_id=found.id)
        session.close()
    console.print(Panel.fit(
        f"[bold]{found.name}[/]\n"
        f"  ID          : {found.id}\n"
        f"  Org         : {found.organization or '-'}\n"
        f"  Owner       : {found.owner or '-'}\n"
        f"  Description : {found.description or '-'}\n"
        f"  Tags        : {', '.join(found.tags) or '-'}\n"
        f"  Scope rules : {len(scopes)}\n"
        f"  Assets      : {assets}\n"
        f"  Findings    : {findings}",
        title="Program",
    ))


# --------------------------------------------------------------------------- #
# `scope` group
# --------------------------------------------------------------------------- #
@scope_group.command("add")
def scope_add(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
    value: str = typer.Argument(..., help="Domain, hostname, wildcard or regex."),
    wildcard: bool = typer.Option(False, "--wildcard", help="Treat the value as a wildcard pattern."),
    exclude: bool = typer.Option(False, "--exclude", help="Mark the value as out-of-scope."),
    regex: bool = typer.Option(False, "--regex", help="Treat the value as a regex pattern."),
    note: str = typer.Option("", "--note", help="Justification / source."),
) -> None:
    """Add a scope rule to a program."""
    settings = load_settings(ctx)
    db = load_database(settings)
    candidate = normalize_hostname(value) if not regex else value.strip()

    if regex:
        kind = ScopeKind.REGEX
    elif wildcard:
        kind = ScopeKind.WILDCARD
        candidate = candidate if candidate.startswith("*.") else f"*.{candidate}"
    else:
        kind = ScopeKind.EXACT

    if not regex and not is_valid_hostname(candidate.replace("*.", "")):
        raise typer.BadParameter(f"invalid hostname: {value!r}")

    with db.session() as session:
        repo = ProgramRepository(session)
        found = _resolve_program(repo, program)
        entry = ScopeEntry(
            program_id=found.id,
            value=candidate,
            kind=kind,
            action=ScopeAction.EXCLUDE if exclude else ScopeAction.INCLUDE,
            note=note,
        )
        ScopeRepository(session).create(entry)
        session.commit()
        console.print(
            f"[green]Added[/] {'EXCLUDE' if exclude else 'INCLUDE'} rule "
            f"[cyan]{candidate}[/] ({kind.value}) to {found.name}"
        )


@scope_group.command("list")
def scope_list(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
) -> None:
    """List scope rules for a program."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        entries = ScopeRepository(session).list_for_program(found.id)
        session.close()
    if not entries:
        console.print(f"[yellow]No scope rules for {found.name}. Add one with `aegisrecon scope add`.[/]")
        return
    rows = [[e.value, e.kind.value, e.action.value, e.note] for e in entries]
    _render_table(f"Scope: {found.name}", ["Value", "Kind", "Action", "Note"], rows)


@scope_group.command("remove")
def scope_remove(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
    value: str = typer.Argument(..., help="Scope value to remove."),
) -> None:
    """Remove a scope rule by its value."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        repo = ScopeRepository(session)
        entries = repo.list_for_program(found.id)
        match = next((e for e in entries if e.value == normalize_hostname(value)), None)
        if match is None:
            raise typer.BadParameter(f"no scope rule {value!r} for {found.name}")
        repo.delete(match.id)
        session.commit()
        console.print(f"[green]Removed[/] scope rule {match.value} from {found.name}")


# --------------------------------------------------------------------------- #
# `recon` group
# --------------------------------------------------------------------------- #
recon_group = typer.Typer(help="Run reconnaissance workflows.", hidden=False)


@recon_group.command("run")
def recon_run(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
    sources: Optional[str] = typer.Option(None, "--source", help="Comma-separated sources (default: crtsh)."),
    dns_concurrency: int = typer.Option(50, "--dns-concurrency", help="Parallel DNS workers."),
) -> None:
    """Run passive discovery and DNS resolution for a program."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        program_id = found.id
        session.close()

    source_list = normalize_list(sources.split(",") if sources else None) or None
    engine = ReconEngine(db, dns_concurrency=dns_concurrency, enable_ct_logs=settings.enable_ct_logs, ct_timeout=settings.ct_logs_timeout)
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"Recon for {found.name}", total=None)
        result = engine.run(program_id, sources=source_list)
        progress.update(task, completed=1)

    console.print(Panel.fit(
        f"[bold]Recon complete[/]\n"
        f"  Candidates discovered : {result.discovered}\n"
        f"  In scope             : {result.in_scope}\n"
        f"  Resolved             : {result.resolved}\n"
        f"  New assets           : {result.new_assets}\n"
        f"  Updated assets       : {result.updated_assets}\n"
        f"  DNS records stored   : {result.dns_records}\n"
        f"  IP records stored    : {result.ip_records}\n"
        + (f"  Failures             : {len(result.errors)}" if result.errors else ""),
        title="Recon",
    ))
    if result.errors:
        console.print("[yellow]Some hostnames failed to resolve (NXDOMAIN/timeouts). Run with --debug for details.[/]")


@recon_group.command("ingest")
def recon_ingest(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
    input_file: Path = typer.Argument(..., help="Text file with one hostname per line."),
    dns_concurrency: int = typer.Option(50, "--dns-concurrency", help="Parallel DNS workers."),
) -> None:
    """Ingest externally-discovered hostnames into a program."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        session.close()

    if not input_file.exists():
        raise typer.BadParameter(f"input file {input_file} not found")

    hostnames = [
        normalize_hostname(line)
        for line in input_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and is_valid_hostname(line)
    ]
    engine = ReconEngine(db, dns_concurrency=dns_concurrency)
    result = engine.ingest(found.id, hostnames)
    console.print(
        f"[green]Ingested {result.in_scope}[/] of {result.discovered} hostnames "
        f"(new assets: {result.new_assets}, resolved: {result.resolved})"
    )


# --------------------------------------------------------------------------- #
# `report` group
# --------------------------------------------------------------------------- #
@report_group.command("json")
def report_json(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
    title: Optional[str] = typer.Option(None, "--title", help="Report title."),
) -> None:
    """Generate a JSON report for a program."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        session.close()
    report = generate_json_report(db, found.id, settings.reports_path, title=title)
    console.print(f"[green]Report generated:[/] [cyan]{report.path}[/]")


# --------------------------------------------------------------------------- #
# `config` group
# --------------------------------------------------------------------------- #
@config_group.command("show")
def config_show(ctx: typer.Context) -> None:
    """Print effective runtime configuration."""
    settings = load_settings(ctx)
    settings.prepare()
    rows = [
        ["Data directory", str(settings.data_dir)],
        ["Database", str(settings.database_path)],
        ["Reports directory", str(settings.reports_path)],
        ["Concurrency", str(settings.concurrency)],
        ["DNS concurrency", str(settings.dns_concurrency)],
        ["Timeout (s)", str(settings.timeout_seconds)],
        ["Retries", str(settings.retries)],
        ["CT logs enabled", "yes" if settings.enable_ct_logs else "no"],
        ["Scope enforcement", "on" if settings.require_scope else "off"],
        ["httpx binary", settings.httpx_bin],
    ]
    _render_table("Configuration", ["Setting", "Value"], rows)


__all__ = ["program_group", "scope_group", "recon_group", "report_group", "config_group"]
