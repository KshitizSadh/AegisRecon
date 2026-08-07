"""CLI command implementations, grouped into Typer sub-applications.

Kept separate from :mod:`aegisrecon.cli` so the app wiring stays minimal and
each group reads as a self-contained module.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from aegisrecon.cli import load_database, load_settings
from aegisrecon.core.models import Asset, Program, ScheduledJob, ScopeAction, ScopeEntry, ScopeKind
from aegisrecon.core.repositories import (
    AssetAliasRepository,
    AssetRepository,
    FindingRepository,
    ProgramRepository,
    ScheduledJobRepository,
    ScopeRepository,
)
from aegisrecon.engines.dedup import DedupEngine
from aegisrecon.engines.gitleaks import GitleaksEngine
from aegisrecon.engines.js import JsHarvestEngine
from aegisrecon.engines.monitor import MonitorEngine
from aegisrecon.engines.naabu import PortEngine
from aegisrecon.engines.nuclei import NucleiEngine
from aegisrecon.engines.probe import ProbeEngine
from aegisrecon.engines.recon import ReconEngine
from aegisrecon.engines.screenshot import ScreenshotEngine
from aegisrecon.engines.secretscan import SecretEngine
from aegisrecon.exceptions import EntityNotFoundError
from aegisrecon.notify import (
    ConsoleNotifier,
    NotifierDispatcher,
    available_notifiers,
)
from aegisrecon.reporting.json_report import generate_json_report
from aegisrecon.reporting.markdown_report import generate_markdown_report
from aegisrecon.scheduler import VALID_WORKFLOWS, Scheduler
from aegisrecon.utils.console import console
from aegisrecon.utils.fs import unique_output_path
from aegisrecon.utils.validators import is_valid_hostname, normalize_hostname, normalize_list

program_group = typer.Typer(help="Manage engagement programs.")
scope_group = typer.Typer(help="Manage program scope rules.")
report_group = typer.Typer(help="Generate engagement reports.")
config_group = typer.Typer(help="Inspect runtime configuration.")
probe_group = typer.Typer(help="Probe assets for live endpoints.")
harvest_group = typer.Typer(help="Harvest and store JavaScript files.")
secrets_group = typer.Typer(help="Detect and manage leaked secrets.")
ports_group = typer.Typer(help="Discover open ports on assets.")
vuln_group = typer.Typer(help="Scan for vulnerabilities with ProjectDiscovery nuclei.")
screenshot_group = typer.Typer(help="Capture screenshots of live endpoints.")
monitor_group = typer.Typer(help="Snapshot state and detect changes over time.")
notify_group = typer.Typer(help="Deliver notifications to external channels.")
asset_group = typer.Typer(help="List and inspect discovered assets.")
asset_alias_group = typer.Typer(help="Manage asset aliases.")
asset_group.add_typer(asset_alias_group, name="alias", help="Manage asset aliases.")
finding_group = typer.Typer(help="Query and triage findings.")
schedule_group = typer.Typer(help="Manage recurring scheduled workflows.")


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
            raise typer.BadParameter(
                f"program {value!r} not found (use `aegisrecon program list`)"
            ) from None
        return found


def _render_table(title: str, columns: list[str], rows: list[list[str]]) -> None:
    table = Table(title=title, show_lines=False, header_style="bold cyan")
    for column in columns:
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(*row)
    console.print(table)


def _resolve_asset(repo: AssetRepository, program_id: str, value: str) -> Asset:
    """Resolve an asset by id, canonical name, or alias within a program."""
    try:
        return repo.get(value)
    except EntityNotFoundError:
        found = repo.get_by_name(program_id, value)
        if found is not None:
            return found
        alias = AssetAliasRepository(repo.session).get_by_name(program_id, normalize_hostname(value))
        if alias is not None:
            return repo.get(alias.asset_id)
        raise typer.BadParameter(
            f"asset {value!r} not found in this program (use `aegisrecon asset list`)"
        ) from None


# --------------------------------------------------------------------------- #
# `api` group
# --------------------------------------------------------------------------- #
api_group = typer.Typer(help="Serve the REST API and dashboard.")


@api_group.command("serve")
def api_serve(
    ctx: typer.Context,
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address."),
    port: int = typer.Option(8000, "--port", help="Bind port."),
) -> None:
    """Run the FastAPI server (requires the ``api`` extra)."""
    try:
        import uvicorn  # type: ignore[import-not-found]
    except ImportError:
        raise typer.BadParameter(
            "the API requires 'fastapi' and 'uvicorn': pip install -e \".[api]\""
        ) from None
    settings = load_settings(ctx)
    db = load_database(settings)
    from aegisrecon.api import create_app

    app = create_app(db, settings)
    console.print(
        f"[green]Serving AegisRecon API on[/] [cyan]http://{host}:{port}[/] "
        f"(docs at /docs)"
    )
    uvicorn.run(app, host=host, port=port, log_level="info")


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
    tags: str | None = typer.Option(None, "--tag", help="Comma-separated tags."),
) -> None:
    """Create a new engagement program."""
    settings = load_settings(ctx)
    db = load_database(settings)
    program = Program(
        name=name,
        organization=organization,
        owner=owner,
        description=description,
        tags=normalize_list(tags.split(",") if tags else None),
    )
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
    rows = [
        [p.name, p.id, p.organization, ",".join(p.tags), "yes" if p.enabled else "no"]
        for p in programs
    ]
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
    console.print(
        Panel.fit(
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
        )
    )


# --------------------------------------------------------------------------- #
# `scope` group
# --------------------------------------------------------------------------- #
@scope_group.command("add")
def scope_add(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
    value: str = typer.Argument(..., help="Domain, hostname, wildcard or regex."),
    wildcard: bool = typer.Option(
        False, "--wildcard", help="Treat the value as a wildcard pattern."
    ),
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
        console.print(
            f"[yellow]No scope rules for {found.name}. Add one with `aegisrecon scope add`.[/]"
        )
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
    sources: str | None = typer.Option(
        None, "--source", help="Comma-separated sources (default: crtsh)."
    ),
    dns_concurrency: int = typer.Option(50, "--dns-concurrency", help="Parallel DNS workers."),
    resume: bool = typer.Option(
        False, "--resume", help="Continue from a previously saved scan checkpoint."
    ),
) -> None:
    """Run passive discovery and DNS resolution for a program."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        program_id = found.id
        session.close()

    source_list = normalize_list(sources.split(",") if sources else None) or None
    engine = ReconEngine(
        db,
        dns_concurrency=dns_concurrency,
        enable_ct_logs=settings.enable_ct_logs,
        ct_timeout=settings.ct_logs_timeout,
        dns_bin=settings.dnsx_bin,
    )
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"Recon for {found.name}", total=None)
        result = engine.run(program_id, sources=source_list, resume=resume)
        progress.update(task, completed=1)

    console.print(
        Panel.fit(
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
        )
    )
    if result.errors:
        console.print(
            "[yellow]Some hostnames failed to resolve (NXDOMAIN/timeouts). Run with --debug for details.[/]"
        )


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
    title: str | None = typer.Option(None, "--title", help="Report title."),
) -> None:
    """Generate a JSON report for a program."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        session.close()
    report = generate_json_report(db, found.id, settings.reports_path, title=title)
    console.print(f"[green]Report generated:[/] [cyan]{report.path}[/]")


@report_group.command("markdown")
def report_markdown(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
    title: str | None = typer.Option(None, "--title", help="Report title."),
) -> None:
    """Generate a Markdown executive summary for a program."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        session.close()
    report = generate_markdown_report(db, found.id, settings.reports_path, title=title)
    console.print(f"[green]Markdown report generated:[/] [cyan]{report.path}[/]")


@report_group.command("dashboard")
def report_dashboard(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
    title: str | None = typer.Option(None, "--title", help="Report title."),
) -> None:
    """Generate a self-contained HTML dashboard for a program."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        session.close()
    from aegisrecon.reporting.dashboard import render_dashboard_file
    from aegisrecon.reporting.json_report import build_payload

    payload = build_payload(db, found.id)
    effective_title = title or payload["program"]["name"]
    path = unique_output_path(
        settings.reports_path, stem=f"{effective_title}-dashboard", suffix=".html"
    )
    render_dashboard_file(path, payload)
    console.print(f"[green]Dashboard generated:[/] [cyan]{path}[/]")
    console.print("[yellow]Open in any browser — no server required.[/]")


# --------------------------------------------------------------------------- #
# `suggest` group
# --------------------------------------------------------------------------- #
suggest_group = typer.Typer(help="Context-aware manual-testing suggestions.")
@suggest_group.command("run")
def suggest_run(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
    category: str | None = typer.Option(None, "--category", help="Filter by category."),
) -> None:
    """Generate manual-testing suggestions for a program."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        session.close()
    from aegisrecon.reporting.json_report import build_payload
    from aegisrecon.suggestions import generate_suggestions

    payload = build_payload(db, found.id)
    suggestions = generate_suggestions(payload)
    if category:
        suggestions = [s for s in suggestions if s.category == category]
    if not suggestions:
        console.print(
            f"[yellow]No suggestions matched for {found.name}. "
            "Run `aegisrecon probe run`, `harvest js`, `ports scan` to build up context.[/]"
        )
        return
    table = Table(title=f"Manual-testing suggestions: {found.name}", show_lines=False, header_style="bold cyan")
    table.add_column("Risk", overflow="fold")
    table.add_column("Category", overflow="fold")
    table.add_column("Suggestion", overflow="fold")
    for s in suggestions:
        table.add_row(s.risk.upper(), s.category, s.title)
    console.print(table)
    for s in suggestions:
        console.print(
            Panel.fit(
                f"[bold]{s.title}[/] ([{_risk_color(s.risk)}]{s.risk.upper()}[/])\n\n"
                f"{s.detail}\n"
                + (f"\nEvidence: {', '.join(s.evidence)}" if s.evidence else ""),
                title=f"{s.category}",
            )
        )


def _risk_color(risk: str) -> str:
    return {"high": "red", "medium": "yellow", "low": "green"}.get(risk, "blue")


# --------------------------------------------------------------------------- #
# `probe` group
# --------------------------------------------------------------------------- #
@probe_group.command("run")
def probe_run(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
) -> None:
    """Probe a program's assets for live endpoints, tech and parameters."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        session.close()
    result = ProbeEngine(db, binary=settings.httpx_bin).run(found.id)
    console.print(
        Panel.fit(
            f"[bold]Probe complete[/]\n"
            f"  Probed              : {result.probed}\n"
            f"  Endpoints           : {result.endpoints} ({result.new_endpoints} new)\n"
            f"  Technologies        : {result.technologies}\n"
            f"  Parameters          : {result.parameters}"
            + (f"\n  Out-of-scope skipped: {len(result.errors)}" if result.errors else ""),
            title=f"Probe: {found.name}",
        )
    )


# --------------------------------------------------------------------------- #
# `harvest` group
# --------------------------------------------------------------------------- #
@harvest_group.command("js")
def harvest_js(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
) -> None:
    """Discover and download JavaScript files for a program's assets."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        session.close()
    result = JsHarvestEngine(db, binary=settings.katana_bin).run(found.id)
    console.print(
        Panel.fit(
            f"[bold]JavaScript harvest complete[/]\n"
            f"  Candidates   : {result.candidates}\n"
            f"  Downloaded   : {result.fetched}\n"
            f"  New files    : {result.new_files}\n"
            f"  Unchanged    : {result.unchanged}\n"
            f"  Out of scope : {len(result.errors)}",
            title=f"JS Harvest: {found.name}",
        )
    )


# --------------------------------------------------------------------------- #
# `secrets` group
# --------------------------------------------------------------------------- #
@secrets_group.command("scan")
def secrets_scan(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
    min_entropy: float = typer.Option(0.0, "--min-entropy", help="Extra entropy floor (0 disables)."),
) -> None:
    """Scan harvested files for likely leaked secrets."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        session.close()
    result = SecretEngine(db, min_entropy=min_entropy).run(found.id)
    kind_summary = ", ".join(f"{k}: {v}" for k, v in sorted(result.by_kind.items())) or "none"
    console.print(
        Panel.fit(
            f"[bold]Secret scan complete[/]\n"
            f"  Files checked : {result.files_checked}\n"
            f"  Candidates    : {result.candidates}\n"
            f"  New secrets   : {result.new_secrets}\n"
            f"  By kind       : {kind_summary}",
            title=f"Secrets: {found.name}",
        )
    )


@secrets_group.command("scan-repo")
def secrets_scan_repo(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
    path: Path = typer.Argument(..., help="Git repository or directory to scan with gitleaks."),
) -> None:
    """Scan a git repo / directory with the Go gitleaks binary."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        session.close()
    engine = GitleaksEngine(db, binary=settings.gitleaks_bin)
    result = engine.run(found.id, [Path(path)])
    console.print(
        Panel.fit(
            f"[bold]gitleaks scan complete[/]\n"
            f"  Sources scanned : {result.sources}\n"
            f"  Candidates      : {result.candidates}\n"
            f"  New secrets     : {result.new_secrets}\n"
            f"  Skipped (no asset / error) : {len(result.errors)}",
            title=f"Secrets (gitleaks): {found.name}",
        )
    )
    for err in result.errors[:5]:
        console.print(f"[yellow]  {err}[/]")


@secrets_group.command("list")
def secrets_list(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
) -> None:
    """List stored secret candidates for a program."""
    settings = load_settings(ctx)
    db = load_database(settings)
    from aegisrecon.core.repositories import SecretRepository

    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        rows = [
            [s.kind, s.value, s.location, f"{s.entropy:.2f}", "verified" if s.is_verified else "candidate"]
            for s in SecretRepository(session).list(program_id=found.id)
        ]
        session.close()
    if not rows:
        console.print(f"[yellow]No secrets recorded for {found.name}.[/]")
        return
    _render_table(f"Secrets: {found.name}", ["Kind", "Value", "Location", "Entropy", "Status"], rows)


# --------------------------------------------------------------------------- #
# `ports` group
# --------------------------------------------------------------------------- #
@ports_group.command("scan")
def ports_scan(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
    ports: str = typer.Option("", "--ports", help="Comma-separated ports to probe."),
) -> None:
    """Discover open ports on a program's in-scope assets."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        session.close()
    engine = PortEngine(db, binary=settings.naabu_bin, ports=ports) if ports else PortEngine(db, binary=settings.naabu_bin)
    result = engine.run(found.id)
    console.print(
        Panel.fit(
            f"[bold]Port scan complete[/]\n"
            f"  Hosts scanned : {result.hosts}\n"
            f"  Open ports    : {result.open_ports}\n"
            f"  New ports     : {result.new_ports}\n"
            f"  Out of scope  : {len(result.errors)}",
            title=f"Ports: {found.name}",
        )
    )


# --------------------------------------------------------------------------- #
# `vuln` group
# --------------------------------------------------------------------------- #
@vuln_group.command("run")
def vuln_run(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
    severity: str = typer.Option(
        "low,medium,high,critical", "--severity", help="Nuclei severity filter (comma-separated)."
    ),
    tags: str = typer.Option("", "--tags", help="Nuclei template tags filter."),
) -> None:
    """Scan endpoints for vulnerabilities with ProjectDiscovery nuclei."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        session.close()
    engine = NucleiEngine(db, binary=settings.nuclei_bin, severity=severity, tags=tags)
    result = engine.run(found.id)
    console.print(
        Panel.fit(
            f"[bold]Nuclei scan complete[/]\n"
            f"  Targets scanned : {result.targets}\n"
            f"  Matches found   : {result.matched}\n"
            f"  New findings    : {result.new_findings}\n"
            f"  Errors          : {len(result.errors)}",
            title=f"Vulnerability scan: {found.name}",
        )
    )


# --------------------------------------------------------------------------- #
# `screenshot` group
# --------------------------------------------------------------------------- #
@screenshot_group.command("run")
def screenshot_run(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
) -> None:
    """Capture screenshots of a program's live endpoints."""
    settings = load_settings(ctx)
    db = load_database(settings)
    settings.screenshots_path.mkdir(parents=True, exist_ok=True)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        session.close()
    engine = ScreenshotEngine(db, binary=settings.httpx_bin, output_root=settings.screenshots_path)
    result = engine.run(found.id)
    console.print(
        Panel.fit(
            f"[bold]Screenshot pass complete[/]\n"
            f"  Endpoints attempted : {result.endpoints_attempted}\n"
            f"  New screenshots     : {result.new_files}\n"
            f"  Skipped (duplicate) : {result.skipped}\n"
            f"  Stored under        : {settings.screenshots_path}"
            + (f"\n  Errors              : {len(result.errors)}" if result.errors else ""),
            title=f"Screenshots: {found.name}",
        )
    )


# --------------------------------------------------------------------------- #
# `monitor` group
# --------------------------------------------------------------------------- #
@monitor_group.command("run")
def monitor_run(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
) -> None:
    """Capture a snapshot and report changes against the previous one."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        session.close()
    result = MonitorEngine(db).run(found.id)
    console.print(
        Panel.fit(
            f"[bold]Monitoring pass complete[/]\n"
            f"  Endpoints seen : {result.endpoints_seen}\n"
            f"  Changes        : {result.changes}\n"
            f"  Findings       : {result.findings_created}",
            title=f"Monitor: {found.name}",
        )
    )


# --------------------------------------------------------------------------- #
# `asset` group
# --------------------------------------------------------------------------- #
@asset_group.command("list")
def asset_list(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
    show_aliases: bool = typer.Option(
        False, "--show-aliases", help="Include aliases resolving to each asset."
    ),
) -> None:
    """List all assets belonging to a program."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        assets = AssetRepository(session).list(program_id=found.id)
        aliases: dict[str, list[str]] = {}
        if show_aliases:
            for alias in AssetAliasRepository(session).list(program_id=found.id):
                aliases.setdefault(alias.asset_id, []).append(alias.name)
        rows = [
            [
                a.name,
                a.kind,
                a.source,
                a.last_seen_at.isoformat() if a.last_seen_at else "",
                ", ".join(sorted(x for x in aliases.get(a.id, []) if x != a.name)),
            ]
            for a in assets
        ]
        session.close()
    if not rows:
        console.print(f"[yellow]No assets for {found.name}. Run `aegisrecon recon run` first.[/]")
        return
    columns = ["Name", "Kind", "Source", "Last seen"]
    if show_aliases:
        columns.append("Aliases")
    _render_table(f"Assets: {found.name}", columns, rows)


asset_alias_group = typer.Typer(help="Manage asset aliases.")
asset_group.add_typer(asset_alias_group, name="alias", help="Manage asset aliases.")


@asset_alias_group.command("add")
def asset_alias_add(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
    name: str = typer.Argument(..., help="Canonical asset id or name."),
    aliases: list[str] = typer.Argument(..., help="Variant hostnames to bind."),
) -> None:
    """Bind one or more variant hostnames as aliases of a canonical asset."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        target = _resolve_asset(AssetRepository(session), found.id, name)
        repo = AssetAliasRepository(session)
        bound = 0
        for alias in aliases:
            if repo.register(target, alias) is not None:
                bound += 1
        session.commit()
        session.close()
    console.print(
        f"[green]Bound {bound} alias(es) to[/] [cyan]{target.name}[/] "
        f"({', '.join(aliases)})"
    )


@asset_group.command("dedup")
def asset_dedup(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Report candidates without modifying anything."
    ),
    www_strip: bool = typer.Option(
        False,
        "--www-strip",
        help="Merge www-prefixed hosts by name even without shared IP evidence.",
    ),
) -> None:
    """Find and merge duplicate assets, reparenting child records."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        session.close()
    engine = DedupEngine(db)
    result = engine.run(found.id, dry_run=dry_run, www_strip=www_strip)
    mode = "dry-run" if result.dry_run else "applied"
    status = "would merge" if result.dry_run else "merged"
    console.print(
        Panel.fit(
            f"[bold]Asset dedup ({mode})[/]\n"
            f"  Candidates          : {result.candidates}\n"
            f"  {status.capitalize()}             : {result.merged}\n"
            f"  Child rows reparented : {result.reparented}\n"
            f"  Duplicates dropped   : {result.deleted_duplicates}\n"
            f"  Aliases registered   : {result.aliases_registered}\n"
            + (
                "\n  Merged:\n  "
                + "\n  ".join(f"{loser} -> {survivor}" for loser, survivor in result.merged_pairs)
                if result.merged_pairs
                else ""
            ),
            title=f"Dedup: {found.name}",
        )
    )


# --------------------------------------------------------------------------- #
# `finding` group
# --------------------------------------------------------------------------- #
@finding_group.command("list")
def finding_list(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
    status: str | None = typer.Option(None, "--status", help="Filter by lifecycle status."),
) -> None:
    """List findings for a program, optionally filtered by status."""
    settings = load_settings(ctx)
    db = load_database(settings)
    from aegisrecon.core.repositories import FindingRepository

    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        rows = [
            [f.severity.value.upper(), f.status.value, f.title]
            for f in FindingRepository(session).list(program_id=found.id, status=status)
        ]
        session.close()
    if not rows:
        console.print(f"[yellow]No findings for {found.name}.[/]")
        return
    _render_table(f"Findings: {found.name}", ["Severity", "Status", "Title"], rows)


@finding_group.command("set-status")
def finding_status_update(
    ctx: typer.Context,
    finding_id: str = typer.Argument(..., help="Finding id."),
    status: str = typer.Argument(..., help="New status: open|triaged|accepted|false_positive|fixed."),
) -> None:
    """Update the lifecycle status of a finding."""
    from aegisrecon.core.models import FindingStatus

    settings = load_settings(ctx)
    db = load_database(settings)

    try:
        new_status = FindingStatus(status.lower())
    except ValueError:
        valid = ", ".join(s.value for s in FindingStatus)
        raise typer.BadParameter(f"invalid status {status!r}. Use one of: {valid}") from None

    with db.session() as session:
        repo = FindingRepository(session)
        try:
            updated = repo.update(finding_id, status=new_status)
        except EntityNotFoundError as exc:
            raise typer.BadParameter(str(exc)) from exc
        session.commit()
        session.close()
    console.print(f"[green]Updated[/] finding {updated.id} to status [cyan]{new_status.value}[/]")


# --------------------------------------------------------------------------- #
# `notify` group
# --------------------------------------------------------------------------- #
@notify_group.command("list")
def notify_list() -> None:
    """List built-in notifier plugins."""
    _render_table("Notifiers", ["Name"], [[name] for name in available_notifiers()])


@notify_group.command("test")
def notify_test(
    ctx: typer.Context,
    message: str = typer.Argument("AegisRecon test notification", help="Message to send."),
) -> None:
    """Send a test notification to the console channel."""
    dispatcher = NotifierDispatcher([ConsoleNotifier()])
    results = dispatcher.dispatch({"title": "Test", "program": "local", "message": message})
    console.print(f"[green]Dispatcher result:[/] {results}")


# --------------------------------------------------------------------------- #
# `schedule` group
# --------------------------------------------------------------------------- #
@schedule_group.command("add")
def schedule_add(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
    name: str = typer.Argument(..., help="Unique job name."),
    workflow: str = typer.Argument(..., help="Workflow: probe|monitor|secrets|ports|harvest."),
    interval_hours: int = typer.Option(24, "--every", min=1, help="Run interval in hours."),
) -> None:
    """Register a recurring workflow for a program."""
    if workflow.lower() not in VALID_WORKFLOWS:
        raise typer.BadParameter(
            f"invalid workflow {workflow!r}; use one of: {', '.join(VALID_WORKFLOWS)}"
        )
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        repo = ScheduledJobRepository(session)
        if repo.get_by_name(found.id, name) is not None:
            raise typer.BadParameter(f"a job named {name!r} already exists for {found.name}")
        job = ScheduledJob(
            program_id=found.id,
            name=name,
            workflow=workflow.lower(),
            interval_seconds=interval_hours * 3600,
        )
        repo.create(job)
        session.commit()
        console.print(
            f"[green]Scheduled[/] workflow [cyan]{job.workflow}[/] every {interval_hours}h "
            f"for {found.name} (job: {job.name})"
        )


@schedule_group.command("list")
def schedule_list(ctx: typer.Context) -> None:
    """List all scheduled jobs."""
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        jobs = ScheduledJobRepository(session).list()
        session.close()
    if not jobs:
        console.print("[yellow]No scheduled jobs. Add one with `aegisrecon schedule add`.[/]")
        return
    rows = [
        [
            job.name,
            job.workflow,
            f"{job.interval_seconds // 3600}h",
            "yes" if job.enabled else "no",
            str(job.run_count),
            job.last_status or "-",
            job.last_run_at.isoformat() if job.last_run_at else "-",
        ]
        for job in jobs
    ]
    _render_table("Scheduled jobs", ["Name", "Workflow", "Interval", "Enabled", "Runs", "Status", "Last run"], rows)


@schedule_group.command("run")
def schedule_run(ctx: typer.Context) -> None:
    """Run every scheduled job that is currently due."""
    settings = load_settings(ctx)
    db = load_database(settings)
    report = Scheduler(db).run_due()
    if report.jobs_due == 0:
        console.print("[yellow]No scheduled jobs are due right now.[/]")
        return
    console.print(
        Panel.fit(
            f"[bold]Scheduler sweep complete[/]\n"
            f"  Evaluated : {report.jobs_evaluated}\n"
            f"  Due       : {report.jobs_due}\n"
            f"  Completed : {report.completed}"
            + (f"\n  Failed    : {len(report.failed)}" if report.failed else ""),
            title="Schedule",
        )
    )
    for name, detail in report.results.items():
        console.print(f"[cyan]{name}[/]: {detail} ok")
    for name, error in report.failed.items():
        console.print(f"[red]{name}[/]: {error}")


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
        ["Screenshots directory", str(settings.screenshots_path)],
        ["Concurrency", str(settings.concurrency)],
        ["DNS concurrency", str(settings.dns_concurrency)],
        ["Timeout (s)", str(settings.timeout_seconds)],
        ["Retries", str(settings.retries)],
        ["CT logs enabled", "yes" if settings.enable_ct_logs else "no"],
        ["Scope enforcement", "on" if settings.require_scope else "off"],
        ["httpx binary", settings.httpx_bin],
        ["subfinder binary", settings.subfinder_bin],
        ["naabu binary", settings.naabu_bin],
        ["katana binary", settings.katana_bin],
        ["dnsx binary", settings.dnsx_bin],
        ["nuclei binary", settings.nuclei_bin],
        ["gitleaks binary", settings.gitleaks_bin],
    ]
    _render_table("Configuration", ["Setting", "Value"], rows)


# --------------------------------------------------------------------------- #
# `collab` group
# --------------------------------------------------------------------------- #
collab_group = typer.Typer(help="Manage program collaborators and roles.")


@collab_group.command("add")
def collab_add(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
    email: str = typer.Argument(..., help="Collaborator email."),
    role: str = typer.Option("viewer", "--role", "-r", help="viewer|member|admin|owner"),
) -> None:
    """Grant a collaborator access to a program."""
    from aegisrecon.core.models import Collaborator, CollaboratorRole
    from aegisrecon.core.repositories import CollaboratorRepository

    try:
        granted = CollaboratorRole(role)
    except ValueError:
        raise typer.BadParameter(
            f"invalid role {role!r}: choose viewer, member, admin, owner"
        ) from None
    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        repo = CollaboratorRepository(session)
        existing = repo.get_for_program(found.id, email)
        if existing is not None:
            repo.update(existing.id, role=granted)
            session.commit()
            console.print(
                f"[yellow]Updated[/] [cyan]{email}[/] -> [green]{granted.value}[/] "
                f"on [bold]{found.name}[/]"
            )
            session.close()
            return
        collab = Collaborator(program_id=found.id, email=email, role=granted)
        repo.create(collab)
        session.commit()
        session.close()
    console.print(
        f"[green]Granted[/] [cyan]{email}[/] role [bold]{granted.value}[/] on [bold]{found.name}[/]"
    )


@collab_group.command("list")
def collab_list(ctx: typer.Context, program: str = typer.Argument(..., help="Program id or name.")) -> None:
    """List collaborators for a program."""
    from aegisrecon.core.repositories import CollaboratorRepository

    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        rows = [
            [c.email, c.role, c.invited_by or "-"]
            for c in CollaboratorRepository(session).list_for_program(found.id)
        ]
        session.close()
    _render_table(f"Collaborators: {found.name}", ["Email", "Role", "Invited by"], rows)


@collab_group.command("remove")
def collab_remove(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or name."),
    email: str = typer.Argument(..., help="Collaborator email."),
) -> None:
    """Revoke a collaborator's access to a program."""
    from aegisrecon.core.repositories import CollaboratorRepository

    settings = load_settings(ctx)
    db = load_database(settings)
    with db.session() as session:
        found = _resolve_program(ProgramRepository(session), program)
        repo = CollaboratorRepository(session)
        collab = repo.get_for_program(found.id, email)
        if collab is None:
            console.print(f"[yellow]No collaborator {email} on {found.name}.[/]")
        else:
            repo.delete(collab.id)
            session.commit()
            console.print(f"[green]Removed[/] [cyan]{email}[/] from [bold]{found.name}[/]")
        session.close()


# --------------------------------------------------------------------------- #
# `plugin` group
# --------------------------------------------------------------------------- #
plugin_group = typer.Typer(help="Discover, scaffold and install plugins.")


@plugin_group.command("list")
def plugin_list(ctx: typer.Context) -> None:
    """List discovered plugins (entry points + local plugin path)."""
    from aegisrecon.plugins.registry import PluginRegistry

    try:
        infos = PluginRegistry().discover()
    except Exception as exc:
        console.print(f"[red]Plugin discovery failed:[/] {exc}")
        raise typer.Exit(1) from exc
    if not infos:
        console.print("[yellow]No plugins discovered.[/]")
        return
    rows = [[i.name, i.version, i.kind, i.source, i.module] for i in infos]
    _render_table("Discovered plugins", ["Name", "Version", "Kind", "Source", "Module"], rows)


@plugin_group.command("scaffold")
def plugin_scaffold(
    name: str = typer.Argument(..., help="Plugin name, e.g. my-notifier"),
    kind: str = typer.Option("Notifier", "--kind", "-k", help="Notifier|Scanner|ReconProvider|Exporter"),
    author: str = typer.Option("", "--author", "-a", help="Plugin author."),
    output: Path = typer.Option(None, "--output", "-o", help="Output directory (default: ./<name>)."),  # type: ignore[assignment]
) -> None:
    """Generate a minimal plugin package skeleton in the current directory."""
    from aegisrecon.plugins.scaffold import scaffold_plugin

    target = output or Path(name)
    try:
        path = scaffold_plugin(target, name=name, kind=kind, author=author)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None
    console.print(f"[green]Scaffolded plugin in[/] [cyan]{path}[/]")
    console.print(f"[yellow]Install locally with:[/] pip install -e \"{path}\"")


@plugin_group.command("install")
def plugin_install(
    distribution: str = typer.Argument(..., help="PyPI distribution or local path."),
) -> None:
    """Pip-install a distribution and verify its AegisRecon entry point."""
    from aegisrecon.plugins.registry import PluginError, install_distribution

    try:
        install_distribution(distribution)
    except PluginError as exc:
        console.print(f"[red]Install failed:[/] {exc}")
        raise typer.Exit(1) from exc
    console.print(f"[green]Installed and verified:[/] [cyan]{distribution}[/]")


__all__ = [
    "program_group",
    "scope_group",
    "recon_group",
    "report_group",
    "config_group",
    "probe_group",
    "harvest_group",
    "secrets_group",
    "ports_group",
    "screenshot_group",
    "monitor_group",
    "asset_group",
    "finding_group",
    "notify_group",
    "schedule_group",
    "collab_group",
    "plugin_group",
    "vuln_group",
]
