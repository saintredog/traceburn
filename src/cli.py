"""
src/cli.py — TraceBurn CLI Entry Point

All `traceburn` subcommands are registered here. This module owns routing
only — no business logic lives here. Each command delegates immediately to
the appropriate module.

Usage:
    traceburn --help
    traceburn version
    traceburn init
    traceburn scan [--brokers all|tier1|NAME] [--region US|EU|UK|global] [--full|--spot] [--dry-run]
    traceburn remove [--auto] [--dry-run]
    traceburn status
    traceburn history [--lines N]
    traceburn report [--format html|pdf|json] [--output PATH]
    traceburn profiles add|list|delete
    traceburn proof list|export
    traceburn vault rekey
    traceburn schedule status|pause|resume
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

__version__ = "0.1.0"

console = Console()
err_console = Console(stderr=True)

TRACEBURN_DIR = Path.home() / ".traceburn"


def _coming_soon(feature: str) -> None:
    """Display a 'not yet implemented' panel for stub commands."""
    console.print(
        Panel(
            f"[bold yellow]{feature}[/bold yellow]\n\n"
            "This command is not yet implemented.\n"
            "[dim]Coming in a future release.[/dim]",
            title="[cyan]TraceBurn[/cyan]",
            expand=False,
        )
    )


# ── Root group ────────────────────────────────────────────────────────────────


@click.group()
@click.version_option(version=__version__, prog_name="traceburn")
@click.option(
    "--profile",
    default=None,
    metavar="NAME",
    help="Override the active user profile (default: primary).",
)
@click.pass_context
def cli(ctx: click.Context, profile: str | None) -> None:
    """
    TraceBurn — Personal Data Exposure Scanner & Removal Tool.

    Scan data brokers for your personal information, submit opt-out requests,
    and track removal confirmation with tamper-evident proof records.

    Run `traceburn init` to get started.
    """
    ctx.ensure_object(dict)
    ctx.obj["profile"] = profile


# ── version ───────────────────────────────────────────────────────────────────


@cli.command("version")
def cmd_version() -> None:
    """Print TraceBurn version and installation path."""
    script_path = Path(__file__).resolve()
    project_root = script_path.parent.parent
    console.print(f"[bold cyan]TraceBurn[/bold cyan] v{__version__}")
    console.print(f"[dim]Project path:[/dim] {project_root}")
    console.print(f"[dim]Python:[/dim]       {sys.version.split()[0]}")


# ── init ──────────────────────────────────────────────────────────────────────


@cli.command("init")
@click.pass_context
def cmd_init(ctx: click.Context) -> None:
    """
    Run the interactive onboarding wizard.

    Creates ~/.traceburn/, encrypts your PII into the vault, and writes
    your config file. Run this once before any other command.
    """
    try:
        from src.onboarding import run_wizard  # type: ignore[import]

        run_wizard()
    except ImportError:
        _coming_soon("traceburn init — Onboarding Wizard")


# ── scan ──────────────────────────────────────────────────────────────────────


@cli.command("scan")
@click.option(
    "--region",
    type=click.Choice(["US", "EU", "UK", "global"], case_sensitive=False),
    default=None,
    help="Limit scan to brokers in this region.",
)
@click.option(
    "--brokers",
    default="all",
    metavar="all|tier1|NAME",
    help="Which brokers to scan: 'all', 'tier1', or a specific broker name.",
)
@click.option(
    "--full/--spot",
    "scan_type",
    default=True,
    help="Full scan (default) or quick spot-check of high-risk brokers.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Show what would be scanned without running queries.",
)
@click.pass_context
def cmd_scan(
    ctx: click.Context,
    region: str | None,
    brokers: str,
    scan_type: bool,
    dry_run: bool,
) -> None:
    """
    Scan data brokers for your personal information.

    Runs Google dork queries, HIBP breach checks, and Playwright-based
    broker scrapes. Results are saved to the local database.

    Examples:

        traceburn scan

        traceburn scan --region US

        traceburn scan --brokers tier1 --spot
    """
    _coming_soon(
        f"traceburn scan  [region={region or 'all'}  brokers={brokers}  "
        f"type={'full' if scan_type else 'spot'}  dry_run={dry_run}]"
    )


# ── remove ────────────────────────────────────────────────────────────────────


@cli.command("remove")
@click.option(
    "--auto",
    is_flag=True,
    default=False,
    help="Automatically submit all Tier 1 opt-outs without prompts.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Preview which removals would be submitted.",
)
@click.pass_context
def cmd_remove(ctx: click.Context, auto: bool, dry_run: bool) -> None:
    """
    Submit opt-out requests for all confirmed exposures.

    Routes each exposure to the correct removal tier:

      Tier 1 — Automated Playwright form submission

      Tier 2 — Automated opt-out email via SMTP

      Tier 3 — Guided manual wizard (opens browser)
    """
    _coming_soon(f"traceburn remove  [auto={auto}  dry_run={dry_run}]")


# ── status ────────────────────────────────────────────────────────────────────


@cli.command("status")
@click.pass_context
def cmd_status(ctx: click.Context) -> None:
    """
    Show your profile summary and current exposure counts.

    Reads ~/.traceburn/config.yaml and the local database to display:
    active profile, last scan date, active and confirmed removal counts,
    proof records on file, and next scheduled re-verification date.
    """
    config_path = TRACEBURN_DIR / "config.yaml"
    db_path = TRACEBURN_DIR / "traceburn.db"

    # ── Not initialized ───────────────────────────────────────────────────────
    if not config_path.exists():
        console.print(
            Panel(
                "[yellow]TraceBurn is not initialized.[/yellow]\n\n"
                "Run [bold cyan]traceburn init[/bold cyan] to get started.",
                title="[cyan]TraceBurn Status[/cyan]",
                expand=False,
            )
        )
        return

    # ── Load config ───────────────────────────────────────────────────────────
    try:
        import yaml  # type: ignore[import]

        with open(config_path, encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
    except Exception as exc:
        err_console.print(f"[red]Could not read config.yaml: {exc}[/red]")
        sys.exit(1)

    profile_cfg = config.get("profile", {})
    display_name = profile_cfg.get("display_name", "Primary Profile")
    profile_type = profile_cfg.get("profile_type", "primary")

    # ── Query DB if present ───────────────────────────────────────────────────
    last_scan_str = "Never"
    active_removals = 0
    confirmed_removals = 0
    proof_count = 0
    next_reverify_str = "—"

    if db_path.exists():
        try:
            import sqlite3

            conn = sqlite3.connect(str(db_path))
            cur = conn.cursor()

            # Last scan date
            try:
                cur.execute(
                    "SELECT MAX(completed_at) FROM scan_history WHERE completed_at IS NOT NULL"
                )
                row = cur.fetchone()
                if row and row[0]:
                    last_scan_dt = datetime.fromisoformat(str(row[0]))
                    last_scan_str = last_scan_dt.strftime("%B %-d, %Y at %-I:%M %p UTC")
            except sqlite3.OperationalError:
                pass

            # Active removals (pending / submitted / awaiting_confirmation)
            try:
                cur.execute(
                    "SELECT COUNT(*) FROM removal_requests "
                    "WHERE status IN ('pending','submitted','awaiting_confirmation','retrying')"
                )
                row = cur.fetchone()
                if row:
                    active_removals = row[0]
            except sqlite3.OperationalError:
                pass

            # Confirmed removals
            try:
                cur.execute(
                    "SELECT COUNT(*) FROM removal_requests WHERE status = 'confirmed'"
                )
                row = cur.fetchone()
                if row:
                    confirmed_removals = row[0]
            except sqlite3.OperationalError:
                pass

            # Proof records on file
            try:
                cur.execute("SELECT COUNT(*) FROM proof_records")
                row = cur.fetchone()
                if row:
                    proof_count = row[0]
            except sqlite3.OperationalError:
                pass

            # Next re-verification date
            try:
                cur.execute(
                    "SELECT MIN(next_check_at) FROM removal_requests "
                    "WHERE next_check_at IS NOT NULL AND status = 'confirmed'"
                )
                row = cur.fetchone()
                if row and row[0]:
                    next_dt = datetime.fromisoformat(str(row[0]))
                    next_reverify_str = next_dt.strftime("%B %-d, %Y")
            except sqlite3.OperationalError:
                pass

            conn.close()
        except Exception:
            pass  # DB not yet initialized — show defaults

    # ── Render ────────────────────────────────────────────────────────────────
    console.print()
    console.rule("[bold cyan]TraceBurn Status[/bold cyan]")
    console.print()

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column(style="dim", width=26)
    table.add_column()

    table.add_row("Profile", f"[bold]{display_name}[/bold] [dim]({profile_type})[/dim]")
    table.add_row("Last scan", last_scan_str)
    table.add_row("Active removals", str(active_removals))
    table.add_row("Confirmed removals", str(confirmed_removals))
    table.add_row("Proof records on file", str(proof_count))
    table.add_row("Next re-verification", next_reverify_str)
    table.add_row("Config file", str(config_path))
    table.add_row("Database", str(db_path) if db_path.exists() else "[dim]not initialized[/dim]")

    console.print(table)
    console.rule()
    console.print()

    if last_scan_str == "Never":
        console.print(
            "  [yellow]No scans have been run yet.[/yellow]\n"
            "  Run [bold cyan]traceburn scan[/bold cyan] to search for your data."
        )
    else:
        console.print(
            "  Run [bold cyan]traceburn scan[/bold cyan] to check for new exposures."
        )
    console.print()


# ── report ────────────────────────────────────────────────────────────────────


@cli.command("report")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["html", "pdf", "json"], case_sensitive=False),
    default="html",
    show_default=True,
    help="Output format for the report.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    metavar="PATH",
    help="Write report to this file path (default: reports/report.<fmt>).",
)
@click.pass_context
def cmd_report(ctx: click.Context, fmt: str, output: str | None) -> None:
    """
    Generate an exposure and removal status report.

    Produces a human-readable summary of all scanned brokers, confirmed
    exposures, removal requests, and proof records.
    """
    _coming_soon(f"traceburn report  [format={fmt}  output={output or 'auto'}]")


# ── history ───────────────────────────────────────────────────────────────────


@cli.command("history")
@click.option(
    "--lines",
    "-n",
    default=20,
    show_default=True,
    metavar="N",
    help="Number of audit log lines to display.",
)
@click.pass_context
def cmd_history(ctx: click.Context, lines: int) -> None:
    """
    Show recent audit log entries.

    The audit log records every action TraceBurn takes: scans, removal
    submissions, proof captures, and system events. No PII is written to
    this log.
    """
    audit_log = TRACEBURN_DIR / "audit.log"

    if not audit_log.exists():
        console.print(
            "[yellow]Audit log not found.[/yellow] "
            "Run [bold cyan]traceburn init[/bold cyan] to get started."
        )
        return

    try:
        all_lines = audit_log.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        err_console.print(f"[red]Error reading audit log: {exc}[/red]")
        sys.exit(1)

    if not all_lines:
        console.print("[dim]Audit log is empty.[/dim]")
        return

    tail = all_lines[-lines:]

    console.print()
    console.rule(f"[bold cyan]Audit Log[/bold cyan] [dim](last {len(tail)} entries)[/dim]")
    console.print()

    for line in tail:
        # Colour log levels
        if " ERROR " in line:
            console.print(f"  [red]{line}[/red]")
        elif " WARN " in line:
            console.print(f"  [yellow]{line}[/yellow]")
        elif " INFO " in line:
            console.print(f"  [dim]{line}[/dim]")
        else:
            console.print(f"  {line}")

    console.print()
    console.rule()
    console.print(
        f"\n  [dim]Log file:[/dim] {audit_log}  "
        f"[dim]({len(all_lines)} total entries)[/dim]\n"
    )


# ── profiles subgroup ─────────────────────────────────────────────────────────


@cli.group("profiles")
def profiles_group() -> None:
    """Manage user profiles (primary and family member profiles)."""


@profiles_group.command("add")
@click.argument("name")
@click.pass_context
def profiles_add(ctx: click.Context, name: str) -> None:
    """Add a new scanning profile with the given NAME."""
    _coming_soon(f"traceburn profiles add '{name}'")


@profiles_group.command("list")
@click.pass_context
def profiles_list(ctx: click.Context) -> None:
    """List all configured profiles."""
    _coming_soon("traceburn profiles list")


@profiles_group.command("delete")
@click.argument("name")
@click.pass_context
def profiles_delete(ctx: click.Context, name: str) -> None:
    """Delete the profile with the given NAME."""
    _coming_soon(f"traceburn profiles delete '{name}'")


# ── proof subgroup ────────────────────────────────────────────────────────────


@cli.group("proof")
def proof_group() -> None:
    """Manage tamper-evident removal proof records."""


@proof_group.command("list")
@click.option("--broker", default=None, metavar="DOMAIN", help="Filter by broker domain.")
@click.pass_context
def proof_list(ctx: click.Context, broker: str | None) -> None:
    """List all stored proof records."""
    _coming_soon(f"traceburn proof list  [broker={broker or 'all'}]")


@proof_group.command("export")
@click.argument("removal_request_id", type=int)
@click.option(
    "--output",
    "-o",
    default=None,
    metavar="PATH",
    help="Destination path for the exported proof bundle.",
)
@click.pass_context
def proof_export(
    ctx: click.Context, removal_request_id: int, output: str | None
) -> None:
    """Export the proof bundle for REMOVAL_REQUEST_ID."""
    _coming_soon(f"traceburn proof export {removal_request_id}")


# ── vault subgroup ────────────────────────────────────────────────────────────


@cli.group("vault")
def vault_group() -> None:
    """Manage the encrypted PII vault."""


@vault_group.command("rekey")
@click.pass_context
def vault_rekey(ctx: click.Context) -> None:
    """
    Re-encrypt the vault with a new passphrase.

    You will be prompted for your current passphrase and a new passphrase.
    All encrypted fields are re-encrypted atomically — the vault is never
    left in a partially re-keyed state.
    """
    _coming_soon("traceburn vault rekey")


# ── schedule subgroup ─────────────────────────────────────────────────────────


@cli.group("schedule")
def schedule_group() -> None:
    """Manage the background scan schedule."""


@schedule_group.command("status")
@click.pass_context
def schedule_status(ctx: click.Context) -> None:
    """Show the current scan schedule and next run time."""
    _coming_soon("traceburn schedule status")


@schedule_group.command("pause")
@click.pass_context
def schedule_pause(ctx: click.Context) -> None:
    """Pause the background scheduler."""
    _coming_soon("traceburn schedule pause")


@schedule_group.command("resume")
@click.pass_context
def schedule_resume(ctx: click.Context) -> None:
    """Resume the background scheduler."""
    _coming_soon("traceburn schedule resume")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
