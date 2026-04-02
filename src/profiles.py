"""
src/profiles.py — Profile lifecycle management for TraceBurn.

ProfileManager handles creating, listing, retrieving, and deleting user profiles.
It also surfaces lifecycle alerts (upcoming birthdays, age-18 transitions) that
are shown at CLI startup via `check_lifecycle_events()`.

Usage:
    manager = ProfileManager(db=db_gateway, vault=vault)
    manager.list_profiles()
    alerts = manager.check_lifecycle_events()
    for alert in alerts:
        console.print(alert)
"""

from __future__ import annotations

import json
import logging
from datetime import date, datetime
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table

from .onboarding import AddressRecord, UserProfile, run_mini_wizard

if TYPE_CHECKING:
    from .vault import PIIVault

logger = logging.getLogger(__name__)
console = Console()


class ProfileManager:
    """
    Manages the full lifecycle of TraceBurn user profiles.

    Responsibilities:
        - Create new profiles via the mini onboarding wizard
        - List all profiles in a formatted terminal table
        - Retrieve a profile by ID from the database
        - Delete a profile with an explicit Rich Confirm prompt (never silent)
        - Detect and surface upcoming birthday and age-18 lifecycle events

    Args:
        db:    Database gateway providing CRUD operations on profile records.
        vault: PIIVault instance for reading encrypted PII.
    """

    def __init__(self, db: object, vault: "PIIVault") -> None:
        self._db = db
        self._vault = vault

    # ──────────────────────────────────────────────────────────────
    # Profile creation
    # ──────────────────────────────────────────────────────────────

    def add_profile(self, wizard: bool = True) -> UserProfile:
        """
        Add a new profile, optionally running the mini onboarding wizard.

        Prompts the user to choose between 'family_member' (full management)
        and 'monitored_only' (scan and alerts, no removals), then collects
        name, emails, phone, address(es), and DOB via the mini wizard.

        Args:
            wizard: If True, run the interactive mini wizard (steps 1–5).
                    If False, raises ValueError — non-wizard creation is not yet
                    implemented and must be done through the wizard.

        Returns:
            UserProfile populated with the collected information.
        """
        if not wizard:
            raise ValueError(
                "Non-wizard profile creation is not yet implemented. "
                "Call add_profile(wizard=True) to use the interactive flow."
            )

        console.print()
        console.print("  [bold]Profile type:[/]")
        console.print("    [cyan][1][/] Family member [dim](full management — scan, remove, proof)[/]")
        console.print("    [cyan][2][/] Monitored only [dim](scan and alerts, no removals)[/]")
        console.print()

        while True:
            try:
                choice = console.input("  Choose [cyan][1/2][/]: ").strip()
                if choice == "1":
                    profile_type = "family_member"
                    break
                elif choice == "2":
                    profile_type = "monitored_only"
                    break
                else:
                    console.print("  [yellow]Please enter 1 or 2.[/]")
            except (EOFError, KeyboardInterrupt):
                raise

        profile = run_mini_wizard(profile_type=profile_type)

        # Persist metadata to database
        try:
            self._db.create_profile(
                display_name=profile.name,
                profile_type=profile_type,
                name_variants_json=json.dumps(profile.name_variants),
                emails_count=len(profile.emails),
                addresses_count=len(profile.addresses),
            )
            slug = profile.name.lower().replace(" ", "-")
            console.print()
            console.print(
                f"  [green]✓ Profile created.[/] "
                f"Run [italic]traceburn scan --profile {slug}[/] to scan."
            )
        except Exception as exc:
            logger.error("Failed to persist profile '%s' to database: %s", profile.name, exc)
            console.print(
                f"\n  [yellow]⚠ Profile data collected but could not be saved to the database.[/]\n"
                f"    Error: {exc}\n"
                f"    Check the log at [italic]~/.traceburn/logs/traceburn.log[/] for details."
            )

        return profile

    # ──────────────────────────────────────────────────────────────
    # Listing
    # ──────────────────────────────────────────────────────────────

    def list_profiles(self) -> None:
        """
        Print a Rich table of all configured profiles.

        Columns: ID | Name | Type | Last Scan | Active Removals | Status

        Prints a helpful hint about next commands after the table.
        """
        try:
            profiles = self._db.list_profiles()
        except Exception as exc:
            console.print(f"  [red]Could not load profiles: {exc}[/]")
            return

        if not profiles:
            console.print(
                "  [dim]No profiles configured. "
                "Run [italic]traceburn init[/] to get started.[/]"
            )
            return

        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            padding=(0, 1),
        )
        table.add_column("ID", justify="right", style="dim", no_wrap=True)
        table.add_column("Name")
        table.add_column("Type")
        table.add_column("Last Scan")
        table.add_column("Active Removals", justify="right")
        table.add_column("Status")

        for p in profiles:
            last_scan_raw = p.get("last_scan_at")
            last_scan = _format_date(last_scan_raw) if last_scan_raw else "[dim]Never[/]"
            removals = str(p.get("active_removals", 0))
            status = _profile_status_display(p)
            profile_type = (
                p.get("profile_type", "primary").replace("_", " ").title()
            )

            table.add_row(
                str(p.get("id", "—")),
                p.get("display_name", "Unknown"),
                profile_type,
                last_scan,
                removals,
                status,
            )

        console.print()
        console.print(table)
        console.print()
        console.print(
            "  Run [italic]traceburn scan --profile <name>[/] to scan a specific profile.\n"
            "  Run [italic]traceburn profiles add[/] to add a new profile."
        )
        console.print()

    # ──────────────────────────────────────────────────────────────
    # Retrieval
    # ──────────────────────────────────────────────────────────────

    def get_profile(self, profile_id: int) -> UserProfile:
        """
        Retrieve a profile record by its database ID.

        Reconstructs a UserProfile from the DB record. PII fields (emails,
        phones, addresses, DOB) are not decrypted here — callers that need
        PII must unlock the vault separately.

        Args:
            profile_id: Integer primary key of the profile in the database.

        Returns:
            UserProfile with metadata populated from the DB record.

        Raises:
            KeyError: if no profile with the given ID exists.
        """
        try:
            record = self._db.get_profile(profile_id)
        except Exception as exc:
            raise KeyError(f"Profile {profile_id} not found: {exc}") from exc

        if record is None:
            raise KeyError(f"Profile {profile_id} not found.")

        # Reconstruct name_variants from the JSON column (non-sensitive)
        name_variants: list[str] = []
        try:
            raw = record.get("name_variants_json") or "[]"
            name_variants = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            pass

        return UserProfile(
            name=record.get("display_name", ""),
            name_suffix="",
            name_variants=name_variants,
            emails=[],   # PII — requires vault unlock
            phones=[],   # PII — requires vault unlock
            addresses=[], # PII — requires vault unlock
            dob="",      # PII — requires vault unlock
            profile_type=record.get("profile_type", "primary"),
            notifications_enabled=False,
        )

    # ──────────────────────────────────────────────────────────────
    # Deletion
    # ──────────────────────────────────────────────────────────────

    def delete_profile(self, profile_id: int) -> None:
        """
        Delete a profile and all associated data, with mandatory confirmation.

        Presents a prominent summary of what will be deleted, then asks the
        user to confirm via a Rich Confirm prompt. If the user declines, the
        profile is left completely unchanged.

        NEVER silently modifies or removes any profile.

        Args:
            profile_id: Database ID of the profile to delete.
        """
        try:
            record = self._db.get_profile(profile_id)
        except Exception as exc:
            console.print(f"  [red]Could not retrieve profile {profile_id}: {exc}[/]")
            return

        if record is None:
            console.print(f"  [red]No profile found with ID {profile_id}.[/]")
            return

        display_name = record.get("display_name", f"Profile #{profile_id}")
        profile_type = record.get("profile_type", "unknown").replace("_", " ").title()

        console.print()
        console.print(Panel(
            f"[bold]Profile to delete:[/]\n\n"
            f"  Name:  {display_name}\n"
            f"  Type:  {profile_type}\n"
            f"  ID:    {profile_id}\n\n"
            f"[yellow]This will permanently delete:[/]\n"
            f"  • All scan history for this profile\n"
            f"  • All removal request records\n"
            f"  • All proof screenshots\n"
            f"  • All PII stored in the vault for this profile\n\n"
            f"[bold red]This action cannot be undone.[/]",
            title="[bold red]Delete Profile[/]",
            border_style="red",
        ))
        console.print()

        confirmed = Confirm.ask(
            f"  Are you sure you want to permanently delete [bold]{display_name}[/]?",
            default=False,
        )

        if not confirmed:
            console.print("  [green]Deletion cancelled. Profile is unchanged.[/]\n")
            return

        try:
            self._db.delete_profile(profile_id)
            self._delete_profile_pii(profile_id)
            console.print(
                f"  [green]✓ Profile [bold]{display_name}[/] and all associated data deleted.[/]\n"
            )
        except Exception as exc:
            logger.error("Failed to delete profile %d: %s", profile_id, exc)
            console.print(
                f"  [red]✗ Could not delete profile: {exc}[/]\n"
                "    Check the log at [italic]~/.traceburn/logs/traceburn.log[/] for details."
            )

    # ──────────────────────────────────────────────────────────────
    # Lifecycle events
    # ──────────────────────────────────────────────────────────────

    def check_lifecycle_events(self) -> list[str]:
        """
        Check all profiles for upcoming or recent lifecycle events.

        Intended to be called at CLI startup. Returns alert messages for the CLI
        to display. Also prints a prominent red panel for age-18 transitions.

        Checks performed:
            1. Annual birthday within the next 7 days → birthday reminder.
            2. family_member profile turning 18 within 30 days OR who turned 18
               within the last 7 days → prominent alert in a red panel.

        NEVER silently modifies or removes any profile regardless of age.

        Returns:
            List of plain-text (with Rich markup) alert strings.
            Empty list if no events are due.
        """
        alerts: list[str] = []

        try:
            profiles = self._db.list_profiles_with_dob()
        except Exception as exc:
            logger.warning("check_lifecycle_events: could not load profiles: %s", exc)
            return alerts

        today = date.today()

        for p in profiles:
            dob_plain = p.get("dob_plain")
            if not dob_plain:
                continue

            try:
                dob = date.fromisoformat(str(dob_plain))
            except ValueError:
                logger.debug(
                    "check_lifecycle_events: invalid DOB '%s' for profile %s",
                    dob_plain,
                    p.get("id"),
                )
                continue

            name = p.get("display_name", "Unknown")

            # ── Annual birthday reminder ──────────────────────────────
            upcoming_birthday = _next_birthday(dob, today)
            days_to_birthday = (upcoming_birthday - today).days

            if 0 <= days_to_birthday <= 7:
                if days_to_birthday == 0:
                    msg = f"🎂 Today is [bold]{name}[/]'s birthday!"
                elif days_to_birthday == 1:
                    msg = f"🎂 [bold]{name}[/]'s birthday is tomorrow."
                else:
                    birthday_str = upcoming_birthday.strftime("%B %d")
                    msg = (
                        f"🎂 [bold]{name}[/]'s birthday is in {days_to_birthday} days "
                        f"({birthday_str})."
                    )
                alerts.append(msg)

            # ── Age-18 transition alert (family_member profiles only) ──
            if p.get("profile_type") == "family_member":
                try:
                    eighteenth = date(dob.year + 18, dob.month, dob.day)
                except ValueError:
                    # Feb 29 DOB — use Feb 28 for the 18th birthday
                    eighteenth = date(dob.year + 18, 2, 28)

                days_to_18 = (eighteenth - today).days
                eighteenth_str = eighteenth.strftime("%B %d, %Y")

                # Alert window: up to 30 days before or 7 days after the 18th birthday
                if -7 <= days_to_18 <= 30:
                    slug = name.lower().replace(" ", "-")

                    if days_to_18 >= 0:
                        verb = "turns"
                        urgency = f"in {days_to_18} days" if days_to_18 > 0 else "today"
                    else:
                        verb = "turned"
                        urgency = f"{abs(days_to_18)} day(s) ago"

                    alert_msg = (
                        f"[bold red]ALERT[/] Profile [bold]{name}[/] {verb} 18 on "
                        f"[bold]{eighteenth_str}[/] ({urgency}). "
                        f"Their protection settings may need review."
                    )
                    alerts.append(alert_msg)

                    # Print a standalone prominent panel — cannot be missed
                    console.print()
                    console.print(Panel(
                        f"[bold]{name}[/] {verb} 18 on [bold]{eighteenth_str}[/].\n\n"
                        f"Family member profiles continue unchanged after age 18.\n"
                        f"No action is required unless you want to review their settings.\n\n"
                        f"Run: [italic]traceburn profiles review --profile {slug}[/]",
                        title="[bold red]Age-18 Transition Alert[/]",
                        border_style="red",
                    ))
                    console.print()

        return alerts

    # ──────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────

    def _delete_profile_pii(self, profile_id: int) -> None:
        """Remove all vault keys that belong to this profile."""
        prefix = f"profile_{profile_id}_"
        for key in self._vault.list_keys():
            if key.startswith(prefix):
                self._vault.delete(key)


# ──────────────────────────────────────────────────────────────
# Module-level helpers
# ──────────────────────────────────────────────────────────────


def _next_birthday(dob: date, as_of: date) -> date:
    """
    Return the next annual occurrence of *dob* on or after *as_of*.

    Handles Feb 29 leap birthdays by substituting Feb 28 in non-leap years.

    Args:
        dob:   The person's date of birth.
        as_of: The reference date (typically today).

    Returns:
        The next upcoming birthday as a date object.
    """
    year = as_of.year
    try:
        candidate = date(year, dob.month, dob.day)
    except ValueError:
        candidate = date(year, 2, 28)

    if candidate < as_of:
        year += 1
        try:
            candidate = date(year, dob.month, dob.day)
        except ValueError:
            candidate = date(year, 2, 28)

    return candidate


def _format_date(dt: "datetime | str | None") -> str:
    """Format a datetime or ISO-format string as YYYY-MM-DD for table display."""
    if dt is None:
        return "—"
    try:
        if isinstance(dt, str):
            dt = datetime.fromisoformat(dt)
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return str(dt)


def _profile_status_display(p: dict) -> str:
    """Return a Rich-markup status string for a profile row in the list table."""
    open_exposures = p.get("open_exposures", 0)
    active_removals = p.get("active_removals", 0)

    if open_exposures and open_exposures > 0:
        return f"[yellow]{open_exposures} exposure(s) found[/]"
    if active_removals and active_removals > 0:
        return f"[cyan]{active_removals} removal(s) in progress[/]"
    last_scan = p.get("last_scan_at")
    if not last_scan:
        return "[dim]Not yet scanned[/]"
    return "[green]Clear[/]"
