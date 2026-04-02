"""
src/onboarding.py — TraceBurn first-run setup wizard.

Guides the user through a Rich-powered terminal wizard that collects PII,
encrypts it into the vault, and writes non-sensitive config to
~/.traceburn/config.yaml. Target: completes in under 5 minutes.

Entry point for `traceburn init`:
    profile = run_wizard()

Mini-wizard for family member profiles (steps 1–5 only):
    profile = run_mini_wizard(profile_type="family_member")
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

from .vault import PIIVault

console = Console()

CONFIG_DIR: Path = Path.home() / ".traceburn"
CONFIG_PATH: Path = CONFIG_DIR / "config.yaml"
VAULT_PATH: Path = CONFIG_DIR / "vault.enc"

# E.164 phone regex: + followed by 1–15 digits
_E164_RE = re.compile(r"^\+[1-9]\d{1,14}$")
# Permissive email regex — catches obvious mistakes without false negatives
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Common given-name → nickname mappings used to auto-generate scan variants
_NICKNAMES: dict[str, list[str]] = {
    "alexander": ["alex"],
    "barbara": ["barb"],
    "benjamin": ["ben"],
    "catherine": ["cathy", "kate"],
    "charles": ["charlie", "chuck"],
    "christopher": ["chris"],
    "clifford": ["cliff"],
    "daniel": ["dan"],
    "david": ["dave"],
    "dorothy": ["dot"],
    "edward": ["ed", "eddie"],
    "elizabeth": ["liz", "beth"],
    "james": ["jim"],
    "jennifer": ["jen"],
    "john": ["johnny"],
    "joseph": ["joe"],
    "margaret": ["maggie", "peggy"],
    "matthew": ["matt"],
    "michael": ["mike"],
    "nathaniel": ["nate"],
    "nicholas": ["nick"],
    "patricia": ["pat", "trish"],
    "richard": ["rick"],
    "robert": ["rob", "bob"],
    "samantha": ["sam"],
    "susan": ["sue"],
    "theodore": ["ted", "theo"],
    "thomas": ["tom"],
    "timothy": ["tim"],
    "virginia": ["ginny"],
    "william": ["will", "bill"],
}


# ──────────────────────────────────────────────────────────────
# Data structures
# ──────────────────────────────────────────────────────────────


@dataclass
class AddressRecord:
    """Structured representation of a single mailing address."""

    street: str
    city: str
    state: str
    postal_code: str
    country: str = "US"

    def display(self) -> str:
        """Return a single-line human-readable address string."""
        return f"{self.street}, {self.city}, {self.state} {self.postal_code}, {self.country}"

    def to_dict(self) -> dict:
        """Serialize to plain dict for JSON storage."""
        return {
            "street": self.street,
            "city": self.city,
            "state": self.state,
            "postal_code": self.postal_code,
            "country": self.country,
        }


@dataclass
class UserProfile:
    """
    Output of the onboarding wizard. Returned to the CLI after setup.

    PII is encrypted in the vault; this record carries vault-friendly metadata
    and non-sensitive display values. The vault_path field points to the
    vault file holding the encrypted PII.
    """

    name: str
    """Full display name, e.g. 'Jane M. Smith'."""

    name_suffix: str
    """Name suffix, e.g. 'Jr.' or '' if none."""

    name_variants: list[str]
    """All name variations to search — primary name plus auto-generated and custom variants."""

    emails: list[str]
    """All email addresses; primary is first."""

    phones: list[str]
    """E.164-formatted phone numbers."""

    addresses: list[AddressRecord]
    """Current address first, followed by prior addresses."""

    dob: str
    """Date of birth in ISO 8601 format (YYYY-MM-DD)."""

    profile_type: str = "primary"
    """'primary' | 'family_member' | 'monitored_only'."""

    notifications_enabled: bool = False
    """True if Telegram notifications were successfully configured."""

    vault_path: str = str(VAULT_PATH)
    """Absolute path to the encrypted vault file."""


# ──────────────────────────────────────────────────────────────
# Public entry points
# ──────────────────────────────────────────────────────────────


def run_wizard() -> UserProfile:
    """
    Run the TraceBurn first-run setup wizard.

    Walks the user through 9 steps: welcome, name, email(s), phone, address(es),
    date of birth, vault passphrase, optional Telegram setup, and Playwright
    browser installation. Saves PII to the encrypted vault and non-sensitive
    config to ~/.traceburn/config.yaml.

    Returns:
        UserProfile with all collected information.

    Raises:
        KeyboardInterrupt: if the user aborts with Ctrl-C (propagated cleanly).
    """
    start_time = time.monotonic()

    # Step 0: Welcome panel
    _step_welcome()

    # Step 1: Full name
    name, name_suffix, name_variants = _step_name()

    # Steps 2 & 3: Email addresses
    emails = _step_emails()

    # Step 3: Phone number(s)
    phones = _step_phone()

    # Step 4: Addresses (current + prior)
    addresses = _step_addresses()

    # Step 5: Date of birth
    dob = _step_dob()

    # Step 6: Vault passphrase — create and encrypt
    passphrase = _step_passphrase()

    # Persist all PII to the vault
    vault = PIIVault(vault_path=VAULT_PATH)
    _save_to_vault(
        vault=vault,
        passphrase=passphrase,
        name=name,
        name_suffix=name_suffix,
        name_variants=name_variants,
        emails=emails,
        phones=phones,
        addresses=addresses,
        dob=dob,
    )
    # Zero the passphrase from memory immediately after vault write
    passphrase = "\x00" * len(passphrase)
    del passphrase

    # Step 7: Telegram notifications (optional)
    notifications_enabled = _step_notifications()

    # Step 8: Install Playwright Chromium
    _step_install_browser()

    # Build the profile object
    profile = UserProfile(
        name=name,
        name_suffix=name_suffix,
        name_variants=name_variants,
        emails=emails,
        phones=phones,
        addresses=addresses,
        dob=dob,
        profile_type="primary",
        notifications_enabled=notifications_enabled,
    )

    # Step 9: Completion summary
    elapsed = time.monotonic() - start_time
    _step_completion(profile, elapsed)

    # Save non-sensitive config to disk
    _save_config(profile, notifications_enabled)

    return profile


def run_mini_wizard(profile_type: str = "family_member") -> UserProfile:
    """
    Abbreviated wizard for adding a family member or monitored profile.

    Runs steps 1–5 only: name, emails, phone, addresses, and date of birth.
    The vault passphrase and notifications are inherited from the primary profile.

    Args:
        profile_type: "family_member" or "monitored_only".

    Returns:
        UserProfile with PII fields populated; vault and notification fields
        carry default values for the caller to set if needed.
    """
    console.print()
    console.print(Panel(
        f"[bold cyan]Adding a new profile — "
        f"{profile_type.replace('_', ' ').title()}[/]\n\n"
        "This person must have given you explicit permission to scan and remove their data.",
        border_style="cyan",
    ))
    console.print()

    name, name_suffix, name_variants = _step_name()
    emails = _step_emails()
    phones = _step_phone()
    addresses = _step_addresses()
    dob = _step_dob()

    return UserProfile(
        name=name,
        name_suffix=name_suffix,
        name_variants=name_variants,
        emails=emails,
        phones=phones,
        addresses=addresses,
        dob=dob,
        profile_type=profile_type,
        notifications_enabled=False,
    )


# ──────────────────────────────────────────────────────────────
# Wizard steps
# ──────────────────────────────────────────────────────────────


def _step_welcome() -> None:
    """Step 0: Display welcome panel explaining what TraceBurn does."""
    console.print()
    console.print(Panel(
        "[bold white]TraceBurn Setup — under 5 minutes[/]\n\n"
        "Welcome. This setup runs entirely on your computer.\n"
        "[bold]Nothing you enter here is sent anywhere.[/]\n\n"
        "[cyan]What gets stored:[/]\n"
        "  • Your name, email, phone, address, and date of birth\n"
        "  • Encrypted locally with a passphrase only you know\n\n"
        "[cyan]What never leaves your device:[/]\n"
        "  • All PII — encrypted in an AES-256-GCM vault\n"
        "    at [italic]~/.traceburn/vault.enc[/]\n"
        "  • Your passphrase — never stored anywhere\n\n"
        "[cyan]What happens during setup:[/]\n"
        "  1. You enter your details (used to search broker sites)\n"
        "  2. You create a passphrase to encrypt those details\n"
        "  3. Optionally connect Telegram for removal alerts\n"
        "  4. TraceBurn installs the browser it uses to submit opt-outs",
        title="[bold cyan]TraceBurn[/]",
        border_style="cyan",
        padding=(1, 2),
    ))
    console.print()


def _step_name() -> tuple[str, str, list[str]]:
    """
    Step 1: Collect full name with optional middle name/initial and suffix.

    Automatically generates name variants (with/without suffix, common nicknames).
    Allows the user to add custom variants such as maiden names.

    Returns:
        (display_name, suffix, name_variants)
    """
    _print_step_header(
        "Your Name",
        "Data brokers index records by name. The more name variants you\n"
        "provide, the more complete the scan.",
    )

    while True:
        try:
            first = Prompt.ask("  [cyan]First name[/]").strip()
            middle = Prompt.ask(
                "  [cyan]Middle name or initial[/] [dim](press Enter to skip)[/]",
                default="",
            ).strip()
            last = Prompt.ask("  [cyan]Last name[/]").strip()
            suffix = Prompt.ask(
                "  [cyan]Suffix[/] [dim](Jr., Sr., II, etc. — press Enter to skip)[/]",
                default="",
            ).strip()

            if not first or not last:
                console.print("  [yellow]First and last name are required. Please try again.[/]\n")
                continue

            # Build structured display name
            parts = [first]
            if middle:
                parts.append(middle)
            parts.append(last)
            if suffix:
                parts.append(suffix)
            display_name = " ".join(parts)

            # Auto-generate scan variants
            mid_initial = (middle[0].upper() + ".") if middle else ""
            base = f"{first} {last}"

            variants: list[str] = [base]
            if middle:
                variants.append(f"{first} {mid_initial} {last}")
            if suffix:
                variants.append(f"{first} {last} {suffix}")
                if middle:
                    variants.append(f"{first} {mid_initial} {last} {suffix}")

            # Nickname variants
            for nickname in _NICKNAMES.get(first.lower(), []):
                nick = nickname.title()
                variants.append(f"{nick} {last}")
                if suffix:
                    variants.append(f"{nick} {last} {suffix}")

            # Deduplicate while preserving insertion order
            seen: set[str] = set()
            unique: list[str] = []
            for v in variants:
                if v not in seen:
                    seen.add(v)
                    unique.append(v)

            console.print()
            console.print("  [green]Name variants to scan:[/]")
            for v in unique:
                console.print(f"    • {v}")
            console.print()

            # Allow custom additions
            while True:
                add_more = Confirm.ask(
                    "  Add another name variant? [dim](e.g. maiden name, nickname)[/]",
                    default=False,
                )
                if not add_more:
                    break
                extra = Prompt.ask("  [cyan]Additional name[/]").strip()
                if extra and extra not in seen:
                    unique.append(extra)
                    seen.add(extra)
                    console.print(f"  [green]✓[/] {extra}")

            console.print()
            return display_name, suffix, unique

        except (EOFError, KeyboardInterrupt):
            raise


def _step_emails() -> list[str]:
    """
    Steps 2 & 3: Collect primary email then any additional email addresses.

    Validates format with regex before accepting each address.

    Returns:
        List of validated lowercase email addresses (primary first).
    """
    _print_step_header(
        "Email Addresses",
        "Data brokers often index old email addresses. Adding them\n"
        "improves scan coverage.",
    )

    emails: list[str] = []

    # Primary email — mandatory
    while True:
        try:
            raw = Prompt.ask("  [cyan]Primary email address[/]").strip().lower()
            if _EMAIL_RE.match(raw):
                emails.append(raw)
                console.print(f"  [green]✓[/] {raw}")
                break
            console.print(
                f"\n  [yellow]✗ That doesn't look like a valid email address.[/]\n"
                f"    You entered: [bold]{raw}[/]\n"
                f"    Please include the @ symbol and a domain, e.g. jane@example.com\n"
            )
        except (EOFError, KeyboardInterrupt):
            raise

    # Additional emails — optional loop
    console.print()
    while True:
        try:
            add_more = Confirm.ask("  Add another email address?", default=False)
            if not add_more:
                break
            raw = Prompt.ask("  [cyan]Email[/]").strip().lower()
            if not _EMAIL_RE.match(raw):
                console.print(
                    "  [yellow]✗ Invalid format.[/] "
                    "Please include the @ symbol and a domain.\n"
                )
                continue
            if raw not in emails:
                emails.append(raw)
            console.print(f"  [green]✓[/] {raw}")
        except (EOFError, KeyboardInterrupt):
            raise

    console.print()
    return emails


def _step_phone() -> list[str]:
    """
    Step 3: Collect phone number(s), normalized to E.164.

    Accepts US 10-digit numbers and international numbers with country codes.
    Strips all formatting before validating.

    Returns:
        List of E.164-formatted phone strings (e.g. "+15558675309").
    """
    _print_step_header(
        "Phone Number",
        "Include your country code. US example: +1 555 867 5309",
    )

    phones: list[str] = []

    # Primary phone — mandatory
    while True:
        try:
            raw = Prompt.ask(
                "  [cyan]Phone number[/] "
                "[dim](with country code, e.g. +1 555 867 5309)[/]"
            ).strip()
            normalized = _normalize_phone(raw)
            if normalized:
                phones.append(normalized)
                console.print(f"  [green]✓[/] {_format_phone_display(normalized)}")
                break
            console.print(
                f"\n  [yellow]✗ Invalid phone number.[/]\n"
                f"    You entered: [bold]{raw}[/]\n"
                f"    Must be at least 10 digits after stripping formatting.\n"
                f"    Include your country code, e.g. +1 for US/Canada.\n"
            )
        except (EOFError, KeyboardInterrupt):
            raise

    # Additional phones — optional
    console.print()
    while True:
        try:
            add_more = Confirm.ask("  Add another phone number?", default=False)
            if not add_more:
                break
            raw = Prompt.ask("  [cyan]Phone number[/]").strip()
            normalized = _normalize_phone(raw)
            if not normalized:
                console.print(
                    "  [yellow]✗ Invalid phone number.[/] "
                    "Must be at least 10 digits. Include country code.\n"
                )
                continue
            if normalized not in phones:
                phones.append(normalized)
            console.print(f"  [green]✓[/] {_format_phone_display(normalized)}")
        except (EOFError, KeyboardInterrupt):
            raise

    console.print()
    return phones


def _step_addresses() -> list[AddressRecord]:
    """
    Step 4: Collect current address then any prior addresses.

    More prior addresses = better scan coverage since brokers cache historical records.

    Returns:
        List of AddressRecord objects (current address at index 0).
    """
    _print_step_header("Current Address", "")

    addresses: list[AddressRecord] = []

    addr = _collect_single_address()
    addresses.append(addr)
    console.print(f"  [green]✓[/] {addr.display()}")
    console.print()

    # Prior addresses
    console.print(
        "  [dim]Data brokers hold historical address records. Old addresses\n"
        "  often still appear in their databases years after you moved.\n"
        "  Scanning prior addresses finds and removes this stale data.[/]\n"
    )

    while True:
        try:
            add_more = Confirm.ask(
                "  Add a prior address? "
                "[dim]Brokers store history — the more you add, the better coverage.[/]",
                default=False,
            )
            if not add_more:
                break
            prior = _collect_single_address()
            addresses.append(prior)
            console.print(f"  [green]✓[/] {prior.display()}")
            console.print()
        except (EOFError, KeyboardInterrupt):
            raise

    return addresses


def _step_dob() -> str:
    """
    Step 5: Collect date of birth in YYYY-MM-DD (ISO 8601) format.

    Returns:
        Validated ISO 8601 date string.
    """
    _print_step_header(
        "Date of Birth",
        "Your date of birth is used only to match your records on data broker sites.\n"
        "Many brokers list DOB to distinguish people with the same name.\n"
        "It is stored encrypted on this computer and never sent anywhere.",
    )
    console.print(
        "  [dim]Used only to match broker profiles — never transmitted anywhere.[/]\n"
    )

    while True:
        try:
            raw = Prompt.ask("  [cyan]Date of birth[/] [dim](YYYY-MM-DD)[/]").strip()
            dob = _validate_dob(raw)
            if dob:
                console.print(f"  [green]✓[/] {_format_dob_display(dob)}")
                console.print()
                return dob
            console.print(
                "  [yellow]✗ Invalid date.[/] "
                "Please use YYYY-MM-DD format, e.g. 1985-06-14.\n"
            )
        except (EOFError, KeyboardInterrupt):
            raise


def _step_passphrase() -> str:
    """
    Step 6: Create and confirm vault passphrase.

    Enforces minimum strength: 12+ chars, upper + lower + digit.
    Shows a prominent red warning that the passphrase cannot be recovered.

    Returns:
        The validated passphrase string. Caller MUST zero it after vault write.
    """
    _print_step_header(
        "Vault Passphrase",
        "All the information you just entered will be encrypted with\n"
        "a passphrase that only you know. TraceBurn does not store\n"
        "this passphrase and cannot recover it.",
    )

    console.print(Panel(
        "[bold yellow]⚠  This passphrase cannot be recovered. Write it down.[/]\n\n"
        "If you forget it, your vault cannot be decrypted and your data\n"
        "cannot be accessed. Choose something you will remember.",
        border_style="red",
        padding=(0, 2),
    ))
    console.print()

    while True:
        try:
            passphrase = Prompt.ask("  [cyan]Create passphrase[/]", password=True)
            ok, reason = _check_passphrase_strength(passphrase)

            if not ok:
                console.print(
                    f"\n  [red]✗ Passphrase is too weak.[/]\n"
                    f"    {reason}\n\n"
                    f"  Tips for a strong passphrase:\n"
                    f"    • At least 12 characters\n"
                    f"    • Must contain uppercase, lowercase, and a digit\n"
                    f"    • Use 4 or more random words: \"correct-horse-battery-staple\"\n"
                    f"    • Avoid names, dates, and common phrases\n"
                )
                continue

            console.print("  [green]Passphrase strength: Strong ✓[/]")
            console.print()

            confirm = Prompt.ask("  [cyan]Confirm passphrase[/]", password=True)
            if passphrase != confirm:
                console.print(
                    "  [red]✗ Passphrases do not match. Please try again.[/]\n"
                )
                continue

            console.print("  [green]✓ Passphrases match[/]")
            console.print()

            # Write a sentinel key to prove the vault works
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            PIIVault(vault_path=VAULT_PATH).store(
                "__vault_init__", "traceBurnVaultV1", passphrase=passphrase
            )

            console.print(f"  [green]✓ Vault created and encrypted[/]")
            console.print(f"    Location: [italic]{VAULT_PATH}[/]")
            console.print()
            return passphrase

        except (EOFError, KeyboardInterrupt):
            raise


def _step_notifications() -> bool:
    """
    Step 7: Optional Telegram notification setup.

    Prompts for bot token and chat ID, then sends a test message.

    Returns:
        True if notifications were successfully configured and tested.
    """
    _print_step_header(
        "Notifications (optional)",
        "TraceBurn can send you a Telegram message when:\n"
        "  • A removal is confirmed\n"
        "  • Your data reappears after removal\n"
        "  • A scheduled re-verification finds a change",
    )

    try:
        want = Confirm.ask("  Set up Telegram notifications?", default=False)
        if not want:
            console.print(
                "  [dim]Skipped. Configure later: "
                "[italic]traceburn config notifications[/][/]\n"
            )
            return False

        console.print()
        console.print(
            "  To connect Telegram:\n"
            "    1. Open Telegram and search for [bold]@BotFather[/]\n"
            "    2. Send [italic]/newbot[/] and follow the prompts\n"
            "    3. Copy the bot token BotFather gives you\n"
            "    4. Send your bot a message, then retrieve your chat ID:\n"
            "       [italic]curl \"https://api.telegram.org/bot<TOKEN>/getUpdates\"[/]\n"
        )

        bot_token = Prompt.ask("  [cyan]Bot token[/]").strip()
        chat_id = Prompt.ask("  [cyan]Chat ID[/]").strip()

        if not bot_token or not chat_id:
            console.print(
                "  [yellow]Skipping — bot token or chat ID was empty.[/]\n"
                "  Configure later: [italic]traceburn config notifications[/]\n"
            )
            return False

        console.print("  Testing connection...", end="")
        try:
            from .notifier import TelegramNotifier

            success = TelegramNotifier(bot_token=bot_token, chat_id=chat_id).test_connection()
        except Exception:
            success = False

        if success:
            console.print(" [green]✓ Telegram connected — test message sent[/]")
            _save_telegram_config(bot_token, chat_id)
        else:
            console.print()
            console.print(
                "  [yellow]⚠ Could not send test message.[/] "
                "Check your bot token and chat ID.\n"
                "  Configure later: [italic]traceburn config notifications[/]"
            )

        console.print(
            "\n  [dim](You can always change this later with: "
            "[italic]traceburn config notifications[/])[/]\n"
        )
        return success

    except (EOFError, KeyboardInterrupt):
        raise


def _step_install_browser() -> None:
    """
    Step 8: Install Playwright Chromium browser (~120 MB).

    Runs `playwright install chromium` as a subprocess while showing a
    Rich spinner. Handles missing playwright, timeouts, and other failures
    gracefully — the user can retry with `traceburn setup-browser`.
    """
    _print_step_header(
        "Installing Browser",
        "TraceBurn uses a headless browser to submit opt-out forms on your behalf.\n"
        "Installing now (~120 MB).",
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("  Downloading Chromium...", total=None)

        try:
            result = subprocess.run(
                ["playwright", "install", "chromium"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            progress.update(task, completed=True)
        except FileNotFoundError:
            progress.stop()
            console.print(
                "  [yellow]⚠ playwright command not found.[/]\n"
                "    Install it with: [italic]pip install playwright[/]\n"
                "    Then retry: [italic]traceburn setup-browser[/]\n"
            )
            return
        except subprocess.TimeoutExpired:
            progress.stop()
            console.print(
                "  [yellow]⚠ Browser download timed out (5 min limit).[/]\n"
                "    This can happen on slow connections.\n"
                "    Retry later: [italic]traceburn setup-browser[/]\n"
            )
            return
        except Exception as exc:
            progress.stop()
            console.print(
                f"  [yellow]⚠ Could not install browser: {exc}[/]\n"
                "    Retry later: [italic]traceburn setup-browser[/]\n"
            )
            return

    if result.returncode == 0:
        console.print("  [green]✓ Playwright browser installed[/]")
    else:
        err_snippet = result.stderr[:200] if result.stderr else "unknown error"
        console.print(
            "  [yellow]⚠ Playwright install exited with an error.[/]\n"
            f"    {err_snippet}\n"
            "    Retry: [italic]traceburn setup-browser[/]"
        )

    console.print()


def _step_completion(profile: UserProfile, elapsed: float) -> None:
    """
    Step 9: Print a completion summary table and next-step instructions.

    Args:
        profile: The completed UserProfile.
        elapsed: Total elapsed seconds since the wizard started.
    """
    _print_step_header("Setup Complete", "")

    table = Table(
        show_header=True,
        header_style="bold cyan",
        box=None,
        padding=(0, 2),
    )
    table.add_column("Field", style="dim", no_wrap=True)
    table.add_column("Value")

    table.add_row("Name", profile.name)
    table.add_row("Emails", "\n".join(profile.emails))
    table.add_row(
        "Phone",
        "\n".join(_format_phone_display(p) for p in profile.phones)
        if profile.phones
        else "—",
    )
    table.add_row(
        "Addresses",
        "\n".join(a.display() for a in profile.addresses) if profile.addresses else "—",
    )
    table.add_row("DOB", "[dim]•••••••• (encrypted)[/]")
    table.add_row("Vault", f"[italic]{VAULT_PATH}[/] [green](AES-256-GCM encrypted)[/]")
    table.add_row(
        "Notifications",
        "[green]Telegram connected[/]"
        if profile.notifications_enabled
        else "[dim]Not configured[/]",
    )

    console.print(table)
    console.print()

    if elapsed >= 60:
        elapsed_str = f"{int(elapsed // 60)}m {int(elapsed % 60)}s"
    else:
        elapsed_str = f"{int(elapsed)}s"

    console.print(f"  Setup completed in [bold]{elapsed_str}[/]\n")
    console.print(Panel(
        "Your next step:\n\n"
        "  Run [bold cyan]traceburn scan[/] to search for your data across\n"
        "  data broker sites. This typically takes 10–20 minutes.",
        border_style="green",
        padding=(0, 2),
    ))
    console.print()


# ──────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────


def _print_step_header(title: str, description: str) -> None:
    """Print a step rule divider and optional description text."""
    console.rule(f"[bold cyan]{title}[/]")
    if description:
        console.print()
        for line in description.splitlines():
            console.print(f"  {line}")
    console.print()


def _collect_single_address() -> AddressRecord:
    """
    Interactively prompt for a single address.

    Retries if required fields (street, city, postal code) are blank.
    Country defaults to US.
    """
    while True:
        try:
            street = Prompt.ask("  [cyan]Street address[/]").strip()
            city = Prompt.ask("  [cyan]City[/]").strip()
            state = Prompt.ask("  [cyan]State / Province[/]").strip().upper()
            postal = Prompt.ask("  [cyan]Postal code[/]").strip()
            country = Prompt.ask("  [cyan]Country[/]", default="US").strip().upper()

            if not street or not city or not postal:
                console.print(
                    "  [yellow]Street address, city, and postal code are required.[/]\n"
                )
                continue

            return AddressRecord(
                street=street,
                city=city,
                state=state,
                postal_code=postal,
                country=country,
            )
        except (EOFError, KeyboardInterrupt):
            raise


def _normalize_phone(raw: str) -> str | None:
    """
    Normalize an arbitrary phone string to E.164 format.

    Strips whitespace, dashes, dots, parentheses, and other formatting.
    Prepends +1 for bare 10-digit US numbers.

    Returns:
        E.164 string (e.g. "+15558675309") or None if fewer than 10 digits.
    """
    has_plus = raw.strip().startswith("+")
    digits = re.sub(r"\D", "", raw)

    if len(digits) < 10:
        return None

    # Bare 10-digit US number — prepend country code
    if len(digits) == 10 and not has_plus:
        digits = "1" + digits

    candidate = "+" + digits
    return candidate if _E164_RE.match(candidate) else None


def _format_phone_display(e164: str) -> str:
    """Format an E.164 phone number for human-readable display."""
    if e164.startswith("+1") and len(e164) == 12:
        d = e164[2:]
        return f"+1 ({d[:3]}) {d[3:6]}-{d[6:]}"
    return e164


def _validate_dob(raw: str) -> str | None:
    """
    Validate a date-of-birth string in YYYY-MM-DD format.

    Returns:
        ISO 8601 date string or None if the input is invalid.
        Invalid means: wrong format, future date, or before 1900.
    """
    import datetime as dt

    raw = raw.strip()
    try:
        parsed = dt.date.fromisoformat(raw)
    except ValueError:
        return None

    today = dt.date.today()
    if parsed >= today or parsed.year < 1900:
        return None

    return parsed.isoformat()


def _format_dob_display(dob: str) -> str:
    """Format YYYY-MM-DD as 'Month DD, YYYY' for display."""
    import datetime as dt

    _MONTHS = [
        "", "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December",
    ]
    try:
        d = dt.date.fromisoformat(dob)
        return f"{_MONTHS[d.month]} {d.day}, {d.year}"
    except Exception:
        return dob


def _check_passphrase_strength(passphrase: str) -> tuple[bool, str]:
    """
    Check passphrase meets TraceBurn minimum strength requirements.

    Rules:
        - At least 12 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit (0–9)

    Returns:
        (ok, reason) — reason is empty if ok is True.
    """
    if len(passphrase) < 12:
        return False, "Too short — must be at least 12 characters."
    if not any(c.isupper() for c in passphrase):
        return False, "Must contain at least one uppercase letter."
    if not any(c.islower() for c in passphrase):
        return False, "Must contain at least one lowercase letter."
    if not any(c.isdigit() for c in passphrase):
        return False, "Must contain at least one digit (0–9)."
    return True, ""


def _save_to_vault(
    vault: PIIVault,
    passphrase: str,
    name: str,
    name_suffix: str,
    name_variants: list[str],
    emails: list[str],
    phones: list[str],
    addresses: list[AddressRecord],
    dob: str,
) -> None:
    """
    Encrypt and persist all collected PII into the vault.

    Each field uses a unique per-field salt so compromising one blob
    does not aid decryption of others.
    """
    vault.store("name", name, passphrase=passphrase)
    vault.store("name_suffix", name_suffix, passphrase=passphrase)
    vault.store("name_variants", json.dumps(name_variants), passphrase=passphrase)
    vault.store("emails", json.dumps(emails), passphrase=passphrase)
    vault.store("phones", json.dumps(phones), passphrase=passphrase)
    vault.store(
        "addresses",
        json.dumps([a.to_dict() for a in addresses]),
        passphrase=passphrase,
    )
    vault.store("dob", dob, passphrase=passphrase)


def _save_config(profile: UserProfile, notifications_enabled: bool) -> None:
    """
    Write non-sensitive configuration to ~/.traceburn/config.yaml (mode 600).

    PII is never written here — only counts and metadata.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    existing: dict = {}
    if CONFIG_PATH.exists():
        with CONFIG_PATH.open("r", encoding="utf-8") as fh:
            existing = yaml.safe_load(fh) or {}

    existing.update({
        "profile": {
            "display_name": profile.name,
            "profile_type": profile.profile_type,
            "name_variants_count": len(profile.name_variants),
            "emails_count": len(profile.emails),
            "addresses_count": len(profile.addresses),
        },
        "vault": {
            "path": str(VAULT_PATH),
        },
        "notifications": {
            "telegram": {
                "enabled": notifications_enabled,
                # Credentials live in environment vars, not here
            }
        },
    })

    with CONFIG_PATH.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(existing, fh, default_flow_style=False)

    os.chmod(CONFIG_PATH, 0o600)


def _save_telegram_config(bot_token: str, chat_id: str) -> None:
    """
    Persist Telegram credentials to config.yaml.

    Sets file permissions to 0o600 after writing. Credentials should
    ideally be moved to environment variables (TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID) for better security.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    existing: dict = {}
    if CONFIG_PATH.exists():
        with CONFIG_PATH.open("r", encoding="utf-8") as fh:
            existing = yaml.safe_load(fh) or {}

    existing.setdefault("notifications", {}).setdefault("telegram", {})
    existing["notifications"]["telegram"]["enabled"] = True
    existing["notifications"]["telegram"]["bot_token"] = bot_token
    existing["notifications"]["telegram"]["chat_id"] = chat_id

    with CONFIG_PATH.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(existing, fh, default_flow_style=False)

    os.chmod(CONFIG_PATH, 0o600)
