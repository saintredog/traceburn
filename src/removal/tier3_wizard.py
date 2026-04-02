"""
src/removal/tier3_wizard.py — Manual opt-out wizard (Tier 3).

Provides a Rich terminal UI that walks the user through manual opt-out steps
for brokers that cannot be automated (Tier 3). Opens the opt-out URL in the
default browser, displays numbered instructions, and prompts for completion.

User responses:
  Y — Mark complete with timestamp; create manual_attestation proof record
  N — Skip this broker for now (no state change)
  S — Snooze 24 hours (APScheduler job scheduled via db.schedule_snooze)

Step instructions are loaded from broker.notes in the YAML definition.
Falls back to a generic instruction set if broker.notes is empty.
"""

from __future__ import annotations

import asyncio
import logging
import webbrowser
from datetime import datetime, timedelta
from typing import Any

from ..models import (
    BrokerDefinition,
    Exposure,
    RemovalMethod,
    RemovalResult,
    RemovalStatus,
    RemovalTier,
)

logger = logging.getLogger(__name__)

# Generic fallback instructions when broker.notes is empty
_GENERIC_STEPS = [
    "Open your browser and navigate to the opt-out URL shown above.",
    "Search for your name or profile on the site.",
    "Click the opt-out, remove, or privacy request link.",
    "Complete the form — you may need to provide your email address.",
    "Submit the request and check your email for a confirmation link.",
    "Click the confirmation link if one is sent.",
]


class Tier3Wizard:
    """
    Interactive terminal wizard for Tier 3 (manual) broker opt-outs.

    Uses Rich for styled terminal output. Falls back to plain print()
    if Rich is not installed.

    Responsibilities:
    - Display broker info and opt-out URL
    - Open opt-out URL in the system default browser
    - Show step-by-step instructions (from broker.notes or generic fallback)
    - Prompt user: Y (done), N (skip), S (snooze 24h)
    - On Y: write a manual_attestation ProofRecord and update exposure status
    - On S: schedule a 24h re-prompt job via APScheduler (if db supports it)
    """

    def __init__(self, db: Any = None) -> None:
        """
        Args:
            db: Database gateway for writing ProofRecords and scheduling snooze jobs.
                May be None in test contexts (snooze/proof writes will be skipped).
        """
        self._db = db

    async def guide_user(
        self,
        broker: BrokerDefinition,
        exposure: Exposure,
    ) -> RemovalResult:
        """
        Run the manual wizard for one broker/exposure pair.

        This coroutine runs the interactive UI in an executor so it doesn't
        block the event loop (Rich prompts are synchronous).

        Args:
            broker:   BrokerDefinition — provides opt_out_url and notes.
            exposure: The Exposure record being actioned.

        Returns:
            RemovalResult with status CONFIRMED, FAILED (skipped), or SUBMITTED (snoozed).
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self._run_wizard_sync,
            broker,
            exposure,
        )

    # ──────────────────────────────────────────────────────────────
    # Synchronous wizard (runs in thread via executor)
    # ──────────────────────────────────────────────────────────────

    def _run_wizard_sync(
        self,
        broker: BrokerDefinition,
        exposure: Exposure,
    ) -> RemovalResult:
        """Synchronous implementation of the wizard UI."""
        console = _get_console()
        _print_header(console, broker)

        # Open opt-out URL in default browser
        url = broker.opt_out_url
        try:
            webbrowser.open(url)
            _print(console, f"\n[bold green]Opening browser →[/bold green] {url}\n")
        except Exception as exc:
            logger.warning("[Tier3] Failed to open browser: %s", exc)
            _print(console, f"\n[yellow]Could not open browser automatically.[/yellow]\n"
                           f"Please visit: {url}\n")

        # Display step-by-step instructions
        steps = _parse_steps(broker.notes)
        _print(console, "[bold]Step-by-step instructions:[/bold]\n")
        for i, step in enumerate(steps, start=1):
            _print(console, f"  [cyan]{i}.[/cyan] {step}")

        _print(console, "")

        # User prompt loop
        while True:
            try:
                raw = input(
                    "Press Y when complete, N to skip, S to snooze 24h: "
                ).strip().upper()
            except (EOFError, KeyboardInterrupt):
                # Non-interactive environment or user ctrl-c
                _print(console, "\n[yellow]Skipping (non-interactive or interrupted).[/yellow]")
                return RemovalResult(
                    exposure_id=exposure.id,
                    broker_name=broker.name,
                    status=RemovalStatus.FAILED,
                    error="Skipped by user (non-interactive or keyboard interrupt)",
                )

            if raw == "Y":
                return self._handle_complete(console, broker, exposure)
            elif raw == "N":
                return self._handle_skip(console, broker, exposure)
            elif raw == "S":
                return self._handle_snooze(console, broker, exposure)
            else:
                _print(console, "[red]Invalid input.[/red] Please enter Y, N, or S.")

    def _handle_complete(
        self,
        console: Any,
        broker: BrokerDefinition,
        exposure: Exposure,
    ) -> RemovalResult:
        """User confirmed manual completion."""
        completed_at = datetime.utcnow()
        _print(
            console,
            f"\n[bold green]✓ Marked as manually completed[/bold green] at "
            f"{completed_at.strftime('%Y-%m-%d %H:%M UTC')}\n",
        )

        # Write manual_attestation ProofRecord
        proof_id: int | None = None
        if self._db is not None:
            try:
                from ..models import ProofRecord

                proof = ProofRecord(
                    removal_request_id=exposure.removal_request_id or 0,
                    timestamp=completed_at,
                    proof_type="manual_attestation",
                    confirmation_text=(
                        f"User manually confirmed opt-out for {broker.name} "
                        f"at {completed_at.isoformat()}"
                    ),
                )
                proof_id = self._db.insert_proof_record(proof)
                logger.info(
                    "[Tier3] Manual attestation proof written for %s (proof_id=%s)",
                    broker.name,
                    proof_id,
                )
            except Exception as exc:
                logger.warning("[Tier3] Failed to write proof record: %s", exc)

        logger.info("[Tier3] Manual completion recorded for %s", broker.name)
        return RemovalResult(
            exposure_id=exposure.id,
            broker_name=broker.name,
            status=RemovalStatus.CONFIRMED,
            confirmation_text=f"Manually confirmed at {completed_at.isoformat()}",
            proof_record_id=proof_id,
        )

    def _handle_skip(
        self,
        console: Any,
        broker: BrokerDefinition,
        exposure: Exposure,
    ) -> RemovalResult:
        """User chose to skip this broker."""
        _print(console, f"\n[yellow]Skipping {broker.name}.[/yellow]\n")
        logger.info("[Tier3] User skipped %s", broker.name)
        return RemovalResult(
            exposure_id=exposure.id,
            broker_name=broker.name,
            status=RemovalStatus.FAILED,
            error="Skipped by user",
        )

    def _handle_snooze(
        self,
        console: Any,
        broker: BrokerDefinition,
        exposure: Exposure,
    ) -> RemovalResult:
        """User chose to snooze — schedule 24h re-prompt."""
        snooze_until = datetime.utcnow() + timedelta(hours=24)
        _print(
            console,
            f"\n[blue]Snoozed — will remind you again at "
            f"{snooze_until.strftime('%Y-%m-%d %H:%M UTC')}[/blue]\n",
        )

        if self._db is not None:
            try:
                self._db.schedule_snooze(
                    exposure_id=exposure.id,
                    snooze_until=snooze_until,
                    reason=f"User snoozed Tier 3 wizard for {broker.name}",
                )
                logger.info(
                    "[Tier3] Snooze scheduled for %s until %s",
                    broker.name,
                    snooze_until.isoformat(),
                )
            except Exception as exc:
                logger.warning(
                    "[Tier3] Failed to schedule snooze in DB: %s", exc
                )

        return RemovalResult(
            exposure_id=exposure.id,
            broker_name=broker.name,
            status=RemovalStatus.PENDING,
            confirmation_text=f"Snoozed until {snooze_until.isoformat()}",
        )


# ──────────────────────────────────────────────────────────────
# UI helpers
# ──────────────────────────────────────────────────────────────


def _get_console() -> Any:
    """Return a Rich Console if available, otherwise a stub."""
    try:
        from rich.console import Console
        return Console()
    except ImportError:
        return None


def _print(console: Any, msg: str) -> None:
    """Print with Rich markup if available, otherwise strip tags and use print()."""
    if console is not None:
        console.print(msg)
    else:
        # Strip Rich markup tags for plain output
        import re
        plain = re.sub(r"\[/?[^\]]*\]", "", msg)
        print(plain)


def _print_header(console: Any, broker: BrokerDefinition) -> None:
    """Print a styled header panel for the wizard."""
    header = (
        f"\n{'─' * 60}\n"
        f"  TraceBurn Manual Opt-Out Wizard\n"
        f"  Broker: {broker.name} ({broker.domain})\n"
        f"  Opt-out URL: {broker.opt_out_url}\n"
        f"{'─' * 60}\n"
    )
    if console is not None:
        try:
            from rich.panel import Panel
            console.print(
                Panel(
                    f"[bold]{broker.name}[/bold] ({broker.domain})\n"
                    f"[dim]{broker.opt_out_url}[/dim]",
                    title="[bold cyan]TraceBurn Manual Opt-Out Wizard[/bold cyan]",
                    border_style="cyan",
                )
            )
            return
        except ImportError:
            pass
    print(header)


def _parse_steps(notes: str | None) -> list[str]:
    """
    Parse broker.notes into a list of numbered step strings.

    Notes format: newline-separated instructions (leading numbers/bullets stripped).
    Falls back to _GENERIC_STEPS if notes is empty or None.
    """
    if not notes or not notes.strip():
        return _GENERIC_STEPS

    lines = [line.strip() for line in notes.strip().splitlines() if line.strip()]
    steps = []
    for line in lines:
        # Strip leading numbers ("1.", "1)", "-", "•")
        import re
        cleaned = re.sub(r"^[\d\.\)\-\•\*]+\s*", "", line).strip()
        if cleaned:
            steps.append(cleaned)

    return steps if steps else _GENERIC_STEPS
