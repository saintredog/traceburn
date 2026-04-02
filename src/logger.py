"""
src/logger.py — PII-Free Audit Logger

Two logging surfaces:
  1. Rotating file audit log at ~/.traceburn/audit.log
     Format: ISO_TIMESTAMP | ACTION | BROKER | STATUS | DETAILS
     PII policy: entries NEVER contain name, address, phone, email, DOB, or
     any other user-supplied data. Only broker domains, internal IDs, action
     types, and status values appear in the log.

  2. Rich console logger for terminal output (info / warning / error with
     colour highlighting). Controlled by TRACEBURN_LOG_LEVEL env var.

Usage::

    from src.logger import get_logger, log_action

    log_action("SCAN_STARTED", broker="ALL_BROKERS", status="started")
    log_action("BROKER_SCANNED", broker="spokeo.com", status="found", details="exposure:441")

    console = get_logger()
    console.info("Scan complete.")
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler

# ── Constants ─────────────────────────────────────────────────────────────────

AUDIT_LOG_PATH: Path = Path.home() / ".traceburn" / "audit.log"
MAX_BYTES: int = 10 * 1024 * 1024  # 10 MB per file
BACKUP_COUNT: int = 5

_AUDIT_LOGGER_NAME = "traceburn.audit"
_CONSOLE_LOGGER_NAME = "traceburn"

_audit_logger_instance: logging.Logger | None = None
_console_logger_instance: logging.Logger | None = None

# ── Audit log ─────────────────────────────────────────────────────────────────


def _configure_audit_logger() -> logging.Logger:
    """Create and configure the rotating file audit logger (idempotent)."""
    audit = logging.getLogger(_AUDIT_LOGGER_NAME)
    if audit.handlers:
        return audit  # already configured

    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    handler = RotatingFileHandler(
        filename=str(AUDIT_LOG_PATH),
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )
    # Entries arrive pre-formatted — no additional formatting needed
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.rotator = _RotatorWithChmod()

    audit.addHandler(handler)
    audit.setLevel(logging.INFO)
    audit.propagate = False  # Keep audit entries out of the root logger
    return audit


class _RotatorWithChmod:
    """
    Custom rotator that sets rotated audit log files to read-only (444).
    Plugged into RotatingFileHandler.rotator.
    """

    def __call__(self, source: str, dest: str) -> None:  # noqa: D102
        import shutil

        if os.path.exists(source):
            shutil.move(source, dest)
            try:
                os.chmod(dest, 0o444)
            except OSError:
                pass  # Best-effort — don't block rotation


def log_action(
    action: str,
    broker: Optional[str] = None,
    status: Optional[str] = None,
    details: Optional[str] = None,
) -> None:
    """
    Append a single PII-free audit log entry.

    Parameters
    ----------
    action:
        Enumerated action type, e.g. ``"SCAN_STARTED"``, ``"REMOVAL_SUBMITTED"``.
    broker:
        Broker domain or ``"ALL_BROKERS"`` / ``"TELEGRAM"`` for system events.
        Must not contain any user PII.
    status:
        Short outcome string, e.g. ``"started"``, ``"found"``, ``"confirmed"``.
    details:
        Optional record reference such as ``"exposure:441"`` or ``"-"``.
        Must not contain any user PII.

    Thread safety: append mode is POSIX-atomic for writes under ~4 KB.
    """
    global _audit_logger_instance
    if _audit_logger_instance is None:
        _audit_logger_instance = _configure_audit_logger()

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    broker_str = (broker or "-")[:30].ljust(20)
    status_str = (status or "-")[:15].ljust(12)
    details_str = details or "-"
    action_str = action[:25].ljust(20)

    entry = f"{timestamp} | {action_str} | {broker_str} | {status_str} | {details_str}"
    _audit_logger_instance.info(entry)


# ── Console logger ────────────────────────────────────────────────────────────


def _configure_console_logger() -> logging.Logger:
    """Create and configure the Rich console logger (idempotent)."""
    console_log = logging.getLogger(_CONSOLE_LOGGER_NAME)
    if console_log.handlers:
        return console_log

    level_name = os.environ.get("TRACEBURN_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    console = Console(stderr=True)
    handler = RichHandler(
        console=console,
        show_time=False,
        show_path=False,
        markup=True,
        rich_tracebacks=False,  # Suppress tracebacks that might contain variable values
    )
    handler.setLevel(level)

    console_log.addHandler(handler)
    console_log.setLevel(level)
    console_log.propagate = False
    return console_log


def get_logger() -> logging.Logger:
    """
    Return the singleton Rich console logger for terminal output.

    Levels:
    - ``logger.info("...")`` — normal progress messages
    - ``logger.warning("...")`` — non-fatal issues shown in yellow
    - ``logger.error("...")`` — errors shown in red
    """
    global _console_logger_instance
    if _console_logger_instance is None:
        _console_logger_instance = _configure_console_logger()
    return _console_logger_instance


def reset_loggers() -> None:
    """Clear singleton references. Useful in tests."""
    global _audit_logger_instance, _console_logger_instance
    _audit_logger_instance = None
    _console_logger_instance = None
