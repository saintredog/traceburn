"""
src/scheduler.py — APScheduler-based task scheduler for TraceBurn.

Manages three categories of scheduled jobs:
  1. Post-removal reverification at T+7d, T+30d, T+90d
  2. Weekly full-scan (Monday 9 AM by default)
  3. Retry queue for failed removal attempts (1h → 4h → 24h → 72h → manual)

All jobs are persisted in SQLite so they survive process restarts.
The scheduler runs as a background thread embedded in the CLI process —
no separate daemon or cron entry is required.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Days after removal to run reverification checks
DEFAULT_CHECK_INTERVALS: List[int] = [7, 30, 90]

# Retry delay ladder (hours).  After 72-hour failure, route to manual queue.
RETRY_LADDER_HOURS: List[int] = [1, 4, 24, 72]
MAX_AUTO_RETRIES: int = len(RETRY_LADDER_HOURS)

# Default cron expression: Monday at 09:00 UTC
DEFAULT_WEEKLY_CRON: str = "0 9 * * 1"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ScheduledJob:
    """Lightweight representation of a pending APScheduler job for display."""

    job_id: str
    job_type: str           # "reverification" | "weekly_scan" | "retry"
    next_run_at: datetime   # UTC
    removal_request_id: Optional[int] = None
    broker_name: Optional[str] = None
    profile_id: Optional[int] = None
    checkpoint_label: Optional[str] = None   # "7d" | "30d" | "90d"


# ---------------------------------------------------------------------------
# Job functions (module-level so APScheduler can serialize/deserialize them)
# ---------------------------------------------------------------------------

def _run_reverification_job(removal_request_id: int, checkpoint_label: str) -> None:
    """
    APScheduler invokes this at the scheduled time.

    Re-scans the broker for the profile that was previously found.

    Outcomes:
      - Absent: update last_verified, schedule next interval if any remain.
      - Reappeared after VERIFIED_ABSENT: set status to "reappeared",
        trigger a new removal, send a Telegram alert.
      - Broker unreachable: log VERIFICATION_FAILED, reschedule 24 h retry.
    """
    # Import here to avoid circular imports at module load time.
    try:
        from src.db import get_db  # type: ignore[import]
        from src.notifier import send_alert  # type: ignore[import]
    except ImportError:
        logger.warning("DB/notifier not available — running in stub mode")
        return

    logger.info(
        "Running reverification job: removal_request_id=%d checkpoint=%s",
        removal_request_id,
        checkpoint_label,
    )

    db = get_db()
    removal = db.get_removal_request(removal_request_id)
    if removal is None:
        logger.error("Removal request %d not found — skipping", removal_request_id)
        return

    exposure = db.get_exposure(removal.exposure_id)
    broker = db.get_broker(exposure.broker_id)
    profile = db.get_user(exposure.user_id)

    try:
        from src.scanner.engine import spot_check_broker  # type: ignore[import]
        result = spot_check_broker(broker=broker, user_profile=profile)
    except Exception as exc:
        logger.error("spot_check_broker failed: %s", exc)
        db.update_exposure_status(exposure.id, "verification_failed")
        return

    if not result.site_reachable:
        # Broker unreachable — reschedule a 24-hour retry
        logger.warning(
            "Broker %s unreachable during %s check — rescheduling",
            broker.name, checkpoint_label,
        )
        retry_at = datetime.now(timezone.utc) + timedelta(hours=24)
        scheduler = TraceBurnScheduler.get_instance()
        if scheduler:
            scheduler._add_date_job(
                func=_run_reverification_job,
                run_at=retry_at,
                job_id=f"verify_retry_{removal_request_id}_{checkpoint_label}",
                kwargs={"removal_request_id": removal_request_id,
                        "checkpoint_label": checkpoint_label},
            )
        return

    if result.profile_found:
        # Determine if this is a reappearance (was previously confirmed absent)
        proof = db.get_proof_for_removal(removal_request_id)
        was_previously_absent = (
            proof is not None and proof.current_status == "verified_absent"
        )

        if was_previously_absent:
            logger.warning(
                "Data reappeared on %s after confirmed removal (removal_request_id=%d)",
                broker.name, removal_request_id,
            )
            db.update_exposure_status(exposure.id, "reappeared")
            db.enqueue_removal(exposure.id)
            send_alert(
                level="ALERT",
                message=(
                    f"Your data has reappeared on {broker.name}. "
                    "TraceBurn has submitted a new opt-out automatically. "
                    "Run `traceburn status` for details."
                ),
            )
            db.update_proof_checkpoint(
                removal_request_id=removal_request_id,
                checkpoint_label=checkpoint_label,
                status="reappeared",
                note=(
                    f"Profile reappeared on {broker.name} at {checkpoint_label} check. "
                    "Re-removal initiated automatically."
                ),
            )
        else:
            logger.info(
                "Profile still present at %s check for removal_request_id=%d — monitoring",
                checkpoint_label, removal_request_id,
            )
            db.update_proof_checkpoint(
                removal_request_id=removal_request_id,
                checkpoint_label=checkpoint_label,
                status="pending_verification",
                note=f"Profile still present at {checkpoint_label} check. Monitoring.",
            )
    else:
        # Confirmed absent
        logger.info(
            "Profile confirmed absent on %s at %s check",
            broker.name, checkpoint_label,
        )
        db.update_exposure_status(exposure.id, "removed")
        db.update_proof_checkpoint(
            removal_request_id=removal_request_id,
            checkpoint_label=checkpoint_label,
            status="verified_absent",
            note=f"Profile confirmed absent from {broker.name} at {checkpoint_label} check.",
        )


def _run_weekly_scan_job(profile_id: int) -> None:
    """Triggered by the Monday 9 AM cron — kicks off a full scan for the profile."""
    try:
        from src.scanner.engine import run_full_scan  # type: ignore[import]
    except ImportError:
        logger.warning("Scanner engine not available — skipping scheduled scan")
        return

    logger.info("Running scheduled weekly scan for profile_id=%d", profile_id)
    try:
        run_full_scan(profile_id=profile_id)
    except Exception as exc:
        logger.error("Scheduled scan failed for profile_id=%d: %s", profile_id, exc)


def _run_retry_job(removal_request_id: int, attempt_number: int) -> None:
    """
    Retry a failed removal request.

    Attempt numbers (1-indexed):
      1 → wait was 1 h
      2 → wait was 4 h
      3 → wait was 24 h
      4 → wait was 72 h — if still failing, move to manual queue
    """
    try:
        from src.db import get_db  # type: ignore[import]
        from src.removal.engine import retry_removal  # type: ignore[import]
    except ImportError:
        logger.warning("Removal engine not available — skipping retry job")
        return

    logger.info(
        "Running retry attempt %d for removal_request_id=%d",
        attempt_number, removal_request_id,
    )
    db = get_db()
    removal = db.get_removal_request(removal_request_id)
    if removal is None:
        logger.error("Removal request %d not found — aborting retry", removal_request_id)
        return

    success = retry_removal(removal_request_id=removal_request_id)
    if success:
        logger.info("Retry %d succeeded for removal_request_id=%d", attempt_number, removal_request_id)
        return

    # Schedule next retry if within ladder
    if attempt_number < MAX_AUTO_RETRIES:
        next_delay_hours = RETRY_LADDER_HOURS[attempt_number]  # ladder is 0-indexed
        next_attempt = attempt_number + 1
        run_at = datetime.now(timezone.utc) + timedelta(hours=next_delay_hours)
        scheduler = TraceBurnScheduler.get_instance()
        if scheduler:
            scheduler.schedule_retry(
                removal_request_id=removal_request_id,
                delay_hours=next_delay_hours,
                _attempt_number=next_attempt,
            )
        logger.info(
            "Retry %d failed — next retry in %dh (attempt %d)",
            attempt_number, next_delay_hours, next_attempt,
        )
    else:
        # Exhausted all automatic retries — move to manual queue
        logger.warning(
            "All %d retry attempts failed for removal_request_id=%d — moving to manual queue",
            MAX_AUTO_RETRIES, removal_request_id,
        )
        db.update_removal_status(removal_request_id, "manual_required")
        try:
            from src.notifier import send_alert  # type: ignore[import]
            removal = db.get_removal_request(removal_request_id)
            exposure = db.get_exposure(removal.exposure_id)
            broker = db.get_broker(exposure.broker_id)
            send_alert(
                level="WARN",
                message=(
                    f"Automatic removal from {broker.name} failed after 4 attempts. "
                    "Manual action required. Run `traceburn remove --manual` to proceed."
                ),
            )
        except Exception:
            pass  # Notification failure must never propagate


# ---------------------------------------------------------------------------
# Scheduler class
# ---------------------------------------------------------------------------

class TraceBurnScheduler:
    """
    Wraps APScheduler's BackgroundScheduler with a SQLite-backed job store.

    All scheduled jobs persist across process restarts.  The scheduler runs
    as a background thread — no daemon process or system cron is needed.

    Usage:
        scheduler = TraceBurnScheduler(db_path=Path("~/.traceburn/scheduler.db"))
        scheduler.start()
        scheduler.schedule_reverification(removal_request_id=1, broker_name="Spokeo")
        # ... CLI does its work ...
        scheduler.stop()
    """

    # Singleton reference so job functions can reach the running instance.
    _instance: Optional["TraceBurnScheduler"] = None

    def __init__(self, db_path: Path = Path("~/.traceburn/scheduler.db")) -> None:
        resolved = db_path.expanduser().resolve()
        resolved.parent.mkdir(parents=True, exist_ok=True)

        jobstores = {
            "default": SQLAlchemyJobStore(url=f"sqlite:///{resolved}")
        }
        self._scheduler = BackgroundScheduler(
            jobstores=jobstores,
            timezone="UTC",
        )
        self._db_path = resolved

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background scheduler thread.  Safe to call multiple times."""
        if not self._scheduler.running:
            self._scheduler.start()
            TraceBurnScheduler._instance = self
            logger.info("TraceBurn scheduler started (job store: %s)", self._db_path)

    def stop(self) -> None:
        """Gracefully shut down the scheduler."""
        if self._scheduler.running:
            self._scheduler.shutdown(wait=False)
            TraceBurnScheduler._instance = None
            logger.info("TraceBurn scheduler stopped")

    @classmethod
    def get_instance(cls) -> Optional["TraceBurnScheduler"]:
        """Return the running singleton, or None if not started."""
        return cls._instance

    # ------------------------------------------------------------------
    # Public scheduling API
    # ------------------------------------------------------------------

    def schedule_reverification(
        self,
        removal_request_id: int,
        broker_name: str,
        check_intervals: List[int] = DEFAULT_CHECK_INTERVALS,
    ) -> None:
        """
        Schedule reverification jobs at T+7d, T+30d, T+90d (or custom intervals).

        Jobs are idempotent: calling this a second time with the same
        removal_request_id replaces any previously scheduled jobs.

        Args:
            removal_request_id: FK to removal_requests.id in SQLite.
            broker_name: Human-readable broker name for logging.
            check_intervals: Days after now to schedule checks (default [7, 30, 90]).
        """
        now = datetime.now(timezone.utc)
        labels = {7: "7d", 30: "30d", 90: "90d"}

        for days in check_intervals:
            run_at = now + timedelta(days=days)
            label = labels.get(days, f"{days}d")
            job_id = f"verify_{removal_request_id}_{label}"

            self._add_date_job(
                func=_run_reverification_job,
                run_at=run_at,
                job_id=job_id,
                kwargs={
                    "removal_request_id": removal_request_id,
                    "checkpoint_label": label,
                },
            )
            logger.info(
                "Scheduled reverification: broker=%s removal_request_id=%d "
                "checkpoint=%s run_at=%s",
                broker_name, removal_request_id, label,
                run_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            )

    def schedule_weekly_scan(
        self,
        profile_id: int,
        cron: str = DEFAULT_WEEKLY_CRON,
    ) -> None:
        """
        Schedule a recurring weekly full scan for a profile.

        Args:
            profile_id: The user/profile to scan.
            cron: Cron expression (default "0 9 * * 1" = Monday 09:00 UTC).
        """
        job_id = f"weekly_scan_{profile_id}"
        minute, hour, dom, month, dow = cron.split()

        self._scheduler.add_job(
            func=_run_weekly_scan_job,
            trigger=CronTrigger(
                minute=minute,
                hour=hour,
                day=dom,
                month=month,
                day_of_week=dow,
                timezone="UTC",
            ),
            kwargs={"profile_id": profile_id},
            id=job_id,
            replace_existing=True,
            misfire_grace_time=3600,
        )
        logger.info(
            "Scheduled weekly scan: profile_id=%d cron=%s",
            profile_id, cron,
        )

    def schedule_retry(
        self,
        removal_request_id: int,
        delay_hours: int,
        _attempt_number: int = 1,
    ) -> None:
        """
        Schedule a single retry for a failed removal request.

        The retry ladder is managed internally:
          Attempt 1: delay_hours=1
          Attempt 2: delay_hours=4
          Attempt 3: delay_hours=24
          Attempt 4: delay_hours=72  → if this fails, moves to manual queue

        External callers should only call this for the *first* retry (attempt 1).
        Subsequent attempts are scheduled automatically by _run_retry_job.

        Args:
            removal_request_id: FK to removal_requests.id.
            delay_hours: Hours from now to run the retry.
            _attempt_number: Internal — tracks position in the retry ladder.
        """
        run_at = datetime.now(timezone.utc) + timedelta(hours=delay_hours)
        job_id = f"retry_{removal_request_id}_attempt{_attempt_number}"

        self._add_date_job(
            func=_run_retry_job,
            run_at=run_at,
            job_id=job_id,
            kwargs={
                "removal_request_id": removal_request_id,
                "attempt_number": _attempt_number,
            },
        )
        logger.info(
            "Scheduled retry: removal_request_id=%d attempt=%d delay=%dh run_at=%s",
            removal_request_id, _attempt_number, delay_hours,
            run_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

    # ------------------------------------------------------------------
    # Status / display
    # ------------------------------------------------------------------

    def list_pending(self) -> List[ScheduledJob]:
        """
        Return all pending scheduled jobs, ordered by next_run_at ascending.

        Used by `traceburn status` to show upcoming scheduled activities.
        """
        jobs: List[ScheduledJob] = []

        for job in self._scheduler.get_jobs():
            next_run = job.next_run_time
            if next_run is None:
                continue  # paused or completed

            job_id: str = job.id
            job_type, details = self._classify_job(job_id)

            jobs.append(
                ScheduledJob(
                    job_id=job_id,
                    job_type=job_type,
                    next_run_at=next_run,
                    removal_request_id=details.get("removal_request_id"),
                    broker_name=details.get("broker_name"),
                    profile_id=details.get("profile_id"),
                    checkpoint_label=details.get("checkpoint_label"),
                )
            )

        jobs.sort(key=lambda j: j.next_run_at)
        return jobs

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _add_date_job(
        self,
        func,
        run_at: datetime,
        job_id: str,
        kwargs: dict,
    ) -> None:
        """Add (or replace) a one-shot date-triggered job."""
        self._scheduler.add_job(
            func=func,
            trigger=DateTrigger(run_date=run_at, timezone="UTC"),
            kwargs=kwargs,
            id=job_id,
            replace_existing=True,
            misfire_grace_time=3600,  # run up to 1 h late if process was down
        )

    @staticmethod
    def _classify_job(job_id: str) -> tuple[str, dict]:
        """
        Infer job type and metadata from job_id naming convention.

        Conventions:
          verify_{removal_request_id}_{checkpoint_label}  → reverification
          weekly_scan_{profile_id}                        → weekly_scan
          retry_{removal_request_id}_attempt{n}           → retry
          verify_retry_{removal_request_id}_{label}       → reverification (unreachable retry)
        """
        parts = job_id.split("_")

        if job_id.startswith("verify_retry_"):
            # verify_retry_{id}_{label}
            rid = int(parts[2]) if len(parts) > 2 else None
            label = parts[3] if len(parts) > 3 else None
            return "reverification", {"removal_request_id": rid, "checkpoint_label": label}

        if job_id.startswith("verify_"):
            # verify_{id}_{label}
            rid = int(parts[1]) if len(parts) > 1 else None
            label = parts[2] if len(parts) > 2 else None
            return "reverification", {"removal_request_id": rid, "checkpoint_label": label}

        if job_id.startswith("weekly_scan_"):
            pid = int(parts[2]) if len(parts) > 2 else None
            return "weekly_scan", {"profile_id": pid}

        if job_id.startswith("retry_"):
            # retry_{id}_attempt{n}
            rid = int(parts[1]) if len(parts) > 1 else None
            return "retry", {"removal_request_id": rid}

        return "unknown", {}
