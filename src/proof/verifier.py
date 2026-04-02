"""
src/proof/verifier.py — Post-removal verification for TraceBurn.

After a removal request is submitted, TraceBurn schedules re-verification
checks at T+7, T+30, and T+90 days.  This module handles both individual
spot-checks (verify_removal) and bulk processing of all due checks
(bulk_verify_due).

Outcomes (per 2.6-proof-engine-design.md):
  absent      — Profile not found on the broker.  Mark verified_absent.
  reappeared  — Profile found after a prior verified_absent checkpoint.
                Set exposure.status="reappeared", enqueue re-removal,
                fire Telegram ALERT.
  error       — Broker site unreachable or scan error.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class VerificationResult:
    """
    Result of a single post-removal re-verification pass.

    Attributes:
        removal_request_id: FK to removal_requests.id.
        broker_name: Human-readable broker name for display.
        status: "absent" | "reappeared" | "error".
        checked_at: UTC timestamp of the check.
        details: Plain-language description of the outcome.
        http_response_code: HTTP status of the broker response, if available.
    """

    removal_request_id: int
    broker_name: str
    status: str  # "absent" | "reappeared" | "error"
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: str = ""
    http_response_code: Optional[int] = None


# ---------------------------------------------------------------------------
# RemovalVerifier
# ---------------------------------------------------------------------------

class RemovalVerifier:
    """
    Re-scans brokers to verify that previously removed profiles remain absent.

    Designed to be called either:
      - On-demand by the scheduler when a scheduled job fires.
      - Directly via ``bulk_verify_due()`` when the CLI starts up
        (to catch up on any checks that fired while the process was down).

    Dependencies (injected or imported lazily):
      - src.db.get_db()            — database gateway
      - src.scanner.engine.spot_check_broker()  — single-broker profile check
      - src.notifier.send_alert()  — Telegram notification
    """

    def __init__(self) -> None:
        # Lazy imports at method call time to avoid circular imports.
        pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def verify_removal(
        self,
        removal_request,   # RemovalRequest-like object
        broker,            # BrokerDefinition-like object
        profile,           # User-like object
    ) -> VerificationResult:
        """
        Re-scan a single broker for a specific profile to verify removal.

        Args:
            removal_request: The original removal request record.
            broker: The broker definition (name, domain, opt-out URL, …).
            profile: The user profile whose data was removed.

        Returns:
            VerificationResult with status "absent", "reappeared", or "error".
        """
        logger.info(
            "Verifying removal: removal_request_id=%d broker=%s",
            removal_request.id, broker.name,
        )

        try:
            from src.scanner.engine import spot_check_broker  # type: ignore[import]
        except ImportError:
            logger.warning(
                "spot_check_broker not available — returning error result"
            )
            return VerificationResult(
                removal_request_id=removal_request.id,
                broker_name=broker.name,
                status="error",
                details="Scanner engine not available.",
            )

        try:
            result = await spot_check_broker(broker=broker, user_profile=profile)
        except Exception as exc:
            logger.error(
                "spot_check_broker raised for broker=%s: %s", broker.name, exc
            )
            return VerificationResult(
                removal_request_id=removal_request.id,
                broker_name=broker.name,
                status="error",
                details=f"Scan error: {exc}",
            )

        if not result.site_reachable:
            return VerificationResult(
                removal_request_id=removal_request.id,
                broker_name=broker.name,
                status="error",
                details=(
                    f"{broker.name} was unreachable during verification. "
                    "The check will be retried automatically."
                ),
                http_response_code=getattr(result, "http_code", None),
            )

        if result.profile_found:
            return VerificationResult(
                removal_request_id=removal_request.id,
                broker_name=broker.name,
                status="reappeared",
                details=(
                    f"Profile found on {broker.name} — "
                    "data may have reappeared or removal was not yet processed."
                ),
                http_response_code=getattr(result, "http_code", None),
            )

        # Profile absent and site reachable
        return VerificationResult(
            removal_request_id=removal_request.id,
            broker_name=broker.name,
            status="absent",
            details=f"Profile confirmed absent from {broker.name}.",
            http_response_code=getattr(result, "http_code", None),
        )

    def bulk_verify_due(self) -> List[VerificationResult]:
        """
        Find all removal requests whose next_check_at <= now and run
        verify_removal for each.

        Called on CLI startup to catch up on checks that fired while the
        process was not running (jobs have a 1-hour misfire grace window
        in APScheduler, but this provides an additional safety net).

        Returns:
            List of VerificationResult objects, one per processed removal request.
            Results with status "reappeared" have already triggered re-removal
            and Telegram alerts.
        """
        import asyncio

        try:
            from src.db import get_db  # type: ignore[import]
        except ImportError:
            logger.warning("DB not available — skipping bulk_verify_due")
            return []

        db = get_db()
        now = datetime.now(timezone.utc)

        try:
            due_removals = db.get_due_reverifications(as_of=now)
        except Exception as exc:
            logger.error("Failed to query due reverifications: %s", exc)
            return []

        if not due_removals:
            logger.debug("No reverifications due at %s", now.isoformat())
            return []

        logger.info("%d reverification(s) due — processing", len(due_removals))
        results: List[VerificationResult] = []

        for removal in due_removals:
            try:
                exposure = db.get_exposure(removal.exposure_id)
                broker = db.get_broker(exposure.broker_id)
                profile = db.get_user(exposure.user_id)

                # Run the async verify in a synchronous context
                result = asyncio.run(
                    self.verify_removal(
                        removal_request=removal,
                        broker=broker,
                        profile=profile,
                    )
                )
                results.append(result)
                self._apply_result(db, removal, exposure, broker, result)

            except Exception as exc:
                logger.error(
                    "bulk_verify_due failed for removal_request_id=%s: %s",
                    getattr(removal, "id", "?"), exc,
                )
                results.append(
                    VerificationResult(
                        removal_request_id=getattr(removal, "id", 0),
                        broker_name=getattr(broker, "name", "unknown")
                        if "broker" in dir()  # guard in case broker fetch failed
                        else "unknown",
                        status="error",
                        details=str(exc),
                    )
                )

        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _apply_result(
        self,
        db,
        removal,
        exposure,
        broker,
        result: VerificationResult,
    ) -> None:
        """
        Persist the verification result and fire side-effects (alerts,
        re-removal enqueueing) based on the outcome.
        """
        if result.status == "absent":
            db.update_exposure_status(exposure.id, "removed")
            db.update_removal_next_check(removal.id, checked_at=result.checked_at)
            logger.info(
                "Verified absent: broker=%s removal_request_id=%d",
                broker.name, removal.id,
            )

        elif result.status == "reappeared":
            # Check whether this was previously verified absent
            proof = db.get_proof_for_removal(removal.id)
            was_absent = (
                proof is not None
                and getattr(proof, "current_status", "") == "verified_absent"
            )

            db.update_exposure_status(exposure.id, "reappeared")
            db.update_removal_next_check(removal.id, checked_at=result.checked_at)

            if was_absent:
                # True reappearance — enqueue re-removal and alert
                db.enqueue_removal(exposure.id)
                try:
                    from src.notifier import send_alert  # type: ignore[import]
                    send_alert(
                        level="ALERT",
                        message=(
                            f"Your data has reappeared on {broker.name}. "
                            "TraceBurn has submitted a new opt-out automatically. "
                            "Run `traceburn status` for details."
                        ),
                    )
                except Exception as notify_exc:
                    logger.warning("Telegram alert failed: %s", notify_exc)

            logger.warning(
                "Data reappeared: broker=%s removal_request_id=%d was_absent=%s",
                broker.name, removal.id, was_absent,
            )

        elif result.status == "error":
            db.update_removal_next_check(removal.id, checked_at=result.checked_at)
            logger.error(
                "Verification error: broker=%s removal_request_id=%d details=%s",
                broker.name, removal.id, result.details,
            )
