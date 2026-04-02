"""
src/removal/engine.py — Removal orchestrator for TraceBurn.

RemovalEngine receives a list of confirmed Exposure records from the scanner,
routes each to the correct removal tier based on broker.removal_tier, updates
DB state after each attempt, and triggers proof capture.

Usage:
    engine = RemovalEngine(db=db_gateway, config=app_config, notifier=notifier)
    results = await engine.remove_all(profile=user, exposures=exposures)
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import TYPE_CHECKING

from ..models import (
    BrokerDefinition,
    Exposure,
    RemovalMethod,
    RemovalRequest,
    RemovalResult,
    RemovalStatus,
    RemovalTier,
)

if TYPE_CHECKING:
    from ..notifier import TelegramNotifier

logger = logging.getLogger(__name__)


class RemovalEngine:
    """
    Orchestrates removal requests across all three tiers.

    Responsibilities:
    - Load broker definition for each exposure
    - Route to Tier1Remover, Tier2Remover, or Tier3Wizard
    - Update RemovalRequest status in DB after each attempt
    - Fire Telegram notifications (non-blocking) on key events
    - Return a RemovalResult per exposure for the caller to surface to the CLI

    The engine never captures proof itself — proof capture is triggered
    inside each tier handler as a side-effect of the opt-out flow.
    """

    def __init__(
        self,
        db: object,
        config: object,
        notifier: "TelegramNotifier | None" = None,
    ) -> None:
        """
        Args:
            db:       Database gateway (db.py gateway instance).
            config:   AppConfig object loaded at CLI startup.
            notifier: Optional TelegramNotifier for fire-and-forget alerts.
        """
        self._db = db
        self._config = config
        self._notifier = notifier
        self._screenshots_dir = getattr(
            getattr(config, "vault", None), "screenshots_dir", None
        )

    # ──────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────

    async def remove_all(
        self,
        profile: object,
        exposures: list[Exposure],
    ) -> list[RemovalResult]:
        """
        Process all exposures for a profile, routing each to the correct tier.

        Exposures are processed concurrently within each tier group to maximise
        throughput while keeping Playwright sessions from overwhelming resources.
        Tier 3 (manual wizard) is always run last and interactively.

        Args:
            profile:   User profile (vault PII available via vault.get(profile))
            exposures: List of Exposure records with status='found' or 'reappeared'

        Returns:
            List of RemovalResult — one per exposure, in order submitted.
        """
        if not exposures:
            logger.info("[Engine] No exposures to process.")
            return []

        logger.info(
            "[Engine] Processing %d exposure(s) for profile '%s'",
            len(exposures),
            getattr(profile, "display_name", "unknown"),
        )

        # Partition by tier
        tier1: list[Exposure] = []
        tier2: list[Exposure] = []
        tier3: list[Exposure] = []

        for exp in exposures:
            broker = self._load_broker(exp)
            if broker is None:
                logger.warning(
                    "[Engine] No broker definition found for broker_id=%s — skipping",
                    exp.broker_id,
                )
                continue
            if broker.removal_tier == RemovalTier.PLAYWRIGHT:
                tier1.append(exp)
            elif broker.removal_tier == RemovalTier.EMAIL:
                tier2.append(exp)
            else:
                tier3.append(exp)

        results: list[RemovalResult] = []

        # Process Tier 1 (automated, can run concurrently)
        if tier1:
            logger.info("[Engine] Running %d Tier 1 (Playwright) removals", len(tier1))
            t1_results = await self._run_tier1_batch(profile, tier1)
            results.extend(t1_results)

        # Process Tier 2 (email, can run concurrently)
        if tier2:
            logger.info("[Engine] Running %d Tier 2 (Email) removals", len(tier2))
            t2_results = await self._run_tier2_batch(profile, tier2)
            results.extend(t2_results)

        # Process Tier 3 (manual, always sequential/interactive)
        if tier3:
            logger.info("[Engine] Running %d Tier 3 (Manual) removals", len(tier3))
            t3_results = await self._run_tier3_batch(profile, tier3)
            results.extend(t3_results)

        succeeded = sum(1 for r in results if r.succeeded)
        logger.info(
            "[Engine] Done — %d/%d removals submitted/confirmed",
            succeeded,
            len(results),
        )
        return results

    async def remove_one(self, exposure: Exposure) -> RemovalResult:
        """
        Process a single exposure, routing to the correct tier.

        Useful for retry flows or single-broker re-submissions.

        Args:
            exposure: A single Exposure record.

        Returns:
            RemovalResult with outcome status.
        """
        broker = self._load_broker(exposure)
        if broker is None:
            return RemovalResult(
                exposure_id=exposure.id,
                broker_name=exposure.broker_name,
                status=RemovalStatus.FAILED,
                error=f"No broker definition found for broker_id={exposure.broker_id}",
            )

        pii = self._get_pii(exposure)

        if broker.removal_tier == RemovalTier.PLAYWRIGHT:
            return await self._run_tier1(exposure, broker, pii)
        elif broker.removal_tier == RemovalTier.EMAIL:
            return await self._run_tier2(exposure, broker, pii)
        else:
            return await self._run_tier3(exposure, broker)

    # ──────────────────────────────────────────────────────────────
    # Batch helpers
    # ──────────────────────────────────────────────────────────────

    async def _run_tier1_batch(
        self, profile: object, exposures: list[Exposure]
    ) -> list[RemovalResult]:
        """Run Tier 1 removals concurrently (max 3 simultaneous Playwright sessions)."""
        semaphore = asyncio.Semaphore(3)

        async def _guarded(exp: Exposure) -> RemovalResult:
            async with semaphore:
                broker = self._load_broker(exp)
                pii = self._get_pii(exp)
                return await self._run_tier1(exp, broker, pii)

        return list(await asyncio.gather(*[_guarded(e) for e in exposures]))

    async def _run_tier2_batch(
        self, profile: object, exposures: list[Exposure]
    ) -> list[RemovalResult]:
        """Run Tier 2 email removals concurrently."""
        semaphore = asyncio.Semaphore(5)

        async def _guarded(exp: Exposure) -> RemovalResult:
            async with semaphore:
                broker = self._load_broker(exp)
                pii = self._get_pii(exp)
                return await self._run_tier2(exp, broker, pii)

        return list(await asyncio.gather(*[_guarded(e) for e in exposures]))

    async def _run_tier3_batch(
        self, profile: object, exposures: list[Exposure]
    ) -> list[RemovalResult]:
        """Run Tier 3 manual wizard sequentially (interactive terminal UI)."""
        results = []
        for exp in exposures:
            broker = self._load_broker(exp)
            result = await self._run_tier3(exp, broker)
            results.append(result)
        return results

    # ──────────────────────────────────────────────────────────────
    # Per-tier dispatch
    # ──────────────────────────────────────────────────────────────

    async def _run_tier1(
        self,
        exposure: Exposure,
        broker: BrokerDefinition,
        pii: dict,
    ) -> RemovalResult:
        """Dispatch to Tier1Remover. Catches all exceptions to ensure resilience."""
        from .tier1_playwright import Tier1Remover

        try:
            remover = Tier1Remover(screenshots_dir=self._screenshots_dir)
            result = await remover.submit_optout(broker=broker, pii=pii, exposure=exposure)
            self._maybe_notify(result)
            return result
        except Exception as exc:
            logger.exception(
                "[Engine] Tier 1 fatal error for %s: %s", broker.name, exc
            )
            return self._make_error_result(exposure, broker, str(exc))

    async def _run_tier2(
        self,
        exposure: Exposure,
        broker: BrokerDefinition,
        pii: dict,
    ) -> RemovalResult:
        """Dispatch to Tier2Remover. Catches all exceptions to ensure resilience."""
        from .tier2_email import Tier2Remover

        try:
            remover = Tier2Remover(config=self._config)
            result = await remover.send_optout_email(broker=broker, profile=pii)
            self._maybe_notify(result)
            return result
        except Exception as exc:
            logger.exception(
                "[Engine] Tier 2 fatal error for %s: %s", broker.name, exc
            )
            return self._make_error_result(exposure, broker, str(exc))

    async def _run_tier3(
        self,
        exposure: Exposure,
        broker: BrokerDefinition,
    ) -> RemovalResult:
        """Dispatch to Tier3Wizard. Catches all exceptions to ensure resilience."""
        from .tier3_wizard import Tier3Wizard

        try:
            wizard = Tier3Wizard(db=self._db)
            result = await wizard.guide_user(broker=broker, exposure=exposure)
            self._maybe_notify(result)
            return result
        except Exception as exc:
            logger.exception(
                "[Engine] Tier 3 fatal error for %s: %s", broker.name, exc
            )
            return self._make_error_result(exposure, broker, str(exc))

    # ──────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────

    def _load_broker(self, exposure: Exposure) -> BrokerDefinition | None:
        """
        Fetch BrokerDefinition from DB by broker_id.

        Returns None if the broker is not found (logs a warning).
        """
        try:
            return self._db.get_broker(exposure.broker_id)
        except Exception as exc:
            logger.warning(
                "[Engine] Failed to load broker %s: %s", exposure.broker_id, exc
            )
            return None

    def _get_pii(self, exposure: Exposure) -> dict:
        """
        Retrieve PII for the given exposure's user from vault.

        Returns a dict of PII fields needed for form filling and email rendering.
        Returns an empty dict if vault is not available (logs a warning).
        """
        try:
            vault = getattr(self._config, "_vault", None)
            if vault is None:
                logger.warning("[Engine] Vault not configured — PII not available")
                return {}
            return vault.get_all_fields(user_id=exposure.user_id)
        except Exception as exc:
            logger.warning("[Engine] Failed to fetch PII from vault: %s", exc)
            return {}

    def _maybe_notify(self, result: RemovalResult) -> None:
        """Fire-and-forget Telegram notification based on result status."""
        if self._notifier is None:
            return
        try:
            if result.status == RemovalStatus.CONFIRMED:
                self._notifier.send_removal_confirmed(
                    broker_name=result.broker_name,
                    timestamp=result.timestamp.isoformat(),
                )
            elif result.requires_manual_followup:
                self._notifier.send_manual_action_required(
                    broker_name=result.broker_name,
                    url="",  # URL passed in from broker definition if available
                )
        except Exception as exc:
            logger.debug("[Engine] Notification error (swallowed): %s", exc)

    @staticmethod
    def _make_error_result(
        exposure: Exposure,
        broker: BrokerDefinition,
        error_msg: str,
    ) -> RemovalResult:
        return RemovalResult(
            exposure_id=exposure.id,
            broker_name=broker.name,
            status=RemovalStatus.FAILED,
            error=error_msg,
        )
