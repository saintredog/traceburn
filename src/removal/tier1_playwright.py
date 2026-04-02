"""
src/removal/tier1_playwright.py — Automated Playwright opt-out handler (Tier 1).

Dynamically loads a broker-specific script from src/removal/brokers/{broker_domain}.py,
executes the opt-out flow inside a headless Chromium browser, captures proof screenshots,
and returns a RemovalResult.

Error handling matrix:
  - 404 / page not found    → FAILED, schedules retry
  - Element not found       → FAILED, "form_changed" flag, alerts for script update
  - Navigation timeout      → FAILED, emergency screenshot
  - CAPTCHA mid-flow        → CAPTCHA_BLOCKED, downgrades to Tier 3 queue
  - Requires email confirm  → AWAITING_CONFIRMATION, IMAP poller takes over
"""

from __future__ import annotations

import importlib
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from ..models import (
    BrokerDefinition,
    Exposure,
    RemovalMethod,
    RemovalRequest,
    RemovalResult,
    RemovalStatus,
    RemovalTier,
)

logger = logging.getLogger(__name__)

# Python package path for broker-specific opt-out scripts
_BROKERS_PACKAGE = "src.removal.brokers"

# Known CAPTCHA-related page text fragments (heuristic detection)
_CAPTCHA_INDICATORS = [
    "captcha",
    "recaptcha",
    "hcaptcha",
    "robot",
    "are you human",
    "prove you're not a robot",
    "security check",
    "cloudflare",
    "ddos-guard",
    "please verify",
]


class OptOutResult:
    """
    Result returned by a broker-specific opt-out script's run() method.

    success                  — True if the form was submitted without error
    confirmation_text        — Text extracted from the confirmation page
    requires_email_confirm   — True if broker sends a confirmation email to click
    screenshot_taken         — True if the broker script took its own mid-flow screenshot
    error                    — Human-readable error description on failure
    captcha_detected         — True if CAPTCHA was found mid-flow
    form_changed             — True if a required page element was missing (form layout changed)
    """

    def __init__(
        self,
        success: bool,
        confirmation_text: str = "",
        requires_email_confirm: bool = False,
        screenshot_taken: bool = False,
        error: str | None = None,
        captcha_detected: bool = False,
        form_changed: bool = False,
    ) -> None:
        self.success = success
        self.confirmation_text = confirmation_text
        self.requires_email_confirm = requires_email_confirm
        self.screenshot_taken = screenshot_taken
        self.error = error
        self.captcha_detected = captcha_detected
        self.form_changed = form_changed


class Tier1Remover:
    """
    Handles Tier 1 (Playwright) opt-outs.

    For each exposure:
      1. Loads the broker-specific script from src/removal/brokers/
      2. Launches headless Chromium via Playwright
      3. Navigates to the opt-out URL
      4. Executes the broker script's run(page, profile) coroutine
      5. Captures pre/post proof screenshots
      6. Returns a RemovalResult
    """

    def __init__(self, screenshots_dir: Path | str | None = None) -> None:
        """
        Args:
            screenshots_dir: Directory where proof screenshots are saved.
                             Defaults to ~/.traceburn/screenshots if None.
        """
        if screenshots_dir is None:
            self._screenshots_dir = Path.home() / ".traceburn" / "screenshots"
        else:
            self._screenshots_dir = Path(screenshots_dir)
        self._screenshots_dir.mkdir(parents=True, exist_ok=True)

    async def submit_optout(
        self,
        broker: BrokerDefinition,
        pii: dict,
        exposure: Exposure,
    ) -> RemovalResult:
        """
        Execute the full Tier 1 opt-out flow for one exposure.

        Args:
            broker:   BrokerDefinition describing the target broker.
            pii:      Dict of plaintext PII fields from vault (name, address, phone, etc.)
            exposure: The Exposure record being actioned.

        Returns:
            RemovalResult with final status and proof references.
        """
        # Lazy import to avoid making playwright a hard dependency
        try:
            from playwright.async_api import (
                async_playwright,
                TimeoutError as PlaywrightTimeout,
            )
        except ImportError:
            logger.error("[Tier1] playwright not installed — cannot run Tier 1 removal")
            return RemovalResult(
                exposure_id=exposure.id,
                broker_name=broker.name,
                status=RemovalStatus.FAILED,
                error="playwright package not installed",
            )

        # Load broker-specific script
        try:
            broker_module = _load_broker_script(broker.domain)
        except (FileNotFoundError, AttributeError) as exc:
            logger.error("[Tier1] Cannot load broker script for %s: %s", broker.name, exc)
            return RemovalResult(
                exposure_id=exposure.id,
                broker_name=broker.name,
                status=RemovalStatus.FAILED,
                error=str(exc),
            )

        logger.info(
            "[Tier1] Starting opt-out for %s at %s",
            broker.name,
            broker.opt_out_url,
        )

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/123.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1280, "height": 900},
            )
            page = await context.new_page()
            page.set_default_timeout(30_000)  # 30s per action

            pre_screenshot: str | None = None
            post_screenshot: str | None = None
            out_result: OptOutResult | None = None

            try:
                # Navigate to opt-out URL
                response = await page.goto(
                    broker.opt_out_url,
                    wait_until="domcontentloaded",
                    timeout=30_000,
                )

                # Check for 404
                if response and response.status == 404:
                    logger.warning("[Tier1] 404 for %s — opt-out page not found", broker.name)
                    pre_screenshot = await _take_screenshot(
                        page, self._screenshots_dir, broker.domain, "404_error"
                    )
                    return RemovalResult(
                        exposure_id=exposure.id,
                        broker_name=broker.name,
                        status=RemovalStatus.FAILED,
                        error="Opt-out page returned 404 — page may have moved",
                    )

                # Pre-submit proof screenshot
                pre_screenshot = await _take_screenshot(
                    page, self._screenshots_dir, broker.domain, "pre_submit"
                )

                # Check for CAPTCHA before starting the form
                if await _detect_captcha(page):
                    logger.warning(
                        "[Tier1] CAPTCHA detected before form interaction at %s",
                        broker.name,
                    )
                    await _take_screenshot(
                        page, self._screenshots_dir, broker.domain, "captcha_detected"
                    )
                    return RemovalResult(
                        exposure_id=exposure.id,
                        broker_name=broker.name,
                        status=RemovalStatus.CAPTCHA_BLOCKED,
                        error="CAPTCHA detected before form interaction — downgraded to Tier 3",
                        requires_manual_followup=True,
                    )

                # Execute broker-specific opt-out script
                out_result = await broker_module.run(page=page, profile=pii)

                # Post-submit proof screenshot (always attempt)
                post_screenshot = await _take_screenshot(
                    page, self._screenshots_dir, broker.domain, "post_submit"
                )

                # Handle result
                if out_result.captcha_detected:
                    logger.warning(
                        "[Tier1] CAPTCHA detected mid-flow at %s — downgrading to Tier 3",
                        broker.name,
                    )
                    return RemovalResult(
                        exposure_id=exposure.id,
                        broker_name=broker.name,
                        status=RemovalStatus.CAPTCHA_BLOCKED,
                        error="CAPTCHA appeared mid-flow — manual completion required",
                        requires_manual_followup=True,
                    )

                if out_result.form_changed:
                    logger.error(
                        "[Tier1] Form structure changed at %s — broker script needs update",
                        broker.name,
                    )
                    return RemovalResult(
                        exposure_id=exposure.id,
                        broker_name=broker.name,
                        status=RemovalStatus.FAILED,
                        error="Broker opt-out form structure has changed — script update required",
                    )

                if not out_result.success:
                    return RemovalResult(
                        exposure_id=exposure.id,
                        broker_name=broker.name,
                        status=RemovalStatus.FAILED,
                        error=out_result.error or "Broker script reported failure",
                    )

                # Successful submission
                final_status = (
                    RemovalStatus.AWAITING_CONFIRMATION
                    if out_result.requires_email_confirm
                    else RemovalStatus.SUBMITTED
                )

                logger.info(
                    "[Tier1] %s → %s (confirmation_text=%r)",
                    broker.name,
                    final_status.value,
                    out_result.confirmation_text[:80] if out_result.confirmation_text else "",
                )

                return RemovalResult(
                    exposure_id=exposure.id,
                    broker_name=broker.name,
                    status=final_status,
                    confirmation_text=out_result.confirmation_text,
                )

            except PlaywrightTimeout as exc:
                logger.error("[Tier1] Timeout at %s: %s", broker.name, exc)
                await _take_screenshot(
                    page, self._screenshots_dir, broker.domain, "timeout_error"
                )
                return RemovalResult(
                    exposure_id=exposure.id,
                    broker_name=broker.name,
                    status=RemovalStatus.FAILED,
                    error=f"Page timeout: {exc}",
                )

            except Exception as exc:
                logger.exception("[Tier1] Unexpected error at %s: %s", broker.name, exc)
                await _take_screenshot(
                    page, self._screenshots_dir, broker.domain, "unexpected_error"
                )
                return RemovalResult(
                    exposure_id=exposure.id,
                    broker_name=broker.name,
                    status=RemovalStatus.FAILED,
                    error=f"Unexpected error: {exc}",
                )

            finally:
                await context.close()
                await browser.close()


# ──────────────────────────────────────────────────────────────
# Module-level helpers
# ──────────────────────────────────────────────────────────────


def _load_broker_script(broker_domain: str) -> Any:
    """
    Dynamically import a broker opt-out module from src/removal/brokers/.

    The module is resolved by stripping the TLD and replacing dots/hyphens with
    underscores:
        spokeo.com         → src.removal.brokers.spokeo
        peoplefinders.com  → src.removal.brokers.peoplefinders
        been-verified.com  → src.removal.brokers.been_verified

    The module must expose:
        async def run(page: Page, profile: dict) -> OptOutResult

    Raises:
        FileNotFoundError  — if the module does not exist
        AttributeError     — if the module lacks a run() function
    """
    # Derive module name from domain (strip TLD, sanitize)
    base = broker_domain.split(".")[0]  # e.g. "spokeo" from "spokeo.com"
    module_name = base.replace("-", "_").lower()
    full_path = f"{_BROKERS_PACKAGE}.{module_name}"

    try:
        module = importlib.import_module(full_path)
    except ModuleNotFoundError as exc:
        raise FileNotFoundError(
            f"No broker opt-out script found at {full_path} — "
            f"create src/removal/brokers/{module_name}.py"
        ) from exc

    if not hasattr(module, "run") or not callable(module.run):
        raise AttributeError(
            f"Broker script '{full_path}' must define: "
            f"async def run(page, profile) -> OptOutResult"
        )

    return module


async def _take_screenshot(
    page: Any,
    screenshots_dir: Path,
    broker_domain: str,
    label: str,
) -> str | None:
    """
    Take a full-page screenshot and save to screenshots_dir.

    Returns the path on success, None on failure (errors are swallowed).
    """
    try:
        screenshots_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{broker_domain}_{label}_{int(time.time())}.png"
        path = screenshots_dir / filename
        await page.screenshot(path=str(path), full_page=True)
        logger.debug("[Tier1] Screenshot saved: %s", path)
        return str(path)
    except Exception as exc:
        logger.debug("[Tier1] Screenshot failed (%s): %s", label, exc)
        return None


async def _detect_captcha(page: Any) -> bool:
    """
    Heuristic CAPTCHA detection: checks page content and known CAPTCHA element selectors.

    Returns True if a CAPTCHA is likely present.
    """
    try:
        content = (await page.content()).lower()
        if any(indicator in content for indicator in _CAPTCHA_INDICATORS):
            return True
        # Check for common CAPTCHA iframes/elements
        for selector in [
            'iframe[src*="captcha"]',
            'iframe[src*="recaptcha"]',
            'iframe[src*="hcaptcha"]',
            ".g-recaptcha",
            ".h-captcha",
            "#captcha",
        ]:
            el = await page.query_selector(selector)
            if el is not None:
                return True
    except Exception:
        pass
    return False
