"""
src/removal/brokers/spokeo.py — Spokeo Opt-Out Automation

Automates the Spokeo opt-out form submission via Playwright.

Process:
  1. Search Spokeo for the user's listing to find the direct profile URL
  2. Navigate to https://www.spokeo.com/optout
  3. Paste the listing URL into the opt-out form
  4. Enter the user's email address
  5. Submit the form
  6. Wait for and capture the confirmation message

NOTE: Spokeo sends a confirmation email — the user must click the link.
      Email confirmation is handled by tier2_email.py after this returns.

IMPORTANT: All CSS selectors and XPaths below should be verified against
           the live Spokeo site before running in production. These were
           accurate as of the design phase but broker sites change frequently.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_OPT_OUT_URL = "https://www.spokeo.com/optout"
_SEARCH_BASE_URL = "https://www.spokeo.com"


class SpokeoOptOut:
    """
    Automates Spokeo opt-out form submission.

    Usage::

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(java_script_enabled=True)
            page = await context.new_page()

            optout = SpokeoOptOut()
            result = await optout.run(page, profile)
    """

    async def run(
        self,
        page: Any,
        profile: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Execute the Spokeo opt-out flow.

        Parameters
        ----------
        page:
            A Playwright Page object with an open browser context.
        profile:
            Dict of PII field names → plaintext values (from vault).
            Expected keys: ``full_name``, ``email``, ``city``, ``state``.

        Returns
        -------
        dict with keys:
            - ``success`` (bool)
            - ``confirmation_text`` (str | None)
            - ``screenshot_taken`` (bool)
            - ``error`` (str | None)
        """
        name = profile.get("full_name", "")
        email = profile.get("email", "")
        city = profile.get("city", "")
        state = profile.get("state", "")

        if not name or not email:
            return {
                "success": False,
                "confirmation_text": None,
                "screenshot_taken": False,
                "error": "full_name and email are required for Spokeo opt-out",
            }

        # Step 1: Find the listing URL on Spokeo
        listing_url = await self._find_listing_url(page, name, city, state)

        if not listing_url:
            logger.warning("SpokeoOptOut: No listing found for '%s' — opt-out skipped.", name)
            return {
                "success": False,
                "confirmation_text": None,
                "screenshot_taken": False,
                "error": "No listing found to opt out of",
            }

        # Step 2: Navigate to the opt-out page
        try:
            # TODO: Verify opt-out page URL is still https://www.spokeo.com/optout
            await page.goto(_OPT_OUT_URL, wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_timeout(2000)
        except Exception as exc:
            return {
                "success": False,
                "confirmation_text": None,
                "screenshot_taken": False,
                "error": f"Failed to load opt-out page: {exc}",
            }

        # Step 3: Fill in the listing URL field
        # TODO: Verify selector for the listing URL input field on live site
        listing_url_filled = await self._fill_field(
            page,
            selectors=[
                "input[name='listingUrl']",
                "input[placeholder*='listing']",
                "input[placeholder*='URL']",
                "#listingUrl",
                "input[type='url']",
            ],
            value=listing_url,
        )

        if not listing_url_filled:
            logger.warning("SpokeoOptOut: Could not find listing URL input field.")

        # Step 4: Fill in the email field
        # TODO: Verify selector for the email input field on live site
        email_filled = await self._fill_field(
            page,
            selectors=[
                "input[type='email']",
                "input[name='email']",
                "input[placeholder*='email']",
                "#email",
            ],
            value=email,
        )

        if not email_filled:
            return {
                "success": False,
                "confirmation_text": None,
                "screenshot_taken": False,
                "error": "Could not find email input field on opt-out page",
            }

        # Step 5: Submit the form
        # TODO: Verify submit button selector on live site
        submitted = await self._click_submit(
            page,
            selectors=[
                "button[type='submit']",
                "input[type='submit']",
                "button:has-text('Opt Out')",
                "button:has-text('Submit')",
                "button:has-text('Remove')",
            ],
        )

        if not submitted:
            return {
                "success": False,
                "confirmation_text": None,
                "screenshot_taken": False,
                "error": "Could not find or click the submit button",
            }

        # Step 6: Wait for confirmation
        await page.wait_for_timeout(3000)

        screenshot_taken = False
        try:
            import os
            from pathlib import Path
            if os.environ.get("TRACEBURN_DEBUG"):
                debug_dir = Path.home() / ".traceburn" / "debug"
                debug_dir.mkdir(parents=True, exist_ok=True)
                await page.screenshot(path=str(debug_dir / "spokeo_optout_confirmation.png"))
                screenshot_taken = True
        except Exception:
            pass

        # Step 7: Extract confirmation text
        # TODO: Verify confirmation message selector and text on live site
        confirmation_text = await self._extract_confirmation(
            page,
            selectors=[
                ".confirmation-message",
                ".success-message",
                "[data-testid='confirmation']",
                ".opt-out-success",
                "h2",
                ".alert-success",
            ],
            success_phrases=[
                "opt-out",
                "submitted",
                "confirmation",
                "email",
                "check your",
                "sent",
            ],
        )

        success = confirmation_text is not None
        return {
            "success": success,
            "confirmation_text": confirmation_text,
            "screenshot_taken": screenshot_taken,
            "error": None if success else "No confirmation message detected",
        }

    # ── Private helpers ───────────────────────────────────────────────────

    async def _find_listing_url(
        self,
        page: Any,
        name: str,
        city: str,
        state: str,
    ) -> str | None:
        """
        Search Spokeo and return the direct URL of the first matching listing.

        Returns None if no listing is found.

        TODO: Verify Spokeo's search URL structure and result selectors
              against the live site before production use.
        """
        try:
            name_slug = name.strip().replace(" ", "-")
            if city and state:
                search_url = (
                    f"{_SEARCH_BASE_URL}/{name_slug}/{state.upper()}/{city.replace(' ', '-')}"
                )
            else:
                search_url = f"{_SEARCH_BASE_URL}/{name_slug}"

            await page.goto(search_url, wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_timeout(2000)

            # TODO: Update these selectors to match current Spokeo result cards
            link_selectors = [
                "a.card-rec__link",
                "a[href*='/name/']",
                ".result-card a",
                "[data-testid='result-link']",
            ]
            for selector in link_selectors:
                link = await page.query_selector(selector)
                if link:
                    href = await link.get_attribute("href")
                    if href:
                        if href.startswith("/"):
                            href = f"{_SEARCH_BASE_URL}{href}"
                        return href
        except Exception as exc:
            logger.warning("SpokeoOptOut: Error searching for listing: %s", exc)

        return None

    async def _fill_field(
        self,
        page: Any,
        selectors: list[str],
        value: str,
    ) -> bool:
        """Try each selector in order; fill the first one found. Returns True on success."""
        for selector in selectors:
            try:
                element = await page.query_selector(selector)
                if element:
                    await element.click()
                    await element.fill(value)
                    return True
            except Exception:
                continue
        return False

    async def _click_submit(self, page: Any, selectors: list[str]) -> bool:
        """Try each selector; click the first submit element found. Returns True on success."""
        for selector in selectors:
            try:
                element = await page.query_selector(selector)
                if element:
                    await element.click()
                    await page.wait_for_load_state("networkidle", timeout=10000)
                    return True
            except Exception:
                continue
        return False

    async def _extract_confirmation(
        self,
        page: Any,
        selectors: list[str],
        success_phrases: list[str],
    ) -> str | None:
        """
        Look for a confirmation message using *selectors*.

        Returns the text content of the first element that contains any of
        the *success_phrases* (case-insensitive). Returns None if not found.
        """
        for selector in selectors:
            try:
                elements = await page.query_selector_all(selector)
                for element in elements:
                    text = (await element.inner_text()).strip().lower()
                    if any(phrase in text for phrase in success_phrases):
                        return (await element.inner_text()).strip()
            except Exception:
                continue

        # Fallback: check full page text
        try:
            body_text = (await page.inner_text("body")).lower()
            if any(phrase in body_text for phrase in success_phrases):
                return "Opt-out submitted (confirmation detected in page text)."
        except Exception:
            pass

        return None
