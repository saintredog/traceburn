"""
src/removal/brokers/beenverified.py — BeenVerified Opt-Out Automation

Automates the BeenVerified opt-out form via Playwright.

Process:
  1. Navigate to https://www.beenverified.com/app/optout/search
  2. Search by name + state
  3. Select the matching record from results
  4. Submit the opt-out form
  5. Return result — NOTE: BeenVerified requires email confirmation
     The user must click a link sent to their email to complete removal.
     Email confirmation polling is handled by tier2_email.py after this
     method returns.

IMPORTANT: All selectors should be verified against the live BeenVerified
           site before production use. The site is in the PeopleConnect
           network and shares infrastructure with TruthFinder, InstantCheckmate,
           PeopleLooker, and USSearch.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_OPT_OUT_URL = "https://www.beenverified.com/app/optout/search"


class BeenVerifiedOptOut:
    """
    Automates BeenVerified opt-out form submission.

    IMPORTANT: This class submits the opt-out form and captures the initial
    confirmation. BeenVerified then sends an email confirmation link that
    must be clicked to finalise removal. The email confirmation step is
    handled externally by tier2_email.py.

    Usage::

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(java_script_enabled=True)
            page = await context.new_page()

            optout = BeenVerifiedOptOut()
            result = await optout.run(page, profile)
            # If result["email_confirmation_required"]:
            #     tier2_email.py handles IMAP polling for the confirmation link
    """

    async def run(
        self,
        page: Any,
        profile: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Execute the BeenVerified opt-out flow.

        Parameters
        ----------
        page:
            A Playwright Page object with an open browser context.
        profile:
            Dict of PII field names → plaintext values (from vault).
            Expected keys: ``full_name``, ``state`` (required).

        Returns
        -------
        dict with keys:
            - ``success`` (bool) — True if the form was submitted successfully
            - ``confirmation_text`` (str | None)
            - ``screenshot_taken`` (bool)
            - ``email_confirmation_required`` (bool) — always True for BeenVerified
            - ``error`` (str | None)
        """
        name = profile.get("full_name", "")
        state = profile.get("state", "")

        name_parts = name.strip().split()
        first_name = profile.get("first_name") or (name_parts[0] if name_parts else "")
        last_name = profile.get("last_name") or (name_parts[-1] if len(name_parts) > 1 else "")

        if not first_name or not state:
            return {
                "success": False,
                "confirmation_text": None,
                "screenshot_taken": False,
                "email_confirmation_required": True,
                "error": "full_name and state are required for BeenVerified opt-out",
            }

        # Step 1: Navigate to opt-out search page
        try:
            # TODO: Verify opt-out URL is still https://www.beenverified.com/app/optout/search
            await page.goto(_OPT_OUT_URL, wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_timeout(2000)
        except Exception as exc:
            return {
                "success": False,
                "confirmation_text": None,
                "screenshot_taken": False,
                "email_confirmation_required": True,
                "error": f"Failed to load BeenVerified opt-out page: {exc}",
            }

        # Step 2: Fill search form — first name, last name, state
        # TODO: Verify input selectors against current BeenVerified opt-out form DOM
        await self._fill_field(
            page,
            selectors=[
                "input[name='firstName']",
                "input[name='first_name']",
                "input[placeholder*='First']",
                "#firstName",
                "[data-testid='first-name']",
            ],
            value=first_name,
        )
        await self._fill_field(
            page,
            selectors=[
                "input[name='lastName']",
                "input[name='last_name']",
                "input[placeholder*='Last']",
                "#lastName",
                "[data-testid='last-name']",
            ],
            value=last_name,
        )
        await self._select_state(page, state)

        # Step 3: Submit search
        # TODO: Verify search submit button selector
        search_submitted = await self._click_submit(
            page,
            selectors=[
                "button[type='submit']",
                "input[type='submit']",
                "button:has-text('Search')",
                "button:has-text('Find')",
            ],
        )

        if not search_submitted:
            return {
                "success": False,
                "confirmation_text": None,
                "screenshot_taken": False,
                "email_confirmation_required": True,
                "error": "Could not submit the search form",
            }

        await page.wait_for_timeout(3000)

        # Step 4: Select matching record from search results
        # TODO: Verify record selection approach on live BeenVerified results page
        record_selected = await self._select_matching_record(page, name, state)
        if not record_selected:
            logger.warning("BeenVerifiedOptOut: No matching record found for '%s'.", name)
            return {
                "success": False,
                "confirmation_text": None,
                "screenshot_taken": False,
                "email_confirmation_required": True,
                "error": "No matching record found in BeenVerified search results",
            }

        await page.wait_for_timeout(2000)

        # Step 5: Submit the opt-out form
        # TODO: Verify opt-out submission button selector on the record opt-out page
        opt_out_submitted = await self._click_submit(
            page,
            selectors=[
                "button:has-text('Opt Out')",
                "button:has-text('Submit Opt-Out')",
                "button:has-text('Remove My Record')",
                "button[type='submit']",
                "input[type='submit']",
            ],
        )

        await page.wait_for_timeout(3000)

        # Screenshot for debug
        screenshot_taken = False
        try:
            import os
            from pathlib import Path
            if os.environ.get("TRACEBURN_DEBUG"):
                debug_dir = Path.home() / ".traceburn" / "debug"
                debug_dir.mkdir(parents=True, exist_ok=True)
                await page.screenshot(
                    path=str(debug_dir / "beenverified_optout_confirmation.png")
                )
                screenshot_taken = True
        except Exception:
            pass

        # Step 6: Capture confirmation text
        # TODO: Verify confirmation message selector and text on live BeenVerified site
        # Note: BeenVerified typically shows "Check your email" message at this stage
        confirmation_text = await self._extract_confirmation(
            page,
            selectors=[
                ".confirmation-message",
                ".success-message",
                ".opt-out-success",
                ".alert-success",
                "h1",
                "h2",
                "[data-testid='confirmation']",
            ],
            success_phrases=[
                "opt-out",
                "email",
                "check your",
                "confirmation",
                "submitted",
                "received",
                "processing",
            ],
        )

        success = opt_out_submitted
        return {
            "success": success,
            "confirmation_text": confirmation_text,
            "screenshot_taken": screenshot_taken,
            "email_confirmation_required": True,  # Always True for BeenVerified
            "error": None if success else "Could not submit opt-out form",
        }

    # ── Private helpers ───────────────────────────────────────────────────

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

    async def _select_state(self, page: Any, state: str) -> bool:
        """Set the state dropdown or input to *state*."""
        # Try select dropdown
        # TODO: Verify state selector on live BeenVerified form
        for selector in ["select[name='state']", "select#state", "select[name='State']"]:
            try:
                element = await page.query_selector(selector)
                if element:
                    await element.select_option(label=state)
                    return True
            except Exception:
                try:
                    element = await page.query_selector(selector)
                    if element:
                        await element.select_option(value=state.upper()[:2])
                        return True
                except Exception:
                    continue

        return await self._fill_field(
            page,
            selectors=["input[name='state']", "input[placeholder*='State']", "#state"],
            value=state,
        )

    async def _select_matching_record(
        self,
        page: Any,
        name: str,
        state: str,
    ) -> bool:
        """
        In the results list, click the opt-out or select button for the record
        that most closely matches *name* and *state*.

        TODO: Verify record card and select button selectors on live BeenVerified
              results page. The PeopleConnect network sites use React-rendered
              results that may require waiting for hydration.
        """
        norm_name = name.strip().lower()
        norm_state = state.strip().lower()

        # Wait for results to load (React hydration)
        try:
            await page.wait_for_selector(
                ".optout-record, .record-card, [data-testid='record'], li.result",
                timeout=8000,
            )
        except Exception:
            pass  # Continue even if selector not found — try anyway

        # TODO: Update selectors to match current BeenVerified results DOM structure
        record_selectors = [
            ".optout-record",
            ".record-card",
            "[data-testid='record']",
            "li.result",
            ".person-card",
        ]

        opt_out_button_selectors = [
            "button:has-text('Opt Out')",
            "button:has-text('Remove')",
            "button:has-text('Select')",
            "a:has-text('Opt Out')",
            "[data-testid='optout-button']",
        ]

        for record_selector in record_selectors:
            try:
                records = await page.query_selector_all(record_selector)
                for record in records:
                    record_text = (await record.inner_text()).lower()
                    last_name = norm_name.split()[-1] if norm_name else ""

                    if last_name and last_name in record_text:
                        # Found a likely match — click its opt-out button
                        for btn_selector in opt_out_button_selectors:
                            try:
                                btn = await record.query_selector(btn_selector)
                                if btn:
                                    await btn.click()
                                    await page.wait_for_load_state("domcontentloaded", timeout=10000)
                                    return True
                            except Exception:
                                continue
            except Exception:
                continue

        # Fallback: click the first available opt-out button on the page
        for btn_selector in opt_out_button_selectors:
            try:
                btn = await page.query_selector(btn_selector)
                if btn:
                    await btn.click()
                    await page.wait_for_load_state("domcontentloaded", timeout=10000)
                    return True
            except Exception:
                continue

        return False

    async def _click_submit(self, page: Any, selectors: list[str]) -> bool:
        """Try each selector; click the first found. Returns True on success."""
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
        """Extract confirmation text from the page after opt-out submission."""
        for selector in selectors:
            try:
                elements = await page.query_selector_all(selector)
                for element in elements:
                    text = (await element.inner_text()).strip()
                    if any(phrase in text.lower() for phrase in success_phrases):
                        return text
            except Exception:
                continue

        try:
            body_text = (await page.inner_text("body")).lower()
            if any(phrase in body_text for phrase in success_phrases):
                return "Opt-out submitted (confirmation detected in page text)."
        except Exception:
            pass

        return None
