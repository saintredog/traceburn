"""
src/removal/brokers/peoplefinders.py — PeopleFinders Opt-Out Automation

Automates the PeopleFinders opt-out form via Playwright.

Process:
  1. Navigate to https://www.peoplefinders.com/opt-out
  2. Enter name and state
  3. Find the matching record in search results
  4. Click the opt-out link for that record
  5. Submit the opt-out form
  6. Capture confirmation text

PeopleFinders typically does NOT require email confirmation for basic
opt-outs, making it fully automatable in Tier 1.

IMPORTANT: All selectors should be verified against the live site before
           production use. PeopleFinders updates its UI periodically.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_OPT_OUT_URL = "https://www.peoplefinders.com/opt-out"


class PeopleFindersOptOut:
    """
    Automates PeopleFinders opt-out form submission.

    Usage::

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(java_script_enabled=True)
            page = await context.new_page()

            optout = PeopleFindersOptOut()
            result = await optout.run(page, profile)
    """

    async def run(
        self,
        page: Any,
        profile: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Execute the PeopleFinders opt-out flow.

        Parameters
        ----------
        page:
            A Playwright Page object with an open browser context.
        profile:
            Dict of PII field names → plaintext values (from vault).
            Expected keys: ``full_name``, ``state`` (required);
            ``city``, ``first_name``, ``last_name`` (optional, improves accuracy).

        Returns
        -------
        dict with keys:
            - ``success`` (bool)
            - ``confirmation_text`` (str | None)
            - ``screenshot_taken`` (bool)
            - ``error`` (str | None)
        """
        name = profile.get("full_name", "")
        state = profile.get("state", "")

        # Derive first/last name
        name_parts = name.strip().split()
        first_name = profile.get("first_name") or (name_parts[0] if name_parts else "")
        last_name = profile.get("last_name") or (name_parts[-1] if len(name_parts) > 1 else "")

        if not first_name or not state:
            return {
                "success": False,
                "confirmation_text": None,
                "screenshot_taken": False,
                "error": "full_name and state are required for PeopleFinders opt-out",
            }

        # Step 1: Navigate to opt-out page
        try:
            # TODO: Verify opt-out URL is still https://www.peoplefinders.com/opt-out
            await page.goto(_OPT_OUT_URL, wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_timeout(2000)
        except Exception as exc:
            return {
                "success": False,
                "confirmation_text": None,
                "screenshot_taken": False,
                "error": f"Failed to load opt-out page: {exc}",
            }

        # Step 2: Fill name fields
        # TODO: Verify input selectors against current PeopleFinders opt-out form
        first_filled = await self._fill_field(
            page,
            selectors=[
                "input[name='firstname']",
                "input[name='first_name']",
                "input[placeholder*='First']",
                "#firstname",
                "#first-name",
            ],
            value=first_name,
        )
        last_filled = await self._fill_field(
            page,
            selectors=[
                "input[name='lastname']",
                "input[name='last_name']",
                "input[placeholder*='Last']",
                "#lastname",
                "#last-name",
            ],
            value=last_name,
        )

        if not first_filled or not last_filled:
            logger.warning("PeopleFindersOptOut: Could not fill name fields — trying full name.")
            await self._fill_field(
                page,
                selectors=["input[name='name']", "input[placeholder*='Name']", "#name"],
                value=name,
            )

        # Step 3: Select state
        # TODO: Verify state selector/dropdown on live site
        state_selected = await self._select_state(page, state)
        if not state_selected:
            logger.warning("PeopleFindersOptOut: Could not set state field.")

        # Step 4: Submit the search form to find the record
        # TODO: Verify search submit button selector
        search_submitted = await self._click_submit(
            page,
            selectors=[
                "button[type='submit']",
                "input[type='submit']",
                "button:has-text('Search')",
                "button:has-text('Find')",
                "button:has-text('Look Up')",
            ],
        )

        if not search_submitted:
            return {
                "success": False,
                "confirmation_text": None,
                "screenshot_taken": False,
                "error": "Could not submit search form",
            }

        await page.wait_for_timeout(3000)

        # Step 5: Find matching record and click opt-out
        # TODO: Verify record opt-out link selectors on live site results page
        opt_out_clicked = await self._click_record_optout(page, name)

        if not opt_out_clicked:
            return {
                "success": False,
                "confirmation_text": None,
                "screenshot_taken": False,
                "error": "Could not find or click opt-out link in search results",
            }

        await page.wait_for_timeout(2000)

        # Step 6: Confirm the opt-out on the confirmation page
        # TODO: Verify confirmation button selector on live site
        final_submitted = await self._click_submit(
            page,
            selectors=[
                "button[type='submit']",
                "button:has-text('Opt Out')",
                "button:has-text('Remove')",
                "button:has-text('Confirm')",
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
                    path=str(debug_dir / "peoplefinders_optout_confirmation.png")
                )
                screenshot_taken = True
        except Exception:
            pass

        # Step 7: Capture confirmation
        confirmation_text = await self._extract_confirmation(
            page,
            selectors=[
                ".confirmation",
                ".success",
                ".opt-out-success",
                ".alert-success",
                "h1",
                "h2",
                "p.success-message",
            ],
            success_phrases=[
                "opt-out",
                "submitted",
                "removed",
                "processing",
                "request received",
                "success",
            ],
        )

        success = confirmation_text is not None
        return {
            "success": success,
            "confirmation_text": confirmation_text,
            "screenshot_taken": screenshot_taken,
            "error": None if success else "No confirmation message detected after opt-out",
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
        """
        Set the state dropdown or input to *state*.

        Tries both select elements and text inputs.
        """
        # Try select dropdown first
        # TODO: Verify state dropdown selector on live PeopleFinders form
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

        # Try text input
        return await self._fill_field(
            page,
            selectors=[
                "input[name='state']",
                "input[placeholder*='State']",
                "#state",
            ],
            value=state,
        )

    async def _click_record_optout(self, page: Any, name: str) -> bool:
        """
        In the search results, find a record matching *name* and click its opt-out link.

        TODO: Verify record and opt-out link selectors on live PeopleFinders results page.
        """
        norm_name = name.strip().lower()

        # Look for opt-out links near results that contain the user's name
        # TODO: Update selectors to match current PeopleFinders results DOM
        optout_selectors = [
            "a:has-text('Opt Out')",
            "a:has-text('Remove')",
            "a[href*='opt-out']",
            ".optout-link",
            "[data-action='optout']",
        ]

        for selector in optout_selectors:
            try:
                elements = await page.query_selector_all(selector)
                for element in elements:
                    # Check if this result is near text containing the name
                    parent_text = ""
                    parent = await element.evaluate_handle("el => el.closest('.result, .record, li, div')")
                    if parent:
                        parent_text = (await parent.evaluate("el => el.textContent || ''")).lower()

                    if norm_name.split()[-1] in parent_text or not parent_text:
                        await element.click()
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
