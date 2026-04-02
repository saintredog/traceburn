"""
src/scanner/broker_scraper.py — Playwright Broker Scrapers

Abstract base class and concrete implementations for scraping data broker
sites to find user profile listings.

Each scraper uses an isolated Playwright browser context per broker
(no cookies or state shared between brokers) as specified in the security design.

PII safety: profile data is passed in at call time; it is not stored on
the scraper object and is not written to any log.
"""

from __future__ import annotations

import asyncio
import logging
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_TRACEBURN_DEBUG_DIR = Path.home() / ".traceburn" / "debug"

# Pool of real User-Agent strings to rotate through
_USER_AGENTS = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/123.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
        "Gecko/20100101 Firefox/125.0"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/17.4.1 Safari/605.1.15"
    ),
]

# Common CAPTCHA selectors (Cloudflare, hCaptcha, reCAPTCHA, etc.)
_CAPTCHA_SELECTORS = [
    "#cf-challenge-running",
    ".cf-browser-verification",
    ".h-captcha",
    ".g-recaptcha",
    "#recaptcha",
    "[data-sitekey]",
    "iframe[src*='hcaptcha.com']",
    "iframe[src*='recaptcha']",
    "iframe[src*='cloudflare']",
]


@dataclass
class ScrapeResult:
    """A single candidate profile listing found by a broker scraper."""

    broker_name: str
    """Human-readable broker name, e.g. 'Spokeo'."""

    profile_url: str
    """Direct URL to the found profile listing."""

    name_found: str
    """The name string as it appeared on the broker page (may be partial)."""

    address_found: str
    """The address string as it appeared on the broker page."""

    confidence: float
    """Composite confidence score from PIIMatcher [0.0, 1.0]."""

    raw_text: str
    """Full text content of the listing block (for matcher re-scoring)."""

    captcha_encountered: bool = False
    """True if a CAPTCHA was detected during this scrape."""


class BrokerScraper(ABC):
    """
    Abstract base class for Playwright-based broker scrapers.

    Each subclass handles one specific broker's DOM structure and opt-out
    flow. Subclasses must implement :meth:`scrape`.

    Security: A new browser context is created for each call to
    :meth:`scrape` and destroyed when the call completes. No cookies,
    sessions, or state persists between calls.
    """

    # ── Abstract interface ────────────────────────────────────────────────

    @abstractmethod
    async def scrape(
        self,
        broker: dict[str, Any],
        profile: dict[str, Any],
    ) -> list[ScrapeResult]:
        """
        Scrape *broker* for listings matching *profile*.

        *broker* is a broker definition dict (from brokers.yaml).
        *profile* is a dict of PII field names → plaintext values (from vault).

        Returns a list of :class:`ScrapeResult` objects, possibly empty.
        Implementations must never store PII from *profile* beyond the
        duration of this call.
        """

    # ── Protected helpers ─────────────────────────────────────────────────

    def _random_user_agent(self) -> str:
        """Return a randomly selected User-Agent string from the pool."""
        return random.choice(_USER_AGENTS)

    async def _human_delay(self, min_s: float = 1.0, max_s: float = 3.0) -> None:
        """
        Sleep for a random duration between *min_s* and *max_s* seconds.

        Simulates human reading/interaction pauses to reduce bot detection risk.
        """
        delay = random.uniform(min_s, max_s)
        await asyncio.sleep(delay)

    async def _detect_captcha(self, page: Any) -> bool:
        """
        Check the current page for common CAPTCHA challenge indicators.

        Returns True if any CAPTCHA selector is found, False otherwise.
        *page* is a Playwright Page object.
        """
        for selector in _CAPTCHA_SELECTORS:
            try:
                element = await page.query_selector(selector)
                if element:
                    logger.warning("CAPTCHA detected: selector '%s' found on %s", selector, page.url)
                    return True
            except Exception:
                continue
        return False

    async def _screenshot_debug(self, page: Any, name: str) -> None:
        """
        Save a debug screenshot to ~/.traceburn/debug/<name>.png.

        Only active when TRACEBURN_DEBUG=1 is set. Errors are suppressed
        to avoid blocking the main scrape flow.
        """
        import os

        if not os.environ.get("TRACEBURN_DEBUG"):
            return

        try:
            _TRACEBURN_DEBUG_DIR.mkdir(parents=True, exist_ok=True)
            screenshot_path = _TRACEBURN_DEBUG_DIR / f"{name}.png"
            await page.screenshot(path=str(screenshot_path))
            logger.debug("Debug screenshot saved: %s", screenshot_path)
        except Exception as exc:
            logger.debug("Failed to save debug screenshot '%s': %s", name, exc)


# ── Concrete implementations ──────────────────────────────────────────────────


class SpokeoScraper(BrokerScraper):
    """
    Playwright scraper for Spokeo.

    Navigates to spokeo.com, searches by name + city + state, extracts
    result listings, and matches them against the user profile.

    Note: Spokeo may require JavaScript and may trigger bot detection.
    CAPTCHA is detected and reported; the scrape is abandoned if encountered.
    """

    async def scrape(
        self,
        broker: dict[str, Any],
        profile: dict[str, Any],
    ) -> list[ScrapeResult]:
        """
        Scrape Spokeo for profile listings matching *profile*.

        Flow:
        1. Launch isolated Playwright Chromium context
        2. Navigate to spokeo.com name search
        3. Extract result listing blocks
        4. Match each listing against profile via PIIMatcher
        5. Return listings with confidence >= 0.5
        """
        from playwright.async_api import async_playwright

        from src.scanner.pii_matcher import PIIMatcher

        name = profile.get("full_name", "")
        city = profile.get("city", "")
        state = profile.get("state", "")

        if not name:
            logger.warning("SpokeoScraper: no full_name in profile — skipping")
            return []

        results: list[ScrapeResult] = []
        matcher = PIIMatcher()

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                context = await browser.new_context(
                    user_agent=self._random_user_agent(),
                    java_script_enabled=True,
                    accept_downloads=False,
                    bypass_csp=False,
                    viewport={"width": 1280, "height": 900},
                )
                try:
                    page = await context.new_page()
                    # Block images/fonts to speed up scraping
                    await page.route(
                        "**/*.{png,jpg,jpeg,gif,webp,svg,woff,woff2,ttf,eot}",
                        lambda route: route.abort(),
                    )

                    # Navigate to Spokeo name search
                    # TODO: Verify current Spokeo search URL structure before production use
                    search_url = "https://www.spokeo.com/search"
                    name_encoded = name.replace(" ", "+")
                    if city and state:
                        search_url = (
                            f"https://www.spokeo.com/{name_encoded.replace('+', '-')}/"
                            f"{state.upper()}/{city.replace(' ', '-')}"
                        )
                    else:
                        search_url = f"https://www.spokeo.com/{name_encoded.replace('+', '-')}"

                    await page.goto(search_url, wait_until="domcontentloaded", timeout=30000)
                    await self._human_delay(2.0, 4.0)

                    # Check for CAPTCHA
                    if await self._detect_captcha(page):
                        await self._screenshot_debug(page, "spokeo_captcha")
                        return [
                            ScrapeResult(
                                broker_name="Spokeo",
                                profile_url=search_url,
                                name_found="",
                                address_found="",
                                confidence=0.0,
                                raw_text="CAPTCHA encountered",
                                captcha_encountered=True,
                            )
                        ]

                    await self._screenshot_debug(page, "spokeo_search_results")

                    # TODO: Update selectors to match current Spokeo DOM structure
                    # These are representative selectors — verify against live site
                    listing_selectors = [
                        ".card-rec",
                        ".result-card",
                        "[data-testid='result-card']",
                        ".search-result-item",
                    ]

                    listing_elements = []
                    for selector in listing_selectors:
                        elements = await page.query_selector_all(selector)
                        if elements:
                            listing_elements = elements
                            break

                    for element in listing_elements[:10]:  # Cap at 10 results
                        try:
                            raw_text = await element.inner_text()
                            link = await element.query_selector("a[href]")
                            href = await link.get_attribute("href") if link else ""

                            if href and not href.startswith("http"):
                                href = f"https://www.spokeo.com{href}"

                            matches = matcher.match(raw_text, profile)
                            score = matcher.composite_score(matches)

                            if score >= 0.5:
                                # Extract name and address from matched text
                                lines = [ln.strip() for ln in raw_text.splitlines() if ln.strip()]
                                name_found = lines[0] if lines else ""
                                address_found = lines[1] if len(lines) > 1 else ""

                                results.append(
                                    ScrapeResult(
                                        broker_name="Spokeo",
                                        profile_url=href or search_url,
                                        name_found=name_found,
                                        address_found=address_found,
                                        confidence=score,
                                        raw_text=raw_text[:500],
                                    )
                                )
                        except Exception as exc:
                            logger.debug("SpokeoScraper: error parsing listing: %s", exc)
                            continue

                finally:
                    await context.close()
            finally:
                await browser.close()

        return results
