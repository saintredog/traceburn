"""
src/scanner/dork_scanner.py — Google Dork Scanner via DuckDuckGo HTML

Generates dork queries from a user profile and scrapes DuckDuckGo HTML
search results (no API key required). Rate-limited to avoid triggering
bot detection.

DuckDuckGo HTML endpoint: https://html.duckduckgo.com/html/?q={query}
Result elements: <a class="result__a"> (title + URL), <a class="result__snippet">

Rate limit: 2 seconds + random 0–1 second jitter between searches.
"""

from __future__ import annotations

import random
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import requests
from bs4 import BeautifulSoup

_DDG_HTML_URL = "https://html.duckduckgo.com/html/"
_DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}
_RATE_LIMIT_BASE = 2.0   # seconds
_RATE_LIMIT_JITTER = 1.0  # additional random seconds


@dataclass
class DorkResult:
    """A single search result returned by a dork query."""

    url: str
    title: str
    snippet: str
    query_used: str
    found_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class DorkScanner:
    """
    Generates dork queries from a user profile and scrapes DuckDuckGo HTML
    search results.

    Example::

        scanner = DorkScanner()
        profile = {"full_name": "Jane Doe", "city": "Springfield", "state": "IL"}
        dorks = scanner.generate_dorks(profile)
        results = scanner.scan_all(profile)
    """

    def __init__(self, session: requests.Session | None = None) -> None:
        self._session = session or requests.Session()
        self._session.headers.update(_DEFAULT_HEADERS)

    # ── Dork generation ───────────────────────────────────────────────────

    def generate_dorks(self, profile: dict[str, Any]) -> list[str]:
        """
        Build a list of Google dork query strings from *profile*.

        *profile* is a dict of PII field names → plaintext values as
        returned by the vault. Missing fields are silently skipped.

        Covers: broker site lookups, PDF/document exposure, email combos,
        address combos, and name+location refinements.
        """
        name = profile.get("full_name", "")
        city = profile.get("city", "")
        state = profile.get("state", "")
        zip_code = profile.get("zip_code", "")
        email = profile.get("email", "")
        phone = profile.get("phone_number", "")
        street = profile.get("street_address", "")
        dob = profile.get("dob", "")

        dorks: list[str] = []

        broker_domains = [
            "spokeo.com",
            "whitepages.com",
            "intelius.com",
            "beenverified.com",
            "mylife.com",
            "radaris.com",
            "familytreenow.com",
            "peoplefinders.com",
            "zabasearch.com",
            "truthfinder.com",
            "instantcheckmate.com",
            "checkpeople.com",
            "peoplelooker.com",
            "ussearch.com",
        ]

        if name:
            # Broker site lookups — one per broker
            for domain in broker_domains:
                dorks.append(f'site:{domain} "{name}"')

            # Name + location refinements (reduce false positives)
            if city:
                dorks.append(f'site:spokeo.com "{name}" "{city}"')
                dorks.append(f'site:whitepages.com "{name}" "{city}"')
                dorks.append(f'site:radaris.com "{name}" "{city}"')
            if city and state:
                dorks.append(f'site:spokeo.com "{name}" "{city}" "{state}"')
                dorks.append(f'site:whitepages.com "{name}" "{city}" "{state}"')

            # Broad multi-broker sweep
            broker_or = " OR ".join(f"site:{d}" for d in broker_domains[:6])
            dorks.append(f'"{name}" {broker_or}')

            # Document exposure
            dorks.append(f'"{name}" filetype:pdf')
            dorks.append(f'"{name}" filetype:xls OR filetype:xlsx')
            dorks.append(f'"{name}" filetype:csv')
            dorks.append(f'"{name}" filetype:doc OR filetype:docx')

            if city:
                dorks.append(f'"{name}" "{city}" filetype:pdf')
            if email:
                dorks.append(f'"{name}" "{email}" filetype:pdf')
            if street:
                dorks.append(f'"{name}" "{street}" filetype:pdf')
            if zip_code:
                dorks.append(f'"{name}" "{zip_code}" filetype:pdf')

            # Name + address combos
            if street:
                dorks.append(f'"{name}" "{street}"')
            if city and state and zip_code:
                dorks.append(f'"{name}" "{city}" "{state}" "{zip_code}"')
            if city and state:
                dorks.append(f'"{name}" "{city}, {state}"')

            # Name + DOB
            if dob:
                dorks.append(f'"{name}" "{dob}"')

            # Name + phone
            if phone:
                dorks.append(f'"{name}" "{phone}"')
                # Phone with dashes variant
                digits = "".join(c for c in phone if c.isdigit())
                if len(digits) == 10:
                    dashes = f"{digits[:3]}-{digits[3:6]}-{digits[6:]}"
                    dorks.append(f'"{name}" "{dashes}"')

        # Email exposure
        if email:
            dorks.append(f'"{email}"')
            dorks.append(
                f'"{email}" -site:linkedin.com -site:github.com -site:twitter.com'
            )
            dorks.append(f'site:pastebin.com "{email}"')

        # Phone without name
        if phone and not name:
            dorks.append(f'"{phone}"')

        return dorks

    # ── DuckDuckGo scraping ───────────────────────────────────────────────

    def search(self, query: str) -> list[DorkResult]:
        """
        Issue a single dork query to DuckDuckGo HTML and return results.

        Parses <a class="result__a"> for URLs/titles and
        <a class="result__snippet"> (or <div class="result__snippet">) for
        snippets. Returns an empty list on error (logs warning).
        """
        params = {"q": query, "kl": "us-en", "kp": "-2"}
        try:
            response = self._session.get(
                _DDG_HTML_URL,
                params=params,
                timeout=15,
            )
            response.raise_for_status()
        except requests.RequestException:
            return []

        return self._parse_ddg_html(response.text, query)

    def _parse_ddg_html(self, html: str, query: str) -> list[DorkResult]:
        """Parse DuckDuckGo HTML response into DorkResult objects."""
        soup = BeautifulSoup(html, "html.parser")
        results: list[DorkResult] = []

        result_divs = soup.find_all("div", class_="result")
        for div in result_divs:
            # Title + URL
            link_tag = div.find("a", class_="result__a")
            if not link_tag:
                continue

            href = link_tag.get("href", "")
            title = link_tag.get_text(strip=True)

            # DuckDuckGo wraps actual URLs in a redirect — extract real URL
            url = self._extract_real_url(href)
            if not url:
                continue

            # Snippet
            snippet_tag = div.find("a", class_="result__snippet")
            if snippet_tag is None:
                snippet_tag = div.find("div", class_="result__snippet")
            snippet = snippet_tag.get_text(strip=True) if snippet_tag else ""

            results.append(
                DorkResult(
                    url=url,
                    title=title,
                    snippet=snippet,
                    query_used=query,
                )
            )

        return results

    def _extract_real_url(self, href: str) -> str:
        """
        DuckDuckGo HTML results use /l/?uddg=<encoded_url> redirects.
        Extract the real destination URL.
        """
        if not href:
            return ""
        if href.startswith("http") and "duckduckgo.com" not in href:
            return href
        parsed = urllib.parse.urlparse(href)
        uddg = urllib.parse.parse_qs(parsed.query).get("uddg", [""])
        if uddg and uddg[0]:
            return urllib.parse.unquote(uddg[0])
        # Fallback: return as-is if we can't extract
        return href if href.startswith("http") else ""

    # ── Rate limiting ─────────────────────────────────────────────────────

    def _rate_limit_sleep(self) -> None:
        """Sleep for the configured rate limit + random jitter."""
        sleep_time = _RATE_LIMIT_BASE + random.uniform(0, _RATE_LIMIT_JITTER)
        time.sleep(sleep_time)

    # ── Full scan ─────────────────────────────────────────────────────────

    def scan_all(self, profile: dict[str, Any]) -> list[DorkResult]:
        """
        Run all generated dorks for *profile* and return deduplicated results.

        Rate-limits between each search. Deduplicates by URL (keeps first
        occurrence — the one from the most specific dork).
        """
        dorks = self.generate_dorks(profile)
        seen_urls: set[str] = set()
        all_results: list[DorkResult] = []

        for i, query in enumerate(dorks):
            results = self.search(query)
            for r in results:
                if r.url not in seen_urls:
                    seen_urls.add(r.url)
                    all_results.append(r)

            # Rate limit between searches (not after the last one)
            if i < len(dorks) - 1:
                self._rate_limit_sleep()

        return all_results
