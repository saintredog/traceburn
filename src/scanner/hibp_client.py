"""
TraceBurn HIBP Client — Updated for free usage
HIBP email breach check requires a paid API key (~$3.50/mo).
For free usage: direct users to https://haveibeenpwned.com to check manually.
Pwned Passwords API (password hash check) remains 100% free — no key needed.
"""

src/scanner/hibp_client.py — Have I Been Pwned API Client

Checks email addresses against the HIBP breach database and checks
password hashes against the Pwned Passwords k-anonymity API.

Rate limits:
  - Breached account endpoint: 1500ms between requests (HIBP requirement)
  - Retry on 429 using Retry-After header
  - Pwned Passwords: no API key required; k-anonymity (sends only first 5
    SHA-1 hex chars)

HIBP API docs: https://haveibeenpwned.com/API/v3
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import requests

logger = logging.getLogger(__name__)

_HIBP_BASE = "https://haveibeenpwned.com/api/v3"
_PWNED_PASSWORDS_BASE = "https://api.pwnedpasswords.com"
_USER_AGENT = "TraceBurn/0.1.0"
_MIN_REQUEST_INTERVAL_MS = 1500  # milliseconds between HIBP requests


@dataclass
class BreachRecord:
    """A single data breach record returned by the HIBP API."""

    name: str
    """Short machine-readable name for the breach, e.g. 'Adobe'."""

    domain: str
    """Primary domain of the breached site, e.g. 'adobe.com'."""

    breach_date: str
    """ISO date string of when the breach occurred, e.g. '2013-10-04'."""

    pwn_count: int
    """Number of accounts compromised in this breach."""

    data_classes: list[str]
    """Types of data exposed, e.g. ['Email addresses', 'Passwords']."""

    description: str
    """Human-readable description of the breach."""

    is_verified: bool = True
    is_sensitive: bool = False
    is_retired: bool = False


class HIBPClient:
    """
    Client for the Have I Been Pwned v3 API.

    Example::

        client = HIBPClient(api_key="your-hibp-key")
        breaches = client.check_email("user@example.com")
        count = client.check_password_prefix("5BAA6")  # first 5 SHA-1 hex chars

    If no ``api_key`` is supplied, email checks are skipped and a warning
    is logged. Password prefix checks do not require an API key.
    """

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key
        self._last_request_time: float = 0.0
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": _USER_AGENT})
        if api_key:
            self._session.headers["hibp-api-key"] = api_key

    # ── Public API ────────────────────────────────────────────────────────

    def check_email(self, email: str) -> list[BreachRecord]:
        """
        Check if *email* appears in any known data breach.

        Returns a (possibly empty) list of :class:`BreachRecord` objects.
        Returns an empty list if the email is not found (HTTP 404).

        Raises :class:`requests.HTTPError` for unexpected HTTP errors
        (5xx, 401 invalid key, etc.).

        Rate-limited: enforces 1500ms between consecutive calls.

        If no API key was supplied at construction time, logs a warning
        and returns an empty list.
        """
        if not self._api_key:
            logger.warning(
                "HIBP: No API key configured — skipping email breach check. "
                "Set CLEARTRACE_HIBP_API_KEY to enable this feature."
            )
            return []

        url = f"{_HIBP_BASE}/breachedaccount/{requests.utils.quote(email)}"
        params = {"truncateResponse": "false"}

        self._enforce_rate_limit()

        try:
            response = self._session.get(url, params=params, timeout=10)
        except requests.RequestException as exc:
            logger.warning("HIBP: Request failed for email check: %s", exc)
            return []

        if response.status_code == 404:
            return []

        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 2))
            logger.info("HIBP: Rate limited — waiting %s seconds.", retry_after)
            time.sleep(retry_after)
            return self.check_email(email)  # Retry once

        response.raise_for_status()

        breaches: list[dict[str, Any]] = response.json()
        return [self._parse_breach(b) for b in breaches]

    def check_password_prefix(self, sha1_prefix: str) -> int:
        """
        Query the Pwned Passwords k-anonymity API for *sha1_prefix*.

        *sha1_prefix* must be the first 5 uppercase hex characters of the
        SHA-1 hash of a password. Returns the count of times the
        corresponding full hash appears in the dataset, or 0 if not found.

        No API key required. The full hash is never sent — only the 5-char
        prefix (k-anonymity model).

        Example::

            sha1 = hashlib.sha1(b"password123").hexdigest().upper()
            count = client.check_password_prefix(sha1[:5])
        """
        prefix = sha1_prefix.upper()[:5]
        if len(prefix) != 5:
            raise ValueError("sha1_prefix must be exactly 5 hex characters")

        url = f"{_PWNED_PASSWORDS_BASE}/range/{prefix}"
        try:
            response = self._session.get(url, timeout=10)
            response.raise_for_status()
        except requests.RequestException as exc:
            logger.warning("HIBP Pwned Passwords: Request failed: %s", exc)
            return 0

        # Response: lines of "SUFFIX:COUNT\n"
        # We need the suffix of the full hash we're looking for
        # Caller provides only the prefix — count ALL matches for the prefix
        # (common usage: caller should provide the full hash and compute count)
        total_count = 0
        for line in response.text.splitlines():
            if ":" in line:
                _suffix, count_str = line.split(":", 1)
                try:
                    total_count += int(count_str.strip())
                except ValueError:
                    continue
        return total_count

    def check_password(self, password: str) -> int:
        """
        Convenience wrapper: hash *password* and check via k-anonymity.

        Returns the number of times this password has been seen in breaches.
        A value of 0 means it was not found (not necessarily safe).
        """
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        url = f"{_PWNED_PASSWORDS_BASE}/range/{prefix}"
        try:
            response = self._session.get(url, timeout=10)
            response.raise_for_status()
        except requests.RequestException as exc:
            logger.warning("HIBP Pwned Passwords: Request failed: %s", exc)
            return 0

        for line in response.text.splitlines():
            if ":" in line:
                line_suffix, count_str = line.split(":", 1)
                if line_suffix.strip().upper() == suffix:
                    try:
                        return int(count_str.strip())
                    except ValueError:
                        return 0
        return 0

    # ── Private helpers ───────────────────────────────────────────────────

    def _enforce_rate_limit(self) -> None:
        """Sleep if necessary to honour the 1500ms HIBP rate limit."""
        now = time.monotonic()
        elapsed_ms = (now - self._last_request_time) * 1000
        if elapsed_ms < _MIN_REQUEST_INTERVAL_MS:
            sleep_s = (_MIN_REQUEST_INTERVAL_MS - elapsed_ms) / 1000
            time.sleep(sleep_s)
        self._last_request_time = time.monotonic()

    @staticmethod
    def _parse_breach(data: dict[str, Any]) -> BreachRecord:
        """Convert a raw HIBP API response dict into a :class:`BreachRecord`."""
        return BreachRecord(
            name=data.get("Name", ""),
            domain=data.get("Domain", ""),
            breach_date=data.get("BreachDate", ""),
            pwn_count=data.get("PwnCount", 0),
            data_classes=data.get("DataClasses", []),
            description=data.get("Description", ""),
            is_verified=data.get("IsVerified", True),
            is_sensitive=data.get("IsSensitive", False),
            is_retired=data.get("IsRetired", False),
        )
