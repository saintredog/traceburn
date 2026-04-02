"""
src/scanner/engine.py — Scanner Orchestration Engine

Coordinates all scan sources (dork scanner, HIBP, broker scrapers) for a
given user profile. Aggregates results into Exposure records, deduplicates,
and persists to the database via db.py.

PII safety: profile data is fetched from the vault at scan time and passed
through the engine without being stored as instance attributes.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse, urlunparse

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from src.scanner.dork_scanner import DorkScanner, DorkResult
from src.scanner.hibp_client import HIBPClient, BreachRecord
from src.scanner.pii_matcher import PIIMatcher

logger = logging.getLogger(__name__)


@dataclass
class ScanSummary:
    """Summary of a completed scan run."""

    total_found: int = 0
    """Total number of exposures found (including duplicates already tracked)."""

    new_found: int = 0
    """Exposures not previously seen (newly inserted into DB)."""

    brokers_checked: int = 0
    """Number of brokers included in this scan."""

    duration_seconds: float = 0.0
    """Wall-clock duration of the scan."""

    breaches_found: int = 0
    """Number of HIBP breach records found across all emails."""

    errors: int = 0
    """Number of scan errors encountered."""


class ScannerEngine:
    """
    Orchestrates all scanner modules and persists results.

    Usage::

        engine = ScannerEngine(db=db, config=config, vault=vault)
        summary = engine.scan_all(profile={"full_name": "Jane Doe", ...})

    *db*     — :class:`src.db.Database` instance (connected)
    *config* — :class:`src.config.TraceBurnConfig` instance
    *vault*  — :class:`src.vault.PIIVault` instance (for future use; profile
               data passed directly in v1)
    """

    def __init__(self, db: Any, config: Any, vault: Any) -> None:
        self._db = db
        self._config = config
        self._vault = vault
        self._pii_matcher = PIIMatcher()

    # ── Public API ────────────────────────────────────────────────────────

    def scan_all(self, profile: dict[str, Any]) -> ScanSummary:
        """
        Run a full scan: dork queries, HIBP breach check, and broker scrapes.

        *profile* is a dict of PII field names → plaintext values. It is
        used only during this call and not stored.

        Saves all new Exposure records to the database and returns a
        :class:`ScanSummary`.
        """
        summary = ScanSummary()
        start_time = time.monotonic()

        user_id = profile.get("_user_id", 1)

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            transient=True,
        ) as progress:
            # ── Dork scanning ──────────────────────────────────────────
            dork_task = progress.add_task("Running dork queries...", total=None)
            dork_results = self._run_dork_scan(profile, progress, dork_task)
            progress.update(dork_task, completed=True)

            # ── HIBP breach check ──────────────────────────────────────
            hibp_task = progress.add_task("Checking HIBP breach database...", total=None)
            breach_count = self._run_hibp_check(profile)
            summary.breaches_found = breach_count
            progress.update(hibp_task, completed=True)

            # ── Broker scrapes ─────────────────────────────────────────
            brokers = self._load_active_brokers()
            summary.brokers_checked = len(brokers)

            scrape_task = progress.add_task(
                "Scraping brokers...", total=len(brokers)
            )
            scrape_results = self._run_broker_scrapes(profile, brokers, progress, scrape_task)

            progress.update(scrape_task, completed=len(brokers))

        # ── Aggregate and persist ──────────────────────────────────────
        all_candidates = [*dork_results, *scrape_results]
        summary.total_found = len(all_candidates)

        for candidate in all_candidates:
            inserted = self._upsert_exposure(candidate, user_id)
            if inserted:
                summary.new_found += 1

        summary.duration_seconds = time.monotonic() - start_time
        self._write_scan_history(summary, user_id)

        from src.logger import log_action
        log_action(
            "SCAN_COMPLETE",
            broker="ALL_BROKERS",
            status="success",
            details=f"new:{summary.new_found} total:{summary.total_found}",
        )

        return summary

    def scan_broker(
        self,
        broker: dict[str, Any],
        profile: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Run a scan for a single *broker* and return raw result dicts.

        Returns an empty list on error (logs the exception).
        """
        from src.scanner.broker_scraper import SpokeoScraper

        broker_name = broker.get("name", "")
        scraper_map: dict[str, Any] = {
            "Spokeo": SpokeoScraper(),
        }

        scraper = scraper_map.get(broker_name)
        if scraper is None:
            logger.debug("No scraper implemented for broker '%s' — skipping", broker_name)
            return []

        try:
            results = asyncio.run(scraper.scrape(broker, profile))
            return [
                {
                    "broker_name": r.broker_name,
                    "profile_url": r.profile_url,
                    "name_found": r.name_found,
                    "address_found": r.address_found,
                    "confidence": r.confidence,
                    "raw_text": r.raw_text,
                }
                for r in results
            ]
        except Exception as exc:
            logger.warning("Scraper error for '%s': %s", broker_name, exc)
            return []

    # ── Private helpers ───────────────────────────────────────────────────

    def _run_dork_scan(
        self,
        profile: dict[str, Any],
        progress: Any,
        task_id: Any,
    ) -> list[dict[str, Any]]:
        """Run DorkScanner and convert results to candidate exposure dicts."""
        scanner = DorkScanner()
        dork_results: list[DorkResult] = []

        try:
            dork_results = scanner.scan_all(profile)
        except Exception as exc:
            logger.warning("Dork scan failed: %s", exc)

        # Filter by PII match confidence
        threshold = getattr(self._config.scan, "min_confidence_threshold", 0.5)
        candidates: list[dict[str, Any]] = []

        for result in dork_results:
            matches = self._pii_matcher.match(result.snippet + " " + result.title, profile)
            score = self._pii_matcher.composite_score(matches)
            if score >= threshold:
                candidates.append(
                    {
                        "broker_name": self._domain_to_broker_name(result.url),
                        "profile_url": result.url,
                        "normalized_url": _normalize_url(result.url),
                        "composite_confidence": score,
                        "source": "dork",
                        "raw_text": result.snippet[:300],
                    }
                )

        return candidates

    def _run_hibp_check(self, profile: dict[str, Any]) -> int:
        """Run HIBP check for all emails in profile; returns total breach count."""
        api_key = None
        if self._config.hibp.api_key:
            api_key = self._config.hibp.api_key.get_secret_value()

        if not self._config.hibp.enabled:
            return 0

        client = HIBPClient(api_key=api_key)
        emails = []

        for key in ("email", "email_2", "email_3"):
            val = profile.get(key)
            if val:
                emails.append(val)

        total_breaches = 0
        for email in emails:
            try:
                breaches: list[BreachRecord] = client.check_email(email)
                total_breaches += len(breaches)
                if breaches:
                    from src.logger import log_action
                    log_action(
                        "HIBP_BREACH_FOUND",
                        broker="haveibeenpwned.com",
                        status="found",
                        details=f"count:{len(breaches)}",
                    )
            except Exception as exc:
                logger.warning("HIBP check failed: %s", exc)

        return total_breaches

    def _run_broker_scrapes(
        self,
        profile: dict[str, Any],
        brokers: list[dict[str, Any]],
        progress: Any,
        task_id: Any,
    ) -> list[dict[str, Any]]:
        """Run broker scrapers for each broker; return candidate exposure dicts."""
        candidates: list[dict[str, Any]] = []
        threshold = getattr(self._config.scan, "min_confidence_threshold", 0.5)

        for broker in brokers:
            try:
                scrape_results = self.scan_broker(broker, profile)
                for r in scrape_results:
                    if r.get("confidence", 0.0) >= threshold:
                        r["normalized_url"] = _normalize_url(r.get("profile_url", ""))
                        r["source"] = "scrape"
                        candidates.append(r)
            except Exception as exc:
                logger.warning("Broker scrape error (%s): %s", broker.get("name"), exc)
            finally:
                progress.advance(task_id)

        return candidates

    def _load_active_brokers(self) -> list[dict[str, Any]]:
        """Load active broker definitions from the database."""
        try:
            return self._db.list("brokers", filters={"active": 1})
        except Exception as exc:
            logger.warning("Failed to load brokers from DB: %s", exc)
            return []

    def _upsert_exposure(self, candidate: dict[str, Any], user_id: int) -> bool:
        """
        Insert or update an Exposure record in the database.

        Returns True if this is a newly inserted record, False if an
        existing record was updated.

        Deduplication key: (user_id, normalized_url).
        """
        normalized_url = candidate.get("normalized_url", "")
        if not normalized_url:
            return False

        now = datetime.now(timezone.utc).isoformat()

        # Check for existing exposure
        existing = self._db.list(
            "exposures",
            filters={"user_id": user_id, "normalized_url": normalized_url},
        )

        if existing:
            # Update last_seen and confidence if higher
            row = existing[0]
            new_conf = candidate.get("composite_confidence", 0.0)
            if new_conf > row.get("composite_confidence", 0.0):
                self._db.update(
                    "exposures",
                    row["id"],
                    {
                        "last_seen": now,
                        "composite_confidence": new_conf,
                        "status": "found" if row.get("status") == "removed" else row.get("status"),
                    },
                )
            else:
                self._db.update("exposures", row["id"], {"last_seen": now})
            return False

        # Look up broker_id
        broker_name = candidate.get("broker_name", "Unknown")
        broker_rows = self._db.list("brokers", filters={"name": broker_name})
        broker_id = broker_rows[0]["id"] if broker_rows else 0

        self._db.insert(
            "exposures",
            {
                "user_id": user_id,
                "broker_id": broker_id,
                "broker_name": broker_name,
                "profile_url": candidate.get("profile_url", ""),
                "normalized_url": normalized_url,
                "first_seen": now,
                "last_seen": now,
                "matched_fields": [],
                "composite_confidence": candidate.get("composite_confidence", 0.0),
                "status": "found",
            },
        )
        return True

    def _write_scan_history(self, summary: ScanSummary, user_id: int) -> None:
        """Persist a ScanHistory record for this scan run."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            self._db.insert(
                "scan_history",
                {
                    "user_id": user_id,
                    "scan_type": "full",
                    "started_at": now,
                    "completed_at": now,
                    "brokers_checked": summary.brokers_checked,
                    "exposures_found": summary.total_found,
                    "new_exposures": summary.new_found,
                    "reappeared_exposures": 0,
                    "removals_initiated": 0,
                    "errors_encountered": summary.errors,
                    "scan_duration_seconds": summary.duration_seconds,
                },
            )
        except Exception as exc:
            logger.warning("Failed to write scan history: %s", exc)

    def _domain_to_broker_name(self, url: str) -> str:
        """Map a URL's domain to a known broker name, or return the domain."""
        try:
            domain = urlparse(url).netloc.lower().replace("www.", "")
        except Exception:
            return "Unknown"
        domain_map = {
            "spokeo.com": "Spokeo",
            "whitepages.com": "Whitepages",
            "intelius.com": "Intelius",
            "beenverified.com": "BeenVerified",
            "mylife.com": "MyLife",
            "radaris.com": "Radaris",
            "familytreenow.com": "FamilyTreeNow",
            "peoplefinders.com": "PeopleFinders",
            "zabasearch.com": "ZabaSearch",
            "truthfinder.com": "TruthFinder",
            "instantcheckmate.com": "InstantCheckmate",
            "checkpeople.com": "CheckPeople",
            "peoplelooker.com": "PeopleLooker",
            "ussearch.com": "USSearch",
        }
        return domain_map.get(domain, domain)


def _normalize_url(url: str) -> str:
    """Return a canonical URL without query string or fragment."""
    try:
        parsed = urlparse(url.lower().strip())
        return urlunparse(parsed._replace(query="", fragment=""))
    except Exception:
        return url.lower().strip()
