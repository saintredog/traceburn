"""
tests/integration/test_scan_to_report.py — Phase 4.2 Integration Tests
End-to-end scan → report pipeline.

All network calls are mocked. Uses real SQLite databases and PIIVault files
written to pytest's tmp_path. No internet access required.

Covered scenarios:
  - Full scan pipeline with mocked DorkScanner and HIBPClient
  - Deduplication: running the same scan twice keeps one exposure record
  - HIBP breach data saved to scan history
  - Empty scan producing a valid "no exposures found" report
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.db import Database
from src.reporting.generator import ReportGenerator
from src.scanner.dork_scanner import DorkResult
from src.scanner.engine import ScannerEngine
from src.scanner.hibp_client import BreachRecord
from src.vault import PIIVault


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _make_config(threshold: float = 0.5) -> SimpleNamespace:
    """Build a minimal stub config accepted by ScannerEngine."""
    return SimpleNamespace(
        scan=SimpleNamespace(min_confidence_threshold=threshold),
        hibp=SimpleNamespace(enabled=True, api_key=None),
    )


def _make_config_hibp_disabled() -> SimpleNamespace:
    """Config with HIBP disabled."""
    return SimpleNamespace(
        scan=SimpleNamespace(min_confidence_threshold=0.5),
        hibp=SimpleNamespace(enabled=False, api_key=None),
    )


def _email_hash(email: str = "test@example.com") -> str:
    return hashlib.sha256(email.encode()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seed_db(db: Database, user_id: int = 1) -> None:
    """
    Insert the minimum records required for ScannerEngine.scan_all() to
    persist exposures without FK violations.

    Inserts one user and two brokers whose names the DorkScanner mocks
    will reference.
    """
    db.insert(
        "users",
        {
            "display_name": "Test Profile",
            "email_hash": _email_hash(),
            "created_at": _now(),
            "updated_at": _now(),
            "is_active": 1,
        },
    )
    for name, domain in [("Spokeo", "spokeo.com"), ("Whitepages", "whitepages.com")]:
        db.insert(
            "brokers",
            {
                "name": name,
                "domain": domain,
                "region": "US",
                "removal_tier": 1,
                "opt_out_url": f"https://{domain}/optout",
                "active": 1,
                "re_listing_risk": "medium",
                "reverification_days": "[7,30,90]",
            },
        )


def _fake_dork_results(profile: dict) -> list[DorkResult]:
    """
    Return two DorkResult objects whose snippets contain the profile's
    full_name so PIIMatcher scores >= 0.5 (exact match → 1.0).
    """
    name = profile.get("full_name", "Jane Doe")
    return [
        DorkResult(
            url="https://spokeo.com/jane-doe-springfield-il",
            title=f"{name} | Spokeo",
            snippet=f"{name} age 35, Springfield IL",
            query_used=f'site:spokeo.com "{name}"',
        ),
        DorkResult(
            url="https://whitepages.com/name/jane-doe/springfield-il",
            title=f"{name} - Whitepages",
            snippet=f"Find {name} – Springfield, IL",
            query_used=f'site:whitepages.com "{name}"',
        ),
    ]


def _fake_breach() -> BreachRecord:
    return BreachRecord(
        name="TestCorp",
        domain="testcorp.com",
        breach_date="2023-06-15",
        pwn_count=5_000_000,
        data_classes=["Email addresses", "Passwords"],
        description="A fictional breach used in tests.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    """Connected Database written to a temp file, torn down after the test."""
    db_path = tmp_path / "traceburn.db"
    database = Database(db_path=db_path)
    database.connect()
    yield database
    database.close()


@pytest.fixture()
def vault(tmp_path: Path) -> PIIVault:
    """PIIVault backed by a temp file."""
    return PIIVault(vault_path=tmp_path / "vault.enc")


@pytest.fixture()
def profile() -> dict:
    """Sample user profile dict for scan_all()."""
    return {
        "_user_id": 1,
        "full_name": "Jane Doe",
        "city": "Springfield",
        "state": "IL",
        "email": "test@example.com",
    }


@pytest.fixture()
def seeded_db(db: Database) -> Database:
    """Database pre-populated with user + broker records."""
    _seed_db(db)
    return db


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestFullScanPipeline:
    """End-to-end scan followed by report generation."""

    def test_full_scan_pipeline(
        self, seeded_db: Database, vault: PIIVault, profile: dict, tmp_path: Path
    ) -> None:
        """
        Run ScannerEngine.scan_all() with mocked network calls and verify:
          1. ScanSummary.total_found >= 2 (two fake dork results)
          2. Exposure records written to the DB
          3. ReportGenerator produces a report with named sections
          4. The broker table section is present in the report
          5. Exporting to Markdown produces a non-empty file
        """
        config = _make_config()
        engine = ScannerEngine(db=seeded_db, config=config, vault=vault)

        dork_results = _fake_dork_results(profile)

        with (
            patch("src.scanner.engine.DorkScanner") as MockDork,
            patch("src.scanner.engine.HIBPClient") as MockHIBP,
            patch.object(engine, "_load_active_brokers", return_value=[]),
        ):
            MockDork.return_value.scan_all.return_value = dork_results
            MockHIBP.return_value.check_email.return_value = [_fake_breach()]

            summary = engine.scan_all(profile)

        # ── Scan summary assertions ────────────────────────────────────────
        assert summary.total_found >= 2, (
            f"Expected at least 2 exposures from mocked dork results, got {summary.total_found}"
        )

        # ── DB assertions ──────────────────────────────────────────────────
        exposures = seeded_db.list("exposures")
        assert len(exposures) > 0, "No exposures written to DB after scan"

        # ── Report generation ──────────────────────────────────────────────
        gen = ReportGenerator(db=seeded_db, config=config)
        report = gen.generate_exposure_report(profile, scan_summary=summary)

        assert len(report.sections) >= 2, (
            "Report should have at least a Summary and a Broker Exposures section"
        )
        section_headings = [s.heading for s in report.sections]
        assert "Summary" in section_headings, "Report missing Summary section"
        assert "Broker Exposures" in section_headings, "Report missing Broker Exposures section"

        # ── Broker table presence ──────────────────────────────────────────
        broker_section = next(s for s in report.sections if s.heading == "Broker Exposures")
        assert "Broker" in broker_section.content, (
            "Broker Exposures section does not contain a table header"
        )

        # ── Markdown export ────────────────────────────────────────────────
        md_path = tmp_path / "reports" / "exposure.md"
        gen.export_markdown(report, str(md_path))
        assert md_path.exists(), f"Markdown file not created at {md_path}"
        content = md_path.read_text(encoding="utf-8")
        assert len(content) > 0, "Exported Markdown file is empty"
        assert "TraceBurn Exposure Report" in content


class TestScanDeduplication:
    """Running the same scan twice must not create duplicate exposure records."""

    def test_scan_deduplication(
        self, seeded_db: Database, vault: PIIVault, profile: dict
    ) -> None:
        """
        Run scan_all() twice with identical mock results and assert that the
        number of exposure records in the DB is the same after both runs.

        Deduplication key: (user_id, normalized_url) — see
        ScannerEngine._upsert_exposure().
        """
        config = _make_config()
        engine = ScannerEngine(db=seeded_db, config=config, vault=vault)
        dork_results = _fake_dork_results(profile)

        mock_kwargs = dict(
            patch_dork=patch("src.scanner.engine.DorkScanner"),
            patch_hibp=patch("src.scanner.engine.HIBPClient"),
        )

        def _run_scan() -> None:
            with (
                patch("src.scanner.engine.DorkScanner") as MockDork,
                patch("src.scanner.engine.HIBPClient") as MockHIBP,
                patch.object(engine, "_load_active_brokers", return_value=[]),
            ):
                MockDork.return_value.scan_all.return_value = dork_results
                MockHIBP.return_value.check_email.return_value = []
                engine.scan_all(profile)

        _run_scan()
        count_after_first = len(seeded_db.list("exposures"))

        _run_scan()
        count_after_second = len(seeded_db.list("exposures"))

        assert count_after_first == count_after_second, (
            f"Duplicate exposures created: {count_after_first} after 1st scan, "
            f"{count_after_second} after 2nd scan"
        )
        assert count_after_first > 0, "No exposures were created on the first scan"


class TestScanSavesBreachData:
    """HIBP breach data should be reflected in the scan summary and scan history."""

    def test_scan_saves_breach_data(
        self, seeded_db: Database, vault: PIIVault, profile: dict
    ) -> None:
        """
        Run scan_all() with HIBP returning 1 breach for test@example.com.
        Assert:
          - summary.breaches_found >= 1
          - A scan_history record is written to the DB
        """
        config = _make_config()
        engine = ScannerEngine(db=seeded_db, config=config, vault=vault)

        with (
            patch("src.scanner.engine.DorkScanner") as MockDork,
            patch("src.scanner.engine.HIBPClient") as MockHIBP,
            patch.object(engine, "_load_active_brokers", return_value=[]),
        ):
            MockDork.return_value.scan_all.return_value = []
            MockHIBP.return_value.check_email.return_value = [_fake_breach()]

            summary = engine.scan_all(profile)

        assert summary.breaches_found >= 1, (
            "Expected at least 1 breach from mocked HIBPClient"
        )

        # Scan history should record this scan run
        history = seeded_db.list("scan_history", filters={"user_id": 1})
        assert len(history) >= 1, "No scan_history record written after scan"


class TestEmptyScanReport:
    """An all-empty scan must still produce a valid report without errors."""

    def test_empty_scan_report(
        self, seeded_db: Database, vault: PIIVault, profile: dict
    ) -> None:
        """
        Mock all scanners to return no results. Run scan_all() then
        generate_exposure_report(). Assert:
          - No exception is raised
          - The report is generated successfully
          - The Broker Exposures section contains a "No exposures found" message
        """
        config = _make_config()
        engine = ScannerEngine(db=seeded_db, config=config, vault=vault)

        with (
            patch("src.scanner.engine.DorkScanner") as MockDork,
            patch("src.scanner.engine.HIBPClient") as MockHIBP,
            patch.object(engine, "_load_active_brokers", return_value=[]),
        ):
            MockDork.return_value.scan_all.return_value = []
            MockHIBP.return_value.check_email.return_value = []

            summary = engine.scan_all(profile)

        assert summary.total_found == 0

        gen = ReportGenerator(db=seeded_db, config=config)
        report = gen.generate_exposure_report(profile, scan_summary=summary)

        assert report is not None, "Report generator returned None"
        assert len(report.sections) >= 1, "Report has no sections"

        broker_section = next(
            (s for s in report.sections if s.heading == "Broker Exposures"), None
        )
        assert broker_section is not None, "Broker Exposures section missing from report"
        assert "No exposures found" in broker_section.content, (
            f"Expected 'No exposures found' in broker section, got: {broker_section.content!r}"
        )
