"""
tests/unit/test_report_generator.py — Unit tests for ReportGenerator
(src/reporting/generator.py).

All database and config dependencies are mocked — no real DB is used.
File output tests use tmp_path — no real filesystem side effects.

Coverage:
  - Exposure report structure and sections
  - Removal report structure and status counts
  - Markdown and JSON export
  - Broker table formatting
  - PII-free audit log (logger not called with PII)
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from src.reporting.generator import Report, ReportGenerator, ReportSection


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_db(
    exposures: list[dict] | None = None,
    scan_history: list[dict] | None = None,
    removals: list[dict] | None = None,
) -> MagicMock:
    """
    Create a mock Database that returns the provided fixture data.

    list() is side_effect-driven: first call returns exposures, second returns
    scan_history (matching generate_exposure_report's call order).
    execute() returns removals (used by generate_removal_report).
    """
    mock_db = MagicMock()
    mock_db.list.side_effect = [
        exposures or [],
        scan_history or [],
    ]
    mock_db.execute.return_value = removals or []
    return mock_db


def _make_generator(
    exposures: list[dict] | None = None,
    scan_history: list[dict] | None = None,
    removals: list[dict] | None = None,
) -> ReportGenerator:
    """Build a ReportGenerator with mocked DB and config."""
    db = _make_db(
        exposures=exposures,
        scan_history=scan_history,
        removals=removals,
    )
    config = MagicMock()
    return ReportGenerator(db=db, config=config)


def _sample_exposure(**overrides) -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "broker_name": "TestBroker",
        "status": "found",
        "composite_confidence": 0.9,
        "first_seen": "2024-01-15T00:00:00",
        "profile_url": "https://testbroker.com/john-smith",
    }
    defaults.update(overrides)
    return defaults


def _sample_removal(**overrides) -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "broker_name": "TestBroker",
        "status": "confirmed",
        "tier": 1,
        "method": "playwright",
        "submitted_at": "2024-01-15T10:00:00",
        "confirmed_at": "2024-01-16T08:00:00",
        "profile_url": "https://testbroker.com/john-smith",
    }
    defaults.update(overrides)
    return defaults


PROFILE: dict[str, Any] = {"display_name": "John Smith", "_user_id": 1}


# ─────────────────────────────────────────────────────────────────────────────
# Exposure report structure
# ─────────────────────────────────────────────────────────────────────────────


class TestExposureReportStructure:
    def test_exposure_report_structure(self):
        """Exposure report has a title, generated_at timestamp, and sections list."""
        gen = _make_generator(exposures=[_sample_exposure()])
        report = gen.generate_exposure_report(PROFILE)

        assert isinstance(report, Report)
        assert report.title != ""
        assert "John Smith" in report.title or "Primary" in report.title
        assert isinstance(report.generated_at, datetime)
        assert isinstance(report.sections, list)
        assert len(report.sections) >= 1

    def test_exposure_report_has_broker_section(self):
        """When exposures exist, the report includes a 'Broker Exposures' section."""
        gen = _make_generator(exposures=[_sample_exposure()])
        report = gen.generate_exposure_report(PROFILE)

        section_headings = {s.heading for s in report.sections}
        assert "Broker Exposures" in section_headings

    def test_exposure_report_has_summary_section(self):
        """Every exposure report includes a 'Summary' section."""
        gen = _make_generator(exposures=[_sample_exposure()])
        report = gen.generate_exposure_report(PROFILE)

        section_headings = {s.heading for s in report.sections}
        assert "Summary" in section_headings

    def test_exposure_report_empty_scan(self):
        """Zero exposures are handled gracefully — report still renders without error."""
        gen = _make_generator(exposures=[])
        report = gen.generate_exposure_report(PROFILE)

        assert isinstance(report, Report)
        # Should still have sections (summary at minimum)
        assert len(report.sections) >= 1

        # Broker section should indicate no exposures found
        broker_section = next(
            (s for s in report.sections if s.heading == "Broker Exposures"), None
        )
        assert broker_section is not None
        assert "No exposures" in broker_section.content or "no exposures" in broker_section.content.lower()

    def test_exposure_report_profile_name_in_title(self):
        """The profile display name appears in the report title."""
        gen = _make_generator(exposures=[])
        report = gen.generate_exposure_report({"display_name": "Jane Doe", "_user_id": 2})
        assert "Jane Doe" in report.title

    def test_exposure_report_generated_at_is_utc(self):
        """generated_at is a timezone-aware UTC datetime."""
        gen = _make_generator(exposures=[])
        report = gen.generate_exposure_report(PROFILE)
        # Should be timezone-aware
        assert report.generated_at.tzinfo is not None


# ─────────────────────────────────────────────────────────────────────────────
# Removal report structure
# ─────────────────────────────────────────────────────────────────────────────


class TestRemovalReportStructure:
    def test_removal_report_structure(self):
        """Removal report has title, generated_at, profile_name, and sections."""
        gen = _make_generator(removals=[_sample_removal()])
        report = gen.generate_removal_report(PROFILE)

        assert isinstance(report, Report)
        assert report.title != ""
        assert isinstance(report.generated_at, datetime)
        assert report.profile_name == "John Smith"
        assert isinstance(report.sections, list)
        assert len(report.sections) >= 1

    def test_removal_report_has_summary_section(self):
        """Removal report includes a 'Removal Summary' section."""
        gen = _make_generator(removals=[_sample_removal()])
        report = gen.generate_removal_report(PROFILE)

        headings = {s.heading for s in report.sections}
        assert "Removal Summary" in headings

    def test_removal_report_status_counts(self):
        """Summary section data counts pending, confirmed, and failed requests correctly."""
        removals = [
            _sample_removal(status="confirmed"),
            _sample_removal(status="confirmed"),
            _sample_removal(status="failed"),
            _sample_removal(status="pending"),
            _sample_removal(status="submitted"),
        ]
        gen = _make_generator(removals=removals)
        report = gen.generate_removal_report(PROFILE)

        summary = next(s for s in report.sections if s.heading == "Removal Summary")
        data = summary.data

        assert data["confirmed"] == 2
        assert data["failed"] == 1
        assert data["pending"] == 2  # pending + submitted

    def test_removal_report_empty(self):
        """Removal report with no requests renders gracefully."""
        gen = _make_generator(removals=[])
        report = gen.generate_removal_report(PROFILE)

        assert isinstance(report, Report)
        removal_section = next(
            (s for s in report.sections if s.heading == "Removal Requests"), None
        )
        assert removal_section is not None
        assert "No removal requests" in removal_section.content


# ─────────────────────────────────────────────────────────────────────────────
# Markdown export
# ─────────────────────────────────────────────────────────────────────────────


class TestMarkdownExport:
    def test_export_markdown_creates_file(self, tmp_path: Path):
        """export_markdown() writes a .md file with non-empty content."""
        gen = _make_generator(exposures=[_sample_exposure()])
        report = gen.generate_exposure_report(PROFILE)

        out_path = tmp_path / "reports" / "exposure.md"
        gen.export_markdown(report, str(out_path))

        assert out_path.exists()
        content = out_path.read_text(encoding="utf-8")
        assert len(content) > 50
        assert "#" in content  # at least one markdown heading

    def test_export_markdown_contains_title(self, tmp_path: Path):
        """The exported Markdown file starts with the report title as a heading."""
        gen = _make_generator(exposures=[])
        report = gen.generate_exposure_report(PROFILE)

        out_path = tmp_path / "report.md"
        gen.export_markdown(report, str(out_path))

        first_line = out_path.read_text(encoding="utf-8").splitlines()[0]
        assert first_line.startswith("# ")
        assert report.title in first_line

    def test_export_markdown_creates_parent_dirs(self, tmp_path: Path):
        """export_markdown() creates missing parent directories automatically."""
        gen = _make_generator(exposures=[])
        report = gen.generate_exposure_report(PROFILE)

        deep_path = tmp_path / "a" / "b" / "c" / "report.md"
        gen.export_markdown(report, str(deep_path))

        assert deep_path.exists()


# ─────────────────────────────────────────────────────────────────────────────
# JSON export
# ─────────────────────────────────────────────────────────────────────────────


class TestJsonExport:
    def test_export_json_creates_file(self, tmp_path: Path):
        """export_json() writes a .json file."""
        gen = _make_generator(exposures=[_sample_exposure()])
        report = gen.generate_exposure_report(PROFILE)

        out_path = tmp_path / "report.json"
        gen.export_json(report, str(out_path))

        assert out_path.exists()

    def test_export_json_valid_json(self, tmp_path: Path):
        """export_json() writes valid, parseable JSON."""
        gen = _make_generator(exposures=[_sample_exposure()])
        report = gen.generate_exposure_report(PROFILE)

        out_path = tmp_path / "report.json"
        gen.export_json(report, str(out_path))

        raw = out_path.read_text(encoding="utf-8")
        parsed = json.loads(raw)  # must not raise
        assert isinstance(parsed, dict)

    def test_export_json_structure(self, tmp_path: Path):
        """JSON export has the expected top-level keys: title, generated_at, profile_name, sections."""
        gen = _make_generator(exposures=[_sample_exposure()])
        report = gen.generate_exposure_report(PROFILE)

        out_path = tmp_path / "report.json"
        gen.export_json(report, str(out_path))

        data = json.loads(out_path.read_text(encoding="utf-8"))
        for key in ("title", "generated_at", "profile_name", "sections"):
            assert key in data, f"Expected key '{key}' missing from JSON output"

        assert isinstance(data["sections"], list)
        for section in data["sections"]:
            assert "heading" in section
            assert "content" in section
            assert "data" in section


# ─────────────────────────────────────────────────────────────────────────────
# Broker table formatting
# ─────────────────────────────────────────────────────────────────────────────


class TestBrokerTableFormatting:
    def test_broker_table_formatting(self):
        """_format_broker_table() returns a Markdown table string."""
        gen = _make_generator()
        exposures = [
            _sample_exposure(
                broker_name="Spokeo",
                status="found",
                composite_confidence=0.95,
                first_seen="2024-01-15T00:00:00",
                profile_url="https://spokeo.com/john-smith",
            )
        ]
        result = gen._format_broker_table(exposures)

        # Must be a non-empty string containing Markdown table syntax
        assert isinstance(result, str)
        assert "|" in result
        assert "Spokeo" in result
        assert "found" in result

    def test_broker_table_has_header_row(self):
        """Broker table starts with a header row containing expected column names."""
        gen = _make_generator()
        result = gen._format_broker_table([_sample_exposure()])

        lines = result.splitlines()
        assert len(lines) >= 2  # header + separator at minimum
        assert "Broker" in lines[0]
        assert "Status" in lines[0]

    def test_broker_table_empty_exposures(self):
        """_format_broker_table with an empty list still returns a valid table header."""
        gen = _make_generator()
        result = gen._format_broker_table([])

        # Header and separator should be present even with no data rows
        assert "Broker" in result
        assert "|" in result


# ─────────────────────────────────────────────────────────────────────────────
# PII in logs
# ─────────────────────────────────────────────────────────────────────────────


class TestNoPIIInLogs:
    def test_report_no_pii_in_logs(self, tmp_path: Path):
        """
        Generating and exporting a report does not write any PII to the audit log.

        The generator's logger is patched; we assert that no PII fields (name,
        email, phone, address) appear in any log call arguments.
        """
        pii_values = [
            "John Smith",
            "john.smith@example.com",
            "6195551234",
            "123 Main St",
        ]

        exposures = [
            _sample_exposure(
                broker_name="Spokeo",
                # profile_url could theoretically contain a name but isn't PII in the log
                profile_url="https://spokeo.com/person/123",
            )
        ]

        db = _make_db(exposures=exposures, scan_history=[])
        gen = ReportGenerator(db=db, config=MagicMock())

        with patch("src.reporting.generator.logger") as mock_logger:
            report = gen.generate_exposure_report(PROFILE)
            gen.export_markdown(report, str(tmp_path / "report.md"))
            gen.export_json(report, str(tmp_path / "report.json"))

        # Collect all log call arguments into one string for easy scanning
        all_log_text = ""
        for call in mock_logger.info.call_args_list:
            all_log_text += " ".join(str(a) for a in call.args)
        for call in mock_logger.warning.call_args_list:
            all_log_text += " ".join(str(a) for a in call.args)

        for pii in pii_values:
            assert pii not in all_log_text, (
                f"PII value {pii!r} found in log output — audit log must be PII-free"
            )
