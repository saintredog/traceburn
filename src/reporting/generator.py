"""
src/reporting/generator.py — Report Generator

Reads from the database (read-only) and produces structured reports in
Markdown, JSON, and PDF formats.

PII policy:
  - Reports reference broker names, exposure status, and counts only.
  - PII is only included if config.reporting.include_pii_in_export is True,
    in which case it is fetched from the vault at render time and is not
    stored on this object.

PDF generation uses reportlab if available; falls back to Markdown with
a notice if reportlab is not installed.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Status emojis for removal status table
_STATUS_EMOJI: dict[str, str] = {
    "pending": "⏳",
    "submitted": "📤",
    "awaiting_confirmation": "📬",
    "confirmed": "✅",
    "failed": "❌",
    "retrying": "🔄",
}

_EXPOSURE_STATUS_EMOJI: dict[str, str] = {
    "found": "🔍",
    "removal_pending": "⏳",
    "removed": "✅",
    "reappeared": "⚠️",
    "dismissed": "–",
}


@dataclass
class ReportSection:
    """A single named section within a report."""

    heading: str
    """Section heading text."""

    content: str
    """Section body as a Markdown string."""

    data: dict[str, Any] = field(default_factory=dict)
    """Optional structured data for JSON export."""


@dataclass
class Report:
    """A complete generated report."""

    title: str
    generated_at: datetime
    profile_name: str
    sections: list[ReportSection] = field(default_factory=list)


class ReportGenerator:
    """
    Generates exposure and removal reports from the TraceBurn database.

    This class is a read-only database consumer — it never writes to the DB.

    Example::

        gen = ReportGenerator(db=db, config=config)
        report = gen.generate_exposure_report(
            profile={"display_name": "Primary"},
            scan_summary=summary,
        )
        gen.export_markdown(report, "reports/exposure.md")
    """

    def __init__(self, db: Any, config: Any) -> None:
        self._db = db
        self._config = config

    # ── Report generation ─────────────────────────────────────────────────

    def generate_exposure_report(
        self,
        profile: dict[str, Any],
        scan_summary: Any | None = None,
    ) -> Report:
        """
        Generate a full exposure report for *profile*.

        Includes: scan summary, broker exposure table, HIBP breach count,
        and status breakdown.
        """
        now = datetime.now(timezone.utc)
        user_id = profile.get("_user_id", 1)
        profile_name = profile.get("display_name", "Primary Profile")

        exposures = self._db.list("exposures", filters={"user_id": user_id})

        sections: list[ReportSection] = []

        # Summary section
        total = len(exposures)
        active = sum(1 for e in exposures if e.get("status") == "found")
        removed = sum(1 for e in exposures if e.get("status") == "removed")
        pending = sum(1 for e in exposures if e.get("status") == "removal_pending")

        summary_md = (
            f"| Metric | Count |\n"
            f"|--------|-------|\n"
            f"| Total exposures found | {total} |\n"
            f"| Active (not yet removed) | {active} |\n"
            f"| Removal pending | {pending} |\n"
            f"| Confirmed removed | {removed} |\n"
        )
        if scan_summary is not None:
            summary_md += (
                f"| Brokers scanned | {scan_summary.brokers_checked} |\n"
                f"| HIBP breaches found | {scan_summary.breaches_found} |\n"
                f"| Scan duration | {scan_summary.duration_seconds:.1f}s |\n"
            )

        sections.append(
            ReportSection(
                heading="Summary",
                content=summary_md,
                data={
                    "total": total,
                    "active": active,
                    "removed": removed,
                    "pending": pending,
                },
            )
        )

        # Broker exposure table
        if exposures:
            sections.append(
                ReportSection(
                    heading="Broker Exposures",
                    content=self._format_broker_table(exposures),
                    data={"exposures": exposures},
                )
            )
        else:
            sections.append(
                ReportSection(
                    heading="Broker Exposures",
                    content="_No exposures found._",
                    data={},
                )
            )

        # Recent scan history
        history = self._db.list(
            "scan_history",
            filters={"user_id": user_id},
            order_by="started_at DESC",
            limit=5,
        )
        if history:
            hist_rows = "\n".join(
                f"| {h.get('started_at', '')[:19]} | {h.get('scan_type', '')} "
                f"| {h.get('brokers_checked', 0)} | {h.get('new_exposures', 0)} |"
                for h in history
            )
            hist_md = (
                "| Date | Type | Brokers | New Exposures |\n"
                "|------|------|---------|---------------|\n"
                f"{hist_rows}"
            )
            sections.append(ReportSection(heading="Scan History", content=hist_md, data={}))

        return Report(
            title=f"TraceBurn Exposure Report — {profile_name}",
            generated_at=now,
            profile_name=profile_name,
            sections=sections,
        )

    def generate_removal_report(self, profile: dict[str, Any]) -> Report:
        """
        Generate a removal status report for *profile*.

        Shows all RemovalRequest records with their current status, method,
        tier, and proof availability.
        """
        now = datetime.now(timezone.utc)
        user_id = profile.get("_user_id", 1)
        profile_name = profile.get("display_name", "Primary Profile")

        # Join removals with exposures to get broker names
        removals = self._db.execute(
            """
            SELECT rr.*, e.broker_name, e.profile_url
            FROM removal_requests rr
            JOIN exposures e ON rr.exposure_id = e.id
            WHERE e.user_id = ?
            ORDER BY rr.submitted_at DESC
            """,
            [user_id],
        )

        sections: list[ReportSection] = []

        confirmed = sum(1 for r in removals if r.get("status") == "confirmed")
        failed = sum(1 for r in removals if r.get("status") == "failed")
        pending = sum(1 for r in removals if r.get("status") in ("pending", "submitted"))

        summary_md = (
            f"| Metric | Count |\n"
            f"|--------|-------|\n"
            f"| Total removal requests | {len(removals)} |\n"
            f"| Confirmed removals | {confirmed} |\n"
            f"| Failed / needs retry | {failed} |\n"
            f"| Pending / submitted | {pending} |\n"
        )
        sections.append(
            ReportSection(
                heading="Removal Summary",
                content=summary_md,
                data={"confirmed": confirmed, "failed": failed, "pending": pending},
            )
        )

        if removals:
            sections.append(
                ReportSection(
                    heading="Removal Requests",
                    content=self._format_removal_status(removals),
                    data={"removals": removals},
                )
            )
        else:
            sections.append(
                ReportSection(
                    heading="Removal Requests",
                    content="_No removal requests submitted yet._",
                    data={},
                )
            )

        return Report(
            title=f"TraceBurn Removal Report — {profile_name}",
            generated_at=now,
            profile_name=profile_name,
            sections=sections,
        )

    # ── Export methods ────────────────────────────────────────────────────

    def export_markdown(self, report: Report, path: str) -> None:
        """Write *report* to *path* as a Markdown file."""
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        lines: list[str] = [
            f"# {report.title}",
            f"",
            f"**Generated:** {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Profile:** {report.profile_name}",
            f"",
        ]
        for section in report.sections:
            lines.append(f"## {section.heading}")
            lines.append("")
            lines.append(section.content)
            lines.append("")

        output_path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("Markdown report written to %s", output_path)

    def export_json(self, report: Report, path: str) -> None:
        """Write *report* to *path* as a JSON file."""
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "title": report.title,
            "generated_at": report.generated_at.isoformat(),
            "profile_name": report.profile_name,
            "sections": [
                {
                    "heading": s.heading,
                    "content": s.content,
                    "data": s.data,
                }
                for s in report.sections
            ],
        }
        output_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        logger.info("JSON report written to %s", output_path)

    def export_pdf(self, report: Report, path: str) -> None:
        """
        Write *report* to *path* as a PDF file.

        Uses reportlab if available. Falls back to a Markdown file with a
        notice if reportlab is not installed.
        """
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

            doc = SimpleDocTemplate(str(output_path), pagesize=letter)
            styles = getSampleStyleSheet()
            story: list[Any] = []

            story.append(Paragraph(report.title, styles["Title"]))
            story.append(
                Paragraph(
                    f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')} | "
                    f"Profile: {report.profile_name}",
                    styles["Normal"],
                )
            )
            story.append(Spacer(1, 12))

            for section in report.sections:
                story.append(Paragraph(section.heading, styles["Heading2"]))
                # Render content as plain text (strip Markdown)
                plain = section.content.replace("|", " ").replace("-", " ")
                for line in plain.splitlines():
                    line = line.strip()
                    if line:
                        story.append(Paragraph(line, styles["Normal"]))
                story.append(Spacer(1, 8))

            doc.build(story)
            logger.info("PDF report written to %s", output_path)

        except ImportError:
            md_path = str(output_path).replace(".pdf", ".md")
            self.export_markdown(report, md_path)
            notice = (
                f"\n\n---\n"
                f"_Note: PDF export requires `reportlab` (`pip install reportlab`). "
                f"This report was saved as Markdown instead: {md_path}_"
            )
            with open(md_path, "a", encoding="utf-8") as fh:
                fh.write(notice)
            logger.warning(
                "reportlab not installed — PDF export fell back to Markdown at %s", md_path
            )

    # ── Formatting helpers ─────────────────────────────────────────────────

    def _format_broker_table(self, exposures: list[dict[str, Any]]) -> str:
        """Format a Markdown table of broker exposures."""
        header = "| Broker | Status | Confidence | First Seen | Profile URL |\n"
        separator = "|--------|--------|------------|------------|-------------|\n"
        rows: list[str] = []
        for e in exposures:
            status = e.get("status", "")
            emoji = _EXPOSURE_STATUS_EMOJI.get(status, "")
            broker = e.get("broker_name", "")
            confidence = f"{float(e.get('composite_confidence', 0)):.0%}"
            first_seen = str(e.get("first_seen", ""))[:10]
            url = e.get("profile_url", "")
            url_display = f"[link]({url})" if url else "—"
            rows.append(f"| {broker} | {emoji} {status} | {confidence} | {first_seen} | {url_display} |")

        return header + separator + "\n".join(rows)

    def _format_removal_status(self, removals: list[dict[str, Any]]) -> str:
        """Format a Markdown table of removal request statuses."""
        header = "| Broker | Tier | Method | Status | Submitted | Confirmed |\n"
        separator = "|--------|------|--------|--------|-----------|----------|\n"
        rows: list[str] = []
        for r in removals:
            status = r.get("status", "")
            emoji = _STATUS_EMOJI.get(status, "")
            broker = r.get("broker_name", "")
            tier = r.get("tier", "")
            method = r.get("method", "")
            submitted = str(r.get("submitted_at") or "—")[:10]
            confirmed = str(r.get("confirmed_at") or "—")[:10]
            rows.append(
                f"| {broker} | {tier} | {method} | {emoji} {status} | {submitted} | {confirmed} |"
            )

        return header + separator + "\n".join(rows)
