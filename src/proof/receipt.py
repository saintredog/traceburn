"""
src/proof/receipt.py — Removal receipt generator for TraceBurn.

Generates human-readable receipts (Markdown + PDF) for proof records.

PDF backend: WeasyPrint (HTML+CSS via Jinja2).
Fallback: Markdown export if WeasyPrint or its system libraries are absent.

CLI usage:
    traceburn proof --export --broker spokeo
    traceburn proof --export --broker spokeo --format json
    traceburn proof --export --all
    traceburn proof --show --broker spokeo
    traceburn proof --verify --broker spokeo
"""

from __future__ import annotations

import base64
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Jinja2 template (inline — avoids a templates/ dependency for this module)
# ---------------------------------------------------------------------------

_PROOF_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<style>
  body { font-family: Georgia, serif; margin: 40px; color: #1a1a1a; }
  h1 { font-size: 1.6em; border-bottom: 2px solid #333; padding-bottom: 8px; }
  h2 { font-size: 1.1em; margin-top: 2em; color: #444; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 1em; }
  th, td { border: 1px solid #ccc; padding: 8px 12px; text-align: left; }
  th { background: #f0f0f0; }
  .monospace { font-family: monospace; font-size: 0.85em; word-break: break-all; }
  .status-absent { color: #2a7a2a; font-weight: bold; }
  .status-pending { color: #8a6a00; }
  .status-reappeared { color: #8a0000; font-weight: bold; }
  .status-error { color: #666; }
  .screenshot-box { border: 1px dashed #aaa; padding: 16px; text-align: center;
                    color: #666; font-style: italic; margin: 1em 0; }
  .disclaimer { font-size: 0.8em; color: #666; border-top: 1px solid #ccc;
                margin-top: 2em; padding-top: 1em; }
  .watermark { font-size: 0.75em; color: #999; }
</style>
</head>
<body>
<h1>TraceBurn Removal Receipt</h1>
<p class="watermark">Generated {{ generated_at }} UTC &nbsp;|&nbsp;
   This document is a tamper-evident record of a data removal action.</p>

<h2>Broker</h2>
<table>
  <tr><th>Name</th><td>{{ proof.broker_name }}</td></tr>
  <tr><th>Domain</th><td>{{ proof.broker_domain }}</td></tr>
  <tr><th>Opt-out URL</th><td class="monospace">{{ proof.opt_out_url }}</td></tr>
</table>

<h2>Removal Action</h2>
<table>
  <tr><th>Submitted at (UTC)</th>
      <td>{{ proof.submitted_at.strftime('%Y-%m-%dT%H:%M:%SZ') if proof.submitted_at else '—' }}</td></tr>
  <tr><th>HTTP Response</th>
      <td>{{ proof.http_response_code if proof.http_response_code else '—' }}</td></tr>
  <tr><th>Status</th><td>{{ proof.current_status.replace('_', ' ').title() }}</td></tr>
</table>

{% if screenshot_b64 %}
<h2>Screenshot Evidence</h2>
<img src="data:image/png;base64,{{ screenshot_b64 }}"
     style="max-width: 100%; border: 1px solid #ccc;" alt="Confirmation screenshot">
{% else %}
<h2>Screenshot Evidence</h2>
<div class="screenshot-box">
  [Screenshot stored encrypted at {{ proof.screenshot_path }}]<br>
  Run <code>traceburn proof --verify --broker {{ proof.broker_name | lower }}</code>
  to verify integrity.
</div>
{% endif %}

{% if proof.confirmation_text %}
<h2>Confirmation Text</h2>
<pre class="monospace">{{ proof.confirmation_text }}</pre>
{% endif %}

<h2>Tamper-Evidence</h2>
<table>
  <tr><th>SHA-256 Checksum</th>
      <td class="monospace">sha256:{{ proof.screenshot_checksum or '—' }}</td></tr>
</table>
<p style="font-size:0.85em;">
  To independently verify: decrypt
  <code>{{ proof.screenshot_path }}</code> with your vault key and compute
  the SHA-256 hash of the resulting PNG. It must match the checksum above.
</p>

<h2>Verification History</h2>
<table>
  <tr><th>Checkpoint</th><th>Checked At (UTC)</th><th>Status</th><th>Notes</th></tr>
  {% for label, cp in checkpoints %}
  <tr>
    <td>{{ label }}</td>
    {% if cp %}
    <td>{{ cp.checked_at.strftime('%Y-%m-%dT%H:%M:%SZ') if cp.checked_at else '—' }}</td>
    <td class="status-{{ cp.status | replace('_', '-') }}">
        {{ cp.status.replace('_', ' ').title() }}</td>
    <td>{{ cp.note or '' }}</td>
    {% else %}
    <td>Scheduled</td><td>Pending</td><td></td>
    {% endif %}
  </tr>
  {% endfor %}
</table>

<div class="disclaimer">
  <strong>Disclaimer:</strong> TraceBurn submits opt-out requests on your behalf
  and documents the submission. Actual data removal is performed by the data broker
  and is not guaranteed by TraceBurn. Verification checks confirm whether the
  profile was found at the time of the check; they are not legal proof of erasure.
</div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# ReceiptGenerator
# ---------------------------------------------------------------------------

class ReceiptGenerator:
    """
    Generates human-readable removal receipts for proof records.

    Supports three output formats:
      - Markdown (always available, no extra dependencies)
      - PDF      (requires WeasyPrint + libpango/libcairo system libraries)
      - JSON     (delegates to proof_record.to_dict())

    Args:
        proof_store_root: Root directory of the proof store
                          (typically Path("~/.traceburn")).
        vault_key: Optional 32-byte AES-256 vault key.  Required only when
                   embedding the decrypted screenshot in PDF/HTML output.
    """

    def __init__(
        self,
        proof_store_root: Path,
        vault_key: Optional[bytes] = None,
    ) -> None:
        self._proof_root = proof_store_root.expanduser().resolve()
        self._vault_key = vault_key

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_receipt(
        self,
        proof_record,      # ProofRecord from capture.py or models
        removal_request,   # RemovalRequest-like object
        broker,            # BrokerDefinition-like object
    ) -> str:
        """
        Generate a Markdown receipt for a proof record.

        Returns:
            A Markdown string suitable for display or saving to a .md file.
        """
        lines = [
            "# TraceBurn Removal Receipt",
            "",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} UTC",
            "",
            "## Broker",
            "",
            f"- **Name:** {broker.name}",
            f"- **Domain:** {broker.domain}",
            f"- **Opt-out URL:** {broker.opt_out_url}",
            "",
            "## Removal Action",
            "",
        ]

        submitted = (
            proof_record.submitted_at.strftime("%Y-%m-%dT%H:%M:%SZ")
            if proof_record.submitted_at
            else "—"
        )
        lines += [
            f"- **Submitted at (UTC):** {submitted}",
            f"- **HTTP Response:** {proof_record.http_response_code or '—'}",
            f"- **Status:** {proof_record.current_status.replace('_', ' ').title()}",
            "",
        ]

        if proof_record.confirmation_text:
            lines += [
                "## Confirmation Text",
                "",
                "```",
                proof_record.confirmation_text,
                "```",
                "",
            ]

        if proof_record.screenshot_checksum:
            lines += [
                "## Tamper-Evidence",
                "",
                f"- **Checksum:** `sha256:{proof_record.screenshot_checksum}`",
                f"- **Screenshot (encrypted):** `{proof_record.screenshot_path}`",
                "",
                "> To verify integrity: decrypt the .png.enc file with your vault key "
                "and compute SHA-256.  The result must match the checksum above.",
                "",
            ]

        lines += [
            "## Verification History",
            "",
            "| Checkpoint | Checked At (UTC) | Status | Notes |",
            "|------------|-----------------|--------|-------|",
        ]

        checkpoints = [
            ("T+7d",  getattr(proof_record, "checkpoint_7d", None)),
            ("T+30d", getattr(proof_record, "checkpoint_30d", None)),
            ("T+90d", getattr(proof_record, "checkpoint_90d", None)),
        ]
        for label, cp in checkpoints:
            if cp:
                checked = (
                    cp.checked_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                    if hasattr(cp, "checked_at") and cp.checked_at
                    else "—"
                )
                status = getattr(cp, "status", "—")
                note = getattr(cp, "note", "") or ""
                lines.append(f"| {label} | {checked} | {status} | {note} |")
            else:
                lines.append(f"| {label} | Scheduled | Pending | — |")

        lines += [
            "",
            "---",
            "",
            "*Disclaimer: TraceBurn documents opt-out submissions. "
            "Actual data removal is performed by the broker and is not guaranteed. "
            "Verification checks confirm profile absence at the time of checking.*",
        ]

        return "\n".join(lines)

    def export_pdf(
        self,
        proof_record,
        output_path: Path,
        *,
        embed_screenshot: bool = False,
    ) -> Path:
        """
        Export a PDF receipt for a proof record.

        Uses WeasyPrint (HTML+CSS) for rendering.  If WeasyPrint is not
        available (missing package or system libraries), falls back to
        exporting Markdown with a notice.

        Args:
            proof_record: ProofRecord instance.
            output_path: Destination .pdf path.
            embed_screenshot: If True and vault_key is set, decrypt and embed
                              the screenshot in the PDF.  Defaults to False
                              (shows an encrypted-file placeholder instead).

        Returns:
            Path to the generated file (may be .md if PDF is unavailable).
        """
        output_path = output_path.expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # --- Try to get decrypted screenshot bytes ---
        screenshot_b64: Optional[str] = None
        if embed_screenshot and self._vault_key and proof_record.screenshot_path:
            enc_path = self._proof_root / proof_record.screenshot_path
            if enc_path.exists():
                try:
                    from src.proof.capture import verify_screenshot_checksum  # type: ignore[import]
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                    raw_data = enc_path.read_bytes()
                    nonce = raw_data[:12]
                    ciphertext = raw_data[12:]
                    aesgcm = AESGCM(self._vault_key)
                    decrypted = aesgcm.decrypt(nonce, ciphertext, associated_data=None)

                    if proof_record.screenshot_checksum:
                        import hashlib
                        actual = hashlib.sha256(decrypted).hexdigest()
                        if actual != proof_record.screenshot_checksum:
                            logger.warning(
                                "Screenshot checksum mismatch for proof %s — "
                                "not embedding in PDF",
                                proof_record.proof_id,
                            )
                            decrypted = None

                    if decrypted:
                        screenshot_b64 = base64.b64encode(decrypted).decode("ascii")
                except Exception as exc:
                    logger.warning("Could not decrypt screenshot for PDF: %s", exc)

        # --- Render HTML via Jinja2 ---
        checkpoints = [
            ("T+7d",  getattr(proof_record, "checkpoint_7d", None)),
            ("T+30d", getattr(proof_record, "checkpoint_30d", None)),
            ("T+90d", getattr(proof_record, "checkpoint_90d", None)),
        ]
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        try:
            from jinja2 import Environment  # type: ignore[import]
            env = Environment()
            template = env.from_string(_PROOF_HTML_TEMPLATE)
            html_content = template.render(
                proof=proof_record,
                screenshot_b64=screenshot_b64,
                checkpoints=checkpoints,
                generated_at=generated_at,
            )
        except ImportError:
            logger.warning("Jinja2 not available — falling back to Markdown export")
            return self._fallback_markdown_export(proof_record, output_path)

        # --- Render PDF via WeasyPrint ---
        try:
            from weasyprint import HTML  # type: ignore[import]

            pdf_path = output_path.with_suffix(".pdf")
            HTML(string=html_content).write_pdf(str(pdf_path))
            logger.info("PDF receipt exported: %s", pdf_path)
            return pdf_path

        except ImportError:
            logger.warning(
                "WeasyPrint not available (install weasyprint + libpango/libcairo). "
                "Falling back to Markdown export."
            )
            return self._fallback_markdown_export(proof_record, output_path)

        except Exception as exc:
            logger.error("WeasyPrint rendering failed: %s", exc)
            return self._fallback_markdown_export(proof_record, output_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fallback_markdown_export(self, proof_record, output_path: Path) -> Path:
        """
        Export a Markdown receipt when PDF generation is not possible.

        Appends a notice explaining why PDF was not generated.
        """
        md_path = output_path.with_suffix(".md")

        # Build a minimal broker/removal stub for generate_receipt
        class _Stub:
            pass

        broker_stub = _Stub()
        broker_stub.name = proof_record.broker_name
        broker_stub.domain = proof_record.broker_domain
        broker_stub.opt_out_url = proof_record.opt_out_url

        removal_stub = _Stub()

        md = self.generate_receipt(
            proof_record=proof_record,
            removal_request=removal_stub,
            broker=broker_stub,
        )
        notice = (
            "\n\n---\n\n"
            "> **Note:** PDF export requires WeasyPrint and system libraries "
            "(libpango, libcairo).  This receipt was exported as Markdown instead.\n"
            "> Install with: `pip install weasyprint` and the appropriate system packages.\n"
        )
        md_path.write_text(md + notice, encoding="utf-8")
        logger.info("Markdown receipt exported (PDF unavailable): %s", md_path)
        return md_path


# ---------------------------------------------------------------------------
# Convenience function for CLI use
# ---------------------------------------------------------------------------

def export_receipt_for_broker(
    broker_name: str,
    output_dir: Path,
    proof_store_root: Path,
    vault_key: Optional[bytes] = None,
    format: str = "markdown",  # "markdown" | "pdf" | "json"
) -> Optional[Path]:
    """
    Locate the most recent proof record for a broker and export a receipt.

    This is the function invoked by:
        traceburn proof --export --broker spokeo

    Args:
        broker_name: Broker display name (case-insensitive match).
        output_dir: Directory to write the receipt file.
        proof_store_root: Root of the TraceBurn data directory.
        vault_key: Vault key for screenshot decryption (PDF embed only).
        format: Output format — "markdown", "pdf", or "json".

    Returns:
        Path to the generated file, or None if no proof record found.
    """
    try:
        from src.db import get_db  # type: ignore[import]
    except ImportError:
        logger.error("Database not available — cannot export receipt")
        return None

    db = get_db()
    proof = db.get_latest_proof_for_broker(broker_name=broker_name)
    if proof is None:
        logger.warning("No proof record found for broker: %s", broker_name)
        return None

    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    safe_broker = broker_name.lower().replace(" ", "_")
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    generator = ReceiptGenerator(
        proof_store_root=proof_store_root,
        vault_key=vault_key,
    )

    if format == "json":
        output_path = output_dir / f"proof_{safe_broker}_{date_str}.json"
        data = proof.to_dict() if hasattr(proof, "to_dict") else vars(proof)
        output_path.write_text(
            json.dumps(data, indent=2, default=str), encoding="utf-8"
        )
        logger.info("JSON receipt exported: %s", output_path)
        return output_path

    elif format == "pdf":
        output_path = output_dir / f"proof_{safe_broker}_{date_str}.pdf"
        return generator.export_pdf(proof_record=proof, output_path=output_path)

    else:  # markdown
        output_path = output_dir / f"proof_{safe_broker}_{date_str}.md"
        broker_stub_class = type("Broker", (), {
            "name": proof.broker_name,
            "domain": proof.broker_domain,
            "opt_out_url": proof.opt_out_url,
        })
        md = generator.generate_receipt(
            proof_record=proof,
            removal_request=None,
            broker=broker_stub_class,
        )
        output_path.write_text(md, encoding="utf-8")
        return output_path
