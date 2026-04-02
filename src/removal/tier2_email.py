"""
src/removal/tier2_email.py — Email opt-out handler (Tier 2).

Sends a Jinja2-rendered opt-out email via SMTP (TLS), then polls the IMAP inbox
for a confirmation email from the broker domain, extracts the confirmation URL,
and clicks it via requests.get().

Email credentials are loaded from config:
  OPTOUT_EMAIL            — sender email address
  OPTOUT_EMAIL_APP_PASSWORD — app password (never stored in code)

Graceful degradation:
  If email credentials are not configured, returns status="email_not_configured"
  and logs a warning — never raises or blocks the main flow.
"""

from __future__ import annotations

import asyncio
import email as email_lib
import imaplib
import logging
import re
import smtplib
import ssl
import time
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

from ..models import (
    BrokerDefinition,
    RemovalResult,
    RemovalStatus,
)

logger = logging.getLogger(__name__)

# Template directory: src/reporting/templates/ (shared with report generator)
_TEMPLATE_DIR = Path(__file__).parent.parent / "reporting" / "templates"

# IMAP polling cadence
_IMAP_POLL_INTERVAL_SECONDS = 30
_IMAP_DEFAULT_TIMEOUT_MINUTES = 30

# Regex to extract confirmation URLs from email bodies
_CONFIRM_URL_RE = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE,
)


class Tier2Remover:
    """
    Handles Tier 2 (email opt-out) removals.

    Flow per exposure:
      1. Render opt-out email from Jinja2 template
      2. Send via SMTP (TLS)
      3. Poll IMAP inbox for confirmation email from broker domain
      4. Extract confirmation URL and click it via requests.get()
      5. Return RemovalResult

    If email credentials are not configured, returns immediately with
    status=EMAIL_NOT_CONFIGURED so the engine can fall back gracefully.
    """

    def __init__(self, config: Any) -> None:
        """
        Args:
            config: AppConfig object — email credentials read from env vars
                    OPTOUT_EMAIL and OPTOUT_EMAIL_APP_PASSWORD.
        """
        self._config = config
        self._from_address = self._read_env("OPTOUT_EMAIL")
        self._app_password = self._read_env("OPTOUT_EMAIL_APP_PASSWORD")
        self._smtp_host = self._read_env("OPTOUT_SMTP_HOST", "smtp.gmail.com")
        self._smtp_port = int(self._read_env("OPTOUT_SMTP_PORT", "587"))
        self._imap_host = self._read_env("OPTOUT_IMAP_HOST", "imap.gmail.com")
        self._imap_port = int(self._read_env("OPTOUT_IMAP_PORT", "993"))
        self._configured = bool(self._from_address and self._app_password)

        if not self._configured:
            logger.info(
                "[Tier2] Email credentials not configured. "
                "Set OPTOUT_EMAIL and OPTOUT_EMAIL_APP_PASSWORD env vars."
            )

        # Lazy-init Jinja2 environment
        self._jinja_env: Any = None

    # ──────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────

    async def send_optout_email(
        self,
        broker: BrokerDefinition,
        profile: dict,
    ) -> RemovalResult:
        """
        Send an opt-out email to the broker and return a RemovalResult.

        If email credentials are not set, returns EMAIL_NOT_CONFIGURED immediately.

        Args:
            broker:  BrokerDefinition for the target broker (must have opt_out_email set).
            profile: Dict of PII fields from vault for template rendering.

        Returns:
            RemovalResult with status SUBMITTED (or EMAIL_NOT_CONFIGURED / FAILED).
        """
        if not self._configured:
            return RemovalResult(
                exposure_id=profile.get("exposure_id", 0),
                broker_name=broker.name,
                status=RemovalStatus.EMAIL_NOT_CONFIGURED,
                error="OPTOUT_EMAIL / OPTOUT_EMAIL_APP_PASSWORD not set",
            )

        if not broker.opt_out_email:
            return RemovalResult(
                exposure_id=profile.get("exposure_id", 0),
                broker_name=broker.name,
                status=RemovalStatus.FAILED,
                error=f"Broker {broker.name} has no opt_out_email configured",
            )

        try:
            subject, body = self._render_email(broker=broker, profile=profile)
            message_id = await asyncio.get_event_loop().run_in_executor(
                None,
                self._send_smtp,
                broker.opt_out_email,
                subject,
                body,
            )
            logger.info(
                "[Tier2] Opt-out email sent to %s (message-id: %s)",
                broker.opt_out_email,
                message_id,
            )
            return RemovalResult(
                exposure_id=profile.get("exposure_id", 0),
                broker_name=broker.name,
                status=RemovalStatus.SUBMITTED,
                confirmation_text=f"Email sent to {broker.opt_out_email} (msg-id: {message_id})",
            )

        except smtplib.SMTPAuthenticationError as exc:
            logger.error("[Tier2] SMTP authentication failed: %s", exc)
            return RemovalResult(
                exposure_id=profile.get("exposure_id", 0),
                broker_name=broker.name,
                status=RemovalStatus.FAILED,
                error=f"SMTP authentication failed — check OPTOUT_EMAIL_APP_PASSWORD: {exc}",
            )
        except smtplib.SMTPException as exc:
            logger.error("[Tier2] SMTP error for %s: %s", broker.name, exc)
            return RemovalResult(
                exposure_id=profile.get("exposure_id", 0),
                broker_name=broker.name,
                status=RemovalStatus.FAILED,
                error=f"SMTP error: {exc}",
            )
        except Exception as exc:
            logger.exception("[Tier2] Unexpected error for %s: %s", broker.name, exc)
            return RemovalResult(
                exposure_id=profile.get("exposure_id", 0),
                broker_name=broker.name,
                status=RemovalStatus.FAILED,
                error=f"Unexpected error: {exc}",
            )

    async def poll_for_confirmation(
        self,
        broker: BrokerDefinition,
        timeout_minutes: int = _IMAP_DEFAULT_TIMEOUT_MINUTES,
    ) -> RemovalResult | None:
        """
        Poll the IMAP inbox for a confirmation email from the broker domain.

        Checks every 30 seconds for up to timeout_minutes. On finding a
        confirmation email, extracts the confirmation URL and clicks it.

        Args:
            broker:          BrokerDefinition — used to match sender domain.
            timeout_minutes: Max minutes to wait for confirmation (default: 30).

        Returns:
            RemovalResult with CONFIRMED status if found, or None on timeout.
        """
        if not self._configured:
            logger.warning("[Tier2] Cannot poll IMAP — email not configured")
            return None

        deadline = datetime.utcnow() + timedelta(minutes=timeout_minutes)
        poll_count = 0

        logger.info(
            "[Tier2] Polling IMAP for confirmation from %s (timeout: %dm)",
            broker.domain,
            timeout_minutes,
        )

        while datetime.utcnow() < deadline:
            poll_count += 1
            logger.debug("[Tier2] IMAP poll #%d for %s", poll_count, broker.domain)

            try:
                confirm_url = await asyncio.get_event_loop().run_in_executor(
                    None,
                    self._check_imap_for_confirmation,
                    broker.domain,
                )
            except Exception as exc:
                logger.warning("[Tier2] IMAP check error (poll #%d): %s", poll_count, exc)
                confirm_url = None

            if confirm_url:
                logger.info(
                    "[Tier2] Confirmation URL found for %s: %s",
                    broker.name,
                    confirm_url[:80],
                )
                clicked = self._click_confirmation_url(confirm_url)
                return RemovalResult(
                    exposure_id=0,  # Caller should set correct exposure_id
                    broker_name=broker.name,
                    status=RemovalStatus.CONFIRMED if clicked else RemovalStatus.SUBMITTED,
                    confirmation_text=f"Confirmation URL clicked: {confirm_url[:120]}",
                )

            await asyncio.sleep(_IMAP_POLL_INTERVAL_SECONDS)

        logger.info(
            "[Tier2] Confirmation email not received within %dm for %s",
            timeout_minutes,
            broker.name,
        )
        return None

    # ──────────────────────────────────────────────────────────────
    # Private: Email rendering
    # ──────────────────────────────────────────────────────────────

    def _render_email(
        self,
        broker: BrokerDefinition,
        profile: dict,
    ) -> tuple[str, str]:
        """
        Render the opt-out email subject and body using Jinja2.

        Template search order:
          1. opt_out_email_{broker_domain_slug}.txt.j2  (broker-specific)
          2. opt_out_email.txt.j2                        (generic fallback)

        Args:
            broker:  BrokerDefinition
            profile: PII dict for template substitution

        Returns:
            (subject, body) tuple of rendered strings.
        """
        env = self._get_jinja_env()
        domain_slug = broker.domain.replace(".", "_").replace("-", "_")

        # Try broker-specific template first
        broker_tmpl_name = f"opt_out_email_{domain_slug}.txt.j2"
        if (self._get_template_dir() / broker_tmpl_name).exists():
            template = env.get_template(broker_tmpl_name)
        else:
            template = env.get_template("opt_out_email.txt.j2")

        ctx = {
            "broker": broker,
            "profile": profile,
            "now": datetime.utcnow().strftime("%Y-%m-%d"),
            "sender_email": self._from_address,
        }

        rendered = template.render(**ctx)

        # Split subject from body (first line = subject)
        lines = rendered.strip().splitlines()
        subject_line = lines[0].strip()
        if subject_line.lower().startswith("subject:"):
            subject = subject_line[len("subject:"):].strip()
            body = "\n".join(lines[1:]).strip()
        else:
            subject = f"Opt-Out Request — {broker.name}"
            body = rendered

        return subject, body

    def _get_jinja_env(self) -> Any:
        """Lazy-initialize the Jinja2 environment."""
        if self._jinja_env is None:
            try:
                from jinja2 import Environment, FileSystemLoader, select_autoescape

                self._jinja_env = Environment(
                    loader=FileSystemLoader(str(self._get_template_dir())),
                    autoescape=select_autoescape(["html"]),
                    keep_trailing_newline=True,
                )
            except ImportError:
                logger.error("[Tier2] jinja2 not installed — cannot render email templates")
                raise
        return self._jinja_env

    @staticmethod
    def _get_template_dir() -> Path:
        return Path(__file__).parent.parent / "reporting" / "templates"

    # ──────────────────────────────────────────────────────────────
    # Private: SMTP send (blocking — runs in executor)
    # ──────────────────────────────────────────────────────────────

    def _send_smtp(
        self,
        to_address: str,
        subject: str,
        body: str,
    ) -> str:
        """
        Send an email via SMTP with STARTTLS.

        Runs synchronously — call via run_in_executor from async context.

        Returns:
            The SMTP Message-ID header value for tracking.
        """
        msg = MIMEMultipart("alternative")
        msg["From"] = self._from_address
        msg["To"] = to_address
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))

        # Generate a message-id for tracking
        import uuid
        domain = self._from_address.split("@")[-1]
        message_id = f"<{uuid.uuid4().hex}@{domain}>"
        msg["Message-ID"] = message_id

        context = ssl.create_default_context()
        with smtplib.SMTP(self._smtp_host, self._smtp_port) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(self._from_address, self._app_password)
            server.sendmail(self._from_address, [to_address], msg.as_string())

        return message_id

    # ──────────────────────────────────────────────────────────────
    # Private: IMAP polling (blocking — runs in executor)
    # ──────────────────────────────────────────────────────────────

    def _check_imap_for_confirmation(self, broker_domain: str) -> str | None:
        """
        Connect to IMAP inbox and search for an unread email from broker_domain.

        If found, extracts the first URL in the email body as the confirmation URL.

        Returns:
            Confirmation URL string, or None if not found.
        """
        try:
            mail = imaplib.IMAP4_SSL(self._imap_host, self._imap_port)
            mail.login(self._from_address, self._app_password)
            mail.select("INBOX")

            # Search for unseen emails from the broker domain
            # Note: IMAP FROM search matches the full From header
            _, data = mail.search(
                None, f'(UNSEEN FROM "{broker_domain}")'
            )

            if not data or not data[0]:
                mail.logout()
                return None

            # Check the most recent matching email
            msg_ids = data[0].split()
            if not msg_ids:
                mail.logout()
                return None

            latest_id = msg_ids[-1]
            _, msg_data = mail.fetch(latest_id, "(RFC822)")
            raw_email = msg_data[0][1]

            parsed = email_lib.message_from_bytes(raw_email)
            body_text = _extract_email_body(parsed)

            # Extract confirmation URL (first https URL in the body)
            urls = _CONFIRM_URL_RE.findall(body_text)
            confirm_url = None
            for url in urls:
                # Prefer URLs that look like opt-out confirmation links
                if any(kw in url.lower() for kw in ["confirm", "optout", "opt-out", "unsubscribe", "verify", "remove"]):
                    confirm_url = url
                    break
            if not confirm_url and urls:
                confirm_url = urls[0]

            # Mark as read
            mail.store(latest_id, "+FLAGS", "\\Seen")
            mail.logout()

            return confirm_url

        except imaplib.IMAP4.error as exc:
            logger.warning("[Tier2] IMAP error: %s", exc)
            return None
        except Exception as exc:
            logger.warning("[Tier2] Unexpected IMAP error: %s", exc)
            return None

    def _click_confirmation_url(self, url: str) -> bool:
        """
        Click a confirmation URL by sending a GET request.

        Returns True on HTTP 200, False otherwise.
        Errors are logged and swallowed — never propagates.
        """
        try:
            import requests

            response = requests.get(url, timeout=15, allow_redirects=True)
            if response.status_code == 200:
                logger.info("[Tier2] Confirmation URL clicked successfully: %s", url[:80])
                return True
            else:
                logger.warning(
                    "[Tier2] Confirmation URL returned %d: %s",
                    response.status_code,
                    url[:80],
                )
                return False
        except Exception as exc:
            logger.warning("[Tier2] Failed to click confirmation URL: %s", exc)
            return False

    # ──────────────────────────────────────────────────────────────
    # Utility
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def _read_env(name: str, default: str = "") -> str:
        """Read an environment variable, returning default if unset or empty."""
        import os
        return os.environ.get(name, default) or default


# ──────────────────────────────────────────────────────────────
# Module-level helpers
# ──────────────────────────────────────────────────────────────


def _extract_email_body(msg: Any) -> str:
    """
    Extract plain-text body from a parsed email.Message object.

    Handles both simple and multipart messages, prefers text/plain over text/html.
    """
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))
            if content_type == "text/plain" and "attachment" not in disposition:
                charset = part.get_content_charset() or "utf-8"
                try:
                    body = part.get_payload(decode=True).decode(charset, errors="replace")
                    break
                except Exception:
                    continue
    else:
        charset = msg.get_content_charset() or "utf-8"
        try:
            body = msg.get_payload(decode=True).decode(charset, errors="replace")
        except Exception:
            body = str(msg.get_payload())
    return body
