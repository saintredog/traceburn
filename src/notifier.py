"""
src/notifier.py — Telegram notification integration for TraceBurn.

TelegramNotifier sends fire-and-forget alert messages via the Telegram Bot API.
All methods are non-critical: every exception is caught, logged locally, and
swallowed so that a notification failure never interrupts the opt-out flow.

Configuration (via factory):
    TELEGRAM_BOT_TOKEN  — bot token from @BotFather
    TELEGRAM_CHAT_ID    — destination chat/user ID

Usage:
    notifier = get_notifier()
    if notifier:
        notifier.send_scan_complete(stats)
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

import requests

logger = logging.getLogger(__name__)

# All characters that must be escaped in Telegram MarkdownV2 messages
_MDV2_SPECIAL = r"\_*[]()~`>#+-=|{}.!"


class TelegramNotifier:
    """
    Sends TraceBurn event notifications via the Telegram Bot API.

    All public methods are fire-and-forget: they catch every exception,
    log a warning locally at WARNING level, and return without raising.
    A notification failure must never interrupt a scan or removal operation.

    Args:
        bot_token: Telegram bot token obtained from @BotFather.
        chat_id:   Destination chat ID or @username string.
    """

    API_BASE = "https://api.telegram.org/bot"
    TIMEOUT_SECONDS = 10

    def __init__(self, bot_token: str, chat_id: str) -> None:
        self._token = bot_token
        self._chat_id = chat_id

    # ──────────────────────────────────────────────────────────────
    # Public notification methods
    # ──────────────────────────────────────────────────────────────

    def send_scan_complete(self, stats: dict[str, Any]) -> None:
        """
        Send a scan-complete summary notification.

        Args:
            stats: Dict with keys:
                brokers_checked    (int)
                exposures_found    (int)
                removals_initiated (int)
                duration_seconds   (int | float)
                scan_type          (str)
                risk_level         (str): "HIGH" | "MEDIUM" | "LOW" | "CLEAR"
        """
        risk_emoji = {
            "HIGH": "🔴",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "CLEAR": "✅",
        }.get(stats.get("risk_level", ""), "⚪")

        text = (
            f"*TraceBurn Scan Complete* {risk_emoji}\n"
            f"\n"
            f"📅 `{self._now()}`\n"
            f"🔍 Scan type: `{self._escape(str(stats.get('scan_type', 'full')))}`\n"
            f"📊 Brokers checked: `{stats.get('brokers_checked', 0)}`\n"
            f"⚠️ Exposures found: `{stats.get('exposures_found', 0)}`\n"
            f"🗑️ Removals initiated: `{stats.get('removals_initiated', 0)}`\n"
            f"⏱️ Duration: `{stats.get('duration_seconds', 0)}s`\n"
            f"🎯 Risk level: *{self._escape(stats.get('risk_level', 'UNKNOWN'))}*"
        )
        self._send(text)

    def send_removal_confirmed(self, broker_name: str, timestamp: str) -> None:
        """
        Send confirmation that a broker has removed the user's profile.

        Args:
            broker_name: Display name of the broker (e.g. "Spokeo").
            timestamp:   ISO 8601 confirmation timestamp string.
        """
        text = (
            f"*Removal Confirmed* ✅\n"
            f"\n"
            f"🏢 Broker: `{self._escape(broker_name)}`\n"
            f"🕐 Confirmed at: `{self._escape(timestamp)}`\n"
            f"\n"
            f"Your data has been removed from this broker\\. "
            f"TraceBurn will re\\-verify in 30 days\\."
        )
        self._send(text)

    def send_relisting_alert(self, broker_name: str, profile_name: str) -> None:
        """
        🚨 ALERT: a previously-removed profile has reappeared on a broker.

        Args:
            broker_name:  Display name of the broker.
            profile_name: Name of the affected profile (e.g. "Jane Smith").
        """
        text = (
            f"🚨 *REAPPEARANCE ALERT* 🚨\n"
            f"\n"
            f"A previously\\-removed profile has reappeared\\!\n"
            f"\n"
            f"🏢 Broker: *{self._escape(broker_name)}*\n"
            f"👤 Profile: *{self._escape(profile_name)}*\n"
            f"\n"
            f"TraceBurn is automatically re\\-submitting a removal request\\."
        )
        self._send(text)

    def send_manual_action_required(self, broker_name: str, url: str) -> None:
        """
        Notify the user that a Tier 3 broker requires manual opt-out.

        Args:
            broker_name: Display name of the broker.
            url:         Direct URL of the opt-out page the user must visit.
        """
        text = (
            f"*Manual Action Required* 🖐\n"
            f"\n"
            f"🏢 Broker: *{self._escape(broker_name)}*\n"
            f"\n"
            f"This broker requires manual opt\\-out\\. "
            f"TraceBurn cannot automate this removal\\.\n"
            f"\n"
            f"👉 Visit the opt\\-out page:\n"
            f"`{self._escape(url)}`\n"
            f"\n"
            f"After completing, run:\n"
            f"`traceburn removal confirm \\-\\-broker {self._escape(broker_name)}`"
        )
        self._send(text)

    def send_phase_complete(self, phase_name: str, summary: str) -> None:
        """
        Notify that a named phase or batch operation has completed.

        Args:
            phase_name: Human-readable name of the completed phase.
            summary:    One-line summary of the outcome.
        """
        text = (
            f"*Phase Complete* 🏁\n"
            f"\n"
            f"📋 Phase: *{self._escape(phase_name)}*\n"
            f"📅 `{self._now()}`\n"
            f"\n"
            f"{self._escape(summary)}"
        )
        self._send(text)

    def test_connection(self) -> bool:
        """
        Send a test message to verify bot token and chat ID are valid.

        Returns:
            True if the test message was delivered successfully.
        """
        text = (
            f"*TraceBurn* connected successfully ✅\n"
            f"Notifications active as of `{self._now()}`"
        )
        return self._send(text)

    # ──────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def _escape(text: str) -> str:
        """
        Escape special characters for Telegram MarkdownV2.

        Characters requiring escaping: _ * [ ] ( ) ~ ` > # + - = | { } . !
        Each must be preceded by a backslash in MarkdownV2 messages.
        """
        return "".join(
            f"\\{c}" if c in _MDV2_SPECIAL else c for c in str(text)
        )

    def _send(self, text: str) -> bool:
        """
        POST a message to the Telegram Bot API.

        Returns True on success, False on any failure.
        NEVER raises — all exceptions are caught, logged at WARNING, and swallowed.
        """
        url = f"{self.API_BASE}{self._token}/sendMessage"
        payload = {
            "chat_id": self._chat_id,
            "text": text,
            "parse_mode": "MarkdownV2",
        }

        try:
            response = requests.post(url, json=payload, timeout=self.TIMEOUT_SECONDS)

            if response.status_code == 401:
                logger.warning(
                    "Telegram: bot token invalid (401). "
                    "Check TELEGRAM_BOT_TOKEN — no further notifications this session."
                )
                return False
            if response.status_code == 400:
                logger.warning(
                    "Telegram: bad request (400) — likely malformed MarkdownV2. Body: %s",
                    response.text[:300],
                )
                return False
            if response.status_code == 403:
                logger.warning(
                    "Telegram: forbidden (403). "
                    "Bot may have been blocked or removed from chat."
                )
                return False

            response.raise_for_status()
            return True

        except requests.exceptions.ConnectionError:
            logger.warning(
                "Telegram: network unreachable. Notification dropped, logged locally."
            )
            return False
        except requests.exceptions.Timeout:
            logger.warning(
                "Telegram: request timed out after %ds. Notification dropped.",
                self.TIMEOUT_SECONDS,
            )
            return False
        except requests.exceptions.RequestException as exc:
            logger.warning("Telegram: request error: %s", exc)
            return False
        except Exception as exc:
            logger.warning("Telegram: unexpected error: %s", exc)
            return False

    @staticmethod
    def _now() -> str:
        """Return current UTC time as a human-readable string."""
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ──────────────────────────────────────────────────────────────
# Factory
# ──────────────────────────────────────────────────────────────


def get_notifier() -> TelegramNotifier | None:
    """
    Build a TelegramNotifier from environment variables or config file.

    Resolution order:
        1. TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID environment variables.
        2. ~/.traceburn/config.yaml under notifications.telegram.{bot_token,chat_id}.

    Returns:
        A configured TelegramNotifier, or None if credentials are not found.
        Callers MUST check for None before calling any notification method.

    Example::

        notifier = get_notifier()
        if notifier:
            notifier.send_scan_complete(stats)
    """
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")

    if not token or not chat_id:
        # Fallback: read from ~/.traceburn/config.yaml
        try:
            from pathlib import Path

            import yaml

            config_path = Path.home() / ".traceburn" / "config.yaml"
            if config_path.exists():
                with config_path.open("r", encoding="utf-8") as fh:
                    cfg = yaml.safe_load(fh) or {}
                tg = cfg.get("notifications", {}).get("telegram", {})
                token = token or tg.get("bot_token")
                chat_id = chat_id or tg.get("chat_id")
        except Exception as exc:
            logger.debug("Telegram: could not read config.yaml: %s", exc)

    if not token or not chat_id:
        logger.debug(
            "Telegram notifier disabled: "
            "TELEGRAM_BOT_TOKEN and/or TELEGRAM_CHAT_ID not configured."
        )
        return None

    return TelegramNotifier(bot_token=token, chat_id=chat_id)
