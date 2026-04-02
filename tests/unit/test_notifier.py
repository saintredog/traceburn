"""
tests/unit/test_notifier.py — Unit tests for TelegramNotifier (src/notifier.py).

All tests mock requests.post — no real network calls are made.
get_notifier() env-var tests use monkeypatch and tmp_path to avoid reading
~/.traceburn/config.yaml.

Coverage:
  - send_scan_complete message format (broker count, exposure count)
  - send_relisting_alert warning emoji (🚨)
  - MarkdownV2 special character escaping
  - ConnectionError silently ignored (returns False, does not raise)
  - get_notifier() returns None when token not configured
  - _send() never raises even when requests raises
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from src.notifier import TelegramNotifier, get_notifier


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

FAKE_TOKEN = "123456:ABCDEFabcdef_fake_token"
FAKE_CHAT_ID = "987654321"


@pytest.fixture
def notifier() -> TelegramNotifier:
    """A TelegramNotifier instance with fake credentials."""
    return TelegramNotifier(bot_token=FAKE_TOKEN, chat_id=FAKE_CHAT_ID)


@pytest.fixture
def mock_post():
    """
    Patch requests.post for the duration of a test.

    Returns a MagicMock whose return value simulates a successful 200 response.
    """
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.raise_for_status.return_value = None

    with patch("src.notifier.requests.post", return_value=mock_response) as mp:
        yield mp


# ─────────────────────────────────────────────────────────────────────────────
# Message content
# ─────────────────────────────────────────────────────────────────────────────


class TestSendScanComplete:
    def test_send_scan_complete_formats_correctly(self, notifier, mock_post):
        """
        send_scan_complete() message includes broker count and exposure count.

        Verifies that the text payload sent to Telegram contains the key
        statistics the user needs to see at a glance.
        """
        stats = {
            "brokers_checked": 42,
            "exposures_found": 7,
            "removals_initiated": 3,
            "duration_seconds": 14.2,
            "scan_type": "full",
            "risk_level": "HIGH",
        }
        notifier.send_scan_complete(stats)

        assert mock_post.called
        payload = mock_post.call_args[1]["json"]
        text = payload["text"]

        assert "42" in text, "Broker count missing from scan complete message"
        assert "7" in text, "Exposure count missing from scan complete message"

    def test_send_scan_complete_includes_risk_level(self, notifier, mock_post):
        """send_scan_complete() message includes the risk level."""
        stats = {
            "brokers_checked": 10,
            "exposures_found": 0,
            "risk_level": "CLEAR",
            "scan_type": "full",
            "duration_seconds": 5,
            "removals_initiated": 0,
        }
        notifier.send_scan_complete(stats)

        text = mock_post.call_args[1]["json"]["text"]
        assert "CLEAR" in text

    def test_send_scan_complete_uses_markdownv2(self, notifier, mock_post):
        """send_scan_complete() sends with parse_mode=MarkdownV2."""
        notifier.send_scan_complete({
            "brokers_checked": 1,
            "exposures_found": 0,
            "risk_level": "CLEAR",
            "scan_type": "full",
            "duration_seconds": 1,
            "removals_initiated": 0,
        })
        payload = mock_post.call_args[1]["json"]
        assert payload["parse_mode"] == "MarkdownV2"


class TestRelisting:
    def test_relisting_alert_has_warning_emoji(self, notifier, mock_post):
        """send_relisting_alert() message contains the 🚨 warning emoji."""
        notifier.send_relisting_alert(
            broker_name="Spokeo",
            profile_name="John Smith",
        )
        text = mock_post.call_args[1]["json"]["text"]
        assert "🚨" in text, "Relisting alert must include 🚨 emoji"

    def test_relisting_alert_contains_broker_name(self, notifier, mock_post):
        """send_relisting_alert() message references the broker name."""
        notifier.send_relisting_alert(
            broker_name="Intelius",
            profile_name="Jane Doe",
        )
        text = mock_post.call_args[1]["json"]["text"]
        assert "Intelius" in text


# ─────────────────────────────────────────────────────────────────────────────
# MarkdownV2 escaping
# ─────────────────────────────────────────────────────────────────────────────


class TestEscapeMarkdownV2:
    @pytest.mark.parametrize("char", [".", "!", "-", "_", "*", "[", "]", "(", ")"])
    def test_escape_markdownv2(self, char):
        """
        Special characters (. ! - _ * [ ] ( )) are escaped with a backslash
        in Telegram MarkdownV2 format.
        """
        result = TelegramNotifier._escape(f"hello{char}world")
        assert f"\\{char}" in result, (
            f"Character {char!r} should be escaped as \\{char} in MarkdownV2"
        )

    def test_escape_plain_text_unchanged(self):
        """Plain alphanumeric text is returned unchanged."""
        result = TelegramNotifier._escape("HelloWorld123")
        assert result == "HelloWorld123"

    def test_escape_empty_string(self):
        """Escaping an empty string returns an empty string."""
        assert TelegramNotifier._escape("") == ""

    def test_escape_preserves_digits(self):
        """Digits are not escaped."""
        result = TelegramNotifier._escape("42")
        assert result == "42"


# ─────────────────────────────────────────────────────────────────────────────
# Network error handling
# ─────────────────────────────────────────────────────────────────────────────


class TestNetworkErrors:
    def test_network_error_silently_ignored(self, notifier):
        """
        A requests.ConnectionError does NOT propagate to the caller.

        TelegramNotifier is fire-and-forget; network failures must be swallowed
        so they never interrupt a scan or removal operation.
        """
        with patch(
            "src.notifier.requests.post",
            side_effect=requests.exceptions.ConnectionError("unreachable"),
        ):
            # Must not raise
            result = notifier._send("test message")

        assert result is False

    def test_timeout_silently_ignored(self, notifier):
        """requests.Timeout is swallowed; _send() returns False."""
        with patch(
            "src.notifier.requests.post",
            side_effect=requests.exceptions.Timeout("timed out"),
        ):
            result = notifier._send("test message")

        assert result is False

    def test_unexpected_exception_silently_ignored(self, notifier):
        """Any unexpected exception from requests is swallowed; _send() returns False."""
        with patch(
            "src.notifier.requests.post",
            side_effect=RuntimeError("totally unexpected"),
        ):
            result = notifier._send("test message")

        assert result is False

    def test_send_does_not_block(self, notifier):
        """
        send_scan_complete() completes even when requests.post raises.

        Tests that the fire-and-forget contract holds for the public API.
        """
        with patch(
            "src.notifier.requests.post",
            side_effect=requests.exceptions.RequestException("network error"),
        ):
            # Must not raise, must not block
            notifier.send_scan_complete({
                "brokers_checked": 5,
                "exposures_found": 1,
                "risk_level": "MEDIUM",
                "scan_type": "full",
                "duration_seconds": 3,
                "removals_initiated": 0,
            })

    def test_401_returns_false(self, notifier):
        """HTTP 401 (invalid token) causes _send() to return False without raising."""
        mock_response = MagicMock()
        mock_response.status_code = 401

        with patch("src.notifier.requests.post", return_value=mock_response):
            result = notifier._send("test")

        assert result is False

    def test_403_returns_false(self, notifier):
        """HTTP 403 (bot blocked) causes _send() to return False without raising."""
        mock_response = MagicMock()
        mock_response.status_code = 403

        with patch("src.notifier.requests.post", return_value=mock_response):
            result = notifier._send("test")

        assert result is False


# ─────────────────────────────────────────────────────────────────────────────
# get_notifier() factory
# ─────────────────────────────────────────────────────────────────────────────


class TestGetNotifier:
    def test_none_token_returns_none_notifier(self, monkeypatch, tmp_path: Path):
        """
        get_notifier() returns None when TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID
        are not set and no config.yaml provides them.

        tmp_path is used as the fake home directory so ~/.traceburn/config.yaml
        is never read.
        """
        monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
        monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)

        # Redirect Path.home() to tmp_path so no ~/.traceburn/config.yaml is found
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

        result = get_notifier()
        assert result is None

    def test_both_env_vars_set_returns_notifier(self, monkeypatch, tmp_path: Path):
        """
        get_notifier() returns a configured TelegramNotifier when both
        TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID env vars are set.
        """
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", FAKE_TOKEN)
        monkeypatch.setenv("TELEGRAM_CHAT_ID", FAKE_CHAT_ID)
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

        result = get_notifier()
        assert result is not None
        assert isinstance(result, TelegramNotifier)

    def test_missing_chat_id_returns_none(self, monkeypatch, tmp_path: Path):
        """get_notifier() returns None when only one of the two credentials is set."""
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", FAKE_TOKEN)
        monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

        result = get_notifier()
        assert result is None
