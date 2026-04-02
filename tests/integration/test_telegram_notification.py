"""
tests/integration/test_telegram_notification.py — Phase 4.2 Integration Tests
Telegram notifier delivery tests.

All tests mock requests.post — no real Telegram API calls are made.
Tests verify:
  - Correct API endpoint is called
  - Message body contains expected content
  - Network failures are handled gracefully (fire-and-forget)
  - get_notifier() returns None when credentials are not configured
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from src.notifier import TelegramNotifier, get_notifier


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _make_notifier(token: str = "fake-token-123", chat_id: str = "-100999888") -> TelegramNotifier:
    """Return a TelegramNotifier configured with dummy credentials."""
    return TelegramNotifier(bot_token=token, chat_id=chat_id)


def _ok_response() -> MagicMock:
    """A mock requests.Response that reports HTTP 200."""
    resp = MagicMock()
    resp.status_code = 200
    resp.raise_for_status.return_value = None
    return resp


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestScanCompleteNotification:
    """send_scan_complete() calls the Telegram sendMessage endpoint correctly."""

    def test_scan_complete_notification_sent(self) -> None:
        """
        Create a TelegramNotifier with fake credentials and call
        send_scan_complete() with a stats dict containing brokers_checked=10
        and exposures_found=3.

        Asserts:
          - requests.post is called exactly once
          - The call URL contains "sendMessage"
          - The posted message text contains both "10" and "3"
        """
        notifier = _make_notifier()
        stats = {
            "brokers_checked": 10,
            "exposures_found": 3,
            "removals_initiated": 1,
            "duration_seconds": 45.2,
            "scan_type": "full",
            "risk_level": "LOW",
        }

        with patch("requests.post", return_value=_ok_response()) as mock_post:
            notifier.send_scan_complete(stats)

        mock_post.assert_called_once()

        call_args, call_kwargs = mock_post.call_args
        # URL is the first positional argument
        url = call_args[0] if call_args else call_kwargs.get("url", "")
        assert "sendMessage" in url, (
            f"Expected URL to contain 'sendMessage', got: {url!r}"
        )

        # Payload is passed via json=
        payload = call_kwargs.get("json", {})
        message_text = payload.get("text", "")
        assert "10" in message_text, (
            f"Expected '10' (brokers_checked) in message text: {message_text!r}"
        )
        assert "3" in message_text, (
            f"Expected '3' (exposures_found) in message text: {message_text!r}"
        )


class TestRelistingAlert:
    """send_relisting_alert() includes broker name and 🚨 in the message."""

    def test_relisting_alert_sent_on_reappearance(self) -> None:
        """
        Call send_relisting_alert("Spokeo", "John Smith") and verify:
          - requests.post is called
          - The message body contains "Spokeo"
          - The message body contains the 🚨 alert emoji
        """
        notifier = _make_notifier()

        with patch("requests.post", return_value=_ok_response()) as mock_post:
            notifier.send_relisting_alert("Spokeo", "John Smith")

        mock_post.assert_called_once()

        payload = mock_post.call_args.kwargs.get("json", mock_post.call_args[1].get("json", {}))
        message_text = payload.get("text", "")

        assert "Spokeo" in message_text, (
            f"Expected 'Spokeo' in relisting alert message: {message_text!r}"
        )
        assert "🚨" in message_text, (
            f"Expected '🚨' emoji in relisting alert message: {message_text!r}"
        )

    @pytest.mark.parametrize("broker,profile_name", [
        ("BeenVerified", "Alice Smith"),
        ("Whitepages", "Bob Jones"),
        ("MyLife", "Carol Davis"),
    ])
    def test_relisting_alert_various_brokers(
        self, broker: str, profile_name: str
    ) -> None:
        """
        Parametrized: relisting alert must include the correct broker name
        for each broker variant.
        """
        notifier = _make_notifier()

        with patch("requests.post", return_value=_ok_response()) as mock_post:
            notifier.send_relisting_alert(broker, profile_name)

        payload = mock_post.call_args.kwargs.get("json", {})
        if not payload:
            payload = mock_post.call_args[1].get("json", {})
        message_text = payload.get("text", "")

        assert broker in message_text, (
            f"Expected broker name '{broker}' in message: {message_text!r}"
        )


class TestNotifierGracefulFailure:
    """Network errors must be swallowed — fire-and-forget semantics."""

    def test_notifier_fails_gracefully_on_connection_error(self) -> None:
        """
        Mock requests.post to raise ConnectionError. Any TelegramNotifier
        method must not propagate the exception — it logs locally and returns.
        """
        notifier = _make_notifier()

        with patch("requests.post", side_effect=requests.exceptions.ConnectionError("unreachable")):
            # Must not raise
            notifier.send_scan_complete({"brokers_checked": 5, "exposures_found": 0})

    def test_notifier_fails_gracefully_on_timeout(self) -> None:
        """
        Mock requests.post to raise Timeout. The notifier swallows it and
        continues without raising.
        """
        notifier = _make_notifier()

        with patch("requests.post", side_effect=requests.exceptions.Timeout("timed out")):
            notifier.send_removal_confirmed("Spokeo", "2024-01-01T12:00:00Z")

    def test_notifier_fails_gracefully_on_generic_exception(self) -> None:
        """
        Mock requests.post to raise a generic Exception. The notifier must
        catch it, log a warning, and return False without propagating.
        """
        notifier = _make_notifier()

        with patch("requests.post", side_effect=Exception("unexpected error")):
            notifier.send_relisting_alert("Spokeo", "Jane Doe")

    @pytest.mark.parametrize("method_name,args", [
        ("send_scan_complete", ({"brokers_checked": 1, "exposures_found": 0},)),
        ("send_relisting_alert", ("Spokeo", "Jane Doe")),
        ("send_removal_confirmed", ("Spokeo", "2024-01-01T00:00:00Z")),
        ("send_manual_action_required", ("ManualBroker", "https://manualbroker.com/optout")),
    ])
    def test_all_methods_fail_gracefully(self, method_name: str, args: tuple) -> None:
        """
        Parametrized: every public notification method must catch
        ConnectionError and not raise.
        """
        notifier = _make_notifier()
        method = getattr(notifier, method_name)

        with patch("requests.post", side_effect=requests.exceptions.ConnectionError):
            method(*args)  # must not raise


class TestNotifierSkippedWhenUnconfigured:
    """get_notifier() returns None when no credentials are present."""

    def test_notifier_returns_none_without_env_vars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """
        Clear TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID from the environment.
        get_notifier() must return None when neither env var is set and
        no config.yaml is present.

        The caller pattern ``if notifier: notifier.send_...()`` must work
        without crashing when notifier is None.
        """
        monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
        monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)

        # Patch yaml to pretend no config.yaml exists so the fallback also fails
        with patch("pathlib.Path.exists", return_value=False):
            notifier = get_notifier()

        assert notifier is None, (
            "get_notifier() should return None when no credentials are configured"
        )

        # Simulate safe caller pattern — must not raise AttributeError
        stats = {"brokers_checked": 5, "exposures_found": 2}
        if notifier:  # type: ignore[truthy-bool]
            notifier.send_scan_complete(stats)  # should never reach here

    def test_notifier_returned_when_env_vars_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """
        Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID env vars. get_notifier()
        must return a configured TelegramNotifier instance (not None).
        """
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "test-bot-token")
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100123456")

        notifier = get_notifier()

        assert notifier is not None, (
            "get_notifier() should return a TelegramNotifier when env vars are set"
        )
        assert isinstance(notifier, TelegramNotifier)


class TestMessageContentCorrectness:
    """Verify specific content requirements for each notification type."""

    def test_send_removal_confirmed_contains_broker_and_timestamp(self) -> None:
        """
        send_removal_confirmed("Spokeo", "2024-06-01T14:30:00Z") must produce
        a message containing the broker name and the timestamp string.
        """
        notifier = _make_notifier()

        with patch("requests.post", return_value=_ok_response()) as mock_post:
            notifier.send_removal_confirmed("Spokeo", "2024-06-01T14:30:00Z")

        payload = mock_post.call_args.kwargs.get("json", {})
        if not payload:
            payload = mock_post.call_args[1].get("json", {})
        text = payload.get("text", "")

        assert "Spokeo" in text
        assert "2024" in text  # timestamp present

    def test_parse_mode_is_markdownv2(self) -> None:
        """
        The Telegram API payload must specify parse_mode="MarkdownV2" to
        enable correct rendering of bold/code formatting.
        """
        notifier = _make_notifier()

        with patch("requests.post", return_value=_ok_response()) as mock_post:
            notifier.send_scan_complete({"brokers_checked": 1, "exposures_found": 0})

        payload = mock_post.call_args.kwargs.get("json", {})
        if not payload:
            payload = mock_post.call_args[1].get("json", {})

        assert payload.get("parse_mode") == "MarkdownV2", (
            "Telegram payload must use parse_mode='MarkdownV2'"
        )

    def test_chat_id_sent_in_payload(self) -> None:
        """
        The chat_id field in the API payload must match the one passed to
        the TelegramNotifier constructor.
        """
        expected_chat_id = "-100777888999"
        notifier = _make_notifier(chat_id=expected_chat_id)

        with patch("requests.post", return_value=_ok_response()) as mock_post:
            notifier.test_connection()

        payload = mock_post.call_args.kwargs.get("json", {})
        if not payload:
            payload = mock_post.call_args[1].get("json", {})

        assert payload.get("chat_id") == expected_chat_id, (
            f"Expected chat_id {expected_chat_id!r} in payload, got {payload.get('chat_id')!r}"
        )
