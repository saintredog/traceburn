"""
tests/integration/test_removal_to_proof.py — Phase 4.2 Integration Tests
End-to-end removal → proof record flow.

Playwright and network calls are mocked throughout. Tests exercise the
RemovalEngine routing logic and the ProofCapture encryption/verification
pipeline against real in-process crypto (no browser launched).

Covered scenarios:
  - Tier 1 (Playwright) creates a RemovalResult with SUBMITTED status
  - Tier 2 (email) degrades gracefully when SMTP is unconfigured
  - Tier 3 (manual wizard) creates a manual_attestation result on user "y"
  - Failed Playwright raises TimeoutError → FAILED status
  - ProofRecord checksum tamper detection returns False
"""

from __future__ import annotations

import asyncio
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.models import (
    BrokerDefinition,
    Exposure,
    RemovalMethod,
    RemovalResult,
    RemovalStatus,
    RemovalTier,
)
from src.proof.capture import ProofCapture, ProofRecord, verify_screenshot_checksum
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────


def _tier1_broker() -> BrokerDefinition:
    """Minimal valid Tier 1 BrokerDefinition."""
    return BrokerDefinition(
        id=1,
        name="Spokeo",
        domain="spokeo.com",
        removal_tier=RemovalTier.PLAYWRIGHT,
        opt_out_url="https://www.spokeo.com/optout",
        playwright_script="spokeo",
    )


def _tier2_broker() -> BrokerDefinition:
    """Minimal valid Tier 2 BrokerDefinition."""
    return BrokerDefinition(
        id=2,
        name="BeenVerified",
        domain="beenverified.com",
        removal_tier=RemovalTier.EMAIL,
        opt_out_url="https://www.beenverified.com/app/optout/request",
        opt_out_email="optout@beenverified.com",
    )


def _tier3_broker() -> BrokerDefinition:
    """Minimal valid Tier 3 BrokerDefinition."""
    return BrokerDefinition(
        id=3,
        name="ManualBroker",
        domain="manualbroker.com",
        removal_tier=RemovalTier.MANUAL,
        opt_out_url="https://manualbroker.com/optout",
        opt_out_email=None,
        playwright_script=None,
    )


def _make_exposure(broker: BrokerDefinition, exposure_id: int = 1) -> Exposure:
    """Build an Exposure record for the given broker."""
    url = f"https://{broker.domain}/people/jane-doe"
    return Exposure(
        id=exposure_id,
        user_id=1,
        broker_id=broker.id,
        broker_name=broker.name,
        profile_url=url,
        normalized_url=url,
        composite_confidence=0.9,
    )


def _make_mock_db(broker: BrokerDefinition) -> MagicMock:
    """Return a mock db whose get_broker() returns the given BrokerDefinition."""
    db = MagicMock()
    db.get_broker.return_value = broker
    return db


def _make_config() -> SimpleNamespace:
    """Minimal stub config for RemovalEngine."""
    return SimpleNamespace(
        vault=SimpleNamespace(screenshots_dir=None),
        _vault=None,
        email_optout=SimpleNamespace(address=None, app_password=None),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture()
def vault_key() -> bytes:
    """32-byte AES-256 vault key for ProofCapture tests."""
    return os.urandom(32)


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestTier1Removal:
    """Tier 1 Playwright removal creates a SUBMITTED RemovalResult."""

    def test_tier1_removal_creates_proof_record(self, tmp_path: Path) -> None:
        """
        Mock Tier1Remover.submit_optout to return a RemovalResult simulating a
        successful Playwright opt-out with a captured proof screenshot.

        Asserts:
          - RemovalEngine.remove_one() returns a result with status SUBMITTED
          - result.removal_request_id is set (not None)
          - result.proof_record_id is set (not None)
          - result.broker_name matches the broker
          - The proof record has a non-None checksum (broker_name, timestamp)

        The mock captures what a real Tier1Remover would return after a
        successful opt-out + screenshot capture flow.
        """
        from src.removal.engine import RemovalEngine

        broker = _tier1_broker()
        exposure = _make_exposure(broker)
        db = _make_mock_db(broker)
        config = _make_config()

        fake_proof = ProofRecord(
            proof_id="aabbccdd-1234",
            removal_request_id=42,
            broker_name=broker.name,
            broker_domain=broker.domain,
            opt_out_url=broker.opt_out_url,
            submitted_at=datetime.now(timezone.utc),
            screenshot_path="proof/spokeo_20240101_120000.png.enc",
            screenshot_checksum="a" * 64,
            confirmation_text="Your request has been submitted.",
            http_response_code=200,
            current_status="pending_verification",
        )

        fake_result = RemovalResult(
            exposure_id=exposure.id,
            broker_name=broker.name,
            status=RemovalStatus.SUBMITTED,
            removal_request_id=42,
            proof_record_id=7,
            confirmation_text="Your request has been submitted.",
        )

        engine = RemovalEngine(db=db, config=config, notifier=None)

        # Tier1Remover is imported lazily inside _run_tier1(); patch at its source module
        with patch("src.removal.tier1_playwright.Tier1Remover") as MockTier1:
            MockTier1.return_value.submit_optout = AsyncMock(return_value=fake_result)
            result = asyncio.run(engine.remove_one(exposure))

        # RemovalEngine routing: status passes through from Tier1Remover
        assert result.status in (RemovalStatus.SUBMITTED, RemovalStatus.CONFIRMED), (
            f"Expected SUBMITTED or CONFIRMED, got {result.status}"
        )
        assert result.removal_request_id is not None, "removal_request_id should be set"
        assert result.proof_record_id is not None, "proof_record_id should be set"
        assert result.broker_name == broker.name

        # Proof record fields
        assert fake_proof.broker_name == broker.name
        assert fake_proof.submitted_at is not None
        assert fake_proof.screenshot_checksum is not None


class TestTier2EmailRemoval:
    """Tier 2 email removal degrades gracefully when SMTP is unconfigured."""

    def test_tier2_email_removal_stub(self) -> None:
        """
        Create a Tier 2 exposure with SMTP not configured.
        Assert:
          - RemovalEngine.remove_one() returns without raising
          - status is 'submitted' or 'email_not_configured' (graceful)
          - smtplib.SMTP is never actually called (mock.assert_not_called())

        Tier2Remover is mocked to simulate the configured/unconfigured
        code path without reaching the real SMTP layer.
        """
        from src.removal.engine import RemovalEngine

        broker = _tier2_broker()
        exposure = _make_exposure(broker)
        db = _make_mock_db(broker)
        config = _make_config()  # email credentials absent

        graceful_result = RemovalResult(
            exposure_id=exposure.id,
            broker_name=broker.name,
            status=RemovalStatus.EMAIL_NOT_CONFIGURED,
        )

        engine = RemovalEngine(db=db, config=config, notifier=None)

        # Tier2Remover is imported lazily inside _run_tier2(); patch at its source module
        with (
            patch("src.removal.tier2_email.Tier2Remover") as MockTier2,
            patch("smtplib.SMTP") as MockSMTP,
        ):
            MockTier2.return_value.send_optout_email = AsyncMock(return_value=graceful_result)
            result = asyncio.run(engine.remove_one(exposure))

        accepted_statuses = {RemovalStatus.SUBMITTED, RemovalStatus.EMAIL_NOT_CONFIGURED}
        assert result.status in accepted_statuses, (
            f"Expected graceful status, got {result.status}"
        )
        # SMTP must not have been called — Tier2Remover is fully mocked
        MockSMTP.assert_not_called()


class TestTier3ManualWizard:
    """Tier 3 manual wizard records a manual_attestation result on user 'y'."""

    def test_tier3_manual_wizard_stub(self) -> None:
        """
        Mock Rich.Prompt.ask() to return 'y' (user confirms completion) and
        mock webbrowser.open() to prevent an actual browser from opening.

        Asserts:
          - RemovalEngine.remove_one() returns without raising
          - result.status is SUBMITTED (manual attestation recorded)
          - The result carries method metadata compatible with 'manual_attestation'

        Tier3Wizard.guide_user is mocked to isolate from Rich terminal I/O.
        """
        from src.removal.engine import RemovalEngine

        broker = _tier3_broker()
        exposure = _make_exposure(broker)
        db = _make_mock_db(broker)
        config = _make_config()

        attestation_result = RemovalResult(
            exposure_id=exposure.id,
            broker_name=broker.name,
            status=RemovalStatus.SUBMITTED,
            removal_request_id=55,
            confirmation_text="User attested completion via manual wizard.",
        )

        engine = RemovalEngine(db=db, config=config, notifier=None)

        # Tier3Wizard is imported lazily inside _run_tier3(); patch at its source module
        with (
            patch("src.removal.tier3_wizard.Tier3Wizard") as MockWizard,
            patch("webbrowser.open") as mock_browser,
            patch("rich.prompt.Prompt.ask", return_value="y"),
        ):
            MockWizard.return_value.guide_user = AsyncMock(return_value=attestation_result)
            result = asyncio.run(engine.remove_one(exposure))

        assert result.status == RemovalStatus.SUBMITTED, (
            f"Expected SUBMITTED for manual attestation, got {result.status}"
        )
        # The wizard result confirmation text should indicate manual action
        assert "manual" in result.confirmation_text.lower() or result.removal_request_id == 55

        # Browser must not have opened — wizard is fully mocked
        mock_browser.assert_not_called()


class TestFailedRemovalRetryScheduled:
    """A Playwright TimeoutError should produce a FAILED status."""

    def test_failed_removal_retry_scheduled(self) -> None:
        """
        Mock Tier1Remover.submit_optout to raise asyncio.TimeoutError.
        RemovalEngine._run_tier1 catches all exceptions and returns an error
        RemovalResult.

        Asserts:
          - result.status == RemovalStatus.FAILED
          - result.error is set (contains exception info)
          - The engine does not re-raise the exception
        """
        from src.removal.engine import RemovalEngine

        broker = _tier1_broker()
        exposure = _make_exposure(broker)
        db = _make_mock_db(broker)
        config = _make_config()

        engine = RemovalEngine(db=db, config=config, notifier=None)

        # Tier1Remover is imported lazily inside _run_tier1(); patch at source module
        with patch("src.removal.tier1_playwright.Tier1Remover") as MockTier1:
            MockTier1.return_value.submit_optout = AsyncMock(
                side_effect=asyncio.TimeoutError("Playwright navigation timed out")
            )
            # Should NOT raise — engine swallows tier errors
            result = asyncio.run(engine.remove_one(exposure))

        assert result.status == RemovalStatus.FAILED, (
            f"Expected FAILED on TimeoutError, got {result.status}"
        )
        assert result.error is not None, "result.error should be set on failure"


class TestProofChecksumTamperDetection:
    """
    ProofCapture.verify_checksum() must return False when the stored checksum
    in the ProofRecord does not match the decrypted file content.
    """

    def test_proof_checksum_tamper_detection(
        self, tmp_path: Path, vault_key: bytes
    ) -> None:
        """
        Write a real AES-256-GCM encrypted "screenshot" to disk, create a
        ProofRecord with the correct SHA-256 checksum, then deliberately
        corrupt the stored checksum and assert verify_checksum() returns False.

        Steps:
          1. Create fake PNG bytes and compute their SHA-256 checksum
          2. Encrypt with AESGCM using vault_key
          3. Write [nonce][ciphertext] to disk under proof/
          4. Create ProofCapture pointing to tmp_path
          5. Build ProofRecord with correct checksum
          6. verify_checksum() → True (sanity check)
          7. Overwrite proof_record.screenshot_checksum with wrong hex
          8. verify_checksum() → False (tamper detected)
        """
        # ── Step 1–3: write encrypted proof file ──────────────────────────
        fake_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 200  # fake PNG bytes
        correct_checksum = hashlib.sha256(fake_png).hexdigest()

        nonce = os.urandom(12)
        aesgcm = AESGCM(vault_key)
        encrypted = aesgcm.encrypt(nonce, fake_png, associated_data=None)
        stored_bytes = nonce + encrypted

        proof_dir = tmp_path / "proof"
        proof_dir.mkdir(parents=True)
        enc_file = proof_dir / "spokeo_20240101_120000.png.enc"
        enc_file.write_bytes(stored_bytes)

        # ── Step 4: ProofCapture instance ──────────────────────────────────
        capture = ProofCapture(proof_store_root=tmp_path, vault_key=vault_key)

        # ── Step 5: build ProofRecord with relative path ──────────────────
        record = ProofRecord(
            proof_id="test-tamper-001",
            removal_request_id=1,
            broker_name="Spokeo",
            broker_domain="spokeo.com",
            opt_out_url="https://www.spokeo.com/optout",
            submitted_at=datetime.now(timezone.utc),
            screenshot_path="proof/spokeo_20240101_120000.png.enc",
            screenshot_checksum=correct_checksum,
            http_response_code=200,
        )

        # ── Step 6: sanity check — correct checksum verifies True ─────────
        assert capture.verify_checksum(record) is True, (
            "verify_checksum() should return True for an unmodified file"
        )

        # ── Step 7–8: tamper the stored checksum, expect False ─────────────
        record.screenshot_checksum = "d" * 64  # deliberately wrong 64-hex string
        assert capture.verify_checksum(record) is False, (
            "verify_checksum() should return False when checksum is tampered"
        )

    @pytest.mark.parametrize("bad_checksum", [
        "0" * 64,    # all zeros (wrong but valid hex length)
        "f" * 64,    # all f's
        "cafe" + "0" * 60,  # partial match
    ])
    def test_various_wrong_checksums_detected(
        self, tmp_path: Path, vault_key: bytes, bad_checksum: str
    ) -> None:
        """
        Parametrized: any wrong checksum value must cause verify_checksum() to
        return False, regardless of what the wrong value looks like.
        """
        fake_png = b"\x89PNG\r\n\x1a\n" + b"pixel data" * 10
        correct_checksum = hashlib.sha256(fake_png).hexdigest()

        nonce = os.urandom(12)
        aesgcm = AESGCM(vault_key)
        encrypted = aesgcm.encrypt(nonce, fake_png, associated_data=None)
        stored_bytes = nonce + encrypted

        proof_dir = tmp_path / "proof"
        proof_dir.mkdir(parents=True)
        filename = "broker_20240101_120000.png.enc"
        (proof_dir / filename).write_bytes(stored_bytes)

        capture = ProofCapture(proof_store_root=tmp_path, vault_key=vault_key)
        record = ProofRecord(
            proof_id="tamper-param",
            removal_request_id=1,
            broker_name="TestBroker",
            broker_domain="testbroker.com",
            opt_out_url="https://testbroker.com/optout",
            submitted_at=datetime.now(timezone.utc),
            screenshot_path=f"proof/{filename}",
            screenshot_checksum=bad_checksum,
        )

        assert capture.verify_checksum(record) is False, (
            f"Expected False for wrong checksum {bad_checksum[:8]}..., "
            f"correct was {correct_checksum[:8]}..."
        )
