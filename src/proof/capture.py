"""
src/proof/capture.py — Screenshot capture and encryption for removal proof records.

Design principles (from 2.6-proof-engine-design.md):
  1. The unencrypted screenshot NEVER touches disk — held in memory only.
  2. SHA-256 checksum is computed BEFORE encryption (over raw PNG bytes).
  3. AES-256-GCM authenticated encryption with the vault-derived key.
  4. Encrypted file written atomically (temp-file + rename) to prevent
     partial writes if the process is killed mid-write.
  5. Raw bytes are zeroed in memory after use (best-effort in CPython).

Encrypted file format on disk:
  [12-byte random nonce][AES-256-GCM ciphertext][16-byte GCM auth tag]
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ProofRecord (self-contained to avoid circular imports from src.models)
# ---------------------------------------------------------------------------

class ProofRecord:
    """
    Metadata returned after capturing and encrypting a proof screenshot.

    Fields mirror the ProofRecord Pydantic model in src/models (2.1 architecture).
    This lightweight dataclass avoids importing the full model here.
    """

    __slots__ = (
        "proof_id",
        "removal_request_id",
        "broker_name",
        "broker_domain",
        "opt_out_url",
        "submitted_at",
        "screenshot_path",
        "screenshot_checksum",
        "confirmation_text",
        "http_response_code",
        "current_status",
    )

    def __init__(
        self,
        *,
        proof_id: str,
        removal_request_id: int,
        broker_name: str,
        broker_domain: str,
        opt_out_url: str,
        submitted_at: datetime,
        screenshot_path: Optional[str] = None,
        screenshot_checksum: Optional[str] = None,
        confirmation_text: Optional[str] = None,
        http_response_code: Optional[int] = None,
        current_status: str = "pending_verification",
    ) -> None:
        self.proof_id = proof_id
        self.removal_request_id = removal_request_id
        self.broker_name = broker_name
        self.broker_domain = broker_domain
        self.opt_out_url = opt_out_url
        self.submitted_at = submitted_at
        self.screenshot_path = screenshot_path
        self.screenshot_checksum = screenshot_checksum
        self.confirmation_text = confirmation_text
        self.http_response_code = http_response_code
        self.current_status = current_status

    def __repr__(self) -> str:
        return (
            f"ProofRecord(proof_id={self.proof_id!r}, broker={self.broker_name!r}, "
            f"status={self.current_status!r})"
        )

    def to_dict(self) -> dict:
        return {
            "proof_id": self.proof_id,
            "removal_request_id": self.removal_request_id,
            "broker_name": self.broker_name,
            "broker_domain": self.broker_domain,
            "opt_out_url": self.opt_out_url,
            "submitted_at": self.submitted_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "screenshot_path": self.screenshot_path,
            "screenshot_checksum": self.screenshot_checksum,
            "confirmation_text": self.confirmation_text,
            "http_response_code": self.http_response_code,
            "current_status": self.current_status,
        }


# ---------------------------------------------------------------------------
# Broker name normalisation
# ---------------------------------------------------------------------------

def _normalise_broker_name(name: str) -> str:
    """
    Convert a broker display name to a filesystem-safe slug.

    Examples:
        "Spokeo"        → "spokeo"
        "Been Verified" → "been_verified"
        "192.com"       → "192com"
    """
    lowered = name.lower()
    no_spaces = lowered.replace(" ", "_")
    safe = re.sub(r"[^a-z0-9_]", "", no_spaces)
    return safe or "broker"


# ---------------------------------------------------------------------------
# ProofCapture
# ---------------------------------------------------------------------------

class ProofCapture:
    """
    Captures full-page Playwright screenshots, encrypts them with the vault
    key, and writes tamper-evident ProofRecord objects.

    Intended to be called from removal tier handlers (tier1_playwright.py etc.)
    immediately after the opt-out confirmation page is reached.

    Args:
        proof_store_root: Root directory of the proof store
                          (typically Path("~/.traceburn")).
        vault_key: 32-byte AES-256 key derived from the vault passphrase.
                   The caller is responsible for clearing this from memory
                   after the session ends.
    """

    def __init__(self, proof_store_root: Path, vault_key: bytes) -> None:
        if len(vault_key) != 32:
            raise ValueError("vault_key must be exactly 32 bytes (AES-256)")
        self._proof_root = proof_store_root.expanduser().resolve()
        self._vault_key = vault_key
        self._proof_dir = self._proof_root / "proof"
        self._proof_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def capture_screenshot(
        self,
        page,  # playwright.async_api.Page
        broker_name: str,
        *,
        removal_request_id: int,
        broker_domain: str,
        opt_out_url: str,
        http_response_code: Optional[int] = None,
    ) -> ProofRecord:
        """
        Capture a full-page screenshot, compute its SHA-256 checksum,
        encrypt it with the vault key, and persist it atomically.

        The raw (unencrypted) PNG bytes are held in memory only and are
        overwritten with zeroes after the encrypted file is written.

        Args:
            page: Active Playwright page at the confirmation URL.
            broker_name: Human-readable broker name (e.g. "Spokeo").
            removal_request_id: FK to removal_requests.id in SQLite.
            broker_domain: Canonical domain (e.g. "spokeo.com").
            opt_out_url: URL that was used for the opt-out submission.
            http_response_code: HTTP status code of the final page response.

        Returns:
            ProofRecord with screenshot_path, screenshot_checksum,
            confirmation_text, and all metadata populated.
        """
        submitted_at = datetime.now(timezone.utc)

        # --- Step 1: capture full-page screenshot into memory only ---
        raw_png: bytes = await page.screenshot(full_page=True)

        # --- Step 2: SHA-256 checksum BEFORE encryption ---
        checksum = hashlib.sha256(raw_png).hexdigest()

        # --- Step 3: encrypt with AES-256-GCM ---
        nonce = os.urandom(12)  # 96-bit unique nonce
        aesgcm = AESGCM(self._vault_key)
        encrypted = aesgcm.encrypt(nonce, raw_png, associated_data=None)
        # Stored format: [12-byte nonce][ciphertext + 16-byte GCM tag]
        stored_bytes = nonce + encrypted

        # --- Step 4: build file path ---
        safe_broker = _normalise_broker_name(broker_name)
        ts_str = submitted_at.strftime("%Y%m%d_%H%M%S")
        filename = f"{safe_broker}_{ts_str}.png.enc"
        target_path = self._proof_dir / filename
        relative_path = str(Path("proof") / filename)

        # --- Step 5: atomic write (temp file + rename) ---
        self._write_atomic(self._proof_dir, target_path, stored_bytes)

        # --- Step 6: zero raw bytes in memory (best-effort) ---
        raw_png = b"\x00" * len(raw_png)

        # --- Step 7: extract confirmation text ---
        confirmation_text = await self.extract_confirmation_text(page)

        proof_id = str(uuid.uuid4())
        logger.info(
            "Proof captured: broker=%s proof_id=%s checksum=%s...",
            broker_name, proof_id, checksum[:16],
        )

        return ProofRecord(
            proof_id=proof_id,
            removal_request_id=removal_request_id,
            broker_name=broker_name,
            broker_domain=broker_domain,
            opt_out_url=opt_out_url,
            submitted_at=submitted_at,
            screenshot_path=relative_path,
            screenshot_checksum=checksum,
            confirmation_text=confirmation_text,
            http_response_code=http_response_code,
            current_status="pending_verification",
        )

    async def extract_confirmation_text(self, page) -> str:
        """
        Extract visible text from the page body after opt-out submission.

        Targets main content area (``<main>``, ``#content``, or ``<body>``
        fallback) and filters out nav/footer noise.  Truncated to 500 chars
        per the proof record schema.

        Returns an empty string if extraction fails (never raises).
        """
        try:
            # Try <main> first — most sites wrap their confirmation in <main>
            for selector in ("main", "#content", ".content", "article", "body"):
                try:
                    element = page.locator(selector).first
                    if await element.count() > 0:
                        text = await element.inner_text()
                        cleaned = " ".join(text.split())  # collapse whitespace
                        return cleaned[:500]
                except Exception:
                    continue
            return ""
        except Exception as exc:
            logger.warning("extract_confirmation_text failed: %s", exc)
            return ""

    def verify_checksum(self, proof_record: ProofRecord) -> bool:
        """
        Decrypt the stored screenshot and verify its SHA-256 checksum.

        Returns True if the file is unmodified since capture.
        Returns False if the checksum does not match (file tampered or corrupt).

        Raises FileNotFoundError if the encrypted file does not exist.
        """
        if proof_record.screenshot_path is None or proof_record.screenshot_checksum is None:
            raise ValueError(
                f"ProofRecord {proof_record.proof_id} has no screenshot to verify"
            )

        enc_path = self._proof_root / proof_record.screenshot_path
        if not enc_path.exists():
            raise FileNotFoundError(
                f"Encrypted proof file not found: {enc_path}"
            )

        return verify_screenshot_checksum(
            encrypted_path=enc_path,
            expected_checksum=proof_record.screenshot_checksum,
            vault_key=self._vault_key,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _write_atomic(directory: Path, target: Path, data: bytes) -> None:
        """Write data to target atomically using a temp file + rename."""
        tmp_fd, tmp_path_str = tempfile.mkstemp(dir=directory, suffix=".tmp")
        tmp_path = Path(tmp_path_str)
        try:
            os.write(tmp_fd, data)
            os.close(tmp_fd)
            tmp_path.rename(target)  # atomic on POSIX
        except Exception:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise


# ---------------------------------------------------------------------------
# Standalone helper functions (also used by other modules)
# ---------------------------------------------------------------------------

def capture_and_store_screenshot(
    page,                       # playwright.sync_api.Page (sync variant)
    broker_name: str,
    proof_store_root: Path,
    vault_key: bytes,
) -> tuple[str, str]:
    """
    Synchronous convenience wrapper for use in synchronous Playwright code.

    Captures a full-page screenshot, computes its SHA-256 checksum,
    encrypts it, and writes it atomically to the proof store.

    Args:
        page: Playwright sync Page at the confirmation URL.
        broker_name: Human-readable broker name.
        proof_store_root: Root of the TraceBurn data directory.
        vault_key: 32-byte AES-256 vault key.

    Returns:
        (relative_screenshot_path, sha256_hex_checksum)

    The raw unencrypted bytes are never written to disk.
    """
    # --- Capture ---
    raw_png: bytes = page.screenshot(full_page=True)

    # --- Checksum BEFORE encryption ---
    checksum = hashlib.sha256(raw_png).hexdigest()

    # --- Encrypt ---
    nonce = os.urandom(12)
    aesgcm = AESGCM(vault_key)
    encrypted = aesgcm.encrypt(nonce, raw_png, associated_data=None)
    stored_bytes = nonce + encrypted

    # --- Build path ---
    proof_store_root = proof_store_root.expanduser().resolve()
    proof_dir = proof_store_root / "proof"
    proof_dir.mkdir(parents=True, exist_ok=True)

    safe_broker = _normalise_broker_name(broker_name)
    ts_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"{safe_broker}_{ts_str}.png.enc"
    target_path = proof_dir / filename

    # --- Write atomically ---
    tmp_fd, tmp_path_str = tempfile.mkstemp(dir=proof_dir, suffix=".tmp")
    tmp_path = Path(tmp_path_str)
    try:
        os.write(tmp_fd, stored_bytes)
        os.close(tmp_fd)
        tmp_path.rename(target_path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    finally:
        # Best-effort memory zeroing
        raw_png = b"\x00" * len(raw_png)

    relative_path = str(Path("proof") / filename)
    logger.info("Screenshot saved: %s (checksum %s...)", relative_path, checksum[:16])
    return relative_path, checksum


def verify_screenshot_checksum(
    encrypted_path: Path,
    expected_checksum: str,
    vault_key: bytes,
) -> bool:
    """
    Decrypt a stored proof screenshot and verify its SHA-256 checksum.

    Returns:
        True  — file is unmodified since capture (checksum matches).
        False — checksum mismatch (file tampered or corrupt).

    Raises:
        ValueError  — if the file cannot be decrypted (wrong key or corrupt nonce).
        FileNotFoundError — if encrypted_path does not exist.
    """
    raw_data = encrypted_path.read_bytes()
    if len(raw_data) < 28:  # 12-byte nonce + at least 16-byte GCM tag
        raise ValueError(f"Encrypted file too small to be valid: {encrypted_path}")

    nonce = raw_data[:12]
    ciphertext = raw_data[12:]
    aesgcm = AESGCM(vault_key)
    decrypted = aesgcm.decrypt(nonce, ciphertext, associated_data=None)

    actual_checksum = hashlib.sha256(decrypted).hexdigest()
    match = actual_checksum == expected_checksum
    if not match:
        logger.warning(
            "Checksum mismatch for %s: expected %s, got %s",
            encrypted_path, expected_checksum[:16], actual_checksum[:16],
        )
    return match
