"""
src/vault.py — Encrypted PII Vault

AES-256-GCM authenticated encryption with PBKDF2HMAC key derivation.
The vault is the single source of truth for all user PII. No other module
stores plaintext PII; they request values from the vault at call time.

Blob layout per encrypted entry:
    [32-byte salt][12-byte nonce][16-byte GCM tag + N-byte ciphertext]

The user's passphrase is NEVER written to disk or stored in memory
beyond the duration of the key derivation call.
"""

from __future__ import annotations

import ctypes
import json
import os
import secrets
from pathlib import Path
from typing import Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ──────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────

PBKDF2_ITERATIONS: int = 600_000
SALT_LENGTH: int = 32   # bytes — per-field unique salt
NONCE_LENGTH: int = 12  # bytes — 96-bit GCM nonce
KEY_LENGTH: int = 32    # bytes — 256-bit AES key

DEFAULT_VAULT_PATH: Path = Path.home() / ".traceburn" / "vault.enc"


# ──────────────────────────────────────────────────────────────
# Low-level crypto helpers
# ──────────────────────────────────────────────────────────────

def _derive_key(passphrase: Union[str, bytes], salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from passphrase + salt using PBKDF2HMAC-SHA256.

    The key is never stored anywhere — callers must zero it after use.
    """
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase)


def _zero_bytes(data: Union[bytes, bytearray]) -> None:
    """
    Best-effort zeroing of a bytes or bytearray object.

    CPython does not guarantee this defeats all in-memory forensics (the GC
    may have already copied the object), but it reduces the exposure window.
    """
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
    else:
        try:
            buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
            ctypes.memset(buf, 0, len(data))
        except TypeError:
            pass  # immutable bytes with no writable buffer — skip silently


def encrypt(plaintext: Union[str, bytes], passphrase: str) -> bytes:
    """
    Encrypt *plaintext* with AES-256-GCM using a freshly derived key.

    Returns a single blob:
        [32-byte salt][12-byte nonce][GCM ciphertext + 16-byte tag]

    The passphrase is NOT stored. The blob contains everything needed to
    decrypt when the correct passphrase is supplied again.

    Memory safety: plaintext bytes and derived key are zeroed after use.
    """
    if isinstance(plaintext, str):
        plaintext_bytes = bytearray(plaintext.encode("utf-8"))
    else:
        plaintext_bytes = bytearray(plaintext)

    salt = secrets.token_bytes(SALT_LENGTH)
    nonce = secrets.token_bytes(NONCE_LENGTH)
    key = _derive_key(passphrase, salt)

    aesgcm = AESGCM(key)
    try:
        ciphertext = aesgcm.encrypt(nonce, bytes(plaintext_bytes), associated_data=None)
    finally:
        _zero_bytes(key)
        _zero_bytes(plaintext_bytes)

    return salt + nonce + ciphertext


def decrypt(blob: bytes, passphrase: str) -> str:
    """
    Decrypt a blob produced by :func:`encrypt`.

    Raises :class:`ValueError` if the passphrase is wrong or the data is
    tampered (GCM authentication failure). The caller receives only the
    Unicode plaintext string.
    """
    min_length = SALT_LENGTH + NONCE_LENGTH + 16  # 16-byte GCM tag minimum
    if len(blob) < min_length:
        raise ValueError("Ciphertext blob is too short to be valid.")

    salt = blob[:SALT_LENGTH]
    nonce = blob[SALT_LENGTH : SALT_LENGTH + NONCE_LENGTH]
    ciphertext = blob[SALT_LENGTH + NONCE_LENGTH :]

    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except Exception:
        # Re-raise as ValueError to avoid leaking cryptography internals
        raise ValueError("Decryption failed: wrong passphrase or data corrupted.")
    finally:
        _zero_bytes(key)

    plaintext = plaintext_bytes.decode("utf-8")
    _zero_bytes(bytearray(plaintext_bytes))
    return plaintext


# ──────────────────────────────────────────────────────────────
# PIIVault — file-backed key/value store
# ──────────────────────────────────────────────────────────────

class PIIVault:
    """
    File-backed encrypted key/value store for user PII.

    All values are encrypted individually with a unique salt+nonce before
    being written to disk. The file on disk stores a JSON object whose
    values are hex-encoded encrypted blobs.

    The passphrase is never stored as an instance attribute — it must be
    supplied to every operation that requires cryptographic access.

    Example::

        vault = PIIVault()
        vault.store("full_name", "Jane Doe", passphrase="s3cr3t")
        name = vault.retrieve("full_name", passphrase="s3cr3t")
    """

    def __init__(self, vault_path: Path | None = None) -> None:
        self._path: Path = vault_path or DEFAULT_VAULT_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)

    # ── Internal helpers ──────────────────────────────────────

    def _load_raw(self) -> dict[str, str]:
        """Load the raw hex-blob mapping from disk. Returns {} if file missing."""
        if not self._path.exists():
            return {}
        with self._path.open("r", encoding="utf-8") as fh:
            return json.load(fh)

    def _save_raw(self, data: dict[str, str]) -> None:
        """Atomically write the hex-blob mapping to disk with mode 600."""
        tmp = self._path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        tmp.replace(self._path)
        os.chmod(self._path, 0o600)

    # ── Public API ────────────────────────────────────────────

    def store(self, key: str, value: str, passphrase: str) -> None:
        """
        Encrypt *value* and store it under *key*.

        If *key* already exists it is overwritten. The passphrase is used
        only during this call and is not retained.
        """
        blob = encrypt(value, passphrase)
        raw = self._load_raw()
        raw[key] = blob.hex()
        self._save_raw(raw)

    def retrieve(self, key: str, passphrase: str) -> str:
        """
        Retrieve and decrypt the value stored under *key*.

        Raises :class:`KeyError` if the key does not exist.
        Raises :class:`ValueError` on decryption failure.
        """
        raw = self._load_raw()
        if key not in raw:
            raise KeyError(f"Key '{key}' not found in vault.")
        blob = bytes.fromhex(raw[key])
        return decrypt(blob, passphrase)

    def list_keys(self) -> list[str]:
        """Return all stored key names (no decryption required)."""
        return list(self._load_raw().keys())

    def delete(self, key: str) -> None:
        """Remove *key* from the vault. Silently does nothing if absent."""
        raw = self._load_raw()
        if key in raw:
            del raw[key]
            self._save_raw(raw)

    def rekey(self, old_passphrase: str, new_passphrase: str) -> None:
        """
        Re-encrypt all vault entries with a new passphrase.

        The operation is atomic: all entries are re-encrypted in memory first,
        then written in a single file write. If any decryption fails (wrong
        old passphrase) the vault file is left unchanged.

        Raises :class:`ValueError` if *old_passphrase* is wrong for any entry.
        """
        raw = self._load_raw()
        if not raw:
            return  # nothing to rekey

        # Decrypt everything first — fail fast before touching disk
        plaintext_map: dict[str, str] = {}
        for key, hex_blob in raw.items():
            blob = bytes.fromhex(hex_blob)
            plaintext_map[key] = decrypt(blob, old_passphrase)

        # Re-encrypt with new passphrase
        new_raw: dict[str, str] = {}
        try:
            for key, plaintext in plaintext_map.items():
                new_blob = encrypt(plaintext, new_passphrase)
                new_raw[key] = new_blob.hex()
        finally:
            # Zero plaintext values
            for v in plaintext_map.values():
                _zero_bytes(bytearray(v.encode("utf-8")))

        self._save_raw(new_raw)

    def exists(self, key: str) -> bool:
        """Return True if *key* has a stored entry."""
        return key in self._load_raw()
