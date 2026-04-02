"""
tests/unit/test_vault.py — Unit tests for PIIVault (src/vault.py).

Coverage:
  - encrypt/decrypt round-trip
  - authentication failure on wrong passphrase
  - store/retrieve round-trip
  - list_keys without decryption
  - rekey (old passphrase invalidated, new works)
  - per-encryption salt uniqueness
  - empty string and Unicode inputs
  - vault file created with mode 600

All tests use tmp_path — the real ~/.traceburn is never touched.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from src.vault import PIIVault, decrypt, encrypt


# ─────────────────────────────────────────────────────────────────────────────
# Low-level encrypt / decrypt helpers
# ─────────────────────────────────────────────────────────────────────────────


class TestEncryptDecrypt:
    """Unit tests for the module-level encrypt() / decrypt() helpers."""

    PASSPHRASE = "correct-horse-battery-staple"

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypting then decrypting with the same passphrase returns the original plaintext."""
        plaintext = "Hello, TraceBurn!"
        blob = encrypt(plaintext, self.PASSPHRASE)
        result = decrypt(blob, self.PASSPHRASE)
        assert result == plaintext

    def test_wrong_passphrase_fails(self):
        """Decryption with a wrong passphrase raises ValueError (GCM auth failure)."""
        blob = encrypt("sensitive data", self.PASSPHRASE)
        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt(blob, "this-is-the-wrong-passphrase")

    def test_different_salts(self):
        """Two encryptions of the same plaintext produce different ciphertext blobs."""
        plaintext = "same plaintext"
        blob1 = encrypt(plaintext, self.PASSPHRASE)
        blob2 = encrypt(plaintext, self.PASSPHRASE)
        # Different random salt+nonce each time
        assert blob1 != blob2
        # But both decrypt correctly
        assert decrypt(blob1, self.PASSPHRASE) == plaintext
        assert decrypt(blob2, self.PASSPHRASE) == plaintext

    def test_empty_string(self):
        """Encrypting and decrypting an empty string works without error."""
        blob = encrypt("", self.PASSPHRASE)
        result = decrypt(blob, self.PASSPHRASE)
        assert result == ""

    def test_unicode(self):
        """Encrypting and decrypting Unicode characters (accented names, emoji) works."""
        unicode_text = "Héloïse Müller — résumé naïve café"
        blob = encrypt(unicode_text, self.PASSPHRASE)
        result = decrypt(blob, self.PASSPHRASE)
        assert result == unicode_text

    def test_blob_too_short_raises(self):
        """Decrypting a truncated blob raises ValueError without crashing."""
        with pytest.raises(ValueError, match="too short"):
            decrypt(b"\x00" * 10, self.PASSPHRASE)


# ─────────────────────────────────────────────────────────────────────────────
# PIIVault
# ─────────────────────────────────────────────────────────────────────────────


PASSPHRASE = "v@ult-p4ssphrase!"
NEW_PASSPHRASE = "n3w-v@ult-p4ssphrase!"


class TestPIIVault:
    """Tests for PIIVault file-backed key/value store."""

    def test_store_and_retrieve(self, tmp_path):
        """store() followed by retrieve() returns the exact original value."""
        vault = PIIVault(vault_path=tmp_path / "vault.enc")
        vault.store("full_name", "Jane Doe", passphrase=PASSPHRASE)
        result = vault.retrieve("full_name", passphrase=PASSPHRASE)
        assert result == "Jane Doe"

    def test_wrong_passphrase_fails(self, tmp_path):
        """retrieve() with the wrong passphrase raises ValueError."""
        vault = PIIVault(vault_path=tmp_path / "vault.enc")
        vault.store("email", "jane@example.com", passphrase=PASSPHRASE)
        with pytest.raises(ValueError):
            vault.retrieve("email", passphrase="definitely-wrong")

    def test_list_keys(self, tmp_path):
        """list_keys() returns stored key names without requiring decryption."""
        vault = PIIVault(vault_path=tmp_path / "vault.enc")
        vault.store("full_name", "Jane Doe", passphrase=PASSPHRASE)
        vault.store("email", "jane@example.com", passphrase=PASSPHRASE)
        vault.store("phone", "6195550000", passphrase=PASSPHRASE)
        keys = vault.list_keys()
        assert set(keys) == {"full_name", "email", "phone"}

    def test_list_keys_empty_vault(self, tmp_path):
        """list_keys() on a vault with no entries returns an empty list."""
        vault = PIIVault(vault_path=tmp_path / "vault.enc")
        assert vault.list_keys() == []

    def test_rekey(self, tmp_path):
        """
        rekey() re-encrypts all entries with a new passphrase.

        After rekeying:
          - Old passphrase raises ValueError.
          - New passphrase decrypts successfully.
        """
        vault = PIIVault(vault_path=tmp_path / "vault.enc")
        vault.store("full_name", "Jane Doe", passphrase=PASSPHRASE)
        vault.store("city", "Springfield", passphrase=PASSPHRASE)

        vault.rekey(old_passphrase=PASSPHRASE, new_passphrase=NEW_PASSPHRASE)

        # Old passphrase must now fail
        with pytest.raises(ValueError):
            vault.retrieve("full_name", passphrase=PASSPHRASE)

        # New passphrase must succeed and return original values
        assert vault.retrieve("full_name", passphrase=NEW_PASSPHRASE) == "Jane Doe"
        assert vault.retrieve("city", passphrase=NEW_PASSPHRASE) == "Springfield"

    def test_rekey_wrong_old_passphrase_leaves_vault_unchanged(self, tmp_path):
        """rekey() with wrong old passphrase raises ValueError and leaves vault intact."""
        vault = PIIVault(vault_path=tmp_path / "vault.enc")
        vault.store("full_name", "Jane Doe", passphrase=PASSPHRASE)

        with pytest.raises(ValueError):
            vault.rekey(old_passphrase="wrong!", new_passphrase=NEW_PASSPHRASE)

        # Vault should still be decryptable with the original passphrase
        assert vault.retrieve("full_name", passphrase=PASSPHRASE) == "Jane Doe"

    def test_different_salts(self, tmp_path):
        """Two store() calls for the same value produce different ciphertext on disk."""
        vault = PIIVault(vault_path=tmp_path / "vault.enc")
        vault.store("field", "same value", passphrase=PASSPHRASE)
        raw1 = vault._load_raw()["field"]

        vault.store("field", "same value", passphrase=PASSPHRASE)
        raw2 = vault._load_raw()["field"]

        # Each encryption uses a fresh random salt+nonce
        assert raw1 != raw2
        # But both decrypt to the same plaintext
        assert vault.retrieve("field", passphrase=PASSPHRASE) == "same value"

    def test_empty_string(self, tmp_path):
        """Storing and retrieving an empty string value works without error."""
        vault = PIIVault(vault_path=tmp_path / "vault.enc")
        vault.store("empty_key", "", passphrase=PASSPHRASE)
        result = vault.retrieve("empty_key", passphrase=PASSPHRASE)
        assert result == ""

    def test_unicode(self, tmp_path):
        """Storing and retrieving a Unicode value (accented characters) works."""
        vault = PIIVault(vault_path=tmp_path / "vault.enc")
        unicode_name = "Ångström Héloïse Müller"
        vault.store("full_name", unicode_name, passphrase=PASSPHRASE)
        result = vault.retrieve("full_name", passphrase=PASSPHRASE)
        assert result == unicode_name

    def test_vault_file_permissions(self, tmp_path):
        """Vault file is created with mode 0o600 (owner read/write only)."""
        vault_path = tmp_path / "vault.enc"
        vault = PIIVault(vault_path=vault_path)
        vault.store("test", "value", passphrase=PASSPHRASE)

        mode = stat.S_IMODE(os.stat(vault_path).st_mode)
        assert mode == 0o600, (
            f"Expected vault permissions 600, got {oct(mode)}"
        )

    def test_retrieve_missing_key_raises_key_error(self, tmp_path):
        """retrieve() raises KeyError when the requested key does not exist."""
        vault = PIIVault(vault_path=tmp_path / "vault.enc")
        with pytest.raises(KeyError, match="not_a_real_key"):
            vault.retrieve("not_a_real_key", passphrase=PASSPHRASE)

    def test_multiple_keys_independent(self, tmp_path):
        """Multiple keys stored with the same passphrase are independently retrievable."""
        vault = PIIVault(vault_path=tmp_path / "vault.enc")
        data = {
            "full_name": "Jane Doe",
            "email": "jane@example.com",
            "phone": "5550001234",
            "city": "Springfield",
        }
        for key, value in data.items():
            vault.store(key, value, passphrase=PASSPHRASE)

        for key, expected in data.items():
            assert vault.retrieve(key, passphrase=PASSPHRASE) == expected
