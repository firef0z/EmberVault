"""Unit tests for AES-256-GCM envelope encryption and KeyRing."""

from __future__ import annotations

import base64
import os
import secrets

import pytest
from pydantic import SecretStr

from embervault_common.security.crypto import (
    CURRENT_ENVELOPE_VERSION,
    CryptoError,
    DecryptionError,
    InvalidEnvelopeError,
    InvalidKeyError,
    KeyNotFoundError,
    KeyRing,
    decrypt_blob,
    decrypt_blob_to_str,
    derive_or_normalize_key,
    encrypt_blob,
    get_default_key_ring,
    set_default_key_ring,
)


class TestKeyDerivationAndNormalization:
    """Tests for key derivation and normalization."""

    def test_32_byte_raw(self) -> None:
        raw = os.urandom(32)
        key = derive_or_normalize_key(raw)
        assert key == raw
        assert len(key) == 32

    def test_64_char_hex_string(self) -> None:
        raw_bytes = os.urandom(32)
        hex_str = raw_bytes.hex()
        key = derive_or_normalize_key(hex_str)
        assert key == raw_bytes
        assert len(key) == 32

    def test_base64_encoded_key(self) -> None:
        raw_bytes = os.urandom(32)
        b64_str = base64.b64encode(raw_bytes).decode("ascii")
        key = derive_or_normalize_key(b64_str)
        assert key == raw_bytes

    def test_32_char_ascii_string(self) -> None:
        ascii_32 = "0123456789abcdef0123456789abcdef"
        assert len(ascii_32) == 32
        key = derive_or_normalize_key(ascii_32)
        # Note: 32 chars of hex might be interpreted or normalized; here length is 32 chars
        assert len(key) == 32

    def test_secret_str_wrapping(self) -> None:
        raw_hex = secrets.token_hex(32)
        sec = SecretStr(raw_hex)
        key = derive_or_normalize_key(sec)
        assert len(key) == 32
        assert key == bytes.fromhex(raw_hex)

    def test_passphrase_hkdf_derivation(self) -> None:
        passphrase = "my-super-secret-secure-passphrase-at-least-16-chars"
        key1 = derive_or_normalize_key(passphrase)
        key2 = derive_or_normalize_key(passphrase)
        assert len(key1) == 32
        assert key1 == key2  # Deterministic derivation
        # Different passphrase yields different key
        diff_key = derive_or_normalize_key(passphrase + "-different")
        assert key1 != diff_key

    def test_short_passphrase_rejected(self) -> None:
        with pytest.raises(InvalidKeyError, match="at least 16 bytes"):
            derive_or_normalize_key("too-short")

    def test_invalid_type_rejected(self) -> None:
        with pytest.raises(InvalidKeyError, match="Unsupported key type"):
            derive_or_normalize_key(12345)  # type: ignore[arg-type]


class TestKeyRing:
    """Tests for KeyRing management and secret safety."""

    def test_keyring_lifecycle(self) -> None:
        key_v1 = secrets.token_bytes(32)
        key_v2 = secrets.token_bytes(32)

        ring = KeyRing(keys={"v1": key_v1}, primary_key_id="v1")
        assert ring.primary_key_id == "v1"
        assert ring.available_key_ids == ["v1"]
        assert len(ring) == 1
        assert "v1" in ring
        assert "v2" not in ring

        ring.add_key("v2", key_v2, is_primary=True)
        assert ring.primary_key_id == "v2"
        assert ring.available_key_ids == ["v1", "v2"]
        assert len(ring) == 2
        assert ring.get_key("v1") == key_v1
        assert ring.get_key("v2") == key_v2

    def test_keyring_switch_primary(self) -> None:
        ring = KeyRing(keys={"k1": secrets.token_bytes(32), "k2": secrets.token_bytes(32)})
        ring.set_primary_key_id("k2")
        assert ring.primary_key_id == "k2"

        with pytest.raises(KeyNotFoundError, match="unknown key_id"):
            ring.set_primary_key_id("k_nonexistent")

    def test_missing_key_raises(self) -> None:
        ring = KeyRing()
        with pytest.raises(KeyNotFoundError, match="No primary encryption key configured"):
            ring.get_primary_key()

        with pytest.raises(KeyNotFoundError, match="not found in KeyRing"):
            ring.get_key("v99")

    def test_invalid_key_id(self) -> None:
        ring = KeyRing()
        with pytest.raises(InvalidKeyError, match="cannot be empty"):
            ring.add_key("", secrets.token_bytes(32))

        with pytest.raises(InvalidKeyError, match="cannot exceed 255 bytes"):
            ring.add_key("x" * 256, secrets.token_bytes(32))

    def test_repr_and_str_do_not_leak_secrets(self) -> None:
        secret_canary = "SUPER_SECRET_CANARY_TEST_KEY_VALUE_12345678"
        ring = KeyRing(keys={"test_key": secret_canary})

        repr_str = repr(ring)
        str_val = str(ring)

        assert secret_canary not in repr_str
        assert secret_canary not in str_val
        assert "KeyRing" in repr_str
        assert "test_key" in repr_str


class TestEnvelopeEncryption:
    """Tests for AES-256-GCM envelope encryption and decryption."""

    @pytest.fixture
    def test_keyring(self) -> KeyRing:
        return KeyRing(keys={"v1": secrets.token_bytes(32)}, primary_key_id="v1")

    def test_roundtrip_bytes(self, test_keyring: KeyRing) -> None:
        plaintext = b"Hello, EmberVault Secure Storage!"
        blob = encrypt_blob(plaintext, key_ring=test_keyring, aad="remote:1:v1")
        assert isinstance(blob, bytes)
        assert len(blob) > len(plaintext)
        assert blob[0] == CURRENT_ENVELOPE_VERSION

        decrypted = decrypt_blob(blob, key_ring=test_keyring, aad="remote:1:v1")
        assert decrypted == plaintext

    def test_roundtrip_string_and_decrypt_to_str(self, test_keyring: KeyRing) -> None:
        plaintext = "EmberVault credenziali: password=super-secret-123 & üñîçødé 🚀"
        blob = encrypt_blob(plaintext, key_ring=test_keyring, aad="aad-unicode")
        decrypted_str = decrypt_blob_to_str(blob, key_ring=test_keyring, aad="aad-unicode")
        assert decrypted_str == plaintext

    def test_roundtrip_empty_data(self, test_keyring: KeyRing) -> None:
        blob = encrypt_blob(b"", key_ring=test_keyring)
        decrypted = decrypt_blob(blob, key_ring=test_keyring)
        assert decrypted == b""

    def test_roundtrip_large_payload(self, test_keyring: KeyRing) -> None:
        large_payload = os.urandom(256 * 1024)  # 256 KB
        blob = encrypt_blob(large_payload, key_ring=test_keyring, aad=b"large-data")
        decrypted = decrypt_blob(blob, key_ring=test_keyring, aad=b"large-data")
        assert decrypted == large_payload

    def test_nonce_uniqueness(self, test_keyring: KeyRing) -> None:
        payload = b"constant-plaintext"
        blob1 = encrypt_blob(payload, key_ring=test_keyring)
        blob2 = encrypt_blob(payload, key_ring=test_keyring)
        assert blob1 != blob2  # Nonce differs, producing completely different ciphertexts

    def test_aad_tampering_fails(self, test_keyring: KeyRing) -> None:
        blob = encrypt_blob(b"secret", key_ring=test_keyring, aad="remote_42:v1")
        # Matching AAD works
        assert decrypt_blob(blob, key_ring=test_keyring, aad="remote_42:v1") == b"secret"

        # Tampered AAD fails with DecryptionError
        with pytest.raises(DecryptionError, match="Authentication failed"):
            decrypt_blob(blob, key_ring=test_keyring, aad="remote_99:v1")

        # Missing AAD fails
        with pytest.raises(DecryptionError, match="Authentication failed"):
            decrypt_blob(blob, key_ring=test_keyring, aad="")

    def test_ciphertext_tampering_fails(self, test_keyring: KeyRing) -> None:
        blob = bytearray(encrypt_blob(b"sensitive content", key_ring=test_keyring))
        # Flip a bit in the ciphertext payload
        blob[-5] ^= 0x01

        with pytest.raises(DecryptionError, match="Authentication failed"):
            decrypt_blob(bytes(blob), key_ring=test_keyring)

    def test_nonce_tampering_fails(self, test_keyring: KeyRing) -> None:
        blob = bytearray(encrypt_blob(b"sensitive content", key_ring=test_keyring))
        # Nonce is at offset 2 + len("v1") = 4 .. 16
        blob[5] ^= 0xFF

        with pytest.raises(DecryptionError, match="Authentication failed"):
            decrypt_blob(bytes(blob), key_ring=test_keyring)

    def test_unsupported_version_fails(self, test_keyring: KeyRing) -> None:
        blob = bytearray(encrypt_blob(b"data", key_ring=test_keyring))
        blob[0] = 0x99  # Invalid version

        with pytest.raises(InvalidEnvelopeError, match="Unsupported envelope version"):
            decrypt_blob(bytes(blob), key_ring=test_keyring)

    def test_truncated_blob_fails(self, test_keyring: KeyRing) -> None:
        blob = encrypt_blob(b"data", key_ring=test_keyring)
        short_blob = blob[:10]

        with pytest.raises(InvalidEnvelopeError, match="shorter than minimum"):
            decrypt_blob(short_blob, key_ring=test_keyring)

    def test_key_rotation(self) -> None:
        key_v1 = secrets.token_bytes(32)
        key_v2 = secrets.token_bytes(32)

        # Encrypt with v1
        ring_v1 = KeyRing(keys={"v1": key_v1}, primary_key_id="v1")
        blob = encrypt_blob(b"payload-from-v1", key_ring=ring_v1)

        # Multi-key ring with v2 as primary, v1 retained
        ring_v2 = KeyRing(keys={"v1": key_v1, "v2": key_v2}, primary_key_id="v2")

        # Can decrypt old v1 blob
        assert decrypt_blob(blob, key_ring=ring_v2) == b"payload-from-v1"

        # New encryption uses v2
        new_blob = encrypt_blob(b"payload-from-v2", key_ring=ring_v2)
        assert decrypt_blob(new_blob, key_ring=ring_v2) == b"payload-from-v2"

        # Ring without v1 cannot decrypt old blob
        ring_v2_only = KeyRing(keys={"v2": key_v2}, primary_key_id="v2")
        with pytest.raises(KeyNotFoundError, match="Key 'v1' not found"):
            decrypt_blob(blob, key_ring=ring_v2_only)

    def test_global_keyring_fallback(self) -> None:
        ring = KeyRing(keys={"global": secrets.token_bytes(32)}, primary_key_id="global")
        set_default_key_ring(ring)
        assert get_default_key_ring() is ring

        blob = encrypt_blob(b"global-test")
        assert decrypt_blob(blob) == b"global-test"

    def test_invalid_plaintext_type(self) -> None:
        with pytest.raises(CryptoError, match="Plaintext must be bytes or str"):
            encrypt_blob(12345)  # type: ignore[arg-type]
