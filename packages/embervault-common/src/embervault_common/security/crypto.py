"""Envelope encryption and cryptographic key management for EmberVault.

Implements versioned AES-256-GCM envelope encryption with key identifiers (key_id),
Associated Authenticated Data (AAD) binding, and key ring support for seamless key rotation.
"""

from __future__ import annotations

import base64
import os
import struct
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import SecretStr

if TYPE_CHECKING:
    pass

# Current binary envelope format version:
# Format: [1 byte version][1 byte key_id_len][N bytes key_id][12 bytes nonce][C bytes ciphertext + tag]
CURRENT_ENVELOPE_VERSION: int = 1
NONCE_LENGTH_BYTES: int = 12
TAG_LENGTH_BYTES: int = 16
AES_256_KEY_LENGTH: int = 32
MIN_ENVELOPE_LENGTH: int = 1 + 1 + 1 + NONCE_LENGTH_BYTES + TAG_LENGTH_BYTES

# Application-level salt for passphrase-based master key derivation
_DEFAULT_KDF_SALT: bytes = b"embervault-master-key-salt-v1"
_DEFAULT_KDF_INFO: bytes = b"embervault-aes256-master-key"


class CryptoError(Exception):
    """Base exception for all cryptographic errors in EmberVault."""


class DecryptionError(CryptoError):
    """Raised when ciphertext decryption or authentication tag verification fails."""


class InvalidEnvelopeError(DecryptionError):
    """Raised when an encrypted blob envelope is malformed or has an unsupported version."""


class KeyNotFoundError(CryptoError):
    """Raised when the key_id requested by an encrypted envelope is not present in the KeyRing."""


class InvalidKeyError(CryptoError):
    """Raised when a cryptographic key is invalid, improperly formatted, or has incorrect length."""


def derive_or_normalize_key(raw_key: bytes | str | SecretStr) -> bytes:
    """Normalize or derive a 32-byte (256-bit) AES key from various input representations.

    Supports:
    - 32-byte raw bytes
    - 64-character hexadecimal string
    - 44-character Base64 string decoding to 32 bytes
    - Exactly 32-byte UTF-8 string
    - Passphrase (minimum 16 chars): derived into a 32-byte key via HKDF-SHA256

    Args:
        raw_key: Key data as bytes, string, or SecretStr.

    Returns:
        32-byte key for AES-256.

    Raises:
        InvalidKeyError: If the input cannot be converted into a valid 32-byte key.
    """
    unwrapped: bytes | str = (
        raw_key.get_secret_value() if isinstance(raw_key, SecretStr) else raw_key
    )

    secret_val: bytes
    if isinstance(unwrapped, str):
        cleaned = unwrapped.strip()
        # Check if 64-character hexadecimal representation
        if len(cleaned) == 64:
            try:
                decoded = bytes.fromhex(cleaned)
                if len(decoded) == AES_256_KEY_LENGTH:
                    return decoded
            except ValueError:
                pass

        # Check if Base64 representation of 32 bytes
        if len(cleaned) in (43, 44):
            try:
                decoded = base64.b64decode(cleaned)
                if len(decoded) == AES_256_KEY_LENGTH:
                    return decoded
            except Exception:
                pass

        secret_val = cleaned.encode("utf-8")
    elif isinstance(unwrapped, bytes):
        if len(unwrapped) == AES_256_KEY_LENGTH:
            return unwrapped
        secret_val = unwrapped
    else:
        raise InvalidKeyError(f"Unsupported key type: {type(unwrapped).__name__}")

    # If raw bytes are exactly 32 bytes
    if len(secret_val) == AES_256_KEY_LENGTH:
        return secret_val

    # If shorter than 16 bytes, reject as insufficient entropy
    if len(secret_val) < 16:
        raise InvalidKeyError(
            f"Key must be at least 16 bytes for passphrase derivation (got {len(secret_val)})."
        )

    # Derive 32-byte key using HKDF-SHA256
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_256_KEY_LENGTH,
        salt=_DEFAULT_KDF_SALT,
        info=_DEFAULT_KDF_INFO,
    )
    return hkdf.derive(secret_val)


class KeyRing:
    """Manages master encryption keys with key identification and rotation support.

    The KeyRing holds one primary key (used for new encryptions) and zero or more
    historical keys (used for decrypting payloads encrypted with earlier key versions).

    All key material is stored safely and never exposed in __repr__ or __str__.
    """

    def __init__(
        self,
        keys: dict[str, bytes | str | SecretStr] | None = None,
        primary_key_id: str = "v1",
    ) -> None:
        """Initialize the KeyRing.

        Args:
            keys: Mapping of key_id -> key material.
            primary_key_id: Identifier of the primary key used for encryption.
        """
        self._keys: dict[str, bytes] = {}
        self._primary_key_id = primary_key_id

        if keys:
            for k_id, k_val in keys.items():
                self.add_key(k_id, k_val, is_primary=(k_id == primary_key_id))

        if primary_key_id not in self._keys and keys:
            # If primary_key_id was not in keys, default to the first key
            first_key_id = next(iter(self._keys.keys()))
            self._primary_key_id = first_key_id

    @property
    def primary_key_id(self) -> str:
        """Return the current primary key identifier."""
        return self._primary_key_id

    @property
    def available_key_ids(self) -> list[str]:
        """Return a sorted list of registered key identifiers."""
        return sorted(self._keys.keys())

    def add_key(self, key_id: str, key: bytes | str | SecretStr, is_primary: bool = False) -> None:
        """Register a key in the ring.

        Args:
            key_id: Unique string identifier for the key (1-255 characters).
            key: Raw bytes, hex string, base64 string, or passphrase.
            is_primary: Whether this key should become the primary encryption key.
        """
        clean_id = key_id.strip()
        if not clean_id:
            raise InvalidKeyError("key_id cannot be empty.")
        if len(clean_id.encode("utf-8")) > 255:
            raise InvalidKeyError("key_id UTF-8 length cannot exceed 255 bytes.")

        normalized_key = derive_or_normalize_key(key)
        self._keys[clean_id] = normalized_key

        if is_primary or not self._keys:
            self._primary_key_id = clean_id

    def set_primary_key_id(self, key_id: str) -> None:
        """Switch the primary key used for new encryptions."""
        if key_id not in self._keys:
            raise KeyNotFoundError(f"Cannot set unknown key_id '{key_id}' as primary.")
        self._primary_key_id = key_id

    def has_key(self, key_id: str) -> bool:
        """Return True if the key_id is registered in this ring."""
        return key_id.strip() in self._keys

    def __contains__(self, key_id: str) -> bool:
        return self.has_key(key_id)

    def get_key(self, key_id: str) -> bytes:
        """Retrieve key bytes for a given key_id.

        Args:
            key_id: Key identifier to fetch.

        Returns:
            32-byte key.

        Raises:
            KeyNotFoundError: If the key_id is not in this ring.
        """
        if key_id not in self._keys:
            raise KeyNotFoundError(
                f"Key '{key_id}' not found in KeyRing. Available keys: {self.available_key_ids}"
            )
        return self._keys[key_id]

    def get_primary_key(self) -> tuple[str, bytes]:
        """Return tuple of (primary_key_id, 32-byte key).

        Raises:
            KeyNotFoundError: If the primary key is not configured.
        """
        if not self._keys or self._primary_key_id not in self._keys:
            raise KeyNotFoundError("No primary encryption key configured in KeyRing.")
        return self._primary_key_id, self._keys[self._primary_key_id]

    def __len__(self) -> int:
        return len(self._keys)

    def __repr__(self) -> str:
        return (
            f"KeyRing(primary_key_id={self._primary_key_id!r}, key_ids={self.available_key_ids!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


# Process-wide default KeyRing
_GLOBAL_KEY_RING: KeyRing | None = None


def get_default_key_ring(force_reload: bool = False) -> KeyRing:
    """Retrieve the process-wide default KeyRing."""
    global _GLOBAL_KEY_RING
    if _GLOBAL_KEY_RING is None or force_reload:
        # Attempt to initialize from SecuritySettings
        from embervault_common.config.models import SecuritySettings

        sec_settings = SecuritySettings()
        ring = KeyRing(primary_key_id=sec_settings.master_key_id)
        if sec_settings.master_key is not None:
            ring.add_key(
                sec_settings.master_key_id,
                sec_settings.master_key,
                is_primary=True,
            )

        # Also parse secondary / historical keys from EMBERVAULT_MASTER_KEYS ("id1:key1,id2:key2")
        if sec_settings.master_keys is not None:
            raw_multi = sec_settings.master_keys.get_secret_value().strip()
            for pair in raw_multi.split(","):
                pair = pair.strip()
                if not pair:
                    continue
                if ":" in pair:
                    k_id, k_val = pair.split(":", 1)
                    k_id = k_id.strip()
                    k_val = k_val.strip()
                    if k_id and k_val and k_id not in ring:
                        ring.add_key(k_id, k_val, is_primary=(k_id == sec_settings.master_key_id))

        _GLOBAL_KEY_RING = ring
    return _GLOBAL_KEY_RING


def set_default_key_ring(key_ring: KeyRing) -> None:
    """Set the process-wide default KeyRing."""
    global _GLOBAL_KEY_RING
    _GLOBAL_KEY_RING = key_ring


def encrypt_blob(
    plaintext: bytes | str,
    key_ring: KeyRing | None = None,
    key_id: str | None = None,
    aad: bytes | str = b"",
) -> bytes:
    """Encrypt data using AES-256-GCM with versioned envelope and AAD binding.

    Envelope binary layout:
    - Byte 0: Envelope version (0x01)
    - Byte 1: key_id length in bytes (K)
    - Bytes 2 .. 2+K-1: key_id string in UTF-8
    - Bytes 2+K .. 2+K+11: 12-byte random nonce
    - Bytes 2+K+12 .. end: Ciphertext + 16-byte authentication tag

    Args:
        plaintext: The data to encrypt (bytes or UTF-8 str).
        key_ring: KeyRing to fetch encryption key from. Defaults to global KeyRing.
        key_id: Specific key_id to use. If None, uses the primary key of the KeyRing.
        aad: Associated Authenticated Data. Must match on decryption.

    Returns:
        Encrypted blob bytes.

    Raises:
        KeyNotFoundError: If the key_id is not found in the KeyRing.
        CryptoError: On encryption failure.
    """
    if isinstance(plaintext, str):
        data_bytes = plaintext.encode("utf-8")
    elif isinstance(plaintext, bytes):
        data_bytes = plaintext
    else:
        raise CryptoError(f"Plaintext must be bytes or str, got {type(plaintext).__name__}")

    aad_bytes = aad.encode("utf-8") if isinstance(aad, str) else aad

    ring = key_ring if key_ring is not None else get_default_key_ring()
    if key_id is not None:
        key_bytes = ring.get_key(key_id)
        chosen_key_id = key_id
    else:
        chosen_key_id, key_bytes = ring.get_primary_key()

    key_id_bytes = chosen_key_id.encode("utf-8")
    if len(key_id_bytes) > 255:
        raise InvalidKeyError("key_id UTF-8 length exceeds 255 bytes.")

    nonce = os.urandom(NONCE_LENGTH_BYTES)
    aesgcm = AESGCM(key_bytes)

    try:
        ciphertext_and_tag = aesgcm.encrypt(nonce, data_bytes, aad_bytes)
    except Exception as exc:
        raise CryptoError(f"AES-GCM encryption failed: {exc}") from exc

    # Pack envelope: [version: 1B][key_id_len: 1B][key_id][nonce: 12B][ciphertext+tag]
    header = struct.pack("!BB", CURRENT_ENVELOPE_VERSION, len(key_id_bytes))
    return header + key_id_bytes + nonce + ciphertext_and_tag


def decrypt_blob(
    blob: bytes,
    key_ring: KeyRing | None = None,
    aad: bytes | str = b"",
) -> bytes:
    """Decrypt an AES-256-GCM versioned envelope blob.

    Verifies version byte, extracts key_id, fetches corresponding key from KeyRing,
    and authenticates ciphertext, nonce, and AAD.

    Args:
        blob: Encrypted blob bytes.
        key_ring: KeyRing to fetch decryption keys from. Defaults to global KeyRing.
        aad: Associated Authenticated Data. Must match AAD provided during encryption.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        InvalidEnvelopeError: If the envelope is corrupted, truncated, or has an unsupported version.
        KeyNotFoundError: If the key_id stored in the envelope is not in the KeyRing.
        DecryptionError: If ciphertext, tag, nonce, or AAD has been tampered with.
    """
    if not isinstance(blob, bytes):
        raise InvalidEnvelopeError(f"Ciphertext blob must be bytes, got {type(blob).__name__}")

    if len(blob) < MIN_ENVELOPE_LENGTH:
        raise InvalidEnvelopeError(
            f"Envelope length {len(blob)} bytes is shorter than minimum {MIN_ENVELOPE_LENGTH} bytes."
        )

    version, key_id_len = struct.unpack_from("!BB", blob, 0)
    if version != CURRENT_ENVELOPE_VERSION:
        raise InvalidEnvelopeError(
            f"Unsupported envelope version {version}. Expected {CURRENT_ENVELOPE_VERSION}."
        )

    offset = 2
    if len(blob) < offset + key_id_len + NONCE_LENGTH_BYTES + TAG_LENGTH_BYTES:
        raise InvalidEnvelopeError("Envelope truncated: insufficient bytes for key_id and nonce.")

    try:
        key_id = blob[offset : offset + key_id_len].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidEnvelopeError("Invalid UTF-8 in envelope key_id.") from exc

    offset += key_id_len
    nonce = blob[offset : offset + NONCE_LENGTH_BYTES]
    offset += NONCE_LENGTH_BYTES
    ciphertext_and_tag = blob[offset:]

    ring = key_ring if key_ring is not None else get_default_key_ring()
    key_bytes = ring.get_key(key_id)

    aad_bytes = aad.encode("utf-8") if isinstance(aad, str) else aad
    aesgcm = AESGCM(key_bytes)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, aad_bytes)
    except InvalidTag as exc:
        raise DecryptionError(
            "Authentication failed: ciphertext, AAD, or nonce was tampered with or corrupted."
        ) from exc
    except Exception as exc:
        raise DecryptionError(f"Decryption failed: {exc}") from exc

    return plaintext


def decrypt_blob_to_str(
    blob: bytes,
    key_ring: KeyRing | None = None,
    aad: bytes | str = b"",
    encoding: str = "utf-8",
) -> str:
    """Decrypt an encrypted blob directly to a string.

    Args:
        blob: Encrypted blob bytes.
        key_ring: KeyRing for decryption.
        aad: Associated Authenticated Data.
        encoding: String encoding (default utf-8).

    Returns:
        Decrypted plaintext as str.
    """
    raw_bytes = decrypt_blob(blob, key_ring=key_ring, aad=aad)
    try:
        return raw_bytes.decode(encoding)
    except UnicodeDecodeError as exc:
        raise DecryptionError(f"Decrypted payload is not valid {encoding}: {exc}") from exc


def extract_envelope_key_id(blob: bytes) -> str:
    """Extract key_id stored in an AES-256-GCM envelope without decrypting the payload.

    Args:
        blob: Encrypted envelope bytes.

    Returns:
        The key_id string associated with this envelope.

    Raises:
        InvalidEnvelopeError: If the envelope is corrupted, truncated, or invalid.
    """
    if not isinstance(blob, bytes):
        raise InvalidEnvelopeError(f"Ciphertext blob must be bytes, got {type(blob).__name__}")

    if len(blob) < MIN_ENVELOPE_LENGTH:
        raise InvalidEnvelopeError(
            f"Envelope length {len(blob)} bytes is shorter than minimum {MIN_ENVELOPE_LENGTH} bytes."
        )

    version, key_id_len = struct.unpack_from("!BB", blob, 0)
    if version != CURRENT_ENVELOPE_VERSION:
        raise InvalidEnvelopeError(
            f"Unsupported envelope version {version}. Expected {CURRENT_ENVELOPE_VERSION}."
        )

    offset = 2
    if len(blob) < offset + key_id_len + NONCE_LENGTH_BYTES + TAG_LENGTH_BYTES:
        raise InvalidEnvelopeError("Envelope truncated: insufficient bytes for key_id and nonce.")

    try:
        return blob[offset : offset + key_id_len].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidEnvelopeError("Invalid UTF-8 in envelope key_id.") from exc


def reencrypt_blob(
    blob: bytes,
    key_ring: KeyRing | None = None,
    new_key_id: str | None = None,
    aad: bytes | str = b"",
) -> bytes:
    """Decrypt an encrypted envelope blob and re-encrypt it using the specified or primary key.

    If the blob is already encrypted with the target key_id, returns the original blob.

    Args:
        blob: Encrypted envelope bytes.
        key_ring: KeyRing containing both the old and new keys.
        new_key_id: Target key ID (if None, uses KeyRing.primary_key_id).
        aad: Associated Authenticated Data.

    Returns:
        Re-encrypted envelope bytes with new_key_id, or original blob if already current.
    """
    ring = key_ring if key_ring is not None else get_default_key_ring()
    target_key_id = new_key_id if new_key_id is not None else ring.primary_key_id

    current_key_id = extract_envelope_key_id(blob)
    if current_key_id == target_key_id:
        return blob

    plaintext = decrypt_blob(blob, key_ring=ring, aad=aad)
    return encrypt_blob(plaintext, key_ring=ring, key_id=target_key_id, aad=aad)
