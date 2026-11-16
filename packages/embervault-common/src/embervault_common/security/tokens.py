"""Token generation, constant-time comparison, and token hashing utilities."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Literal


def compare_tokens(token_a: str | bytes, token_b: str | bytes) -> bool:
    """Compare two authentication tokens or secrets in constant time.

    Mitigates side-channel timing attacks by delegating to hmac.compare_digest.
    Supports both str and bytes; strings are normalized to UTF-8 bytes before comparison.

    Args:
        token_a: First token.
        token_b: Second token.

    Returns:
        True if tokens are identically equal, False otherwise.
    """
    bytes_a = token_a.encode("utf-8") if isinstance(token_a, str) else token_a
    bytes_b = token_b.encode("utf-8") if isinstance(token_b, str) else token_b
    return hmac.compare_digest(bytes_a, bytes_b)


def generate_secure_token(nbytes: int = 32, encoding: Literal["urlsafe", "hex"] = "urlsafe") -> str:
    """Generate a cryptographically secure random token.

    Args:
        nbytes: Number of random bytes of entropy (default 32 bytes = 256 bits).
        encoding: Output encoding format ('urlsafe' base64 or 'hex').

    Returns:
        Secure random token string.
    """
    if nbytes < 16:
        raise ValueError(f"Token entropy must be at least 16 bytes (got {nbytes}).")

    if encoding == "urlsafe":
        return secrets.token_urlsafe(nbytes)
    elif encoding == "hex":
        return secrets.token_hex(nbytes)
    else:
        raise ValueError(f"Unsupported encoding '{encoding}'. Choose 'urlsafe' or 'hex'.")


def hash_token(token: str | bytes) -> str:
    """Compute a deterministic SHA-256 hex digest of a token.

    Used for storing hashed session tokens, API keys, or recovery tokens in the database,
    ensuring token values are not exposed in plaintext if the database is accessed.

    Args:
        token: The token string or bytes to hash.

    Returns:
        64-character lowercase hexadecimal SHA-256 digest.
    """
    token_bytes = token.encode("utf-8") if isinstance(token, str) else token
    return hashlib.sha256(token_bytes).hexdigest()
