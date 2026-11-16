"""Password hashing, verification, and complexity validation using Argon2id.

Compliant with OWASP guidelines for secure password storage:
Argon2id with 64 MB memory cost, 3 iterations, and 4 parallel threads.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from pydantic import SecretStr

if TYPE_CHECKING:
    pass

# OWASP Recommended Parameters for Argon2id
_DEFAULT_TIME_COST = 3
_DEFAULT_MEMORY_COST = 65536  # 64 MiB
_DEFAULT_PARALLELISM = 4
_DEFAULT_HASH_LEN = 32
_DEFAULT_SALT_LEN = 16

_HASHER = PasswordHasher(
    time_cost=_DEFAULT_TIME_COST,
    memory_cost=_DEFAULT_MEMORY_COST,
    parallelism=_DEFAULT_PARALLELISM,
    hash_len=_DEFAULT_HASH_LEN,
    salt_len=_DEFAULT_SALT_LEN,
)


def hash_password(password: str | SecretStr) -> str:
    """Hash a plaintext password using Argon2id.

    Args:
        password: Plaintext password as string or SecretStr.

    Returns:
        Encoded Argon2id hash string.
    """
    secret = password.get_secret_value() if isinstance(password, SecretStr) else password
    if not secret:
        raise ValueError("Password cannot be empty.")
    return _HASHER.hash(secret)


def verify_password(stored_hash: str, password: str | SecretStr) -> bool:
    """Verify a candidate password against an Argon2id hash.

    Constant-time comparison is handled internally by the Argon2 C library.

    Args:
        stored_hash: The previously generated Argon2 hash.
        password: The candidate password to check.

    Returns:
        True if the password matches, False otherwise.
    """
    secret = password.get_secret_value() if isinstance(password, SecretStr) else password
    if not stored_hash or not secret:
        return False

    try:
        return _HASHER.verify(stored_hash, secret)
    except (VerifyMismatchError, InvalidHashError):
        return False
    except Exception:
        return False


def needs_rehash(stored_hash: str) -> bool:
    """Check if the stored hash was computed with older or weaker parameters.

    Args:
        stored_hash: The encoded hash string.

    Returns:
        True if the password should be re-hashed on successful login, False otherwise.
    """
    try:
        return _HASHER.check_needs_rehash(stored_hash)
    except Exception:
        return True


def validate_password_complexity(password: str | SecretStr) -> tuple[bool, str | None]:
    """Validate that a candidate password meets minimum security standards.

    Rules:
    - Minimum length: 8 characters
    - Must not be whitespace-only
    - Must contain at least one lowercase letter, one uppercase letter, and one digit or special character

    Args:
        password: The candidate password to validate.

    Returns:
        Tuple of (is_valid, error_message_or_none).
    """
    secret = password.get_secret_value() if isinstance(password, SecretStr) else password
    if not secret or len(secret) < 8:
        return False, "La password deve contenere almeno 8 caratteri."

    if secret.strip() == "":
        return False, "La password non può essere composta solo da spazi."

    has_lower = any(c.islower() for c in secret)
    has_upper = any(c.isupper() for c in secret)
    has_digit_or_special = any(c.isdigit() or not c.isalnum() for c in secret)

    if not (has_lower and has_upper and has_digit_or_special):
        return (
            False,
            "La password deve contenere almeno una lettera maiuscola, una minuscola e un numero o carattere speciale.",
        )

    return True, None
