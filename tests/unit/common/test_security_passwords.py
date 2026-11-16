"""Unit tests for Argon2id password hashing and validation."""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from embervault_common.security.passwords import (
    hash_password,
    needs_rehash,
    validate_password_complexity,
    verify_password,
)


def test_hash_password_produces_argon2id() -> None:
    hashed = hash_password("correct-horse-battery-staple")
    assert isinstance(hashed, str)
    assert hashed.startswith("$argon2id$")
    assert len(hashed) > 50


def test_verify_password_success() -> None:
    password = "SuperSecretPassword123!"
    hashed = hash_password(password)

    assert verify_password(hashed, password) is True
    assert verify_password(hashed, SecretStr(password)) is True


def test_verify_password_failure() -> None:
    password = "SuperSecretPassword123!"
    hashed = hash_password(password)

    assert verify_password(hashed, "WrongPassword123!") is False
    assert verify_password(hashed, "") is False
    assert verify_password("", password) is False
    assert verify_password("invalid$hash$format", password) is False


def test_empty_password_raises_value_error() -> None:
    with pytest.raises(ValueError, match="Password cannot be empty"):
        hash_password("")

    with pytest.raises(ValueError, match="Password cannot be empty"):
        hash_password(SecretStr(""))


def test_needs_rehash() -> None:
    hashed = hash_password("my-password-to-check")
    assert needs_rehash(hashed) is False
    assert needs_rehash("invalid-hash") is True


def test_validate_password_complexity() -> None:
    # Too short (< 8 chars)
    ok, err = validate_password_complexity("short")
    assert ok is False
    assert err is not None

    # Whitespace only
    ok, err = validate_password_complexity("        ")
    assert ok is False

    # Numbers only (e.g. 12345678)
    ok, err = validate_password_complexity("12345678")
    assert ok is False
    assert err is not None

    # Lowercase only
    ok, err = validate_password_complexity("abcdefgh")
    assert ok is False

    # Valid password
    ok, err = validate_password_complexity("validPassword123!")
    assert ok is True
    assert err is None
