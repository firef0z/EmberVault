"""Unit tests for token generation, constant-time comparison, and token hashing."""

from __future__ import annotations

import pytest

from embervault_common.security.tokens import (
    compare_tokens,
    generate_secure_token,
    hash_token,
)


class TestCompareTokens:
    """Tests for constant-time token comparison."""

    def test_identical_strings(self) -> None:
        t1 = "my-secret-token-12345"
        t2 = "my-secret-token-12345"
        assert compare_tokens(t1, t2) is True

    def test_different_strings(self) -> None:
        assert compare_tokens("token-a", "token-b") is False
        assert compare_tokens("token-a", "token-aa") is False

    def test_identical_bytes(self) -> None:
        b1 = b"\x01\x02\x03\x04\x05"
        b2 = b"\x01\x02\x03\x04\x05"
        assert compare_tokens(b1, b2) is True

    def test_different_bytes(self) -> None:
        assert compare_tokens(b"\x01", b"\x02") is False

    def test_string_and_bytes_match(self) -> None:
        assert compare_tokens("hello-token", b"hello-token") is True
        assert compare_tokens(b"hello-token", "hello-token") is True

    def test_empty_tokens(self) -> None:
        assert compare_tokens("", "") is True
        assert compare_tokens(b"", b"") is True
        assert compare_tokens("", b"") is True
        assert compare_tokens("abc", "") is False


class TestGenerateSecureToken:
    """Tests for secure token generation."""

    def test_default_urlsafe_token(self) -> None:
        token = generate_secure_token()
        assert isinstance(token, str)
        # 32 bytes in base64url is 43 characters
        assert len(token) >= 42
        # Multiple generated tokens must be distinct
        token2 = generate_secure_token()
        assert token != token2

    def test_hex_token(self) -> None:
        token = generate_secure_token(nbytes=32, encoding="hex")
        assert isinstance(token, str)
        assert len(token) == 64
        # Validate hex characters only
        int(token, 16)

    def test_custom_length(self) -> None:
        token = generate_secure_token(nbytes=16, encoding="hex")
        assert len(token) == 32

    def test_insufficient_entropy_rejected(self) -> None:
        with pytest.raises(ValueError, match="at least 16 bytes"):
            generate_secure_token(nbytes=15)

    def test_invalid_encoding_rejected(self) -> None:
        with pytest.raises(ValueError, match="Unsupported encoding"):
            generate_secure_token(encoding="invalid")  # type: ignore[arg-type]


class TestHashToken:
    """Tests for token hashing (SHA-256)."""

    def test_empty_string_hash_known_vector(self) -> None:
        # Standard known SHA-256 digest of empty string
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert hash_token("") == expected
        assert hash_token(b"") == expected

    def test_known_string_hash(self) -> None:
        token = "EmberVault-Session-Token-Test"
        digest1 = hash_token(token)
        digest2 = hash_token(token.encode("utf-8"))
        assert len(digest1) == 64
        assert digest1 == digest2
        # Deterministic
        assert digest1 == hash_token(token)

    def test_different_tokens_produce_different_hashes(self) -> None:
        h1 = hash_token("token-alpha")
        h2 = hash_token("token-beta")
        assert h1 != h2
