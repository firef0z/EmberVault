"""Unit tests for RClone password obscuring and de-obscuring utilities."""

from embervault_common.remotes.obscure import (
    RCLONE_CRYPT_KEY,
    rclone_deobscure,
    rclone_obscure,
)


def test_rclone_obscure_and_deobscure_roundtrip() -> None:
    """Verify that obscuring and deobscuring passwords works reliably."""
    passwords = [
        "SimplePass1",
        "P@ssw0rd!#$*&()-_=+",
        "VeryLongPasswordWithManyCharactersAndSymbols1234567890",
        "Special Unicode: àèìòù € 🚀",
        "a",
    ]
    for pw in passwords:
        obs = rclone_obscure(pw, rclone_bin="non_existent_binary")
        assert obs != pw
        assert len(obs) >= 22
        recovered = rclone_deobscure(obs)
        assert recovered == pw


def test_rclone_obscure_empty_strings() -> None:
    """Verify that empty inputs produce empty outputs."""
    assert rclone_obscure("") == ""
    assert rclone_deobscure("") == ""


def test_rclone_deobscure_invalid_data() -> None:
    """Verify that invalid base64 or corrupted data gracefully returns input string."""
    assert rclone_deobscure("not_base64_!#@") == "not_base64_!#@"
    assert rclone_deobscure("short") == "short"


def test_crypt_key_length() -> None:
    """Verify standard Rclone AES-256 crypt key length."""
    assert len(RCLONE_CRYPT_KEY) == 32
