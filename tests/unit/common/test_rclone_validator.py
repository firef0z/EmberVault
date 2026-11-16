"""Unit tests for RClone parameter validation and sanitization."""

from __future__ import annotations

import pytest

from embervault_common.rclone.validator import (
    FORBIDDEN_RCLONE_FLAGS,
    sanitize_rclone_parameters,
    validate_rclone_parameter,
)


class TestRcloneParameterValidation:
    """Test validation of user-defined RClone parameters."""

    @pytest.mark.parametrize(
        "param",
        [
            "--fast-list",
            "--min-size 10M",
            "--max-size 1G",
            "-u",
            "-v",
            "--ignore-existing",
            "--buffer-size=64M",
            "--dry-run",
            "--checksum",
            "--metadata",
            "--no-traverse",
        ],
    )
    def test_valid_parameters(self, param: str) -> None:
        is_valid, err = validate_rclone_parameter(param)
        assert is_valid is True
        assert err is None

    @pytest.mark.parametrize(
        "param",
        [
            "",
            "   ",
            "\t",
            None,
        ],
    )
    def test_empty_parameters(self, param: str | None) -> None:
        is_valid, err = validate_rclone_parameter(param)  # type: ignore[arg-type]
        assert is_valid is False
        assert err is not None
        assert "vuoto" in err.lower() or "empty" in err.lower()

    @pytest.mark.parametrize(
        "param",
        [
            "fast-list",
            "min-size 10M",
            "copy",
            "sync",
            "/tmp/dest",
        ],
    )
    def test_parameters_must_start_with_dash(self, param: str) -> None:
        is_valid, err = validate_rclone_parameter(param)
        assert is_valid is False
        assert err is not None
        assert "-" in err

    @pytest.mark.parametrize(
        "param",
        [
            "--flag; rm -rf /",
            "--flag && evil",
            "--flag | bash",
            "--flag `id`",
            "--flag $(whoami)",
            "--flag\n--other",
            "--flag\r--other",
            "--flag > out.txt",
            "--flag < in.txt",
        ],
    )
    def test_parameters_with_dangerous_characters(self, param: str) -> None:
        is_valid, err = validate_rclone_parameter(param)
        assert is_valid is False
        assert err is not None
        assert "caratteri non consentiti" in err.lower()

    @pytest.mark.parametrize(
        "forbidden_flag",
        list(FORBIDDEN_RCLONE_FLAGS),
    )
    def test_forbidden_flags(self, forbidden_flag: str) -> None:
        is_valid, err = validate_rclone_parameter(forbidden_flag)
        assert is_valid is False
        assert err is not None
        assert "consentito" in err.lower()

        # Also with arguments
        is_valid_arg, _ = validate_rclone_parameter(f"{forbidden_flag} some_value")
        assert is_valid_arg is False

        is_valid_eq, _ = validate_rclone_parameter(f"{forbidden_flag}=some_value")
        assert is_valid_eq is False


class TestRcloneParameterSanitization:
    """Test sanitization and deduplication of parameter lists."""

    def test_sanitize_valid_and_invalid_mix(self) -> None:
        raw_list = [
            "--fast-list",
            "invalid_no_dash",
            "--min-size 10M",
            "--rc",  # forbidden
            "--fast-list",  # duplicate
            "   ",  # whitespace
            "--ignore-existing",
            "--flag; echo evil",  # dangerous
        ]
        sanitized = sanitize_rclone_parameters(raw_list)
        assert sanitized == ["--fast-list", "--min-size 10M", "--ignore-existing"]

    def test_sanitize_empty_or_non_iterable(self) -> None:
        assert sanitize_rclone_parameters(None) == []
        assert sanitize_rclone_parameters([]) == []
        assert sanitize_rclone_parameters("not a list") == []
