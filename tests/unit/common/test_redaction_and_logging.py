"""Tests for security redaction, canary scanning, and structured logging."""

import json
from collections.abc import Generator
from io import StringIO

import pytest

from embervault_common.observability.logging import (
    bind_context,
    clear_context,
    configure_logging,
    get_logger,
)
from embervault_common.security.redaction import (
    REDACTED_PLACEHOLDER,
    clear_canaries,
    mask_secret,
    redact_data,
    register_canary,
)


@pytest.fixture(autouse=True)
def cleanup_canaries_and_context() -> Generator[None, None, None]:
    """Ensure canaries and contextvars are wiped clean between tests."""
    clear_canaries()
    clear_context()
    yield
    clear_canaries()
    clear_context()


def test_redact_sensitive_keys() -> None:
    """Ensure sensitive key names in dictionaries are masked."""
    data = {
        "username": "admin",
        "password": "SuperSecretPassword123!",
        "token": "bearer-token-abc-xyz",
        "api_key": "key-999",
        "key_id": "v1",  # Safe key
        "master_key_id": "v2",  # Safe key
        "nested": {
            "rclone_config": "sensitive raw config",
            "normal_field": "hello world",
        },
    }

    cleaned = redact_data(data)
    assert cleaned["username"] == "admin"
    assert cleaned["password"] == REDACTED_PLACEHOLDER
    assert cleaned["token"] == REDACTED_PLACEHOLDER
    assert cleaned["api_key"] == REDACTED_PLACEHOLDER
    assert cleaned["key_id"] == "v1"
    assert cleaned["master_key_id"] == "v2"
    assert cleaned["nested"]["rclone_config"] == REDACTED_PLACEHOLDER
    assert cleaned["nested"]["normal_field"] == "hello world"


def test_regex_patterns_redaction() -> None:
    """Test inline pattern redaction (Bearer tokens, URL credentials, key=val)."""
    # Bearer header in string
    msg1 = "Sending request with header Authorization: Bearer secret-auth-token-9999"
    assert (
        mask_secret(msg1)
        == f"Sending request with header Authorization: Bearer {REDACTED_PLACEHOLDER}"
    )

    # URL credentials
    msg2 = "Connecting to postgresql://myuser:secretpassword@postgres.internal:5432/embervault"
    assert (
        mask_secret(msg2)
        == f"Connecting to postgresql://myuser:{REDACTED_PLACEHOLDER}@postgres.internal:5432/embervault"
    )

    # Key=value in log string
    msg3 = "Failed task execution with password=super_plain_secret in params"
    assert (
        mask_secret(msg3) == f"Failed task execution with password={REDACTED_PLACEHOLDER} in params"
    )


def test_canary_secret_registration_and_scrubbing() -> None:
    """Ensure registered canary secrets never leak into output strings."""
    canary = "custom_dynamic_secret_canary_xyz123"
    register_canary(canary)

    # In plain string
    test_str = f"Error details: token was {canary} and connection failed"
    redacted = mask_secret(test_str)
    assert canary not in redacted
    assert REDACTED_PLACEHOLDER in redacted

    # In deeply nested structure
    nested = ["safe", {"info": f"Found canary: {canary}"}, (canary,)]
    redacted_nested = redact_data(nested)
    assert canary not in str(redacted_nested)


def test_structlog_json_output_with_redaction_and_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test full structlog pipeline formatting with redaction and contextvars."""
    stream = StringIO()
    monkeypatch.setattr("sys.stdout", stream)

    configure_logging(service="test-service", log_level="INFO", log_format="json")
    logger = get_logger("test")

    canary = "super_canary_secret_phrase_to_never_leak"
    register_canary(canary)

    bind_context(request_id="req-12345", run_id="run-99")
    logger.info(
        "processing_event",
        user="john_doe",
        auth_token=canary,
        details=f"Connecting with token {canary}",
    )

    output = stream.getvalue().strip()
    assert output, "Expected log line to be emitted to stdout"

    log_entry = json.loads(output)
    assert log_entry["service"] == "test-service"
    assert log_entry["level"] == "info"
    assert log_entry["event"] == "processing_event"
    assert log_entry["request_id"] == "req-12345"
    assert log_entry["run_id"] == "run-99"
    assert log_entry["user"] == "john_doe"

    # Verify canary secret is scrubbed completely from all fields
    assert canary not in output
    assert log_entry["auth_token"] == REDACTED_PLACEHOLDER
    assert REDACTED_PLACEHOLDER in log_entry["details"]
