"""Redaction utilities for masking sensitive credentials and tokens in logs and data structures."""

from __future__ import annotations

import re
from collections.abc import MutableMapping, Sequence
from typing import Any

REDACTED_PLACEHOLDER = "***REDACTED***"

# Sensitive keywords in dictionary keys (case-insensitive)
SENSITIVE_KEY_SUBSTRINGS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "credential",
    "private_key",
    "privkey",
    "api_key",
    "master_key",
    "config",
)

# Explicit sensitive key names
EXACT_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "pass",
        "key",
        "config",
        "config_encrypted",
        "token_encrypted",
    }
)

# Known safe keys that might contain "key" or "auth"
SAFE_KEYS: frozenset[str] = frozenset(
    {
        "key_id",
        "master_key_id",
        "auth_source",
        "cache_key",
        "event_key",
        "public_params",
        "secret_field_names",
    }
)

# Regex patterns for masking sensitive strings in text
BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9\-_.~+/]+=*)")
URL_CREDENTIAL_PATTERN = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://)([^:\s@]+):([^@\s]+)@")
KEY_VALUE_SECRET_PATTERN = re.compile(
    r"(?i)\b(password|passwd|secret|token|api_key|master_key|master_keys)\s*([:=])\s*([^\s,;'\"]+)"
)

# Canary secrets registered dynamically (e.g. from loaded configurations or test runners)
_CANARIES: set[str] = set()


def register_canary(secret: str) -> None:
    """Register a known secret string as a canary to ensure it is always scrubbed."""
    cleaned = secret.strip()
    if len(cleaned) >= 4:
        _CANARIES.add(cleaned)


def unregister_canary(secret: str) -> None:
    """Unregister a canary secret."""
    cleaned = secret.strip()
    _CANARIES.discard(cleaned)


def clear_canaries() -> None:
    """Clear all registered canaries."""
    _CANARIES.clear()


def is_sensitive_key(key: str) -> bool:
    """Determine whether a key name represents sensitive information."""
    normalized = key.strip().lower()
    if normalized in SAFE_KEYS:
        return False
    if normalized in EXACT_SENSITIVE_KEYS:
        return True
    return any(sub in normalized for sub in SENSITIVE_KEY_SUBSTRINGS)


def mask_secret(value: str) -> str:
    """Mask a secret string completely or apply redaction patterns."""
    if not value:
        return value

    redacted = value

    # Scrub registered canaries first
    for canary in _CANARIES:
        if canary in redacted:
            redacted = redacted.replace(canary, REDACTED_PLACEHOLDER)

    # Scrub Bearer tokens
    redacted = BEARER_PATTERN.sub(f"Bearer {REDACTED_PLACEHOLDER}", redacted)

    # Scrub URL credentials
    redacted = URL_CREDENTIAL_PATTERN.sub(rf"\1\2:{REDACTED_PLACEHOLDER}@", redacted)

    # Scrub inline key=secret patterns
    redacted = KEY_VALUE_SECRET_PATTERN.sub(rf"\1\2{REDACTED_PLACEHOLDER}", redacted)

    return redacted


def redact_data(data: Any) -> Any:
    """Recursively redact sensitive keys and values from arbitrary Python data structures."""
    if isinstance(data, dict):
        result: dict[Any, Any] = {}
        for k, v in data.items():
            str_key = str(k)
            if is_sensitive_key(str_key):
                result[k] = REDACTED_PLACEHOLDER
            else:
                result[k] = redact_data(v)
        return result

    if isinstance(data, (list, tuple, set)):
        items = [redact_data(item) for item in data]
        if isinstance(data, tuple):
            return tuple(items)
        if isinstance(data, set):
            return set(items)
        return items

    if isinstance(data, str):
        return mask_secret(data)

    return data


class RedactionProcessor:
    """Structlog processor that scrubs sensitive keys and masked tokens from log event dictionaries."""

    def __init__(self, additional_sensitive_keys: Sequence[str] | None = None) -> None:
        self.additional_sensitive_keys = frozenset(
            k.lower() for k in (additional_sensitive_keys or ())
        )

    def __call__(
        self,
        _logger: Any,
        _method_name: str,
        event_dict: MutableMapping[str, Any],
    ) -> MutableMapping[str, Any]:
        """Process and scrub the event dict in-place."""
        redacted = redact_data(dict(event_dict))
        event_dict.clear()
        event_dict.update(redacted)
        return event_dict
