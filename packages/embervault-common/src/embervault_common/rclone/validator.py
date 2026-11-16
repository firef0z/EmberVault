"""Validation and sanitization utilities for additional RClone CLI parameters."""

from __future__ import annotations

import re
from typing import Any

# Flags that could compromise proxy security, alter daemon config, or break runner operations
FORBIDDEN_RCLONE_FLAGS: frozenset[str] = frozenset(
    {
        "--rc",
        "--rc-web-gui",
        "--rc-addr",
        "--rc-user",
        "--rc-pass",
        "--password-command",
        "--config",
        "--ask-password",
        "--syslog",
    }
)

# Regex matching valid CLI flag syntax: starts with - or -- followed by alphanumerics/hyphens,
# optionally followed by an argument separated by space or =
FLAG_REGEX = re.compile(r"^--?[a-zA-Z0-9][-a-zA-Z0-9_.]*(?:[=\s].*)?$")

# Forbidden characters that can pose shell escape, injection, or control risk
DANGEROUS_CHARS = re.compile(r"[;&|`$\n\r\x00()<>]")


def validate_rclone_parameter(param: str) -> tuple[bool, str | None]:
    """Validate that a user-specified parameter is safe and syntactically valid for RClone CLI.

    Returns:
        tuple (is_valid, error_message)
    """
    if not param or not param.strip():
        return False, "Il parametro non puo' essere vuoto."

    p = param.strip()

    if not p.startswith("-"):
        return False, "Il parametro deve iniziare con '-' o '--' (ad es. --fast-list)."

    if p in ("-", "--"):
        return False, "Il parametro non puo' consistere solo di '-' o '--'."

    if DANGEROUS_CHARS.search(p):
        return False, "Il parametro contiene caratteri non consentiti."

    if not FLAG_REGEX.match(p):
        return False, "Sintassi del parametro non valida per RClone."

    # Extract flag name (before = or space)
    flag_part = p.split("=")[0].split()[0].lower()
    if flag_part in FORBIDDEN_RCLONE_FLAGS:
        return (
            False,
            f"Il flag '{flag_part}' non e' consentito per motivi di sicurezza o configurazione del proxy.",
        )

    return True, None


def sanitize_rclone_parameters(params: list[str] | Any) -> list[str]:
    """Validate and sanitize a collection of additional rclone parameters.

    Returns only parameters that pass validation.
    """
    if not isinstance(params, (list, tuple)):
        return []

    valid_params: list[str] = []
    seen: set[str] = set()

    for item in params:
        if isinstance(item, str):
            clean = item.strip()
            if clean and clean not in seen:
                is_valid, _ = validate_rclone_parameter(clean)
                if is_valid:
                    valid_params.append(clean)
                    seen.add(clean)

    return valid_params
