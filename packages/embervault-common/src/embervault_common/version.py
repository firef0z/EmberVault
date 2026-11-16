"""Version compatibility checking utilities for EmberVault components."""

from __future__ import annotations

import re

MIN_COMPATIBLE_PROXY_VERSION: str = "1.0.0"


def parse_semver(v_str: str | None) -> tuple[int, int, int]:
    """Parse a semantic version string into a (major, minor, patch) tuple.

    Returns (0, 0, 0) if parsing fails or version is empty/unknown.
    """
    if not v_str:
        return (0, 0, 0)
    cleaned = v_str.strip().lstrip("vV")
    match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", cleaned)
    if not match:
        return (0, 0, 0)
    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3)) if match.group(3) is not None else 0
    return (major, minor, patch)


def is_proxy_version_compatible(
    proxy_version: str | None,
    min_version: str = MIN_COMPATIBLE_PROXY_VERSION,
) -> bool:
    """Evaluate whether a reported proxy version satisfies minimum required compatibility.

    A proxy is considered compatible if its semantic version is greater than or equal to min_version.
    """
    if not proxy_version:
        return False
    parsed_proxy = parse_semver(proxy_version)
    parsed_min = parse_semver(min_version)
    if parsed_proxy == (0, 0, 0):
        return False
    return parsed_proxy >= parsed_min
