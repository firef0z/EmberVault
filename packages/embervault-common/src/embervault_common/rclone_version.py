"""RClone version detection, release fetching, and semantic comparison utilities."""

from __future__ import annotations

import re
import time

import requests

from embervault_common.observability import get_logger

logger = get_logger("embervault_common.rclone_version")

# Fallback recent stable releases in case GitHub/network is unreachable
DEFAULT_RCLONE_VERSIONS: list[str] = [
    "1.68.2",
    "1.68.1",
    "1.68.0",
    "1.67.0",
    "1.66.0",
    "1.65.2",
    "1.65.1",
    "1.65.0",
]

_CACHED_VERSIONS: list[str] | None = None
_CACHED_VERSIONS_TS: float = 0.0
VERSIONS_CACHE_TTL_S: float = 3600.0  # 1 hour


def parse_rclone_version(v_str: str | None) -> tuple[int, int, int]:
    """Parse a version string (e.g., 'rclone v1.68.2', 'v1.68.2', '1.68.2') into (major, minor, patch).

    Returns (0, 0, 0) if parsing fails.
    """
    if not v_str:
        return (0, 0, 0)
    # Search for digit sequence e.g. 1.68.2
    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", str(v_str))
    if not match:
        return (0, 0, 0)
    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3)) if match.group(3) is not None else 0
    return (major, minor, patch)


def format_clean_version(v_str: str | None) -> str:
    """Extract clean semver string 'X.Y.Z' from verbose rclone version output."""
    parsed = parse_rclone_version(v_str)
    if parsed == (0, 0, 0):
        return v_str or ""
    return f"{parsed[0]}.{parsed[1]}.{parsed[2]}"


def fetch_available_rclone_versions(force_refresh: bool = False) -> list[str]:
    """Fetch available stable RClone release versions from GitHub API or rclone downloads.

    Results are cached in memory with a 1-hour TTL.
    Returns a sorted list of version strings descending (e.g. ['1.68.2', '1.68.1', ...]).
    """
    global _CACHED_VERSIONS, _CACHED_VERSIONS_TS
    now = time.monotonic()
    if (
        not force_refresh
        and _CACHED_VERSIONS
        and (now - _CACHED_VERSIONS_TS) < VERSIONS_CACHE_TTL_S
    ):
        return list(_CACHED_VERSIONS)

    versions: list[str] = []

    # 1. Try GitHub Releases API
    try:
        resp = requests.get(
            "https://api.github.com/repos/rclone/rclone/releases?per_page=30",
            headers={
                "User-Agent": "EmberVault-Updater",
                "Accept": "application/vnd.github.v3+json",
            },
            timeout=5.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for rel in data:
                    if not isinstance(rel, dict):
                        continue
                    if rel.get("prerelease") or rel.get("draft"):
                        continue
                    tag = str(rel.get("tag_name", "")).strip().lstrip("vV")
                    parsed = parse_rclone_version(tag)
                    if parsed != (0, 0, 0):
                        v_formatted = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
                        if v_formatted not in versions:
                            versions.append(v_formatted)
    except Exception as exc:
        logger.debug("github_rclone_releases_fetch_failed", error=str(exc))

    # 2. Try rclone.org version.txt if GitHub returned nothing
    if not versions:
        try:
            resp = requests.get("https://downloads.rclone.org/version.txt", timeout=4.0)
            if resp.status_code == 200:
                txt = resp.text.strip()
                parsed = parse_rclone_version(txt)
                if parsed != (0, 0, 0):
                    v_formatted = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
                    versions.append(v_formatted)
        except Exception as exc:
            logger.debug("rclone_org_version_fetch_failed", error=str(exc))

    # Merge with default fallback versions to ensure a rich list is always available
    for def_ver in DEFAULT_RCLONE_VERSIONS:
        if def_ver not in versions:
            versions.append(def_ver)

    # Sort descending by semver
    versions.sort(key=lambda v: parse_rclone_version(v), reverse=True)

    _CACHED_VERSIONS = versions
    _CACHED_VERSIONS_TS = now
    return list(_CACHED_VERSIONS)


def get_latest_rclone_version() -> str:
    """Retrieve the latest available stable RClone version string."""
    vers = fetch_available_rclone_versions()
    return vers[0] if vers else DEFAULT_RCLONE_VERSIONS[0]


def is_rclone_update_available(
    current_version: str | None,
    target_version: str | None = None,
) -> tuple[bool, str]:
    """Check if an update is available compared to the current installed version.

    Args:
        current_version: Version currently installed on the proxy.
        target_version: Optional specific target version; if None, checks against latest.

    Returns:
        tuple (is_available, target_version_clean)
    """
    target = target_version or get_latest_rclone_version()
    clean_target = format_clean_version(target)
    parsed_current = parse_rclone_version(current_version)
    parsed_target = parse_rclone_version(clean_target)

    if parsed_current == (0, 0, 0):
        # Unknown or not installed -> update available if valid target
        return (parsed_target != (0, 0, 0), clean_target)

    is_newer = parsed_target > parsed_current
    return (is_newer, clean_target)
