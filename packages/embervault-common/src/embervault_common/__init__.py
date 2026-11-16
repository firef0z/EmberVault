"""EmberVault Common package."""

from embervault_common.rclone_version import (
    fetch_available_rclone_versions,
    format_clean_version,
    get_latest_rclone_version,
    is_rclone_update_available,
    parse_rclone_version,
)
from embervault_common.version import (
    MIN_COMPATIBLE_PROXY_VERSION,
    is_proxy_version_compatible,
    parse_semver,
)

__version__ = "1.0.0"

__all__ = [
    "__version__",
    "MIN_COMPATIBLE_PROXY_VERSION",
    "is_proxy_version_compatible",
    "parse_semver",
    "fetch_available_rclone_versions",
    "format_clean_version",
    "get_latest_rclone_version",
    "is_rclone_update_available",
    "parse_rclone_version",
]
