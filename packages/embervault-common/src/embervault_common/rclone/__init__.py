"""RClone integration, configuration, obscure, and filter utilities."""

from embervault_common.rclone.filters import (
    evaluate_filters,
    filter_paths,
    match_path_rule,
    parse_filter_rules,
)
from embervault_common.rclone.options import resolve_job_rclone_options
from embervault_common.rclone.validator import (
    FORBIDDEN_RCLONE_FLAGS,
    sanitize_rclone_parameters,
    validate_rclone_parameter,
)

__all__ = [
    "FORBIDDEN_RCLONE_FLAGS",
    "evaluate_filters",
    "filter_paths",
    "match_path_rule",
    "parse_filter_rules",
    "resolve_job_rclone_options",
    "sanitize_rclone_parameters",
    "validate_rclone_parameter",
]
