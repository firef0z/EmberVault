"""RClone backend catalog and remote configuration utilities."""

from embervault_common.remotes.catalog import (
    BACKEND_CATALOG,
    BackendField,
    BackendSpec,
    get_backend_catalog,
    get_backend_spec,
    is_obscured_secret_field,
    validate_and_split_remote_config,
)
from embervault_common.remotes.obscure import rclone_deobscure, rclone_obscure

__all__ = [
    "BACKEND_CATALOG",
    "BackendField",
    "BackendSpec",
    "get_backend_catalog",
    "get_backend_spec",
    "is_obscured_secret_field",
    "rclone_deobscure",
    "rclone_obscure",
    "validate_and_split_remote_config",
]
