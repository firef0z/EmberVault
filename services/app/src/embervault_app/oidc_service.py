"""OIDC integration service for EmberVault Web Application (Milestone M5).

Provides:
- Resolution of OIDC configuration from SettingsStore / environment.
- Persistence of OIDC configuration changes with audit logging.
- Connection testing and diagnostic reporting.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING, Any
from uuid import UUID

import structlog
from flask import current_app, has_app_context
from pydantic import SecretStr

from embervault_common.security.oidc import OidcConfig, check_oidc_connectivity
from embervault_db.settings_store import SettingsStore

if TYPE_CHECKING:
    pass

logger = structlog.get_logger("embervault_app.oidc_service")


def _resolve_store(session_or_store: Any = None) -> SettingsStore:
    """Resolve a SettingsStore instance from argument, Flask app context, or session."""
    if isinstance(session_or_store, SettingsStore):
        return session_or_store

    if has_app_context() and current_app and "SETTINGS_STORE" in current_app.config:
        return current_app.config["SETTINGS_STORE"]

    if callable(session_or_store):
        return SettingsStore(session_or_store)

    if session_or_store is not None:

        @contextmanager
        def _single_session_context():
            yield session_or_store

        return SettingsStore(_single_session_context)  # type: ignore[arg-type]

    raise ValueError("SettingsStore or session_factory is required to access settings.")


def get_oidc_config(session_or_store: Any = None) -> tuple[bool, OidcConfig]:
    """Retrieve resolved OIDC configuration from SettingsStore.

    Returns:
        (is_enabled: bool, config: OidcConfig)
    """
    store = _resolve_store(session_or_store)
    enabled = bool(store.get_setting("oidc_enabled"))

    client_sec = store.get_setting("oidc_client_secret")
    if isinstance(client_sec, SecretStr) or hasattr(client_sec, "get_secret_value"):
        client_sec_str = client_sec.get_secret_value()
    else:
        client_sec_str = str(client_sec or "")

    config = OidcConfig(
        enabled=enabled,
        provider_name=str(store.get_setting("oidc_provider_name") or "PocketID"),
        issuer_url=str(store.get_setting("oidc_issuer_url") or ""),
        client_id=str(store.get_setting("oidc_client_id") or ""),
        client_secret=client_sec_str,
        scopes=str(store.get_setting("oidc_scopes") or "openid profile email groups"),
        username_claim=str(store.get_setting("oidc_username_claim") or "preferred_username"),
        groups_claim=str(store.get_setting("oidc_groups_claim") or "groups"),
        admin_group=str(store.get_setting("oidc_admin_group") or ""),
        operator_group=str(store.get_setting("oidc_operator_group") or ""),
        viewer_group=str(store.get_setting("oidc_viewer_group") or ""),
        validate_cert=bool(store.get_setting("oidc_validate_cert")),
        ca_cert_pem=str(store.get_setting("oidc_ca_cert_pem") or ""),
        enforce_mfa=True
        if store.get_setting("oidc_enforce_mfa") is None
        else bool(store.get_setting("oidc_enforce_mfa")),
    )
    return enabled, config


def save_oidc_config(
    session: Any = None,
    data: dict[str, Any] | None = None,
    user_id: UUID | None = None,
    ip: str | None = None,
) -> None:
    """Save or update OIDC configuration keys in SettingsStore."""
    store = _resolve_store(session)
    data = data or {}

    string_keys = [
        "oidc_provider_name",
        "oidc_issuer_url",
        "oidc_client_id",
        "oidc_scopes",
        "oidc_username_claim",
        "oidc_groups_claim",
        "oidc_admin_group",
        "oidc_operator_group",
        "oidc_viewer_group",
        "oidc_ca_cert_pem",
    ]
    for key in string_keys:
        if key in data:
            store.set_setting(key, str(data[key]).strip(), user_id=user_id, ip=ip)

    if "oidc_enabled" in data:
        store.set_setting("oidc_enabled", bool(data["oidc_enabled"]), user_id=user_id, ip=ip)

    if "oidc_validate_cert" in data:
        store.set_setting(
            "oidc_validate_cert", bool(data["oidc_validate_cert"]), user_id=user_id, ip=ip
        )

    if "oidc_enforce_mfa" in data:
        store.set_setting(
            "oidc_enforce_mfa", bool(data["oidc_enforce_mfa"]), user_id=user_id, ip=ip
        )

    # Only update client secret if provided and non-empty
    if "oidc_client_secret" in data:
        raw_secret = str(data["oidc_client_secret"]).strip()
        if raw_secret and raw_secret != "••••••••":
            store.set_setting("oidc_client_secret", SecretStr(raw_secret), user_id=user_id, ip=ip)


def test_oidc_from_settings(
    session_or_store: Any = None,
    overrides: dict[str, Any] | None = None,
) -> tuple[bool, str, dict[str, Any]]:
    """Test OIDC connectivity using current settings with optional temporary overrides."""
    _, base_config = get_oidc_config(session_or_store)

    if overrides:
        client_sec = overrides.get("oidc_client_secret")
        if not client_sec or client_sec == "••••••••":
            client_sec = base_config.client_secret
        if hasattr(client_sec, "get_secret_value"):
            client_sec_str = client_sec.get_secret_value()
        else:
            client_sec_str = str(client_sec or "")

        test_config = OidcConfig(
            enabled=bool(overrides.get("oidc_enabled", base_config.enabled)),
            provider_name=str(overrides.get("oidc_provider_name", base_config.provider_name)),
            issuer_url=str(overrides.get("oidc_issuer_url", base_config.issuer_url)),
            client_id=str(overrides.get("oidc_client_id", base_config.client_id)),
            client_secret=client_sec_str,
            scopes=str(overrides.get("oidc_scopes", base_config.scopes)),
            username_claim=str(overrides.get("oidc_username_claim", base_config.username_claim)),
            groups_claim=str(overrides.get("oidc_groups_claim", base_config.groups_claim)),
            admin_group=str(overrides.get("oidc_admin_group", base_config.admin_group)),
            operator_group=str(overrides.get("oidc_operator_group", base_config.operator_group)),
            viewer_group=str(overrides.get("oidc_viewer_group", base_config.viewer_group)),
            validate_cert=bool(overrides.get("oidc_validate_cert", base_config.validate_cert)),
            ca_cert_pem=str(overrides.get("oidc_ca_cert_pem", base_config.ca_cert_pem)),
            enforce_mfa=bool(overrides.get("oidc_enforce_mfa", base_config.enforce_mfa)),
        )
    else:
        test_config = base_config

    return check_oidc_connectivity(test_config)
