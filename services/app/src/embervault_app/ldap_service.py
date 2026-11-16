"""LDAP integration service for EmberVault Web Application (Milestone M4).

Provides:
- Resolution of LDAP configuration from SettingsStore / environment.
- Persistence of LDAP configuration changes with audit logging.
- Connection testing and diagnostic reporting.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING, Any
from uuid import UUID

import structlog
from flask import current_app, has_app_context
from pydantic import SecretStr

from embervault_common.security.ldap import LdapConfig, test_ldap_connection
from embervault_db.settings_store import SettingsStore

if TYPE_CHECKING:
    pass

logger = structlog.get_logger("embervault_app.ldap_service")


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


def get_ldap_config(session_or_store: Any = None) -> tuple[bool, LdapConfig]:
    """Retrieve resolved LDAP configuration from SettingsStore.

    Returns:
        (is_enabled: bool, config: LdapConfig)
    """
    store = _resolve_store(session_or_store)
    enabled = bool(store.get_setting("ldap_enabled"))

    bind_pwd = store.get_setting("ldap_bind_password")
    if isinstance(bind_pwd, SecretStr) or hasattr(bind_pwd, "get_secret_value"):
        bind_pwd_str = bind_pwd.get_secret_value()
    else:
        bind_pwd_str = str(bind_pwd or "")

    config = LdapConfig(
        server_url=str(store.get_setting("ldap_server_url")),
        require_tls=bool(store.get_setting("ldap_require_tls")),
        bind_dn=str(store.get_setting("ldap_bind_dn") or ""),
        bind_password=bind_pwd_str,
        base_dn=str(store.get_setting("ldap_base_dn") or ""),
        user_filter=str(store.get_setting("ldap_user_filter")),
        group_attribute=str(store.get_setting("ldap_group_attribute")),
        admin_group=str(store.get_setting("ldap_admin_group") or ""),
        operator_group=str(store.get_setting("ldap_operator_group") or ""),
        viewer_group=str(store.get_setting("ldap_viewer_group") or ""),
        connect_timeout_s=int(store.get_setting("ldap_connect_timeout_s") or 5),
        validate_cert=bool(store.get_setting("ldap_validate_cert")),
        ca_cert_pem=str(store.get_setting("ldap_ca_cert_pem") or ""),
    )
    return enabled, config


def save_ldap_config(
    session: Any = None,
    data: dict[str, Any] | None = None,
    user_id: UUID | None = None,
    ip: str | None = None,
) -> None:
    """Save or update LDAP configuration keys in SettingsStore."""
    store = _resolve_store(session)
    data = data or {}

    string_keys = [
        "ldap_server_url",
        "ldap_bind_dn",
        "ldap_base_dn",
        "ldap_user_filter",
        "ldap_group_attribute",
        "ldap_admin_group",
        "ldap_operator_group",
        "ldap_viewer_group",
        "ldap_ca_cert_pem",
    ]
    for key in string_keys:
        if key in data:
            store.set_setting(key, str(data[key]).strip(), user_id=user_id, ip=ip)

    if "ldap_enabled" in data:
        store.set_setting("ldap_enabled", bool(data["ldap_enabled"]), user_id=user_id, ip=ip)

    if "ldap_require_tls" in data:
        store.set_setting(
            "ldap_require_tls", bool(data["ldap_require_tls"]), user_id=user_id, ip=ip
        )

    if "ldap_validate_cert" in data:
        store.set_setting(
            "ldap_validate_cert", bool(data["ldap_validate_cert"]), user_id=user_id, ip=ip
        )

    if "ldap_connect_timeout_s" in data:
        try:
            timeout_val = int(data["ldap_connect_timeout_s"])
            store.set_setting(
                "ldap_connect_timeout_s", max(1, min(60, timeout_val)), user_id=user_id, ip=ip
            )
        except (ValueError, TypeError):
            pass

    # Only update bind password if provided and non-empty
    if "ldap_bind_password" in data:
        raw_pwd = str(data["ldap_bind_password"]).strip()
        if raw_pwd and raw_pwd != "••••••••":
            store.set_setting("ldap_bind_password", SecretStr(raw_pwd), user_id=user_id, ip=ip)


def test_ldap_from_settings(
    session_or_store: Any = None,
    overrides: dict[str, Any] | None = None,
) -> tuple[bool, str, dict[str, Any]]:
    """Test LDAP connection using current settings with optional temporary overrides."""
    _, base_config = get_ldap_config(session_or_store)

    if overrides:
        bind_pwd = overrides.get("ldap_bind_password")
        if not bind_pwd or bind_pwd == "••••••••":
            bind_pwd = base_config.bind_password
        if hasattr(bind_pwd, "get_secret_value"):
            bind_pwd_str = bind_pwd.get_secret_value()
        else:
            bind_pwd_str = str(bind_pwd or "")

        config = LdapConfig(
            server_url=str(overrides.get("ldap_server_url", base_config.server_url)),
            require_tls=bool(overrides.get("ldap_require_tls", base_config.require_tls)),
            bind_dn=str(overrides.get("ldap_bind_dn", base_config.bind_dn) or "").strip(),
            bind_password=bind_pwd_str,
            base_dn=str(overrides.get("ldap_base_dn", base_config.base_dn) or ""),
            user_filter=str(overrides.get("ldap_user_filter", base_config.user_filter)),
            group_attribute=str(overrides.get("ldap_group_attribute", base_config.group_attribute)),
            admin_group=str(overrides.get("ldap_admin_group", base_config.admin_group) or ""),
            operator_group=str(
                overrides.get("ldap_operator_group", base_config.operator_group) or ""
            ),
            viewer_group=str(overrides.get("ldap_viewer_group", base_config.viewer_group) or ""),
            connect_timeout_s=int(
                overrides.get("ldap_connect_timeout_s", base_config.connect_timeout_s)
            ),
            validate_cert=bool(overrides.get("ldap_validate_cert", base_config.validate_cert)),
            ca_cert_pem=str(overrides.get("ldap_ca_cert_pem", base_config.ca_cert_pem) or ""),
        )
    else:
        config = base_config

    return test_ldap_connection(config)
