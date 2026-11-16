"""Tests for EmberVault typed configuration, *_FILE resolution, and validation."""

import os
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from embervault_common.config import (
    AppSettings,
    CommonSettings,
    ConfigurationError,
    DatabaseSettings,
    OrchestratorSettings,
    ProxySettings,
    SecuritySettings,
    get_config_by_env,
    get_config_by_name,
    get_gui_overridable_keys,
)


@pytest.fixture(autouse=True)
def clean_env() -> Generator[None, None, None]:
    """Ensure environment is cleaned up after each test."""
    original_env = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(original_env)


def test_registry_helpers() -> None:
    """Test helper functions to query the configuration registry."""
    key = get_config_by_name("env")
    assert key is not None
    assert key.env_var == "EMBERVAULT_ENV"

    by_env = get_config_by_env("POSTGRES_PASSWORD")
    assert by_env is not None
    assert by_env.name == "postgres_password"
    assert by_env.secret is True

    gui_keys = get_gui_overridable_keys()
    assert len(gui_keys) == 107
    assert any(k.name == "default_missed_run_policy" for k in gui_keys)
    assert any(k.name == "default_overlap_policy" for k in gui_keys)
    assert any(k.name == "default_pending_policy" for k in gui_keys)
    assert any(k.name == "discovery_timeout_s" for k in gui_keys)
    assert any(k.name == "log_level" for k in gui_keys)
    assert any(k.name == "public_url" for k in gui_keys)
    assert any(k.name == "ai_enabled" for k in gui_keys)
    assert any(k.name == "ai_error_handling_enabled" for k in gui_keys)
    assert any(k.name == "ai_reporting_analysis_enabled" for k in gui_keys)
    assert any(k.name == "default_locale" for k in gui_keys)
    assert any(k.name == "trusted_proxies" for k in gui_keys)
    assert any(k.name == "heartbeat_interval_s" for k in gui_keys)
    assert any(k.name == "notifications_enabled" for k in gui_keys)
    assert any(k.name == "notification_job_policy" for k in gui_keys)
    assert any(k.name == "notification_proxy_offline_enabled" for k in gui_keys)
    assert any(k.name == "ldap_enabled" for k in gui_keys)
    assert any(k.name == "ldap_validate_cert" for k in gui_keys)
    assert any(k.name == "ldap_ca_cert_pem" for k in gui_keys)
    assert any(k.name == "ldap_viewer_group" for k in gui_keys)
    assert any(k.name == "oidc_enabled" for k in gui_keys)
    assert any(k.name == "oidc_provider_name" for k in gui_keys)
    assert any(k.name == "oidc_issuer_url" for k in gui_keys)
    assert any(k.name == "oidc_enforce_mfa" for k in gui_keys)
    assert any(k.name == "login_custom_background" for k in gui_keys)
    assert not any(k.name == "postgres_password" for k in gui_keys)
    assert not any(k.name == "database_url" for k in gui_keys)
    assert not any(k.name == "master_key" for k in gui_keys)


def test_common_settings_defaults_and_env() -> None:
    """Test CommonSettings default values and environment overrides."""
    s = CommonSettings()
    assert s.env == "dev"
    assert s.log_level == "INFO"
    assert s.log_format == "json"

    os.environ["EMBERVAULT_ENV"] = "prod"
    os.environ["EMBERVAULT_LOG_LEVEL"] = "debug"
    os.environ["EMBERVAULT_LOG_FORMAT"] = "console"

    s2 = CommonSettings()
    assert s2.env == "prod"
    assert s2.log_level == "DEBUG"
    assert s2.log_format == "console"

    os.environ["EMBERVAULT_ENV"] = "production"
    assert CommonSettings().env == "prod"

    os.environ["EMBERVAULT_ENV"] = "development"
    assert CommonSettings().env == "dev"


def test_common_settings_invalid_log_level() -> None:
    """Test that invalid log_level raises ConfigurationError."""
    with pytest.raises(ConfigurationError) as exc_info:
        CommonSettings.load(log_level="SUPER_VERBOSE")
    assert "Invalid log_level" in str(exc_info.value)


def test_database_settings_url_resolution() -> None:
    """Test PostgreSQL connection URL resolution logic."""
    db = DatabaseSettings(
        postgres_host="pg.internal",
        postgres_port=5433,
        postgres_user="testuser",
        postgres_password="testpassword",  # type: ignore[arg-type]
        postgres_db="testdb",
    )
    assert (
        db.resolved_database_url
        == "postgresql+psycopg://testuser:testpassword@pg.internal:5433/testdb"
    )

    # Explicit database_url takes precedence
    db2 = DatabaseSettings(
        database_url="postgresql+psycopg://custom:secret@db.external:5432/customdb",  # type: ignore[arg-type]
    )
    assert (
        db2.resolved_database_url == "postgresql+psycopg://custom:secret@db.external:5432/customdb"
    )


def test_file_secrets_resolution_and_precedence() -> None:
    """Test reading secrets from files via *_FILE environment variables."""
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write("  secret_from_file_with_spaces  \n")
        file_path = f.name

    try:
        # File secret should take precedence over env var
        os.environ["POSTGRES_PASSWORD"] = "plain_env_password"
        os.environ["POSTGRES_PASSWORD_FILE"] = file_path

        db = DatabaseSettings()
        assert db.postgres_password.get_secret_value() == "secret_from_file_with_spaces"
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_missing_file_secret_raises_configuration_error() -> None:
    """Test that specifying a non-existent secret file raises a clear ConfigurationError."""
    os.environ["POSTGRES_PASSWORD_FILE"] = "/path/to/non_existent_secret_file.txt"

    with pytest.raises(ConfigurationError) as exc_info:
        DatabaseSettings.load()
    assert "does not exist" in str(exc_info.value)
    assert "/path/to/non_existent_secret_file.txt" in str(exc_info.value)


def test_security_settings_master_key_validation() -> None:
    """Test master key length validation."""
    with pytest.raises(ConfigurationError) as exc_info:
        SecuritySettings.load(master_key="short")
    assert "EMBERVAULT_MASTER_KEY must be at least 16 characters" in str(exc_info.value)

    sec = SecuritySettings.load(
        master_key="0123456789abcdef0123456789abcdef",
    )
    assert sec.master_key is not None
    assert sec.master_key.get_secret_value() == "0123456789abcdef0123456789abcdef"


def test_proxy_settings_token_validation() -> None:
    """Test proxy TOKEN length validation and requirements."""
    # Token < 32 characters must fail
    with pytest.raises(ConfigurationError) as exc_info:
        ProxySettings.load(token="too_short_token")
    assert "at least 32 characters long" in str(exc_info.value)

    # Valid token >= 32 characters succeeds
    valid_token = "a" * 32
    proxy = ProxySettings.load(token=valid_token)
    assert proxy.token.get_secret_value() == valid_token
    assert proxy.proxy_port == 8443
    assert proxy.proxy_max_concurrent_tasks == 1


def test_proxy_token_file_loading() -> None:
    """Test loading proxy TOKEN via TOKEN_FILE."""
    valid_token = "b" * 48
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(f"\n  {valid_token}  \n")
        file_path = f.name

    try:
        os.environ["TOKEN_FILE"] = file_path
        proxy = ProxySettings.load()
        assert proxy.token.get_secret_value() == valid_token
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_app_and_orchestrator_settings() -> None:
    """Test loading AppSettings and OrchestratorSettings."""
    app = AppSettings()
    assert app.app_port == 8080
    assert app.default_locale == "en"

    orch = OrchestratorSettings()
    assert orch.heartbeat_interval_s == 15
    assert orch.per_proxy_concurrency == 1
    assert orch.parallel_warn_threshold == 50
    assert orch.parallel_hard_limit == 500
