"""Configuration management and typed settings models for EmberVault."""

from embervault_common.config.base import (
    ConfigurationError,
    EmberVaultSettings,
    FileSecretsSettingsSource,
)
from embervault_common.config.models import (
    AppSettings,
    CommonSettings,
    DatabaseSettings,
    OrchestratorSettings,
    ProxySettings,
    SecuritySettings,
    get_demo_browse_listing,
    is_demo_mode,
)
from embervault_common.config.registry import (
    CONFIG_REGISTRY,
    ConfigKey,
    generate_configuration_docs,
    generate_env_example,
    get_config_by_env,
    get_config_by_name,
    get_gui_overridable_keys,
)

__all__ = [
    "CONFIG_REGISTRY",
    "AppSettings",
    "CommonSettings",
    "ConfigKey",
    "ConfigurationError",
    "DatabaseSettings",
    "EmberVaultSettings",
    "FileSecretsSettingsSource",
    "OrchestratorSettings",
    "ProxySettings",
    "SecuritySettings",
    "generate_configuration_docs",
    "generate_env_example",
    "get_config_by_env",
    "get_config_by_name",
    "get_demo_browse_listing",
    "get_gui_overridable_keys",
    "is_demo_mode",
]
