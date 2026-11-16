"""Base settings class with Docker secrets (*_FILE) resolution and user-friendly error formatting."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TypeVar

from pydantic import SecretStr, ValidationError
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from embervault_common.config.registry import CONFIG_REGISTRY
from embervault_common.security.redaction import register_canary

TSettings = TypeVar("TSettings", bound="EmberVaultSettings")


class ConfigurationError(Exception):
    """Raised when application configuration is missing, invalid, or cannot be loaded."""

    def __init__(self, message: str, errors: Sequence[Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.errors = list(errors or ())


class FileSecretsSettingsSource(PydanticBaseSettingsSource):
    """Custom settings source that resolves *_FILE environment variables."""

    def get_field_value(self, _field: Any, field_name: str) -> tuple[Any, str, bool]:
        # Handled in __call__
        return None, field_name, False

    def __call__(self) -> dict[str, Any]:
        results: dict[str, Any] = {}
        env_prefix = (self.config.get("env_prefix") or "").upper()

        # Build mapping of field names to possible *_FILE env var candidates
        field_to_candidates: dict[str, list[str]] = {}
        for field_name, field_info in self.settings_cls.model_fields.items():
            candidates = [
                f"{env_prefix}{field_name.upper()}_FILE",
                f"{field_name.upper()}_FILE",
            ]
            if field_info.validation_alias:
                if isinstance(field_info.validation_alias, str):
                    candidates.append(f"{field_info.validation_alias.upper()}_FILE")
                elif hasattr(field_info.validation_alias, "choices"):
                    for choice in getattr(field_info.validation_alias, "choices", ()):
                        if isinstance(choice, str):
                            candidates.append(f"{choice.upper()}_FILE")

            # Also check if registry knows about a file_env_var for this name
            for reg in CONFIG_REGISTRY:
                if (
                    reg.name == field_name
                    and reg.file_env_var
                    and reg.file_env_var not in candidates
                ):
                    candidates.append(reg.file_env_var)
            field_to_candidates[field_name] = candidates

        for field_name, candidates in field_to_candidates.items():
            for env_var in candidates:
                if env_var in os.environ:
                    file_path_str = os.environ[env_var].strip()
                    if not file_path_str:
                        continue
                    file_path = Path(file_path_str)
                    if not file_path.is_file():
                        raise ConfigurationError(
                            f"Configuration error: file specified in {env_var}='{file_path_str}' does not exist."
                        )
                    try:
                        content = file_path.read_text(encoding="utf-8").strip()
                        results[field_name] = content
                        if field_info.validation_alias:
                            if isinstance(field_info.validation_alias, str):
                                results[field_info.validation_alias] = content
                            elif hasattr(field_info.validation_alias, "choices"):
                                for choice in getattr(field_info.validation_alias, "choices", ()):
                                    if isinstance(choice, str):
                                        results[choice] = content
                        break
                    except OSError as e:
                        raise ConfigurationError(
                            f"Configuration error: failed to read file in {env_var}='{file_path_str}': {e}"
                        ) from e

        return results


class EmberVaultSettings(BaseSettings):
    """Base class for all EmberVault configuration models."""

    model_config = SettingsConfigDict(
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,  # noqa: ARG003
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # Precedence: init_settings > file_secrets > env_settings > dotenv_settings
        return (
            init_settings,
            FileSecretsSettingsSource(settings_cls),
            env_settings,
            dotenv_settings,
        )

    def model_post_init(self, __context: Any) -> None:
        """Post-initialization hook to automatically register secret canaries."""
        super().model_post_init(__context)
        for field_name, _field_info in self.__class__.model_fields.items():
            val = getattr(self, field_name)
            if isinstance(val, SecretStr):
                secret_str = val.get_secret_value()
                if secret_str:
                    register_canary(secret_str)

    @classmethod
    def load(cls: type[TSettings], **kwargs: Any) -> TSettings:
        """Load and validate configuration, raising ConfigurationError with human-friendly diagnostics on failure."""
        try:
            return cls(**kwargs)
        except ValidationError as e:
            formatted_errors: list[str] = []
            for err in e.errors():
                loc = " -> ".join(str(x) for x in err.get("loc", ()))
                msg = err.get("msg", "invalid value")
                formatted_errors.append(f"  - {loc}: {msg}")

            error_summary = "\n".join(formatted_errors)
            raise ConfigurationError(
                f"Failed to load {cls.__name__} due to invalid or missing configuration:\n{error_summary}",
                errors=e.errors(),
            ) from e
