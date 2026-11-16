"""Typed Pydantic configuration models for EmberVault services."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import SettingsConfigDict

from embervault_common.config.base import EmberVaultSettings

VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


class CommonSettings(EmberVaultSettings):
    """Common configuration shared by all EmberVault services."""

    model_config = SettingsConfigDict(
        env_prefix="EMBERVAULT_",
        extra="ignore",
    )

    env: Literal["dev", "prod"] = "dev"
    log_level: str = "INFO"
    log_format: Literal["json", "console"] = "json"
    demo_mode: bool = False

    @field_validator("env", mode="before")
    @classmethod
    def normalize_env(cls, v: Any) -> Any:
        if isinstance(v, str):
            lower_v = v.strip().lower()
            if lower_v == "production":
                return "prod"
            if lower_v == "development":
                return "dev"
            return lower_v
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        upper_v = v.upper().strip()
        if upper_v not in VALID_LOG_LEVELS:
            raise ValueError(
                f"Invalid log_level '{v}'. Must be one of: {', '.join(sorted(VALID_LOG_LEVELS))}"
            )
        return upper_v


class DatabaseSettings(EmberVaultSettings):
    """Database connection configuration for PostgreSQL."""

    model_config = SettingsConfigDict(
        extra="ignore",
    )

    database_url: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("DATABASE_URL", "EMBERVAULT_DATABASE_URL"),
    )
    postgres_host: str = Field(
        default="postgres",
        validation_alias=AliasChoices("POSTGRES_HOST", "EMBERVAULT_POSTGRES_HOST"),
    )
    postgres_port: int = Field(
        default=5432,
        ge=1,
        le=65535,
        validation_alias=AliasChoices("POSTGRES_PORT", "EMBERVAULT_POSTGRES_PORT"),
    )
    postgres_db: str = Field(
        default="embervault",
        validation_alias=AliasChoices("POSTGRES_DB", "EMBERVAULT_POSTGRES_DB"),
    )
    postgres_user: str = Field(
        default="embervault",
        validation_alias=AliasChoices("POSTGRES_USER", "EMBERVAULT_POSTGRES_USER"),
    )
    postgres_password: SecretStr = Field(
        default=SecretStr(""),
        validation_alias=AliasChoices("POSTGRES_PASSWORD", "EMBERVAULT_POSTGRES_PASSWORD"),
    )

    @property
    def resolved_database_url(self) -> str:
        """Return the effective PostgreSQL connection URL."""
        if self.database_url and self.database_url.get_secret_value():
            return self.database_url.get_secret_value()

        pw = self.postgres_password.get_secret_value()
        auth = f"{self.postgres_user}:{pw}" if pw else self.postgres_user
        return f"postgresql+psycopg://{auth}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"


class SecuritySettings(EmberVaultSettings):
    """Cryptographic and internal security credentials."""

    model_config = SettingsConfigDict(
        env_prefix="EMBERVAULT_",
        extra="ignore",
    )

    master_key: SecretStr | None = None
    master_key_id: str = "v1"
    master_keys: SecretStr | None = None
    secret_key: SecretStr | None = None
    internal_api_token: SecretStr | None = None

    @field_validator("master_key")
    @classmethod
    def validate_master_key(cls, v: SecretStr | None) -> SecretStr | None:
        if v is not None:
            raw = v.get_secret_value().strip()
            if raw and len(raw) < 16:
                raise ValueError("EMBERVAULT_MASTER_KEY must be at least 16 characters long.")
        return v


class AppSettings(CommonSettings):
    """Web UI application service configuration."""

    app_bind: str = "0.0.0.0"
    app_port: int = Field(default=8080, ge=1, le=65535)
    public_url: str = "http://localhost:8080"
    portal_url: str = ""
    session_cookie_secure: bool = False
    default_locale: str = "en"
    trusted_proxy_count: int = Field(default=0, ge=0)
    trusted_proxies: str = ""
    dev_noauth: bool = False


class OrchestratorSettings(CommonSettings):
    """Orchestrator service configuration (including dynamic settings)."""

    # Dynamic GUI overridable parameters
    min_proxy_version: str = "1.0.0"
    heartbeat_interval_s: int = Field(default=15, ge=1)
    offline_after_failures: int = Field(default=3, ge=1)
    online_after_successes: int = Field(default=2, ge=1)
    global_concurrency: int | None = Field(default=None, ge=1)
    per_proxy_concurrency: int = Field(default=1, ge=1)
    per_job_concurrency: int | None = Field(default=None, ge=1)
    task_max_attempts: int = Field(default=3, ge=1)
    retry_base_s: int = Field(default=30, ge=1)
    retry_max_s: int = Field(default=900, ge=1)
    proxy_cooldown_s: int = Field(default=60, ge=1)
    assignment_timeout_s: int = Field(default=600, ge=1)
    lost_after_s: int = Field(default=120, ge=1)
    parallel_warn_threshold: int = Field(default=50, ge=1)
    parallel_hard_limit: int = Field(default=500, ge=1)
    discovery_timeout_s: int = Field(default=30, ge=1)
    log_retention_days: int = Field(default=30, ge=1)
    throughput_retention_days: int = Field(default=7, ge=1)
    hooks_enabled: bool = False
    hooks_timeout_s: int = Field(default=60, ge=1)
    hook_runner_url: str = ""

    # Static env-only parameters
    orch_bind: str = "0.0.0.0"
    orch_port: int = Field(default=8081, ge=1, le=65535)
    orch_metrics_port: int = Field(default=9091, ge=1, le=65535)
    scheduler_tick_s: int = Field(default=5, ge=1)
    dispatch_tick_s: int = Field(default=2, ge=1)
    http_connect_timeout_s: int = Field(default=5, ge=1)
    http_read_timeout_s: int = Field(default=10, ge=1)


class ProxySettings(CommonSettings):
    """Proxy execution agent service configuration."""

    model_config = SettingsConfigDict(
        extra="ignore",
    )

    token: SecretStr = Field(
        validation_alias=AliasChoices("TOKEN", "EMBERVAULT_TOKEN"),
    )
    previous_token: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "EMBERVAULT_PROXY_PREVIOUS_TOKEN", "PROXY_PREVIOUS_TOKEN", "PREVIOUS_TOKEN"
        ),
    )
    proxy_bind: str = Field(
        default="0.0.0.0",
        validation_alias=AliasChoices("EMBERVAULT_PROXY_BIND", "PROXY_BIND"),
    )
    proxy_port: int = Field(
        default=8443,
        ge=1,
        le=65535,
        validation_alias=AliasChoices("EMBERVAULT_PROXY_PORT", "PROXY_PORT"),
    )
    proxy_tls_cert_file: Path | None = Field(
        default=None,
        validation_alias=AliasChoices("EMBERVAULT_PROXY_TLS_CERT_FILE", "PROXY_TLS_CERT_FILE"),
    )
    proxy_tls_key_file: Path | None = Field(
        default=None,
        validation_alias=AliasChoices("EMBERVAULT_PROXY_TLS_KEY_FILE", "PROXY_TLS_KEY_FILE"),
    )
    proxy_tls_auto_self_signed: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "EMBERVAULT_PROXY_TLS_AUTO_SELF_SIGNED", "PROXY_TLS_AUTO_SELF_SIGNED"
        ),
    )
    proxy_max_concurrent_tasks: int = Field(
        default=1,
        ge=1,
        validation_alias=AliasChoices(
            "EMBERVAULT_PROXY_MAX_CONCURRENT_TASKS", "PROXY_MAX_CONCURRENT_TASKS"
        ),
    )
    proxy_state_dir: Path = Field(
        default=Path("/var/lib/embervault/proxy"),
        validation_alias=AliasChoices("EMBERVAULT_PROXY_STATE_DIR", "PROXY_STATE_DIR"),
    )
    proxy_result_retention_s: int = Field(
        default=3600,
        ge=60,
        validation_alias=AliasChoices(
            "EMBERVAULT_PROXY_RESULT_RETENTION_S", "PROXY_RESULT_RETENTION_S"
        ),
    )
    proxy_orphan_timeout_s: int = Field(
        default=300,
        ge=30,
        validation_alias=AliasChoices(
            "EMBERVAULT_PROXY_ORPHAN_TIMEOUT_S", "PROXY_ORPHAN_TIMEOUT_S"
        ),
    )
    proxy_rclone_bin: str = Field(
        default="rclone",
        validation_alias=AliasChoices("EMBERVAULT_PROXY_RCLONE_BIN", "PROXY_RCLONE_BIN"),
    )

    @field_validator("token", "previous_token")
    @classmethod
    def validate_token(cls, v: SecretStr | None) -> SecretStr | None:
        if v is None:
            return None
        val = v.get_secret_value().strip()
        if len(val) < 32:
            raise ValueError(
                f"Proxy TOKEN is required and must be at least 32 characters long (received {len(val)} characters)."
            )
        return v


def is_demo_mode(settings: Any = None) -> bool:
    """Return whether EmberVault is running in demo mode.

    Activatable exclusively via the EMBERVAULT_DEMO_MODE environment variable.
    """
    import os

    if settings is not None:
        if hasattr(settings, "demo_mode"):
            return bool(settings.demo_mode)
        if hasattr(settings, "get_setting"):
            val = settings.get_setting("demo_mode")
            if val is not None:
                if isinstance(val, bool):
                    return val
                return str(val).strip().lower() in ("1", "true", "yes", "on")
    val = os.environ.get("EMBERVAULT_DEMO_MODE", "").strip().lower()
    return val in ("1", "true", "yes", "on")


def get_demo_browse_listing(path: str = "") -> dict[str, Any]:
    """Generate simulated directory and file tree for Demo Mode."""
    clean = str(path or "").strip("/").strip()
    if not clean:
        directories = ["documents", "media", "projects", "database"]
        directory_details = [
            {"name": "documents", "size": 0, "mod_time": "2026-11-15T00:00:00Z"},
            {"name": "media", "size": 0, "mod_time": "2026-11-15T00:00:00Z"},
            {"name": "projects", "size": 0, "mod_time": "2026-11-15T00:00:00Z"},
            {"name": "database", "size": 0, "mod_time": "2026-11-15T00:00:00Z"},
        ]
        files = [
            {"name": "backup_manifest.json", "size": 2048, "mod_time": "2026-11-15T00:00:00Z"},
            {"name": "system_info.txt", "size": 1024, "mod_time": "2026-11-15T00:00:00Z"},
        ]
    elif clean == "documents":
        directories = ["invoices", "reports"]
        directory_details = [
            {"name": "invoices", "size": 0, "mod_time": "2026-11-15T00:00:00Z"},
            {"name": "reports", "size": 0, "mod_time": "2026-11-15T00:00:00Z"},
        ]
        files = [
            {"name": "annual_summary_2026.pdf", "size": 1548576, "mod_time": "2026-11-15T00:00:00Z"},
            {"name": "notes.docx", "size": 34512, "mod_time": "2026-11-15T00:00:00Z"},
        ]
    elif clean == "media":
        directories = ["photos", "videos"]
        directory_details = [
            {"name": "photos", "size": 0, "mod_time": "2026-11-15T00:00:00Z"},
            {"name": "videos", "size": 0, "mod_time": "2026-11-15T00:00:00Z"},
        ]
        files = [
            {"name": "banner.webp", "size": 524288, "mod_time": "2026-11-15T00:00:00Z"},
            {"name": "logo.png", "size": 102400, "mod_time": "2026-11-15T00:00:00Z"},
        ]
    elif clean == "database":
        directories = []
        directory_details = []
        files = [
            {"name": "dump.sql", "size": 10485760, "mod_time": "2026-11-15T00:00:00Z"},
            {"name": "schema.sql", "size": 20480, "mod_time": "2026-11-15T00:00:00Z"},
        ]
    else:
        directories = []
        directory_details = []
        files = [
            {"name": "readme.txt", "size": 512, "mod_time": "2026-11-15T00:00:00Z"},
        ]

    return {
        "status": "ok",
        "path": clean,
        "directories": directories,
        "directory_details": directory_details,
        "files": files,
    }


