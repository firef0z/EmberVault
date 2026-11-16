"""Dynamic system settings store with env resolution, validation, caching, audit logging, and NOTIFY."""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Callable
from typing import Any
from uuid import UUID

from pydantic import SecretStr
from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from embervault_common.config.registry import (
    CONFIG_REGISTRY,
    ConfigKey,
    get_config_by_name,
)
from embervault_common.observability import get_logger
from embervault_common.security.crypto import decrypt_blob_to_str, encrypt_blob
from embervault_db.models.auth import AuditLog, Setting
from embervault_db.models.base import utc_now

logger = get_logger("embervault_db.settings_store")

SETTINGS_NOTIFY_CHANNEL = "settings_changed"


class SettingsError(Exception):
    """Base exception for settings store operations."""


class UnknownSettingError(SettingsError):
    """Raised when an unknown setting key is requested or modified."""


class NonOverridableSettingError(SettingsError):
    """Raised when an attempt is made to override a bootstrap or non-overridable setting."""


class InvalidSettingValueError(SettingsError):
    """Raised when a setting value fails type, bounds, or semantic validation."""


def validate_setting_value(key_def: ConfigKey, value: Any) -> Any:
    """Validate and coerce a setting value according to its registry specification.

    Args:
        key_def: Metadata definition from CONFIG_REGISTRY.
        value: Input value to validate.

    Returns:
        Coerced, validated value.

    Raises:
        InvalidSettingValueError: If the value cannot be validated.
    """
    if value is None:
        if key_def.name in ("global_concurrency", "per_job_concurrency"):
            return None
        if key_def.default is not None:
            raise InvalidSettingValueError(f"Setting '{key_def.name}' cannot be None.")
        return None

    if key_def.type_name == "int":
        try:
            int_val = int(value)
        except (ValueError, TypeError) as exc:
            raise InvalidSettingValueError(
                f"Setting '{key_def.name}' must be an integer (got {value!r})."
            ) from exc

        # Semantic range validations for known keys
        if (
            key_def.name
            in (
                "heartbeat_interval_s",
                "offline_after_failures",
                "online_after_successes",
                "per_proxy_concurrency",
                "task_max_attempts",
                "retry_base_s",
                "retry_max_s",
                "proxy_cooldown_s",
                "assignment_timeout_s",
                "lost_after_s",
                "parallel_warn_threshold",
                "parallel_hard_limit",
                "log_retention_days",
                "throughput_retention_days",
                "hooks_timeout_s",
                "rclone_checkers",
                "rclone_transfers",
                "scheduler_tick_s",
                "dispatch_tick_s",
                "http_connect_timeout_s",
                "http_read_timeout_s",
                "proxy_max_concurrent_tasks",
                "proxy_result_retention_s",
                "proxy_orphan_timeout_s",
                "ai_timeout_seconds",
                "discovery_timeout_s",
            )
            and int_val < 1
        ):
            raise InvalidSettingValueError(
                f"Setting '{key_def.name}' must be a positive integer >= 1 (got {int_val})."
            )
        if key_def.name == "ai_timeout_seconds" and int_val > 300:
            raise InvalidSettingValueError(
                f"Setting 'ai_timeout_seconds' non può superare 300 secondi (got {int_val})."
            )
        if key_def.name in ("task_retries", "trusted_proxy_count") and int_val < 0:
            raise InvalidSettingValueError(
                f"Setting '{key_def.name}' must be an integer >= 0 (got {int_val})."
            )
        return int_val

    elif key_def.type_name == "bool":
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            clean = value.strip().lower()
            if clean in ("true", "1", "yes", "on"):
                return True
            if clean in ("false", "0", "no", "off"):
                return False
        raise InvalidSettingValueError(
            f"Setting '{key_def.name}' must be a boolean (got {value!r})."
        )

    elif key_def.type_name == "str":
        if isinstance(value, (list, tuple)) and key_def.name in (
            "rclone_first_level_filters",
            "rclone_second_level_filters",
        ):
            value = "\n".join(str(item) for item in value)
        elif not isinstance(value, str):
            raise InvalidSettingValueError(
                f"Setting '{key_def.name}' must be a string (got {type(value).__name__})."
            )
        cleaned = value.strip()
        if key_def.name == "log_level" and cleaned.upper() not in (
            "DEBUG",
            "INFO",
            "WARNING",
            "ERROR",
            "CRITICAL",
        ):
            raise InvalidSettingValueError(
                f"Setting 'log_level' must be DEBUG, INFO, WARNING, ERROR, or CRITICAL (got {cleaned!r})."
            )
        if key_def.name == "log_format" and cleaned.lower() not in ("json", "console"):
            raise InvalidSettingValueError(
                f"Setting 'log_format' must be 'json' or 'console' (got {cleaned!r})."
            )
        if key_def.name == "portal_language" and cleaned.lower() not in (
            "it",
            "en",
            "de",
            "es",
            "fr",
            "zh",
            "ja",
            "ko",
            "ar",
        ):
            raise InvalidSettingValueError(
                f"Setting 'portal_language' non valido (got {cleaned!r})."
            )
        if key_def.name == "default_locale" and cleaned.lower() not in (
            "it",
            "en",
            "de",
            "es",
            "fr",
            "zh",
            "ja",
            "ko",
            "ar",
        ):
            raise InvalidSettingValueError(
                f"Setting 'default_locale' non valido (got {cleaned!r})."
            )
        if key_def.name == "notification_job_policy" and cleaned.lower() not in (
            "only_errors",
            "always",
        ):
            raise InvalidSettingValueError(
                f"Setting '{key_def.name}' must be 'only_errors' or 'always' (got {cleaned!r})."
            )
        if key_def.name == "default_missed_run_policy" and cleaned.lower() not in (
            "run_once",
            "skip",
            "fail",
        ):
            raise InvalidSettingValueError(
                f"Setting '{key_def.name}' must be 'run_once', 'skip', or 'fail' (got {cleaned!r})."
            )
        if key_def.name == "default_overlap_policy" and cleaned.lower() not in (
            "skip",
            "allow",
            "cancel_previous",
            "queue",
            "fail",
        ):
            raise InvalidSettingValueError(
                f"Setting '{key_def.name}' must be 'skip', 'allow', 'cancel_previous', 'queue', or 'fail' (got {cleaned!r})."
            )
        if key_def.name == "default_pending_policy" and cleaned.lower() not in (
            "fail",
            "retry",
        ):
            raise InvalidSettingValueError(
                f"Setting '{key_def.name}' must be 'fail' or 'retry' (got {cleaned!r})."
            )
        if key_def.name == "ai_provider_type" and cleaned.lower() not in (
            "openai_compatible",
            "ollama",
        ):
            raise InvalidSettingValueError(
                f"Setting 'ai_provider_type' deve essere 'openai_compatible' o 'ollama' (got {cleaned!r})."
            )
        if key_def.name == "trusted_proxies" and cleaned:
            import ipaddress

            parts = [p.strip() for p in cleaned.split(",") if p.strip()]
            for item in parts:
                try:
                    ipaddress.ip_network(item, strict=False)
                except ValueError as exc:
                    raise InvalidSettingValueError(
                        f"Valore non valido per 'trusted_proxies': '{item}' non è un indirizzo IP o subnet valida."
                    ) from exc
        if key_def.name == "log_level":
            return cleaned.upper()
        if key_def.name in (
            "log_format",
            "default_locale",
            "notification_job_policy",
            "default_missed_run_policy",
            "default_overlap_policy",
            "default_pending_policy",
            "ai_provider_type",
            "portal_language",
        ):
            return cleaned.lower()
        return cleaned

    elif key_def.type_name == "SecretStr":
        if hasattr(value, "get_secret_value"):
            return value
        if isinstance(value, str):
            return SecretStr(value)
        raise InvalidSettingValueError(
            f"Setting '{key_def.name}' must be a SecretStr or string (got {type(value).__name__})."
        )

    return value


class SettingsStore:
    """Manages system settings resolution (Default < Env < GUI), persistence, caching, and audit trail."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        cache_ttl_s: float = 10.0,
    ) -> None:
        self.session_factory = session_factory
        self.cache_ttl_s = cache_ttl_s

        self._cache: dict[str, Any] = {}
        self._cache_timestamp: float = 0.0
        self._cache_lock = threading.Lock()
        self._listeners: list[Callable[[str], None]] = []

    def register_change_listener(self, listener: Callable[[str], None]) -> None:
        """Register a callback invoked whenever a setting is updated or deleted."""
        self._listeners.append(listener)

    def _notify_change(self, session: Session, key: str) -> None:
        """Notify cluster and local listeners of a setting change."""
        payload = json.dumps({"key": key, "ts": time.time()})
        bind = session.get_bind()
        dialect_name = bind.dialect.name if bind else "unknown"

        if dialect_name == "postgresql":
            try:
                session.execute(
                    text("SELECT pg_notify(:channel, :payload)"),
                    {"channel": SETTINGS_NOTIFY_CHANNEL, "payload": payload},
                )
            except Exception as exc:
                logger.warning("pg_notify_settings_changed_failed", error=str(exc))

        # Local in-memory listeners
        for listener in self._listeners:
            try:
                listener(key)
            except Exception as exc:
                logger.error("settings_listener_error", key=key, error=str(exc))

    def invalidate_cache(self) -> None:
        """Invalidate the local in-memory settings cache."""
        with self._cache_lock:
            self._cache.clear()
            self._cache_timestamp = 0.0

    def _refresh_cache_if_needed(self) -> None:
        """Reload settings from the database if TTL has expired."""
        now = time.monotonic()
        if now - self._cache_timestamp < self.cache_ttl_s:
            return

        with self._cache_lock:
            if now - self._cache_timestamp < self.cache_ttl_s:
                return

            with self.session_factory() as session:
                stmt = select(Setting)
                rows = list(session.scalars(stmt).all())
                new_cache: dict[str, Any] = {}
                for row in rows:
                    if row.value_encrypted is not None:
                        try:
                            aad = f"setting:{row.key}".encode()
                            decrypted = decrypt_blob_to_str(row.value_encrypted, aad=aad)
                            key_def = get_config_by_name(row.key)
                            if key_def and key_def.type_name == "SecretStr":
                                new_cache[row.key] = SecretStr(decrypted)
                            else:
                                new_cache[row.key] = decrypted
                        except Exception as exc:
                            logger.error("setting_decrypt_failed", key=row.key, error=str(exc))
                            new_cache[row.key] = None
                    else:
                        new_cache[row.key] = row.value

                self._cache = new_cache
                self._cache_timestamp = now

    def get_setting(self, key_name: str, fallback_to_env: bool = True) -> Any:
        """Resolve a setting following hierarchy: Default < Env < GUI.

        Args:
            key_name: Setting key name.
            fallback_to_env: If True, falls back to env variable or default when GUI row is absent.

        Returns:
            Resolved setting value.

        Raises:
            UnknownSettingError: If the key is not declared in CONFIG_REGISTRY.
        """
        key_def = get_config_by_name(key_name)
        if key_def is None:
            raise UnknownSettingError(f"Setting '{key_name}' is not declared in CONFIG_REGISTRY.")

        # 1. Check GUI overrides (if key is overridable)
        if key_def.overridable_from_gui:
            self._refresh_cache_if_needed()
            with self._cache_lock:
                if key_name in self._cache:
                    return self._cache[key_name]

        if not fallback_to_env:
            return None

        # 2. Check Environment Variable (and *_FILE)
        if key_def.file_env_var and key_def.file_env_var in os.environ:
            file_path = os.environ[key_def.file_env_var].strip()
            if os.path.isfile(file_path):
                with open(file_path, encoding="utf-8") as f:
                    raw_val = f.read().strip()
                return validate_setting_value(key_def, raw_val)

        if key_def.env_var in os.environ:
            raw_val = os.environ[key_def.env_var].strip()
            if raw_val or key_def.type_name != "int":
                return validate_setting_value(key_def, raw_val)

        # 3. Code default
        return key_def.default

    def get_all_resolved_settings(self) -> dict[str, Any]:
        """Resolve all registered settings returning dictionary of key -> resolved value."""
        return {key_def.name: self.get_setting(key_def.name) for key_def in CONFIG_REGISTRY}

    def get_dynamic_orchestrator_settings(self) -> dict[str, Any]:
        """Return all overridable settings governing orchestrator execution."""
        return {
            key_def.name: self.get_setting(key_def.name)
            for key_def in CONFIG_REGISTRY
            if key_def.service == "orchestrator" and key_def.overridable_from_gui
        }

    def set_setting(
        self,
        key_name: str,
        value: Any,
        user_id: UUID | None = None,
        ip: str | None = None,
    ) -> Setting:
        """Save or update a GUI configuration setting with audit logging and notification.

        Args:
            key_name: Canonical setting name.
            value: New value to set.
            user_id: Actor UUID performing the update.
            ip: Originating client IP.

        Returns:
            Updated Setting database model.

        Raises:
            UnknownSettingError: If the key does not exist.
            NonOverridableSettingError: If the key is bootstrap or not overridable.
            InvalidSettingValueError: If value validation fails.
        """
        key_def = get_config_by_name(key_name)
        if key_def is None:
            raise UnknownSettingError(f"Setting '{key_name}' is not declared in CONFIG_REGISTRY.")

        if not key_def.overridable_from_gui:
            raise NonOverridableSettingError(
                f"Setting '{key_name}' is a bootstrap parameter and cannot be overridden from GUI."
            )

        clean_value = validate_setting_value(key_def, value)

        with self.session_factory() as session:
            setting = session.get(Setting, key_name)
            old_value: Any = None
            is_new = setting is None

            if setting is not None:
                old_value = setting.value if setting.value_encrypted is None else "[ENCRYPTED]"
            else:
                setting = Setting(key=key_name)
                session.add(setting)

            # Determine whether the setting value was actually modified
            is_modified = True
            if not is_new:
                if key_def.secret:
                    if setting.value_encrypted is not None and clean_value is not None:
                        try:
                            aad = f"setting:{key_name}".encode()
                            old_secret_str = decrypt_blob_to_str(setting.value_encrypted, aad=aad)
                            raw_new = (
                                clean_value.get_secret_value()
                                if hasattr(clean_value, "get_secret_value")
                                else str(clean_value)
                            )
                            if old_secret_str == raw_new:
                                is_modified = False
                        except Exception:
                            is_modified = True
                    elif setting.value_encrypted is None and clean_value is None:
                        is_modified = False
                else:
                    if old_value == clean_value:
                        is_modified = False

            if key_def.secret and clean_value is not None:
                aad = f"setting:{key_name}".encode()
                raw_to_encrypt = (
                    clean_value.get_secret_value()
                    if hasattr(clean_value, "get_secret_value")
                    else str(clean_value)
                )
                setting.value_encrypted = encrypt_blob(raw_to_encrypt, aad=aad)
                setting.value = None
            else:
                setting.value = clean_value
                setting.value_encrypted = None

            setting.updated_by = user_id
            setting.updated_at = utc_now()

            # Record Audit Log only when newly created or value is actually modified
            if is_new or is_modified:
                audit_details: dict[str, Any] = {
                    "old_value": old_value,
                    "new_value": "[ENCRYPTED]" if key_def.secret else clean_value,
                    "requires_restart": key_def.requires_restart,
                }
                audit_entry = AuditLog(
                    actor_user_id=user_id,
                    action="setting.create" if is_new else "setting.update",
                    entity_type="setting",
                    entity_id=key_name,
                    details=audit_details,
                    ip=ip,
                )
                session.add(audit_entry)

            if is_new or is_modified:
                self._notify_change(session, key_name)
            session.commit()

        if is_new or is_modified:
            self.invalidate_cache()
            logger.info(
                "setting_updated",
                key=key_name,
                requires_restart=key_def.requires_restart,
                user_id=str(user_id) if user_id else None,
            )
        return setting

    def delete_setting(
        self,
        key_name: str,
        user_id: UUID | None = None,
        ip: str | None = None,
    ) -> bool:
        """Remove a GUI setting override, reverting resolution to environment or default."""
        key_def = get_config_by_name(key_name)
        if key_def is None:
            raise UnknownSettingError(f"Setting '{key_name}' is not declared in CONFIG_REGISTRY.")

        if not key_def.overridable_from_gui:
            raise NonOverridableSettingError(
                f"Setting '{key_name}' is a bootstrap parameter and cannot be deleted via GUI."
            )

        with self.session_factory() as session:
            setting = session.get(Setting, key_name)
            if setting is None:
                return False

            old_val = setting.value if setting.value_encrypted is None else "[ENCRYPTED]"
            session.delete(setting)

            audit_entry = AuditLog(
                actor_user_id=user_id,
                action="setting.delete",
                entity_type="setting",
                entity_id=key_name,
                details={"reverted_value": old_val},
                ip=ip,
            )
            session.add(audit_entry)
            self._notify_change(session, key_name)
            session.commit()

        self.invalidate_cache()
        logger.info("setting_deleted", key=key_name, user_id=str(user_id) if user_id else None)
        return True

    def reencrypt_secret_settings(self, new_key_id: str | None = None) -> int:
        """Re-encrypt all encrypted settings using the target or primary key.

        Returns the number of re-encrypted settings.
        """
        from embervault_common.security.crypto import reencrypt_blob

        reencrypted_count = 0
        with self.session_factory() as session:
            stmt = select(Setting).where(Setting.value_encrypted.is_not(None))
            settings = list(session.scalars(stmt).all())
            for s in settings:
                if s.value_encrypted is not None:
                    aad = f"setting:{s.key}".encode()
                    reencrypted = reencrypt_blob(s.value_encrypted, new_key_id=new_key_id, aad=aad)
                    if reencrypted != s.value_encrypted:
                        s.value_encrypted = reencrypted
                        reencrypted_count += 1
            if reencrypted_count > 0:
                session.commit()
                self.invalidate_cache()
        return reencrypted_count
