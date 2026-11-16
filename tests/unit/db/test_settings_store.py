"""Unit tests for SettingsStore: resolution precedence, validation, audit logging, and caching."""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models.auth import AuditLog
from embervault_db.models.base import Base
from embervault_db.settings_store import (
    InvalidSettingValueError,
    NonOverridableSettingError,
    SettingsStore,
    UnknownSettingError,
)


@pytest.fixture
def db_session_factory() -> sessionmaker[Session]:
    set_default_key_ring(KeyRing(keys={"v1": "test_settings_master_key_16_chars"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture
def settings_store(db_session_factory: sessionmaker[Session]) -> SettingsStore:
    return SettingsStore(session_factory=db_session_factory, cache_ttl_s=10.0)


class TestSettingsStorePrecedence:
    """Test resolution order: Default < Environment < GUI."""

    def test_default_value_when_unset(self, settings_store: SettingsStore) -> None:
        # Default for heartbeat_interval_s is 15
        os.environ.pop("EMBERVAULT_HEARTBEAT_INTERVAL_S", None)
        val = settings_store.get_setting("heartbeat_interval_s")
        assert val == 15

    def test_env_var_overrides_default(
        self, settings_store: SettingsStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("EMBERVAULT_HEARTBEAT_INTERVAL_S", "25")
        settings_store.invalidate_cache()
        val = settings_store.get_setting("heartbeat_interval_s")
        assert val == 25

    def test_gui_setting_overrides_env_and_default(
        self, settings_store: SettingsStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("EMBERVAULT_HEARTBEAT_INTERVAL_S", "25")
        user_id = uuid4()

        # Save GUI override
        settings_store.set_setting("heartbeat_interval_s", 45, user_id=user_id)

        # Resolution returns GUI value (45) instead of env (25) or default (15)
        val = settings_store.get_setting("heartbeat_interval_s")
        assert val == 45

    def test_delete_reverts_to_env_or_default(
        self, settings_store: SettingsStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("EMBERVAULT_HEARTBEAT_INTERVAL_S", "35")
        settings_store.set_setting("heartbeat_interval_s", 60)
        assert settings_store.get_setting("heartbeat_interval_s") == 60

        # Delete GUI override
        assert settings_store.delete_setting("heartbeat_interval_s") is True

        # Reverts to env var value
        assert settings_store.get_setting("heartbeat_interval_s") == 35


class TestSettingsSecurityAndValidation:
    """Test rejection of non-overridable settings and invalid values."""

    def test_bootstrap_settings_cannot_be_overridden_from_gui(
        self, settings_store: SettingsStore
    ) -> None:
        with pytest.raises(NonOverridableSettingError, match="bootstrap parameter"):
            settings_store.set_setting("database_url", "postgresql://...")

        with pytest.raises(NonOverridableSettingError, match="bootstrap parameter"):
            settings_store.set_setting("master_key", "secret123456789012")

        with pytest.raises(NonOverridableSettingError, match="bootstrap parameter"):
            settings_store.set_setting("token", "secret123456789012")

        with pytest.raises(NonOverridableSettingError, match="bootstrap parameter"):
            settings_store.set_setting("app_port", 9000)

    def test_unknown_setting_raises(self, settings_store: SettingsStore) -> None:
        with pytest.raises(UnknownSettingError, match="not declared"):
            settings_store.set_setting("non_existent_key", "value")

        with pytest.raises(UnknownSettingError, match="not declared"):
            settings_store.get_setting("non_existent_key")

    def test_int_value_validation(self, settings_store: SettingsStore) -> None:
        # Valid integer
        settings_store.set_setting("task_max_attempts", 5)
        assert settings_store.get_setting("task_max_attempts") == 5

        # Invalid type
        with pytest.raises(InvalidSettingValueError, match="must be an integer"):
            settings_store.set_setting("task_max_attempts", "not_a_number")

        # Below minimum (< 1)
        with pytest.raises(InvalidSettingValueError, match="positive integer"):
            settings_store.set_setting("task_max_attempts", 0)

        with pytest.raises(InvalidSettingValueError, match="positive integer"):
            settings_store.set_setting("task_max_attempts", -1)

    def test_rclone_filters_validation(self, settings_store: SettingsStore) -> None:
        # Accepting list of filter rules
        settings_store.set_setting("rclone_first_level_filters", ["+ *.pdf", "- *.tmp"])
        val = settings_store.get_setting("rclone_first_level_filters")
        assert val == "+ *.pdf\n- *.tmp"

        # Accepting tuple
        settings_store.set_setting("rclone_second_level_filters", ("- *.log", "+ *.txt"))
        val2 = settings_store.get_setting("rclone_second_level_filters")
        assert val2 == "- *.log\n+ *.txt"

        # Accepting raw string
        settings_store.set_setting("rclone_first_level_filters", "+ *.doc\n- *.bak")
        val3 = settings_store.get_setting("rclone_first_level_filters")
        assert val3 == "+ *.doc\n- *.bak"


class TestSettingsAuditLogAndNotification:
    """Test audit log trail and notification listeners."""

    def test_audit_log_recorded_on_set_and_delete(
        self,
        settings_store: SettingsStore,
        db_session_factory: sessionmaker[Session],
    ) -> None:
        user_id = uuid4()
        ip_addr = "192.168.1.100"

        # 1. Create setting
        settings_store.set_setting("retry_base_s", 45, user_id=user_id, ip=ip_addr)

        with db_session_factory() as session:
            audits = (
                session.query(AuditLog)
                .filter_by(entity_type="setting", entity_id="retry_base_s")
                .all()
            )
            assert len(audits) == 1
            assert audits[0].action == "setting.create"
            assert audits[0].actor_user_id == user_id
            assert audits[0].ip == ip_addr
            assert audits[0].details is not None
            assert audits[0].details["new_value"] == 45

        # 2. Update setting
        settings_store.set_setting("retry_base_s", 60, user_id=user_id, ip=ip_addr)

        with db_session_factory() as session:
            audits = (
                session.query(AuditLog)
                .filter_by(entity_type="setting", entity_id="retry_base_s")
                .order_by(AuditLog.id)
                .all()
            )
            assert len(audits) == 2
            assert audits[1].action == "setting.update"
            assert audits[1].details is not None
            assert audits[1].details["old_value"] == 45
            assert audits[1].details["new_value"] == 60

        # 2b. Re-set identical value (new_value == old_value) -> MUST NOT create audit log
        settings_store.set_setting("retry_base_s", 60, user_id=user_id, ip=ip_addr)

        with db_session_factory() as session:
            audits = (
                session.query(AuditLog)
                .filter_by(entity_type="setting", entity_id="retry_base_s")
                .order_by(AuditLog.id)
                .all()
            )
            assert len(audits) == 2  # Still 2, no duplicate setting.update recorded

        # 3. Delete setting
        settings_store.delete_setting("retry_base_s", user_id=user_id)

        with db_session_factory() as session:
            audits = (
                session.query(AuditLog)
                .filter_by(entity_type="setting", entity_id="retry_base_s")
                .order_by(AuditLog.id)
                .all()
            )
            assert len(audits) == 3
            assert audits[2].action == "setting.delete"

    def test_listener_invoked_on_change(self, settings_store: SettingsStore) -> None:
        notifications: list[str] = []

        def on_change(key: str) -> None:
            notifications.append(key)

        settings_store.register_change_listener(on_change)

        settings_store.set_setting("parallel_warn_threshold", 100)
        assert notifications == ["parallel_warn_threshold"]

        settings_store.delete_setting("parallel_warn_threshold")
        assert notifications == ["parallel_warn_threshold", "parallel_warn_threshold"]

    def test_get_dynamic_orchestrator_settings(self, settings_store: SettingsStore) -> None:
        settings_store.set_setting("heartbeat_interval_s", 22)
        settings_store.set_setting("per_proxy_concurrency", 4)

        dynamic = settings_store.get_dynamic_orchestrator_settings()
        assert dynamic["heartbeat_interval_s"] == 22
        assert dynamic["per_proxy_concurrency"] == 4
        assert "task_max_attempts" in dynamic

    def test_secret_setting_encryption_and_retrieval(
        self,
        settings_store: SettingsStore,
        db_session_factory: sessionmaker[Session],
    ) -> None:
        """Ensure SecretStr values are encrypted with plaintext, not masked string."""
        from pydantic import SecretStr

        from embervault_common.security.crypto import decrypt_blob_to_str
        from embervault_db.models.auth import Setting

        plain_pwd = "MyRealDomainPassword123!"
        settings_store.set_setting("ldap_bind_password", SecretStr(plain_pwd))

        # Check DB row is encrypted and decodes to plaintext
        with db_session_factory() as session:
            row = session.get(Setting, "ldap_bind_password")
            assert row is not None
            assert row.value is None
            assert row.value_encrypted is not None

            # Decrypt directly to verify it was NOT stored as "**********"
            aad = b"setting:ldap_bind_password"
            decrypted = decrypt_blob_to_str(row.value_encrypted, aad=aad)
            assert decrypted == plain_pwd
            assert decrypted != "**********"

        # Check in-memory resolution returns SecretStr with plaintext
        resolved = settings_store.get_setting("ldap_bind_password")
        assert isinstance(resolved, SecretStr)
        assert resolved.get_secret_value() == plain_pwd

        # Check cache invalidation & reload still returns SecretStr
        settings_store.invalidate_cache()
        reloaded = settings_store.get_setting("ldap_bind_password")
        assert isinstance(reloaded, SecretStr)
        assert reloaded.get_secret_value() == plain_pwd

        # Check that re-setting identical secret does not emit setting.update audit
        with db_session_factory() as session:
            initial_count = (
                session.query(AuditLog).filter_by(entity_id="ldap_bind_password").count()
            )
            assert initial_count == 1

        settings_store.set_setting("ldap_bind_password", SecretStr(plain_pwd))

        with db_session_factory() as session:
            count_after = session.query(AuditLog).filter_by(entity_id="ldap_bind_password").count()
            assert count_after == 1
