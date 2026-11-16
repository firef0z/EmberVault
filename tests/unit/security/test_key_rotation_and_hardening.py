"""Unit tests for Milestone M9: Key Rotation, Hardening, and Operational Resilience."""

from __future__ import annotations

import base64
import os
import secrets
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask, jsonify
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

import importlib.util

backup_restore_path = (
    Path(__file__).resolve().parents[3] / "deploy" / "scripts" / "backup_restore.py"
)
spec = importlib.util.spec_from_file_location("backup_restore", backup_restore_path)
backup_restore = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
spec.loader.exec_module(backup_restore)  # type: ignore[union-attr]
create_backup = backup_restore.create_backup
verify_backup = backup_restore.verify_backup
from embervault_common.config.models import ProxySettings
from embervault_common.security.crypto import (
    KeyRing,
    decrypt_blob_to_str,
    encrypt_blob,
    extract_envelope_key_id,
    get_default_key_ring,
    reencrypt_blob,
)
from embervault_db.models import (
    Base,
    Job,
    JobRun,
    NotificationChannel,
    Proxy,
    RcloneRemote,
    Setting,
    Task,
    TaskLog,
    User,
    UserMfaFactor,
)
from embervault_db.repositories.execution_repository import ExecutionRepository
from embervault_db.repositories.notification_repository import NotificationRepository
from embervault_db.repositories.proxy_repository import ProxyRepository
from embervault_db.repositories.remote_repository import RemoteRepository
from embervault_db.repositories.user_repository import UserRepository
from embervault_db.rotation import rotate_all_credentials
from embervault_db.settings_store import SettingsStore
from embervault_proxy.auth import require_proxy_auth


@pytest.fixture
def dual_keyring() -> tuple[KeyRing, str, str]:
    """Create a keyring with two distinct master keys (k1 primary, k2 secondary)."""
    raw_key1 = secrets.token_bytes(32)
    raw_key2 = secrets.token_bytes(32)
    ring = KeyRing()
    ring.add_key("k1", raw_key1, is_primary=True)
    ring.add_key("k2", raw_key2, is_primary=False)
    return ring, "k1", "k2"


@pytest.fixture
def db_session() -> Session:
    """In-memory SQLite session with all tables created."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()


# ==============================================================================
# 1. ENVELOPE INSPECTION & MULTI-KEY ROTATION
# ==============================================================================


def test_extract_envelope_key_id_and_multi_key_decryption(
    dual_keyring: tuple[KeyRing, str, str],
) -> None:
    ring, k1, k2 = dual_keyring
    secret_text = "ultra-secret-backup-passphrase"
    aad = b"context:remotes"

    # Encrypt explicitly with k2
    blob_k2 = encrypt_blob(secret_text, key_ring=ring, key_id=k2, aad=aad)
    assert extract_envelope_key_id(blob_k2) == "k2"

    # Decrypt with keyring containing both k1 and k2
    decrypted = decrypt_blob_to_str(blob_k2, key_ring=ring, aad=aad)
    assert decrypted == secret_text

    # Re-encrypt to k1 (the primary key)
    blob_k1 = reencrypt_blob(blob_k2, key_ring=ring, new_key_id=k1, aad=aad)
    assert extract_envelope_key_id(blob_k1) == "k1"

    # Decrypt re-encrypted blob
    decrypted_again = decrypt_blob_to_str(blob_k1, key_ring=ring, aad=aad)
    assert decrypted_again == secret_text

    # Re-encrypting a blob that already matches target key is idempotent
    blob_k1_again = reencrypt_blob(blob_k1, key_ring=ring, new_key_id=k1, aad=aad)
    assert blob_k1_again == blob_k1


def test_get_default_key_ring_multi_key_env() -> None:
    raw1 = secrets.token_bytes(32)
    raw2 = secrets.token_bytes(32)
    b64_1 = base64.b64encode(raw1).decode()
    b64_2 = base64.b64encode(raw2).decode()

    with patch.dict(
        os.environ,
        {
            "EMBERVAULT_MASTER_KEY": b64_1,
            "EMBERVAULT_MASTER_KEY_ID": "key-2026",
            "EMBERVAULT_MASTER_KEYS": f"key-2025:{b64_2}",
        },
    ):
        ring = get_default_key_ring(force_reload=True)
        assert ring.primary_key_id == "key-2026"
        assert ring.has_key("key-2026")
        assert ring.has_key("key-2025")

        # Test encrypt/decrypt cross-key
        blob = encrypt_blob("test-env", key_ring=ring, key_id="key-2025")
        assert extract_envelope_key_id(blob) == "key-2025"
        assert decrypt_blob_to_str(blob, key_ring=ring) == "test-env"


# ==============================================================================
# 2. CENTRALIZED CREDENTIAL ROTATION (rotate_all_credentials)
# ==============================================================================


def test_rotate_all_credentials(
    db_session: Session, dual_keyring: tuple[KeyRing, str, str]
) -> None:
    ring, k1, k2 = dual_keyring

    with patch(
        "embervault_common.security.crypto.get_default_key_ring",
        return_value=ring,
    ):
        # 1. RClone Remote encrypted with k2
        remote_id = uuid.uuid4()
        remote_aad = f"remote:{remote_id}".encode()
        remote_blob = encrypt_blob(
            '{"token": "old-token"}', key_ring=ring, key_id=k2, aad=remote_aad
        )
        remote = RcloneRemote(
            id=remote_id,
            name="s3-backup",
            backend_type="s3",
            config_encrypted=remote_blob,
            public_params={"endpoint": "https://s3.example.com"},
            secret_field_names=["token"],
            version=1,
            is_enabled=True,
        )
        db_session.add(remote)

        # 2. Proxy encrypted with k2
        proxy_id = uuid.uuid4()
        proxy_aad = f"proxy:{proxy_id}".encode()
        proxy_blob = encrypt_blob(
            "proxy-secret-token-min-32-characters-long", key_ring=ring, key_id=k2, aad=proxy_aad
        )
        proxy = Proxy(
            id=proxy_id,
            name="edge-node-01",
            host="192.168.1.50",
            port=8443,
            token_encrypted=proxy_blob,
            cert_fingerprint_sha256="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            is_enabled=True,
        )
        db_session.add(proxy)

        # 3. Notification Channel encrypted with k2
        chan_id = uuid.uuid4()
        chan_aad = f"notification_channel:{chan_id}".encode()
        chan_blob = encrypt_blob(
            "mailto://user:pass@smtp.example.com", key_ring=ring, key_id=k2, aad=chan_aad
        )
        channel = NotificationChannel(
            id=chan_id,
            name="alert-email",
            channel_type="email",
            url_encrypted=chan_blob,
            enabled=True,
        )
        db_session.add(channel)

        # 4. User MFA Factor encrypted with k2
        user_id = uuid.uuid4()
        from embervault_db.models import Role, TaskAssignment

        role = Role(id=uuid.uuid4(), name="admin")
        db_session.add(role)
        db_session.flush()

        user = User(
            id=user_id,
            username="security_admin",
            email="sec@example.com",
            password_hash="argon2_placeholder",
            role_id=role.id,
            is_active=True,
        )
        db_session.add(user)

        mfa_aad = f"user_mfa:{user_id}".encode()
        mfa_blob = encrypt_blob("JBSWY3DPEHPK3PXP", key_ring=ring, key_id=k2, aad=mfa_aad)
        mfa = UserMfaFactor(
            id=uuid.uuid4(),
            user_id=user_id,
            type="totp",
            label="Default TOTP",
            secret_encrypted=mfa_blob,
            confirmed_at=datetime.now(UTC),
        )
        db_session.add(mfa)
        db_session.commit()

        # Initialize SettingsStore with a secret setting encrypted with k2
        import contextlib

        @contextlib.contextmanager
        def fake_session_factory():
            yield db_session

        store = SettingsStore(fake_session_factory)

        # Manually create a secret setting with k2 encryption
        setting_aad = b"setting:oidc_client_secret"
        setting_blob = encrypt_blob("secret-oidc-key", key_ring=ring, key_id=k2, aad=setting_aad)
        db_session.add(
            Setting(
                key="oidc_client_secret",
                value=None,
                value_encrypted=setting_blob,
            )
        )
        db_session.commit()

        # Verify initial keys are all k2
        assert extract_envelope_key_id(remote.config_encrypted) == "k2"
        assert extract_envelope_key_id(proxy.token_encrypted) == "k2"
        assert extract_envelope_key_id(channel.url_encrypted) == "k2"
        assert extract_envelope_key_id(mfa.secret_encrypted) == "k2"

        # Execute full rotation to k1
        result = rotate_all_credentials(db_session, settings_store=store, target_key_id=k1)
        db_session.commit()

        assert result["remotes"] == 1
        assert result["proxies"] == 1
        assert result["notification_channels"] == 1
        assert result["mfa_factors"] == 1
        assert result["settings"] == 1
        assert result["total"] == 5

        # Verify all records are now on k1 and decrypt cleanly
        db_session.refresh(remote)
        db_session.refresh(proxy)
        db_session.refresh(channel)
        db_session.refresh(mfa)

        assert extract_envelope_key_id(remote.config_encrypted) == k1
        assert extract_envelope_key_id(proxy.token_encrypted) == k1
        assert extract_envelope_key_id(channel.url_encrypted) == k1
        assert extract_envelope_key_id(mfa.secret_encrypted) == k1

        assert RemoteRepository.get_decrypted_config(remote) == {"token": "old-token"}
        assert (
            ProxyRepository.decrypt_token(proxy.token_encrypted, proxy.id)
            == "proxy-secret-token-min-32-characters-long"
        )
        assert (
            NotificationRepository.get_decrypted_url(channel)
            == "mailto://user:pass@smtp.example.com"
        )
        assert (
            decrypt_blob_to_str(mfa.secret_encrypted, key_ring=ring, aad=mfa_aad)
            == "JBSWY3DPEHPK3PXP"
        )


# ==============================================================================
# 3. PROXY DUAL-TOKEN AUTHENTICATION
# ==============================================================================


def test_proxy_auth_accepts_primary_and_previous_token() -> None:
    current_token_str = "primary-proxy-token-32-chars-long-12345678"
    previous_token_str = "previous-proxy-token-32-chars-long-87654321"

    proxy_settings = ProxySettings(
        token=current_token_str,  # type: ignore[arg-type]
        previous_token=previous_token_str,  # type: ignore[arg-type]
    )

    app = Flask("test_proxy_auth")
    app.config["SETTINGS"] = proxy_settings

    @app.route("/tasks", methods=["GET"])
    @require_proxy_auth
    def dummy_task_endpoint():
        return jsonify({"status": "ok"})

    client = app.test_client()

    # 1. Primary token succeeds
    res1 = client.get("/tasks", headers={"Authorization": f"Bearer {current_token_str}"})
    assert res1.status_code == 200
    assert res1.get_json()["status"] == "ok"

    # 2. Previous token succeeds during rotation window
    res2 = client.get("/tasks", headers={"Authorization": f"Bearer {previous_token_str}"})
    assert res2.status_code == 200
    assert res2.get_json()["status"] == "ok"

    # 3. Invalid token fails
    res3 = client.get("/tasks", headers={"Authorization": "Bearer invalid-wrong-token-value-here"})
    assert res3.status_code == 401

    # 4. Missing header fails
    res4 = client.get("/tasks")
    assert res4.status_code == 401


# ==============================================================================
# 4. LOG RETENTION & EXPIRATION CLEANUP
# ==============================================================================


def test_cleanup_expired_task_logs(db_session: Session) -> None:
    from embervault_db.models import TaskAssignment

    # Remotes for job FK
    src_remote = RcloneRemote(
        id=uuid.uuid4(),
        name="src-rem",
        backend_type="local",
        config_encrypted=b"dummy",
        public_params={},
        secret_field_names=[],
    )
    dst_remote = RcloneRemote(
        id=uuid.uuid4(),
        name="dst-rem",
        backend_type="local",
        config_encrypted=b"dummy",
        public_params={},
        secret_field_names=[],
    )
    # Proxy for assignment FK
    proxy = Proxy(
        id=uuid.uuid4(),
        name="log-proxy",
        host="127.0.0.1",
        port=8443,
        token_encrypted=b"dummy",
        cert_fingerprint_sha256="dummy",
    )
    db_session.add_all([src_remote, dst_remote, proxy])
    db_session.flush()

    job = Job(
        id=uuid.uuid4(),
        name="retention-test-job",
        source_remote_id=src_remote.id,
        source_path="/source",
        destination_remote_id=dst_remote.id,
        destination_path="/backup",
    )
    db_session.add(job)

    run = JobRun(
        id=uuid.uuid4(),
        job_id=job.id,
        trigger="manual",
        status="succeeded",
        job_snapshot={},
    )
    db_session.add(run)

    task = Task(
        id=uuid.uuid4(),
        run_id=run.id,
        kind="transfer",
        scope="whole",
        seq=1,
        spec={},
        status="succeeded",
    )
    db_session.add(task)
    db_session.flush()

    assignment = TaskAssignment(
        id=uuid.uuid4(),
        task_id=task.id,
        attempt_no=1,
        proxy_id=proxy.id,
        status="succeeded",
    )
    db_session.add(assignment)
    db_session.commit()

    now = datetime.now(UTC)
    old_time = now - timedelta(days=45)
    recent_time = now - timedelta(days=5)

    # Old log (should be pruned with 30d retention)
    log_old = TaskLog(
        assignment_id=assignment.id,
        task_id=task.id,
        run_id=run.id,
        seq=1,
        ts=old_time,
        level="info",
        stream="stdout",
        message="Old expired backup log entry",
    )
    # Recent log (should be preserved)
    log_recent = TaskLog(
        assignment_id=assignment.id,
        task_id=task.id,
        run_id=run.id,
        seq=2,
        ts=recent_time,
        level="info",
        stream="stdout",
        message="Recent valid log entry",
    )
    db_session.add_all([log_old, log_recent])
    db_session.commit()

    # Verify 2 logs exist
    total_logs = db_session.scalar(select(TaskLog))
    assert total_logs is not None

    # Run cleanup with 30 days retention
    deleted_count = ExecutionRepository.cleanup_expired_task_logs(db_session, retention_days=30)
    assert deleted_count == 1

    remaining_logs = list(db_session.scalars(select(TaskLog)).all())
    assert len(remaining_logs) == 1
    assert remaining_logs[0].message == "Recent valid log entry"


# ==============================================================================
# 5. BACKUP & RESTORE UTILITY INTEGRITY
# ==============================================================================


def test_backup_create_and_verify() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        bak_file = Path(tmp_dir) / "test_backup.tar.gz"

        # Create backup archive
        created_path = create_backup(bak_file, master_key_id="test-key-v1")
        assert created_path.exists()
        assert created_path.stat().st_size > 0

        # Verify backup integrity
        manifest = verify_backup(created_path)
        assert manifest["master_key_id"] == "test-key-v1"
        assert manifest["app_version"] == "1.0.0"
        assert "database_dump_sha256" in manifest
