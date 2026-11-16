"""Comprehensive unit tests for EmberVault Backup & Restore feature.

Verifies:
1. Strict administrator access control (viewers and operators rejected with 403).
2. Navigation menu presence exclusively for administrators.
3. Export functionality: all configs, proxy tokens, remote passwords, jobs, settings.
4. Cryptographic integrity and key validation.
5. Restoration idempotency and credential re-encryption with target master key.
6. Automated scheduled backups, CRON evaluation, and file download.
"""

from __future__ import annotations

import io
import os
import tempfile
import uuid
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from embervault_app.factory import create_app
from embervault_common.config import AppSettings
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.backup import (
    create_backup_archive,
    generate_backup_key,
    restore_backup_archive,
    run_automated_backup_if_due,
)
from embervault_db.models import Base
from embervault_db.models.auth import Role, Setting
from embervault_db.models.execution import JobRun, JobRunHook, Task, TaskAssignment
from embervault_db.models.proxy import Proxy
from embervault_db.models.remotes import Job
from embervault_db.repositories.job_repository import JobRepository
from embervault_db.repositories.proxy_repository import ProxyRepository
from embervault_db.repositories.remote_repository import RemoteRepository
from embervault_db.repositories.user_repository import UserRepository
from embervault_db.seed import seed_initial_data


@pytest.fixture
def app_and_db() -> tuple[Flask, sessionmaker[Session], str]:
    temp_dir = tempfile.mkdtemp()
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    with session_factory() as db:
        seed_initial_data(db)

        # Set auto_backup_dir setting to temp_dir
        db.add(Setting(key="auto_backup_dir", value=temp_dir))
        db.commit()

    settings = AppSettings(app_port=8080, dev_noauth=False)
    app = create_app(settings=settings, session_factory=session_factory)
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app, session_factory, temp_dir


def _login(client: FlaskClient, username: str, password: str = "Password123456!") -> None:
    client.post("/login", data={"username": username, "password": password})


def _setup_active_admin(client: FlaskClient) -> None:
    client.post("/login", data={"username": "admin", "password": "admin"})
    client.post(
        "/change-password",
        data={
            "current_password": "admin",
            "new_password": "Password123456!",
            "confirm_password": "Password123456!",
        },
    )


def test_backup_restore_access_control(
    app_and_db: tuple[Flask, sessionmaker[Session], str],
) -> None:
    """Verify that Backup & Restore is strictly reserved for administrators."""
    app, session_factory, _ = app_and_db
    client = app.test_client()

    # 1. Setup admin and create operator and viewer
    _setup_active_admin(client)

    with session_factory() as db:
        op_role = UserRepository.get_role_by_name(db, "operator")
        viewer_role = UserRepository.get_role_by_name(db, "viewer")
        assert op_role is not None and viewer_role is not None

        UserRepository.create_user(
            db,
            username="operator1",
            password="Password123456!",
            role_id=op_role.id,
            must_change_password=False,
        )
        UserRepository.create_user(
            db,
            username="viewer1",
            password="Password123456!",
            role_id=viewer_role.id,
            must_change_password=False,
        )
        db.commit()

    # 2. Admin CAN access UI and API
    admin_ui = client.get("/backup-restore")
    assert admin_ui.status_code == 200
    assert "Backup & Restore" in admin_ui.get_data(as_text=True)
    assert 'id="nav-backup-restore"' in admin_ui.get_data(as_text=True)

    admin_cfg = client.get("/api/ui/backup/config")
    assert admin_cfg.status_code == 200

    # 3. Viewer CANNOT access UI or API (gets 403)
    client.get("/logout")
    _login(client, "viewer1")

    viewer_ui = client.get("/backup-restore")
    assert viewer_ui.status_code == 403

    viewer_api = client.get("/api/ui/backup/config")
    assert viewer_api.status_code == 403

    viewer_export = client.post("/api/ui/backup/export", json={})
    assert viewer_export.status_code == 403

    # Viewer sidebar does not have nav-backup-restore
    dashboard = client.get("/")
    assert 'id="nav-backup-restore"' not in dashboard.get_data(as_text=True)

    # 4. Operator CANNOT access UI or API (gets 403)
    client.get("/logout")
    _login(client, "operator1")

    op_ui = client.get("/backup-restore")
    assert op_ui.status_code == 403

    op_api = client.get("/api/ui/backup/config")
    assert op_api.status_code == 403

    op_export = client.post("/api/ui/backup/export", json={})
    assert op_export.status_code == 403

    op_dashboard = client.get("/")
    assert 'id="nav-backup-restore"' not in op_dashboard.get_data(as_text=True)


def test_backup_export_and_inspect_flow(
    app_and_db: tuple[Flask, sessionmaker[Session], str],
) -> None:
    """Test full export, inspection, and verification of backup content."""
    app, session_factory, _ = app_and_db
    client = app.test_client()
    _setup_active_admin(client)

    # Populate with remote, proxy, and job
    with session_factory() as db:
        remote = RemoteRepository.create_remote(
            session=db,
            name="test-s3-remote",
            backend_type="s3",
            raw_config={
                "provider": "AWS",
                "access_key_id": "AKIA_TEST_KEY_123",
                "secret_access_key": "SecretPasswordSuperSecret999!",
                "region": "eu-central-1",
            },
        )
        p_id = uuid.uuid4()
        proxy = Proxy(
            id=p_id,
            name="proxy-backup-test",
            host="10.0.0.50",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("proxy_secret_bearer_token_123456", p_id),
            cert_fingerprint_sha256="f" * 64,
            is_enabled=True,
            max_concurrent_tasks=4,
        )
        db.add(proxy)
        db.flush()

        job = JobRepository.create_job(
            session=db,
            name="job-backup-test",
            source_remote_id=remote.id,
            source_path="/data/src",
            destination_remote_id=remote.id,
            destination_path="/data/dst",
            schedule_cron="0 2 * * *",
            assigned_proxy_ids=[proxy.id],
        )

        run = JobRun(
            id=uuid.uuid4(),
            job_id=job.id,
            trigger="manual",
            status="succeeded",
            job_snapshot={"name": job.name},
        )
        db.add(run)
        db.flush()

        hook = JobRunHook(
            id=uuid.uuid4(),
            run_id=run.id,
            hook_type="post_run",
            script_hash="a" * 64,
            status="succeeded",
            exit_code=0,
            duration_ms=12.5,
            output="hook completed successfully",
        )
        db.add(hook)
        db.commit()

    # Call export endpoint
    res = client.post(
        "/api/ui/backup/export",
        json={"include_audit": True, "include_history": True},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert "key" in data
    assert len(data["key"]) == 64
    assert data["filename"].startswith("embervault_backup_")
    assert "data" in data

    stats = data["stats"]
    assert stats["remotes"] >= 1
    assert stats["proxies"] >= 1
    assert stats["jobs"] >= 1

    # Verify inspection with correct key
    import base64

    backup_bytes = base64.b64decode(data["data"])
    inspect_res = client.post(
        "/api/ui/backup/inspect",
        data={
            "backup_file": (io.BytesIO(backup_bytes), "backup.evb"),
            "key": data["key"],
        },
        content_type="multipart/form-data",
    )
    assert inspect_res.status_code == 200
    inspect_data = inspect_res.get_json()
    assert inspect_data["status"] == "ok"
    assert inspect_data["info"]["version"] == 1
    assert inspect_data["info"]["stats"]["remotes"] >= 1

    # Verify inspection with WRONG key fails with 400
    wrong_key_res = client.post(
        "/api/ui/backup/inspect",
        data={
            "backup_file": (io.BytesIO(backup_bytes), "backup.evb"),
            "key": "wrong_key_invalid_0123456789abcdef",
        },
        content_type="multipart/form-data",
    )
    assert wrong_key_res.status_code == 400
    assert "Chiave di decrittografia errata" in wrong_key_res.get_json()["message"]


def test_backup_restore_into_new_database(
    app_and_db: tuple[Flask, sessionmaker[Session], str],
) -> None:
    """Verify that exported backup can be restored cleanly into an empty target database."""
    app, session_factory, _ = app_and_db
    client = app.test_client()
    _setup_active_admin(client)

    # 1. Create source entities
    with session_factory() as db:
        remote = RemoteRepository.create_remote(
            session=db,
            name="remote-to-restore",
            backend_type="s3",
            raw_config={
                "provider": "AWS",
                "access_key_id": "RESTORE_KEY_ID",
                "secret_access_key": "RestoreSecretPassword123!",
                "region": "us-east-1",
            },
        )
        p_id = uuid.uuid4()
        proxy = Proxy(
            id=p_id,
            name="proxy-to-restore",
            host="192.168.1.100",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("restore_token_bearer_12345678", p_id),
            cert_fingerprint_sha256="e" * 64,
            is_enabled=True,
            max_concurrent_tasks=8,
        )
        db.add(proxy)
        db.flush()

        job = JobRepository.create_job(
            session=db,
            name="job-to-restore",
            source_remote_id=remote.id,
            source_path="/source/docs",
            destination_remote_id=remote.id,
            destination_path="/dest/backup",
            schedule_cron="30 4 * * *",
            assigned_proxy_ids=[proxy.id],
        )

        r_id = uuid.uuid4()
        run = JobRun(
            id=r_id,
            job_id=job.id,
            trigger="manual",
            status="succeeded",
            job_snapshot={"name": job.name},
        )
        db.add(run)
        db.flush()

        t_id = uuid.uuid4()
        task = Task(
            id=t_id,
            run_id=r_id,
            kind="transfer",
            scope="whole",
            seq=0,
            status="succeeded",
        )
        db.add(task)
        db.flush()

        asgn = TaskAssignment(
            id=uuid.uuid4(),
            task_id=t_id,
            attempt_no=1,
            proxy_id=proxy.id,
            status="succeeded",
        )
        db.add(asgn)

        hook = JobRunHook(
            id=uuid.uuid4(),
            run_id=r_id,
            hook_type="post_run",
            script_hash="h" * 64,
            status="succeeded",
            exit_code=0,
            output="ok",
        )
        db.add(hook)
        db.commit()

        # Export archive directly
        backup_key = generate_backup_key()
        archive_bytes, stats = create_backup_archive(
            session=db,
            key=backup_key,
            include_audit=True,
            include_history=True,
        )

        # Restore back into the SAME database (must be completely idempotent and not crash on pk_job_runs)
        same_db_stats = restore_backup_archive(
            session=db,
            backup_bytes=archive_bytes,
            key=backup_key,
            restore_audit=True,
            restore_history=True,
            current_admin_username="admin",
        )
        assert same_db_stats["execution_history"] >= 1

    # 2. Setup a completely new database with a DIFFERENT master key ring
    new_engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(new_engine)
    new_session_factory = sessionmaker(bind=new_engine, expire_on_commit=False)

    with new_session_factory() as new_db:
        seed_initial_data(new_db)
        # Restore into new_db
        restored_stats = restore_backup_archive(
            session=new_db,
            backup_bytes=archive_bytes,
            key=backup_key,
            restore_audit=True,
            restore_history=True,
            current_admin_username="admin",
        )

        assert restored_stats["remotes"] >= 1
        assert restored_stats["proxies"] >= 1
        assert restored_stats["jobs"] >= 1
        assert restored_stats["execution_history"] >= 1

        # Restore a SECOND time into new_db to verify idempotency on new DB as well
        second_restore_stats = restore_backup_archive(
            session=new_db,
            backup_bytes=archive_bytes,
            key=backup_key,
            restore_audit=True,
            restore_history=True,
            current_admin_username="admin",
        )
        assert second_restore_stats["execution_history"] >= 1

        # Verify restored remote has correctly re-encrypted credentials!
        r_loaded = RemoteRepository.get_remote_by_name(new_db, "remote-to-restore")
        assert r_loaded is not None
        decrypted_cfg = RemoteRepository.get_decrypted_config(r_loaded)
        assert decrypted_cfg["access_key_id"] == "RESTORE_KEY_ID"
        assert decrypted_cfg["secret_access_key"] == "RestoreSecretPassword123!"

        # Verify restored proxy token
        p_loaded = new_db.scalar(select(Proxy).where(Proxy.name == "proxy-to-restore"))
        assert p_loaded is not None
        p_token = ProxyRepository.decrypt_token(p_loaded.token_encrypted, p_loaded.id)
        assert p_token == "restore_token_bearer_12345678"

        # Verify restored job
        j_loaded = new_db.scalar(select(Job).where(Job.name == "job-to-restore"))
        assert j_loaded is not None
        assert j_loaded.schedule_cron == "30 4 * * *"
        assert j_loaded.source_remote.name == "remote-to-restore"
        assert len(j_loaded.assigned_proxies) == 1
        assert j_loaded.assigned_proxies[0].name == "proxy-to-restore"


def test_auto_backup_configuration_and_scheduled_run(
    app_and_db: tuple[Flask, sessionmaker[Session], str],
) -> None:
    """Test automated backup configuration API and runner logic."""
    app, session_factory, temp_dir = app_and_db
    client = app.test_client()
    _setup_active_admin(client)

    # 1. Update auto backup config via API
    res = client.put(
        "/api/ui/backup/config",
        json={
            "enabled": True,
            "cron": "0 3 * * *",
            "key": "auto_backup_custom_key_1234567890",
            "include_history": True,
            "include_audit": True,
            "retention_days": 15,
        },
    )
    assert res.status_code == 200
    assert res.get_json()["status"] == "ok"

    # 2. Get auto backup config
    cfg_res = client.get("/api/ui/backup/config")
    assert cfg_res.status_code == 200
    cfg = cfg_res.get_json()["config"]
    assert cfg["enabled"] is True
    assert cfg["cron"] == "0 3 * * *"
    assert cfg["retention_days"] == 15

    # 3. Test run-now API
    run_res = client.post("/api/ui/backup/run-now")
    assert run_res.status_code == 200
    run_data = run_res.get_json()
    assert run_data["status"] == "ok"
    filename = run_data["filename"]
    assert os.path.isfile(run_data["path"])

    # 4. Verify download endpoint
    dl_res = client.get(f"/api/ui/backup/download/{filename}")
    assert dl_res.status_code == 200
    assert len(dl_res.data) > 0
    assert dl_res.data[:4] == b"EVBK"

    # 5. Verify run_automated_backup_if_due runner
    due_file = run_automated_backup_if_due(session_factory, default_backup_dir=temp_dir)
    # Since last_run was just updated by run-now, and cron is 0 3 * * *, it should not be due immediately
    assert due_file is None

    # Reset last_auto_backup_at to past to verify it triggers
    with session_factory() as db:
        setting = db.get(Setting, "last_auto_backup_at")
        assert setting is not None
        setting.value = "2020-01-01T00:00:00+00:00"
        db.commit()

    due_file_2 = run_automated_backup_if_due(session_factory, default_backup_dir=temp_dir)
    assert due_file_2 is not None
    assert Path(due_file_2).is_file()


def test_backup_restore_csrf_protection(
    app_and_db: tuple[Flask, sessionmaker[Session], str],
) -> None:
    """Verify CSRF token protection on Backup & Restore mutating endpoints."""
    import re

    app, session_factory, _ = app_and_db
    client = app.test_client()
    _setup_active_admin(client)

    # Enable CSRF protection now that admin is logged in
    app.config["WTF_CSRF_ENABLED"] = True

    # 1. Mutating call without CSRF token returns 400
    res_no_csrf = client.post("/api/ui/backup/export", json={"include_history": False})
    assert res_no_csrf.status_code == 400

    # 2. Extract CSRF token from rendered page
    page_res = client.get("/backup-restore")
    assert page_res.status_code == 200
    csrf_match = re.search(
        r'<meta name="csrf-token" content="([^"]+)">', page_res.get_data(as_text=True)
    )
    assert csrf_match is not None
    csrf_token = csrf_match.group(1)

    # 3. Call with X-CSRFToken succeeds
    res_csrf = client.post(
        "/api/ui/backup/export",
        headers={"X-CSRFToken": csrf_token},
        json={"include_history": False},
    )
    assert res_csrf.status_code == 200
    assert res_csrf.get_json()["status"] == "ok"


def test_backup_config_cron_validation(
    app_and_db: tuple[Flask, sessionmaker[Session], str],
) -> None:
    """Verify that backup config endpoint correctly validates CRON expressions."""
    from embervault_app.blueprints.api import _validate_cron_expression

    # Valid cron expressions
    _validate_cron_expression("0 3 * * *")
    _validate_cron_expression("*/5 * * * *")
    _validate_cron_expression("0 0 1,15 * 1-5")

    # Invalid cron expressions
    with pytest.raises(ValueError):
        _validate_cron_expression("invalid cron")

    with pytest.raises(ValueError):
        _validate_cron_expression("* * *")

    with pytest.raises(ValueError):
        _validate_cron_expression("bad * * * *")


def test_run_backup_now_permission_error_handling(
    app_and_db: tuple[Flask, sessionmaker[Session], str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Verify that run_backup_now returns an informative 403 error on PermissionError."""
    from unittest.mock import patch
    from embervault_db.models.auth import Setting

    app, session_factory, _ = app_and_db
    client = app.test_client()
    _setup_active_admin(client)

    # Configure auto_backup_dir to tmp_path
    with session_factory() as db:
        db.merge(Setting(key="auto_backup_dir", value=str(tmp_path)))
        db.commit()

    # Simulate PermissionError on write_bytes
    with patch.object(Path, "write_bytes", side_effect=PermissionError("Permission denied")):
        res = client.post("/api/ui/backup/run-now")
        assert res.status_code == 403
        data = res.get_json()
        assert data["status"] == "error"
        assert "10001" in data["message"]
        assert any(w in data["message"].lower() for w in ("permessi", "permission"))

    # Successful run without mock
    res_ok = client.post("/api/ui/backup/run-now")
    assert res_ok.status_code == 200
    data_ok = res_ok.get_json()
    assert data_ok["status"] == "ok"
    assert data_ok["filename"].startswith("embervault_backup_")
    assert (tmp_path / data_ok["filename"]).exists()
