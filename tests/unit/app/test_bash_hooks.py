"""Unit tests for Bash Hooks Settings API, Job hooks persistence, and Orchestrator execution (Milestone M8)."""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import MagicMock

import pytest
from flask.testing import FlaskClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from embervault_app.factory import create_app
from embervault_common.config import AppSettings
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models import Base
from embervault_db.models.execution import JobRunHook
from embervault_db.repositories.execution_repository import ExecutionRepository
from embervault_db.repositories.job_repository import JobRepository
from embervault_db.repositories.remote_repository import RemoteRepository
from embervault_db.seed import seed_initial_data
from embervault_db.settings_store import SettingsStore
from embervault_orchestrator.factory import create_orchestrator_app
from embervault_orchestrator.internal_api import set_proxy_client
from embervault_orchestrator.proxy_client import ProxyClient
from embervault_orchestrator.reconciler import ExecutionReconciler


@pytest.fixture
def app_and_store() -> tuple[FlaskClient, SettingsStore, sessionmaker[Session]]:
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    with session_factory() as session:
        seed_initial_data(session)

    store = SettingsStore(session_factory)
    settings = AppSettings(app_port=8080, dev_noauth=True)
    app = create_app(
        settings=settings,
        session_factory=session_factory,
        settings_store=store,
    )
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    return app.test_client(), store, session_factory


@pytest.fixture
def orch_setup() -> tuple[FlaskClient, sessionmaker[Session], SettingsStore]:
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    with session_factory() as session:
        seed_initial_data(session)

    mock_proxy_client = MagicMock(spec=ProxyClient)
    mock_proxy_client.dispatch_task.return_value = {"status": "accepted"}
    mock_proxy_client.get_task_status.return_value = {
        "status": "succeeded",
        "exit_code": 0,
        "progress": {"bytes_transferred": 5000, "files_transferred": 10},
    }
    mock_proxy_client.get_task_logs.return_value = {"lines": []}
    mock_proxy_client.cancel_task.return_value = {"status": "cancelled"}
    set_proxy_client(mock_proxy_client)

    store = SettingsStore(session_factory)
    app = create_orchestrator_app(session_factory=session_factory, settings_store=store)
    app.config["TESTING"] = True
    return app.test_client(), session_factory, store


def test_hooks_settings_api(
    app_and_store: tuple[FlaskClient, SettingsStore, sessionmaker[Session]],
) -> None:
    client, store, _ = app_and_store

    # 1. Default settings: hooks_enabled=False, hooks_timeout_s=60
    res = client.get("/api/ui/settings/hooks")
    assert res.status_code == 200
    assert res.json["hooks_enabled"] is False
    assert res.json["hooks_timeout_s"] == 60

    # 2. Update hooks settings
    res = client.put(
        "/api/ui/settings/hooks",
        json={"hooks_enabled": True, "hooks_timeout_s": 120},
    )
    assert res.status_code == 200
    assert res.json["hooks_enabled"] is True
    assert res.json["hooks_timeout_s"] == 120
    assert store.get_setting("hooks_enabled") is True
    assert store.get_setting("hooks_timeout_s") == 120

    # 3. Invalid timeout validation
    res = client.put(
        "/api/ui/settings/hooks",
        json={"hooks_enabled": True, "hooks_timeout_s": 0},
    )
    assert res.status_code == 400


def test_job_hooks_crud(
    app_and_store: tuple[FlaskClient, SettingsStore, sessionmaker[Session]],
) -> None:
    client, _, session_factory = app_and_store

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "src-remote", "local", {"path": "/data"})
        r2 = RemoteRepository.create_remote(session, "dst-remote", "local", {"path": "/backup"})
        session.commit()
        r1_id = str(r1.id)
        r2_id = str(r2.id)

    # 1. Create job with pre_run_hook and post_run_hook via POST /api/ui/jobs
    create_resp = client.post(
        "/api/ui/jobs",
        json={
            "name": "backup-with-hooks",
            "source_remote_id": r1_id,
            "source_path": "/",
            "destination_remote_id": r2_id,
            "destination_path": "/",
            "pre_run_hook": "echo 'Starting backup'",
            "post_run_hook": "echo 'Backup finished: $EMBERVAULT_RUN_STATUS'",
        },
    )
    assert create_resp.status_code == 201
    job_id = uuid.UUID(create_resp.json["job_id"])

    with session_factory() as session:
        job = JobRepository.get_job_by_id(session, job_id)
        assert job is not None
        assert job.pre_run_hook == "echo 'Starting backup'"
        assert job.post_run_hook == "echo 'Backup finished: $EMBERVAULT_RUN_STATUS'"

    # 2. Update job hooks via PUT /api/ui/jobs/<id>
    update_resp = client.put(
        f"/api/ui/jobs/{job_id}",
        json={
            "pre_run_hook": "echo 'Updated pre hook'",
            "post_run_hook": "",
        },
    )
    assert update_resp.status_code == 200

    with session_factory() as session:
        job = JobRepository.get_job_by_id(session, job_id)
        assert job is not None
        assert job.pre_run_hook == "echo 'Updated pre hook'"
        assert job.post_run_hook is None


def test_orchestrator_job_run_hooks_lifecycle(
    orch_setup: tuple[FlaskClient, sessionmaker[Session], SettingsStore],
) -> None:
    client, session_factory, store = orch_setup

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "s-rem", "local", {"path": "/s"})
        r2 = RemoteRepository.create_remote(session, "d-rem", "local", {"path": "/d"})
        job = JobRepository.create_job(
            session=session,
            name="job-hooks-lifecycle",
            source_remote_id=r1.id,
            source_path="/",
            destination_remote_id=r2.id,
            destination_path="/",
            pre_run_hook="echo 'Pre-run ok'",
            post_run_hook="echo 'Post-run ok'",
        )
        session.commit()
        job_id = job.id

    # 1. Feature flag is disabled by default: pre-run hook must be SKIPPED
    store.set_setting("hooks_enabled", False)
    run_resp = client.post(f"/internal/v1/jobs/{job_id}/run")
    assert run_resp.status_code == 200
    run_id = uuid.UUID(run_resp.json["run_id"])

    with session_factory() as session:
        hooks = ExecutionRepository.get_run_hooks(session, run_id)
        assert len(hooks) == 1
        assert hooks[0].hook_type == "pre_run"
        assert hooks[0].status == "skipped"

    # 2. Enable hooks globally: pre-run hook executes successfully
    store.set_setting("hooks_enabled", True)
    with session_factory() as session:
        job2 = JobRepository.create_job(
            session=session,
            name="job-hooks-success",
            source_remote_id=r1.id,
            source_path="/",
            destination_remote_id=r2.id,
            destination_path="/",
            pre_run_hook="echo 'Pre-run success'",
            post_run_hook="echo 'Post-run success'",
        )
        session.commit()
        job2_id = job2.id

    run2_resp = client.post(f"/internal/v1/jobs/{job2_id}/run")
    assert run2_resp.status_code == 200
    run2_id = uuid.UUID(run2_resp.json["run_id"])

    with session_factory() as session:
        hooks2 = ExecutionRepository.get_run_hooks(session, run2_id)
        assert len(hooks2) == 1
        assert hooks2[0].hook_type == "pre_run"
        assert hooks2[0].status == "succeeded"
        assert "Pre-run success" in hooks2[0].output

    # 3. Failing pre-run hook does not block job start; run is started/dispatched with warning_code and hook failure recorded
    with session_factory() as session:
        job_fail = JobRepository.create_job(
            session=session,
            name="job-hooks-fail",
            source_remote_id=r1.id,
            source_path="/",
            destination_remote_id=r2.id,
            destination_path="/",
            pre_run_hook="exit 42",
        )
        session.commit()
        job_fail_id = job_fail.id

    run_fail_resp = client.post(f"/internal/v1/jobs/{job_fail_id}/run")
    assert run_fail_resp.status_code == 200
    assert run_fail_resp.json["status"] == "dispatched"
    run_fail_id = uuid.UUID(run_fail_resp.json["run_id"])

    with session_factory() as session:
        run_fail = ExecutionRepository.get_run_by_id(session, run_fail_id)
        assert run_fail is not None
        assert run_fail.status in ("queued", "running")
        assert run_fail.warning_code == "PRE_HOOK_FAILED"
        hooks_fail = ExecutionRepository.get_run_hooks(session, run_fail_id)
        assert len(hooks_fail) == 1
        assert hooks_fail[0].status == "failed"
        assert hooks_fail[0].exit_code != 0

    # 4. Post-run hook execution in reconciler
    reconciler = ExecutionReconciler(
        session_factory=session_factory,
        settings_store=store,
    )
    # Mark run2 as succeeded to simulate task completion
    with session_factory() as session:
        r_succ = ExecutionRepository.get_run_by_id(session, run2_id)
        assert r_succ is not None
        r_succ.status = "succeeded"
        r_succ.notification_sent_at = None
        session.commit()

    reconciler.reconcile_once()

    with session_factory() as session:
        hooks_post = ExecutionRepository.get_run_hooks(session, run2_id)
        # Should now have both pre_run and post_run
        assert len(hooks_post) == 2
        post_h = next(h for h in hooks_post if h.hook_type == "post_run")
        assert post_h.status == "succeeded"
        assert "Post-run success" in post_h.output

    # 5. Failing post-run hook records failed hook and triggers failure handling without crashing
    with session_factory() as session:
        job_post_fail = JobRepository.create_job(
            session=session,
            name="job-post-fail",
            source_remote_id=r1.id,
            source_path="/",
            destination_remote_id=r2.id,
            destination_path="/",
            post_run_hook="exit 99",
        )
        session.commit()
        job_post_fail_id = job_post_fail.id

    run_post_resp = client.post(f"/internal/v1/jobs/{job_post_fail_id}/run")
    assert run_post_resp.status_code == 200
    run_post_id = uuid.UUID(run_post_resp.json["run_id"])

    with session_factory() as session:
        r_post = ExecutionRepository.get_run_by_id(session, run_post_id)
        assert r_post is not None
        r_post.status = "succeeded"
        session.commit()

    reconciler.reconcile_once()

    with session_factory() as session:
        hooks_post_fail = ExecutionRepository.get_run_hooks(session, run_post_id)
        assert len(hooks_post_fail) == 1
        assert hooks_post_fail[0].hook_type == "post_run"
        assert hooks_post_fail[0].status == "failed"
        assert hooks_post_fail[0].exit_code != 0
