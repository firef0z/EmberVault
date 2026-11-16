"""Unit tests for M7 Realtime SSE Streams, Metrics Snapshot, and Event Broadcasting."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from flask import Flask
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from embervault_app.factory import create_app
from embervault_common.config import AppSettings
from embervault_common.contracts.enums import RunState, TaskState
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models import (
    AuditLog,
    Base,
    Job,
    JobRun,
    Proxy,
    ProxyStatus,
    RcloneRemote,
    Role,
    Task,
    TaskAssignment,
    TaskLog,
    User,
)
from embervault_db.models.base import utc_now
from embervault_db.seed import seed_initial_data


@pytest.fixture
def test_app_and_db() -> tuple[Flask, sessionmaker[Session]]:
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    with session_factory() as db:
        seed_initial_data(db)

    settings = AppSettings(app_port=8080, dev_noauth=False)
    app = create_app(settings=settings, session_factory=session_factory)
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app, session_factory


def test_realtime_events_stream_unauthorized(
    test_app_and_db: tuple[Flask, sessionmaker[Session]],
) -> None:
    app, _ = test_app_and_db
    client = app.test_client()

    # Unauthenticated request redirects to /login or returns 401
    res = client.get("/api/ui/events")
    assert res.status_code in (302, 401)


def test_realtime_events_stream_authorized_snapshot(
    test_app_and_db: tuple[Flask, sessionmaker[Session]],
) -> None:
    app, session_factory = test_app_and_db
    client = app.test_client()

    with session_factory() as db:
        user = db.scalar(select(User).where(User.username == "admin"))
        user.must_change_password = False
        db.commit()

    login_res = client.post("/login", data={"username": "admin", "password": "admin"})
    assert login_res.status_code == 302

    # Request SSE stream with short duration to test initial snapshot & stream format
    res = client.get("/api/ui/events?duration=0.01&interval=0.01")
    assert res.status_code == 200
    assert "text/event-stream" in res.headers["Content-Type"]
    assert res.headers["Cache-Control"] == "no-cache, no-transform"
    assert res.headers["X-Accel-Buffering"] == "no"

    content = res.data.decode("utf-8")
    assert "event: connected" in content

    # Extract JSON payload from event: connected
    for line in content.splitlines():
        if line.startswith("data:"):
            payload = json.loads(line[5:].strip())
            assert payload["status"] == "ok"
            assert "proxies_count" in payload
            assert "runs_count" in payload
            assert "fleet_capacity" in payload
            assert "throughput" in payload
            assert "recent_runs" in payload
            break


def test_realtime_events_stream_forbidden_without_permissions(
    test_app_and_db: tuple[Flask, sessionmaker[Session]],
) -> None:
    app, session_factory = test_app_and_db
    client = app.test_client()

    # Create a user with a custom empty role (no permissions)
    with session_factory() as db:
        empty_role = Role(name="noperms", description="No permissions")
        db.add(empty_role)
        db.flush()

        from embervault_common.security.passwords import hash_password

        restricted_user = User(
            username="restricted",
            password_hash=hash_password("password123"),
            role_id=empty_role.id,
            is_active=True,
            must_change_password=False,
        )
        db.add(restricted_user)
        db.commit()

    client.post("/login", data={"username": "restricted", "password": "password123"})
    res = client.get("/api/ui/events?duration=0.01")
    assert res.status_code == 403
    assert res.json["error"] == "forbidden"


def test_run_realtime_events_stream_snapshot_and_completion(
    test_app_and_db: tuple[Flask, sessionmaker[Session]],
) -> None:
    app, session_factory = test_app_and_db
    client = app.test_client()

    with session_factory() as db:
        user = db.scalar(select(User).where(User.username == "admin"))
        user.must_change_password = False

        # Create dummy remote, job, run, and task
        remote = RcloneRemote(
            name="test-rem",
            backend_type="local",
            config_encrypted=b"dummy",
            public_params={},
            secret_field_names=[],
        )
        db.add(remote)
        db.flush()

        job = Job(
            name="Backup Realtime Job",
            source_remote_id=remote.id,
            source_path="/src",
            destination_remote_id=remote.id,
            destination_path="/dst",
            enabled=True,
            source_kind="folder",
            operation="copy",
            parallelization="none",
        )
        db.add(job)
        db.flush()

        run = JobRun(
            job_id=job.id,
            status=RunState.RUNNING.value,
            trigger="manual",
            job_snapshot={"name": job.name},
            planned_task_count=2,
            tasks_succeeded=1,
            started_at=utc_now(),
        )
        db.add(run)
        db.flush()
        run_id = run.id

        proxy = Proxy(
            name="proxy-realtime-1",
            host="192.168.1.10",
            port=8443,
            token_encrypted=b"enc_token",
            cert_fingerprint_sha256="a" * 64,
            is_enabled=True,
            max_concurrent_tasks=4,
        )
        db.add(proxy)
        db.flush()

        task = Task(
            run_id=run.id,
            kind="transfer",
            scope="files",
            seq=1,
            spec={"rel_path": "data/file1.bin", "operation": "copy"},
            status=TaskState.RUNNING.value,
        )
        db.add(task)
        db.flush()

        assignment = TaskAssignment(
            task_id=task.id,
            attempt_no=1,
            proxy_id=proxy.id,
            status="running",
        )
        db.add(assignment)
        db.flush()

        # Add a task log
        log1 = TaskLog(
            assignment_id=assignment.id,
            task_id=task.id,
            run_id=run.id,
            seq=1,
            level="info",
            stream="stdout",
            message="Transferred: 50/100, 50%, 10.5 MiB/s, ETA 5s",
        )
        db.add(log1)
        db.commit()

    # Login as admin
    client.post("/login", data={"username": "admin", "password": "admin"})

    # Connect to run events stream
    res = client.get(f"/api/ui/runs/{run_id}/events?duration=0.01&interval=0.01")
    assert res.status_code == 200
    assert "text/event-stream" in res.headers["Content-Type"]

    content = res.data.decode("utf-8")
    assert "event: run_snapshot" in content
    assert "Backup Realtime Job" in content
    assert "progress_pct" in content


def test_run_realtime_events_stream_not_found(
    test_app_and_db: tuple[Flask, sessionmaker[Session]],
) -> None:
    app, session_factory = test_app_and_db
    client = app.test_client()

    with session_factory() as db:
        user = db.scalar(select(User).where(User.username == "admin"))
        user.must_change_password = False
        db.commit()

    client.post("/login", data={"username": "admin", "password": "admin"})

    random_id = uuid4()
    res = client.get(f"/api/ui/runs/{random_id}/events?duration=0.01")
    assert res.status_code == 200
    content = res.data.decode("utf-8")
    assert "event: error" in content
    assert "Run non trovata" in content or "Run not found" in content


def test_run_realtime_events_stream_completed_event(
    test_app_and_db: tuple[Flask, sessionmaker[Session]],
) -> None:
    app, session_factory = test_app_and_db
    client = app.test_client()

    with session_factory() as db:
        user = db.scalar(select(User).where(User.username == "admin"))
        user.must_change_password = False

        remote = RcloneRemote(
            name="test-rem-2",
            backend_type="local",
            config_encrypted=b"dummy",
            public_params={},
            secret_field_names=[],
        )
        db.add(remote)
        db.flush()

        job = Job(
            name="Completed Job",
            source_remote_id=remote.id,
            source_path="/src",
            destination_remote_id=remote.id,
            destination_path="/dst",
            enabled=True,
            source_kind="folder",
            operation="copy",
            parallelization="none",
        )
        db.add(job)
        db.flush()

        run = JobRun(
            job_id=job.id,
            status=RunState.SUCCEEDED.value,
            trigger="manual",
            job_snapshot={"name": job.name},
            planned_task_count=1,
            tasks_succeeded=1,
            started_at=utc_now(),
            finished_at=utc_now(),
        )
        db.add(run)
        db.commit()
        run_id = run.id

    client.post("/login", data={"username": "admin", "password": "admin"})

    res = client.get(f"/api/ui/runs/{run_id}/events?duration=1.0&interval=0.01")
    assert res.status_code == 200
    content = res.data.decode("utf-8")
    assert "event: run_completed" in content
    assert "succeeded" in content
