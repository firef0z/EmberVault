"""Unit tests verifying lease renewal during task execution and expiration on unreachable proxy."""

from __future__ import annotations

import datetime
from datetime import timedelta
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from embervault_common.contracts import ErrorCode, ProxyState, TaskState
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models import Job, JobRun, Task, TaskAssignment
from embervault_db.models.base import Base, utc_now
from embervault_db.models.proxy import Proxy
from embervault_db.repositories.execution_repository import ExecutionRepository
from embervault_db.repositories.proxy_repository import ProxyRepository
from embervault_db.repositories.remote_repository import RemoteRepository
from embervault_orchestrator.proxy_client import ProxyClient, ProxyUnreachableError
from embervault_orchestrator.reconciler import ExecutionReconciler


@pytest.fixture
def session_factory() -> sessionmaker[Session]:
    set_default_key_ring(KeyRing(keys={"v1": "test_encryption_key_32_characters_"}))
    engine = create_engine(
        "sqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def test_active_task_renews_lease_during_reconciliation(
    session_factory: sessionmaker[Session],
) -> None:
    """A running task polled by the reconciler must have its lease extended so long transfers never fail."""
    mock_proxy_client = MagicMock(spec=ProxyClient)
    mock_proxy_client.get_task_status.return_value = {
        "status": "running",
        "progress": {"bytes_transferred": 1000000, "files_transferred": 1},
    }
    mock_proxy_client.get_task_logs.return_value = {"lines": []}

    reconciler = ExecutionReconciler(
        session_factory=session_factory,
        proxy_client=mock_proxy_client,
    )

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "src", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst", "local", {"path": "/dst"})
        pid = uuid4()
        token = ProxyRepository.encrypt_token("tok" * 15, pid)
        proxy = Proxy(
            id=pid,
            name="p1",
            host="127.0.0.1",
            port=8443,
            token_encrypted=token,
            cert_fingerprint_sha256="aa" * 32,
        )
        session.add(proxy)

        job = Job(name="job-1", source_remote_id=r1.id, destination_remote_id=r2.id)
        session.add(job)
        session.flush()

        run = JobRun(job_id=job.id, trigger="manual", status="running")
        session.add(run)
        session.flush()

        task = Task(
            run_id=run.id, kind="transfer", scope="whole", seq=0, status=TaskState.RUNNING.value
        )
        session.add(task)
        session.flush()

        # Assignment initially with lease expiring in 5 seconds
        initial_expiry = utc_now() + timedelta(seconds=5)
        assignment = ExecutionRepository.create_assignment(
            session, task.id, proxy.id, lease_duration_s=5
        )
        session.commit()

        # Run reconciler sync
        stats = {"tasks_updated": 0, "leases_reaped": 0}
        reconciler._sync_assignment(session, assignment, task, run, stats)
        session.commit()

        # Verify that lease was renewed far into the future (at least 500s from now)
        assignment_updated = session.get(TaskAssignment, assignment.id)
        assert assignment_updated is not None
        assert assignment_updated.lease_expires_at > initial_expiry
        assert assignment_updated.lease_expires_at > utc_now() + timedelta(seconds=500)
        assert assignment_updated.status == "running"
        assert stats["leases_reaped"] == 0


def test_unreachable_proxy_expires_lease_when_past_deadline(
    session_factory: sessionmaker[Session],
) -> None:
    """If proxy is unreachable and lease has expired, task must be reaped as LEASE_EXPIRED."""
    mock_proxy_client = MagicMock(spec=ProxyClient)
    mock_proxy_client.get_task_status.side_effect = ProxyUnreachableError("Connection refused")

    reconciler = ExecutionReconciler(
        session_factory=session_factory,
        proxy_client=mock_proxy_client,
    )

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "src", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst", "local", {"path": "/dst"})
        pid = uuid4()
        token = ProxyRepository.encrypt_token("tok" * 15, pid)
        proxy = Proxy(
            id=pid,
            name="p1",
            host="127.0.0.1",
            port=8443,
            token_encrypted=token,
            cert_fingerprint_sha256="aa" * 32,
        )
        session.add(proxy)

        job = Job(name="job-1", source_remote_id=r1.id, destination_remote_id=r2.id)
        session.add(job)
        session.flush()

        run = JobRun(job_id=job.id, trigger="manual", status="running")
        session.add(run)
        session.flush()

        task = Task(
            run_id=run.id, kind="transfer", scope="whole", seq=0, status=TaskState.RUNNING.value
        )
        session.add(task)
        session.flush()

        # Assignment already expired in the past
        past_expiry = utc_now() - timedelta(seconds=10)
        assignment = ExecutionRepository.create_assignment(
            session, task.id, proxy.id, lease_duration_s=60
        )
        assignment.lease_expires_at = past_expiry
        session.commit()

        stats = {"tasks_updated": 0, "leases_reaped": 0}
        reconciler._sync_assignment(session, assignment, task, run, stats)
        session.commit()

        assignment_updated = session.get(TaskAssignment, assignment.id)
        assert assignment_updated is not None
        assert assignment_updated.status == "failed"
        assert assignment_updated.error_code == "LEASE_EXPIRED"
        assert stats["leases_reaped"] == 1


def test_unreachable_proxy_keeps_lease_when_before_deadline(
    session_factory: sessionmaker[Session],
) -> None:
    """If proxy is momentarily unreachable but lease has NOT expired yet, task is NOT reaped."""
    mock_proxy_client = MagicMock(spec=ProxyClient)
    mock_proxy_client.get_task_status.side_effect = ProxyUnreachableError("Temporary timeout")

    reconciler = ExecutionReconciler(
        session_factory=session_factory,
        proxy_client=mock_proxy_client,
    )

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "src", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst", "local", {"path": "/dst"})
        pid = uuid4()
        token = ProxyRepository.encrypt_token("tok" * 15, pid)
        proxy = Proxy(
            id=pid,
            name="p1",
            host="127.0.0.1",
            port=8443,
            token_encrypted=token,
            cert_fingerprint_sha256="aa" * 32,
        )
        session.add(proxy)

        job = Job(name="job-1", source_remote_id=r1.id, destination_remote_id=r2.id)
        session.add(job)
        session.flush()

        run = JobRun(job_id=job.id, trigger="manual", status="running")
        session.add(run)
        session.flush()

        task = Task(
            run_id=run.id, kind="transfer", scope="whole", seq=0, status=TaskState.RUNNING.value
        )
        session.add(task)
        session.flush()

        future_expiry = utc_now() + timedelta(seconds=300)
        assignment = ExecutionRepository.create_assignment(
            session, task.id, proxy.id, lease_duration_s=300
        )
        session.commit()

        stats = {"tasks_updated": 0, "leases_reaped": 0}
        reconciler._sync_assignment(session, assignment, task, run, stats)
        session.commit()

        assignment_updated = session.get(TaskAssignment, assignment.id)
        assert assignment_updated is not None
        assert assignment_updated.status == "assigned"  # Still active, not failed
        assert stats["leases_reaped"] == 0
