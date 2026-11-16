"""Unit tests for startup recovery of stale running jobs and active runs."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from embervault_common.contracts.enums import RunState, TaskState
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models.auth import AuditLog
from embervault_db.models.base import Base, utc_now
from embervault_db.models.execution import JobRun, Task, TaskAssignment
from embervault_db.models.proxy import Proxy, ProxyStatus
from embervault_db.models.remotes import Job
from embervault_db.repositories.execution_repository import ExecutionRepository
from embervault_db.repositories.proxy_repository import ProxyRepository
from embervault_db.repositories.remote_repository import RemoteRepository


@pytest.fixture
def db_session() -> sessionmaker[Session]:
    set_default_key_ring(KeyRing(keys={"v1": "test_encryption_key_32_characters_"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def test_abort_stale_running_runs_on_startup(db_session: sessionmaker[Session]) -> None:
    """Active runs left over from prior execution or reboot must be marked as failed on startup."""
    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src-remote", "local", {"path": "/data/src"})
        r2 = RemoteRepository.create_remote(session, "dst-remote", "local", {"path": "/data/dst"})
        job1 = Job(name="job-alpha", source_remote_id=r1.id, destination_remote_id=r2.id)
        job2 = Job(name="job-beta", source_remote_id=r1.id, destination_remote_id=r2.id)
        session.add_all([job1, job2])
        session.flush()

        # Create proxy with running tasks > 0
        proxy_id = uuid4()
        token = ProxyRepository.encrypt_token("tok" * 15, proxy_id)
        proxy = Proxy(
            id=proxy_id,
            name="proxy-1",
            host="127.0.0.1",
            port=8443,
            token_encrypted=token,
            cert_fingerprint_sha256="aa" * 32,
        )
        session.add(proxy)
        session.flush()

        proxy_status = ProxyStatus(
            proxy_id=proxy.id,
            state="online",
            running_tasks=3,
        )
        session.add(proxy_status)

        # 1. Stale run in 'running' state for job1
        run1 = JobRun(
            job_id=job1.id,
            trigger="schedule",
            status="running",
            started_at=utc_now(),
        )
        # 2. Stale run in 'planning' state for job2
        run2 = JobRun(
            job_id=job2.id,
            trigger="manual",
            status="planning",
            started_at=utc_now(),
        )
        session.add_all([run1, run2])
        session.flush()

        # Add running task + assignment to run1
        task1 = Task(
            run_id=run1.id,
            kind="transfer",
            scope="whole",
            seq=0,
            status=TaskState.RUNNING.value,
        )
        session.add(task1)
        session.flush()

        assignment1 = TaskAssignment(
            task_id=task1.id,
            attempt_no=1,
            proxy_id=proxy.id,
            status="running",
        )
        session.add(assignment1)

        # Already completed run should NOT be affected
        run_completed = JobRun(
            job_id=job1.id,
            trigger="manual",
            status="succeeded",
            started_at=utc_now(),
            finished_at=utc_now(),
        )
        session.add(run_completed)
        session.commit()

        # Execute recovery on startup
        aborted_count = ExecutionRepository.abort_stale_running_runs_on_startup(session)
        session.commit()

        assert aborted_count == 2

        # Verify run1 was marked failed
        session.refresh(run1)
        assert run1.status == RunState.FAILED.value
        assert run1.finished_at is not None
        assert run1.error_code == "SYSTEM_RESTART_ABORTED"
        assert "Esecuzione interrotta dal riavvio del sistema" in (run1.error_message or "")
        assert run1.notification_sent_at is not None

        # Verify run2 was marked failed
        session.refresh(run2)
        assert run2.status == RunState.FAILED.value
        assert run2.finished_at is not None
        assert run2.error_code == "SYSTEM_RESTART_ABORTED"

        # Verify task1 and assignment1 were aborted
        session.refresh(task1)
        assert task1.status == TaskState.FAILED.value
        assert task1.last_error_code == "SYSTEM_RESTART_ABORTED"

        session.refresh(assignment1)
        assert assignment1.status == "failed"
        assert assignment1.error_code == "SYSTEM_RESTART_ABORTED"

        # Verify proxy running_tasks was reset to 0
        session.refresh(proxy_status)
        assert proxy_status.running_tasks == 0

        # Verify audit logs were written
        audit_logs = list(
            session.scalars(
                select(AuditLog).where(AuditLog.action == "job_run.system_aborted_on_startup")
            ).all()
        )
        assert len(audit_logs) == 2

        # Verify already succeeded run was unchanged
        session.refresh(run_completed)
        assert run_completed.status == "succeeded"

        # Verify running again is idempotent and returns 0
        second_run_aborted = ExecutionRepository.abort_stale_running_runs_on_startup(session)
        assert second_run_aborted == 0

        # Verify that now a NEW run can be created for job1 without hitting active run overlap block
        new_run = ExecutionRepository.create_job_run(session, job1.id, trigger="manual")
        assert new_run is not None
        assert new_run.status == RunState.PLANNING.value


def test_abort_stale_running_runs_on_startup_retry_and_policy_events(
    db_session: sessionmaker[Session],
) -> None:
    """Verify pending_policy='retry' restarts active runs and records policy_events_out."""
    with db_session() as session:
        rem_src = RemoteRepository.create_remote(session, "r-src-retry", "local", {"path": "/s"})
        rem_dst = RemoteRepository.create_remote(session, "r-dst-retry", "local", {"path": "/d"})

        job_retry = Job(
            id=uuid4(),
            name="Retry On Startup Job",
            source_remote_id=rem_src.id,
            source_path="/",
            destination_remote_id=rem_dst.id,
            destination_path="/",
            operation="copy",
            pending_policy="retry",
            pending_notify=True,
        )
        job_fail = Job(
            id=uuid4(),
            name="Fail Quiet On Startup Job",
            source_remote_id=rem_src.id,
            source_path="/",
            destination_remote_id=rem_dst.id,
            destination_path="/b",
            operation="copy",
            pending_policy="fail",
            pending_notify=False,
        )
        session.add_all([job_retry, job_fail])
        session.flush()

        # Run 1: running with existing task and in-flight assignment -> retry should reset task
        run_with_tasks = JobRun(
            id=uuid4(),
            job_id=job_retry.id,
            trigger="schedule",
            status=RunState.RUNNING.value,
            started_at=utc_now(),
            planned_task_count=1,
            tasks_succeeded=1,
            bytes_transferred=2048,
        )
        session.add(run_with_tasks)
        session.flush()

        task_a = Task(
            id=uuid4(),
            run_id=run_with_tasks.id,
            kind="transfer",
            scope="whole",
            seq=0,
            spec={"operation": "copy"},
            status=TaskState.RUNNING.value,
            attempt_count=2,
            last_error_code="OLD_ERR",
        )
        session.add(task_a)
        session.flush()

        assign_a = TaskAssignment(
            id=uuid4(),
            task_id=task_a.id,
            attempt_no=2,
            status="running",
            assigned_at=utc_now(),
        )
        session.add(assign_a)

        # Run 2: planning with zero tasks -> retry should synthesize fallback task
        run_empty = JobRun(
            id=uuid4(),
            job_id=job_retry.id,
            trigger="manual",
            status=RunState.PLANNING.value,
            started_at=utc_now(),
        )
        # Run 3: pending_policy='fail' -> should fail cleanly
        run_fail = JobRun(
            id=uuid4(),
            job_id=job_fail.id,
            trigger="schedule",
            status=RunState.RUNNING.value,
            started_at=utc_now(),
        )
        session.add_all([run_empty, run_fail])
        session.commit()

        policy_events: list[dict] = []
        processed = ExecutionRepository.abort_stale_running_runs_on_startup(
            session, policy_events_out=policy_events
        )
        session.commit()

        assert processed == 3
        assert len(policy_events) == 3

        session.refresh(run_with_tasks)
        assert run_with_tasks.status == RunState.RUNNING.value
        assert run_with_tasks.warning_code == "RETRIED_ON_STARTUP"
        assert run_with_tasks.error_code is None
        assert "RETRY" in (run_with_tasks.error_message or "")
        assert run_with_tasks.bytes_transferred == 0
        assert run_with_tasks.tasks_succeeded == 0

        session.refresh(task_a)
        assert task_a.status == TaskState.READY.value
        assert task_a.attempt_count == 0
        assert task_a.last_error_code is None

        session.refresh(assign_a)
        assert assign_a.status == "failed"
        assert assign_a.error_code == "SYSTEM_RESTART_RETRY"

        session.refresh(run_empty)
        assert run_empty.status == RunState.RUNNING.value
        assert run_empty.planned_task_count == 1
        assert len(run_empty.tasks) == 1
        assert run_empty.tasks[0].status == TaskState.READY.value

        session.refresh(run_fail)
        assert run_fail.status == RunState.FAILED.value
        assert run_fail.error_code == "SYSTEM_RESTART_ABORTED"

        values_by_run = {ev["run"].id: ev["policy_value"] for ev in policy_events}
        assert values_by_run[run_with_tasks.id] == "retry"
        assert values_by_run[run_empty.id] == "retry"
        assert values_by_run[run_fail.id] == "fail"
