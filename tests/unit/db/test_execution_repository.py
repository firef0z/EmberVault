"""Unit tests for ExecutionRepository (Milestones M1.4, M1.6, M1.7)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_common.contracts.enums import (
    RunState,
    TaskKind,
    TaskOperation,
    TaskScope,
    TaskState,
)
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models.base import Base
from embervault_db.repositories.execution_repository import ExecutionRepository
from embervault_db.repositories.job_repository import JobRepository
from embervault_db.repositories.proxy_repository import ProxyRepository
from embervault_db.repositories.remote_repository import RemoteRepository
from embervault_orchestrator.planner.spec import JobPlanningSpec, PlannedTask, plan_job_tasks


@pytest.fixture
def db_session() -> sessionmaker[Session]:
    set_default_key_ring(KeyRing(keys={"v1": "test_encryption_key_32_characters_"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def test_create_job_run_and_materialize_tasks(db_session: sessionmaker[Session]) -> None:
    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src-local", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-local", "local", {"path": "/dst"})
        session.commit()
        r1_id, r2_id = r1.id, r2.id

    with db_session() as session:
        job = JobRepository.create_job(
            session=session,
            name="job-test-run",
            source_remote_id=r1_id,
            source_path="/photos",
            destination_remote_id=r2_id,
            destination_path="/photos-backup",
        )
        session.commit()
        job_id = job.id

    # 1. Create run
    with db_session() as session:
        run = ExecutionRepository.create_job_run(session, job_id=job_id, trigger="manual")
        session.commit()
        run_id = run.id
        assert run.status == RunState.PLANNING.value
        assert run.job_snapshot["name"] == "job-test-run"

    # 2. Materialize tasks
    spec = JobPlanningSpec(
        source_type="folder",
        parallel_mode="none",
        operation=TaskOperation.COPY,
        source_path="/photos",
        dest_path="/photos-backup",
    )
    planned = plan_job_tasks(spec)

    with db_session() as session:
        tasks = ExecutionRepository.materialize_planned_tasks(session, run_id, planned)
        session.commit()
        assert len(tasks) == 1
        assert tasks[0].status == TaskState.READY.value
        assert tasks[0].seq == 0
        task_id = tasks[0].id

    # 3. Create assignment & lease
    with db_session() as session:
        from embervault_db.models.proxy import Proxy

        proxy_id = uuid.uuid4()
        proxy = Proxy(
            id=proxy_id,
            name="node-runner",
            host="127.0.0.1",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("a" * 32, proxy_id),
            cert_fingerprint_sha256="aa" * 32,
            is_enabled=True,
        )
        session.add(proxy)
        ProxyRepository.get_or_create_status(session, proxy_id)
        session.commit()

        assignment = ExecutionRepository.create_assignment(session, task_id, proxy_id)
        session.commit()
        assignment_id = assignment.id
        assert assignment.status == "assigned"
        assert assignment.attempt_no == 1

    # 4. Progress and logs
    with db_session() as session:
        ExecutionRepository.update_assignment_status(
            session=session,
            assignment_id=assignment_id,
            status="running",
            bytes_transferred=1024,
            files_transferred=2,
        )
        ExecutionRepository.record_task_log(
            session=session,
            assignment_id=assignment_id,
            task_id=task_id,
            run_id=run_id,
            message="Transferring photo1.jpg",
        )
        session.commit()

    with db_session() as session:
        logs = ExecutionRepository.get_task_logs(session, task_id)
        assert len(logs) == 1
        assert logs[0].message == "Transferring photo1.jpg"

        # Complete assignment
        ExecutionRepository.update_assignment_status(
            session=session,
            assignment_id=assignment_id,
            status="succeeded",
            exit_code=0,
            bytes_transferred=2048,
            files_transferred=3,
        )
        session.commit()

    # 5. Check run reconciliation
    with db_session() as session:
        final_run = ExecutionRepository.get_run_by_id(session, run_id)
        assert final_run is not None
        assert final_run.status == RunState.SUCCEEDED.value
        assert final_run.tasks_succeeded == 1
        assert final_run.tasks_failed == 0
        assert final_run.bytes_transferred == 2048
        assert final_run.files_transferred == 3


def test_cancel_run(db_session: sessionmaker[Session]) -> None:
    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src-cancel", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-cancel", "local", {"path": "/dst"})
        job = JobRepository.create_job(
            session=session,
            name="job-to-cancel",
            source_remote_id=r1.id,
            source_path="/a",
            destination_remote_id=r2.id,
            destination_path="/b",
        )
        session.commit()
        job_id = job.id

    with db_session() as session:
        run = ExecutionRepository.create_job_run(session, job_id=job_id)
        ExecutionRepository.materialize_planned_tasks(
            session,
            run.id,
            [
                PlannedTask(
                    kind=TaskKind.TRANSFER, scope=TaskScope.WHOLE, operation=TaskOperation.COPY
                )
            ],
        )
        session.commit()
        run_id = run.id

    with db_session() as session:
        ok, active_assignments = ExecutionRepository.cancel_run(session, run_id)
        assert ok is True
        assert isinstance(active_assignments, list)
        session.commit()

    with db_session() as session:
        loaded = ExecutionRepository.get_run_by_id(session, run_id)
        assert loaded is not None
        assert loaded.status == RunState.CANCELLED.value
        assert loaded.tasks[0].status == TaskState.CANCELLED.value


def test_get_run_proxies_activity(db_session: sessionmaker[Session]) -> None:
    from embervault_db.models.proxy import Proxy

    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src-prox", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-prox", "local", {"path": "/dst"})
        job = JobRepository.create_job(
            session=session,
            name="job-prox",
            source_remote_id=r1.id,
            source_path="/data",
            destination_remote_id=r2.id,
            destination_path="/backup",
        )
        p1_id = uuid.uuid4()
        p1 = Proxy(
            id=p1_id,
            name="proxy-alpha",
            host="10.0.0.1",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("x" * 32, p1_id),
            cert_fingerprint_sha256="11" * 32,
            is_enabled=True,
        )
        p2_id = uuid.uuid4()
        p2 = Proxy(
            id=p2_id,
            name="proxy-beta",
            host="10.0.0.2",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("y" * 32, p2_id),
            cert_fingerprint_sha256="22" * 32,
            is_enabled=True,
        )
        session.add_all([p1, p2])
        st1 = ProxyRepository.get_or_create_status(session, p1_id)
        st1.state = "online"
        st2 = ProxyRepository.get_or_create_status(session, p2_id)
        st2.state = "offline"

        run = ExecutionRepository.create_job_run(session, job_id=job.id)
        tasks = ExecutionRepository.materialize_planned_tasks(
            session,
            run.id,
            [
                PlannedTask(
                    kind=TaskKind.TRANSFER,
                    scope=TaskScope.SUBFOLDER,
                    operation=TaskOperation.COPY,
                    source_subpath="folder1",
                )
            ],
        )
        task_id = tasks[0].id
        session.commit()
        run_id = run.id

    # Assign task to proxy-alpha
    with db_session() as session:
        assign = ExecutionRepository.create_assignment(session, task_id, p1_id)
        assert assign.proxy is not None
        assert assign.proxy.name == "proxy-alpha"
        session.commit()

    with db_session() as session:
        run = ExecutionRepository.get_run_by_id(session, run_id)
        assert run is not None
        proxies_activity = ExecutionRepository.get_run_proxies_activity(session, run)
        assert len(proxies_activity) == 2
        p_alpha = next(p for p in proxies_activity if p["name"] == "proxy-alpha")
        p_beta = next(p for p in proxies_activity if p["name"] == "proxy-beta")

        assert p_alpha["state"] == "busy"
        assert "folder1" in p_alpha["activity"]
        assert p_beta["state"] == "offline"
        assert p_beta["activity"] == "Offline"


def test_get_run_tasks_progress_stats(db_session: sessionmaker[Session]) -> None:
    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src-local", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-local", "local", {"path": "/dst"})
        session.commit()
        job = JobRepository.create_job(session, "job-stats", r1.id, "/data", r2.id, "/bk")
        run = ExecutionRepository.create_job_run(session, job.id)
        tasks = ExecutionRepository.materialize_planned_tasks(
            session,
            run.id,
            [
                PlannedTask(
                    kind=TaskKind.TRANSFER,
                    scope=TaskScope.SUBFOLDER,
                    operation=TaskOperation.COPY,
                    source_subpath="iso",
                )
            ],
        )
        t_id = tasks[0].id
        session.commit()
        run_id = run.id

    # 1. Before logs exist -> defaults to '-'
    with db_session() as session:
        run = ExecutionRepository.get_run_by_id(session, run_id)
        assert run is not None
        stats = ExecutionRepository.get_run_tasks_progress_stats(session, run)
        assert stats[t_id]["checks_display"] == "-"
        assert stats[t_id]["transferred_display"] == "-"

    # 2. Record simulated rclone logs into task_logs
    with db_session() as session:
        p_id = uuid.uuid4()
        assign = ExecutionRepository.create_assignment(session, t_id, p_id)
        session.commit()
        assign_id = assign.id

    with db_session() as session:
        log_lines = [
            {"level": "info", "message": "2026/10/20 21:35:21 INFO :"},
            {"level": "info", "message": "Elapsed time: 57.0s"},
            {"level": "info", "message": "Transferred:            0 / 1, 0%"},
            {"level": "info", "message": "Checks:                 1 / 1, 100%"},
            {
                "level": "info",
                "message": "Transferred: \t  566.500 MiB / 7.222 GiB, 8%, 7.596 MiB/s, ETA 14m58s",
            },
        ]
        ExecutionRepository.record_task_logs_batch(
            session=session,
            assignment_id=assign_id,
            task_id=t_id,
            run_id=run_id,
            lines=log_lines,
        )
        session.commit()

    with db_session() as session:
        run = ExecutionRepository.get_run_by_id(session, run_id)
        assert run is not None
        stats = ExecutionRepository.get_run_tasks_progress_stats(session, run)
        assert stats[t_id]["checks_display"] == "1"
        assert stats[t_id]["transferred_display"] == "0/1 - 0%"

    # 3. Subsequent completion log
    with db_session() as session:
        later_lines = [
            {"level": "info", "message": "Transferred:            1 / 1, 100%"},
            {"level": "info", "message": "Checks:                 1 / 1, 100%"},
            {
                "level": "info",
                "message": "Transferred: 7.222 GiB / 7.222 GiB, 100%, 8.0 MiB/s, ETA 0s",
            },
        ]
        ExecutionRepository.record_task_logs_batch(
            session=session,
            assignment_id=assign_id,
            task_id=t_id,
            run_id=run_id,
            lines=later_lines,
        )
        session.commit()

    with db_session() as session:
        run = ExecutionRepository.get_run_by_id(session, run_id)
        assert run is not None
        # When running, eta and speed are reported
        run.tasks[0].status = "running"
        stats = ExecutionRepository.get_run_tasks_progress_stats(session, run)
        assert stats[t_id]["checks_display"] == "1"
        assert stats[t_id]["transferred_display"] == "1/1 - 100%"
        assert stats[t_id]["eta_display"] == "0s"
        assert stats[t_id]["speed_display"] == "8.0 MiB/s"
        assert stats[t_id]["speed_bytes_per_sec"] > 0


def test_reconcile_job_run_statuses(db_session: sessionmaker[Session]) -> None:
    """Verify run status resolution: cancelled, failed, partially_failed with warnings/errors, succeeded."""
    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src-rec", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-rec", "local", {"path": "/dst"})
        job = JobRepository.create_job(
            session=session,
            name="job-reconcile-rules",
            source_remote_id=r1.id,
            source_path="/a",
            destination_remote_id=r2.id,
            destination_path="/b",
        )
        session.commit()
        job_id = job.id

    # Case 1: 1 cancelled, 1 succeeded -> partially_failed (Completata con avvisi)
    with db_session() as session:
        run = ExecutionRepository.create_job_run(session, job_id=job_id)
        ExecutionRepository.materialize_planned_tasks(
            session,
            run.id,
            [
                PlannedTask(
                    kind=TaskKind.TRANSFER, scope=TaskScope.WHOLE, operation=TaskOperation.COPY
                ),
                PlannedTask(
                    kind=TaskKind.TRANSFER, scope=TaskScope.SUBFOLDER, operation=TaskOperation.COPY
                ),
            ],
        )
        session.commit()
        run.tasks[0].status = TaskState.SUCCEEDED.value
        run.tasks[1].status = TaskState.CANCELLED.value
        ExecutionRepository._reconcile_job_run_state(session, run)
        assert run.status == RunState.PARTIALLY_FAILED.value
        assert run.tasks_failed == 0
        session.commit()

    # Case 2: 1 failed, 1 cancelled, 1 succeeded -> partially_failed (Completata con errori)
    with db_session() as session:
        run2 = ExecutionRepository.create_job_run(session, job_id=job_id)
        ExecutionRepository.materialize_planned_tasks(
            session,
            run2.id,
            [
                PlannedTask(
                    kind=TaskKind.TRANSFER, scope=TaskScope.WHOLE, operation=TaskOperation.COPY
                ),
                PlannedTask(
                    kind=TaskKind.TRANSFER, scope=TaskScope.SUBFOLDER, operation=TaskOperation.COPY
                ),
                PlannedTask(
                    kind=TaskKind.TRANSFER, scope=TaskScope.SUBFOLDER, operation=TaskOperation.COPY
                ),
            ],
        )
        session.commit()
        run2.tasks[0].status = TaskState.SUCCEEDED.value
        run2.tasks[1].status = TaskState.CANCELLED.value
        run2.tasks[2].status = TaskState.FAILED.value
        ExecutionRepository._reconcile_job_run_state(session, run2)
        assert run2.status == RunState.PARTIALLY_FAILED.value
        assert run2.tasks_failed == 1
        session.commit()

    # Case 3: All cancelled -> cancelled
    with db_session() as session:
        run3 = ExecutionRepository.create_job_run(session, job_id=job_id)
        ExecutionRepository.materialize_planned_tasks(
            session,
            run3.id,
            [
                PlannedTask(
                    kind=TaskKind.TRANSFER, scope=TaskScope.WHOLE, operation=TaskOperation.COPY
                )
            ],
        )
        session.commit()
        run3.tasks[0].status = TaskState.CANCELLED.value
        ExecutionRepository._reconcile_job_run_state(session, run3)
        assert run3.status == RunState.CANCELLED.value
        session.commit()

    # Case 4: All failed -> failed
    with db_session() as session:
        run4 = ExecutionRepository.create_job_run(session, job_id=job_id)
        ExecutionRepository.materialize_planned_tasks(
            session,
            run4.id,
            [
                PlannedTask(
                    kind=TaskKind.TRANSFER, scope=TaskScope.WHOLE, operation=TaskOperation.COPY
                )
            ],
        )
        session.commit()
        run4.tasks[0].status = TaskState.FAILED.value
        ExecutionRepository._reconcile_job_run_state(session, run4)
        assert run4.status == RunState.FAILED.value
        session.commit()


def test_get_task_logs_unlimited_and_options(db_session: sessionmaker[Session]) -> None:
    """Verify get_task_logs handles >5000 lines without truncating, and supports limit, from_seq, and tail."""
    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src-logs", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-logs", "local", {"path": "/dst"})
        job = JobRepository.create_job(
            session=session,
            name="job-logs-test",
            source_remote_id=r1.id,
            source_path="/",
            destination_remote_id=r2.id,
            destination_path="/backup",
            operation="copy",
        )
        run = ExecutionRepository.create_job_run(session, job_id=job.id)
        ExecutionRepository.materialize_planned_tasks(
            session,
            run.id,
            [
                PlannedTask(
                    kind=TaskKind.TRANSFER, scope=TaskScope.WHOLE, operation=TaskOperation.COPY
                )
            ],
        )
        session.commit()
        task_id = run.tasks[0].id

        from embervault_db.models.proxy import Proxy

        proxy_id = uuid.uuid4()
        p = Proxy(
            id=proxy_id,
            name="proxy-logs",
            host="127.0.0.1",
            port=8443,
            token_encrypted=b"secret",
            cert_fingerprint_sha256="ff" * 32,
            is_enabled=True,
        )
        session.add(p)
        session.commit()

        assignment = ExecutionRepository.create_assignment(session, task_id, proxy_id)
        assignment_id = assignment.id
        session.commit()

    # Bulk insert 5200 log lines
    with db_session() as session:
        lines = [
            {"seq": i, "stream": "stdout", "level": "info", "message": f"Log line {i}"}
            for i in range(5200)
        ]
        ExecutionRepository.record_task_logs_batch(
            session=session,
            assignment_id=assignment_id,
            task_id=task_id,
            run_id=run.id,
            lines=lines,
        )
        session.commit()

    # Verify default get_task_logs returns ALL 5200 lines (no 5000 cut-off)
    with db_session() as session:
        logs_all = ExecutionRepository.get_task_logs(session, task_id)
        assert len(logs_all) == 5200
        assert logs_all[0].seq == 0
        assert logs_all[-1].seq == 5199

        # Test limit
        logs_limit = ExecutionRepository.get_task_logs(session, task_id, limit=100)
        assert len(logs_limit) == 100
        assert logs_limit[0].seq == 0
        assert logs_limit[-1].seq == 99

        # Test from_seq
        logs_from = ExecutionRepository.get_task_logs(session, task_id, from_seq=5100)
        assert len(logs_from) == 100
        assert logs_from[0].seq == 5100
        assert logs_from[-1].seq == 5199

        # Test tail=True with limit
        logs_tail = ExecutionRepository.get_task_logs(session, task_id, limit=50, tail=True)
        assert len(logs_tail) == 50
        assert logs_tail[0].seq == 5150
        assert logs_tail[-1].seq == 5199


def test_progress_stats_active_for_assigned_task(db_session: sessionmaker[Session]) -> None:
    """Verify that tasks in ASSIGNED state are treated as active for progress stats and throughput."""
    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src-assigned", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-assigned", "local", {"path": "/dst"})
        job = JobRepository.create_job(
            session=session,
            name="job-assigned-test",
            source_remote_id=r1.id,
            source_path="/",
            destination_remote_id=r2.id,
            destination_path="/backup",
            operation="copy",
        )
        run = ExecutionRepository.create_job_run(session, job_id=job.id)
        ExecutionRepository.materialize_planned_tasks(
            session,
            run.id,
            [
                PlannedTask(
                    kind=TaskKind.TRANSFER, scope=TaskScope.WHOLE, operation=TaskOperation.COPY
                )
            ],
        )
        session.commit()
        task = run.tasks[0]
        from embervault_db.models.proxy import Proxy

        proxy_id = uuid.uuid4()
        p = Proxy(
            id=proxy_id,
            name="proxy-assigned",
            host="127.0.0.1",
            port=8443,
            token_encrypted=b"secret",
            cert_fingerprint_sha256="ff" * 32,
            is_enabled=True,
        )
        session.add(p)
        session.commit()

        assignment = ExecutionRepository.create_assignment(session, task.id, proxy_id)
        # Task is in ASSIGNED state
        assert task.status == TaskState.ASSIGNED.value

        ExecutionRepository.record_task_log(
            session=session,
            assignment_id=assignment.id,
            task_id=task.id,
            run_id=run.id,
            message="Checks: 7769 / 7769, 100%",
        )
        ExecutionRepository.record_task_log(
            session=session,
            assignment_id=assignment.id,
            task_id=task.id,
            run_id=run.id,
            message="Transferred: 50 / 100, 50%, 15.5 MiB/s, ETA 1m30s",
        )
        session.commit()

    with db_session() as session:
        run_obj = ExecutionRepository.get_run_by_id(session, run.id)
        assert run_obj is not None
        stats = ExecutionRepository.get_run_tasks_progress_stats(session, run_obj)
        task_stat = stats[task.id]

        assert task_stat["checks_display"] == "7769"
        assert task_stat["transferred_display"] == "50/100 - 50%"
        assert task_stat["speed_display"] == "15.5 MiB/s"
        assert task_stat["speed_bytes_per_sec"] > 15 * 1024 * 1024
        assert task_stat["eta_display"] == "1m30s"
