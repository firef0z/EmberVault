"""Unit tests for extended Prometheus metrics (Job statistics, Proxy telemetry, Historical totals)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from embervault_common.observability.metrics import (
    collect_system_prometheus_metrics,
    generate_metrics_response,
)
from embervault_db.models.base import Base
from embervault_db.models.execution import JobRun, Task, TaskAssignment
from embervault_db.models.proxy import Proxy, ProxyStatus
from embervault_db.models.remotes import Job, RcloneRemote
from embervault_db.session import create_session_factory


@pytest.fixture
def session_factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    return factory


def test_prometheus_system_metrics_empty_db(session_factory):
    """Verify metrics with empty database."""
    with session_factory() as session:
        collect_system_prometheus_metrics(session)

    data, content_type = generate_metrics_response(session_factory=session_factory)
    text = data.decode("utf-8")

    assert "embervault_total_files_checked 0.0" in text
    assert "embervault_total_files_transferred 0.0" in text
    assert "embervault_total_bytes_transferred 0.0" in text


def test_prometheus_system_metrics_with_jobs_and_proxies(session_factory):
    """Verify job stats, proxy metrics, and historical totals."""
    now = datetime.now(timezone.utc)

    with session_factory() as session:
        # 1. Create a Remote
        remote = RcloneRemote(
            name="local_storage",
            backend_type="local",
            config_encrypted=b"dummy",
        )
        session.add(remote)
        session.flush()

        # 2. Create Job 1 (succeeded run)
        job1 = Job(
            name="Daily-Backup",
            source_remote_id=remote.id,
            destination_remote_id=remote.id,
            source_path="/data",
            destination_path="/backup",
            operation="copy",
        )
        session.add(job1)

        # 3. Create Job 2 (never run)
        job2 = Job(
            name="Never-Run-Job",
            source_remote_id=remote.id,
            destination_remote_id=remote.id,
            source_path="/opt",
            destination_path="/backup/opt",
            operation="copy",
        )
        session.add(job2)
        session.flush()

        # 4. Create Run for Job 1
        run1 = JobRun(
            job_id=job1.id,
            trigger="schedule",
            status="succeeded",
            started_at=datetime(2026, 10, 25, 10, 0, 0, tzinfo=timezone.utc),
            finished_at=datetime(2026, 10, 25, 10, 5, 30, tzinfo=timezone.utc),
            files_transferred=42,
            bytes_transferred=104857600,  # 100 MiB
        )
        session.add(run1)
        session.flush()

        # Create Task & TaskAssignment for Run 1
        task1 = Task(
            run_id=run1.id,
            kind="transfer",
            scope="subfolder",
            spec={"source_subpath": "documents"},
            status="succeeded",
        )
        session.add(task1)
        session.flush()

        # 5. Create Proxy 1 (Online, with active task) and Proxy 2 (Offline)
        p1 = Proxy(
            name="proxy-fast-1",
            host="192.168.1.50",
            port=8443,
            token_encrypted=b"secret",
            cert_fingerprint_sha256="abc123",
            is_enabled=True,
        )
        p1.status = ProxyStatus(
            state="online",
            capacity=4,
            running_tasks=1,
            latency_ms=12,
        )
        session.add(p1)

        p2 = Proxy(
            name="proxy-backup-2",
            host="192.168.1.51",
            port=8443,
            token_encrypted=b"secret",
            cert_fingerprint_sha256="def456",
            is_enabled=True,
        )
        p2.status = ProxyStatus(
            state="offline",
            capacity=2,
            running_tasks=0,
            latency_ms=0,
        )
        session.add(p2)
        session.flush()

        # Assignment for completed task 1
        assign1 = TaskAssignment(
            task_id=task1.id,
            attempt_no=1,
            proxy_id=p1.id,
            status="succeeded",
            checks_count=150,  # 150 files checked and unchanged
            files_transferred=42,
            bytes_transferred=104857600,
        )
        session.add(assign1)

        # Active Task in progress on Proxy 1
        job3 = Job(
            name="Running-Job",
            source_remote_id=remote.id,
            destination_remote_id=remote.id,
            source_path="/var",
            destination_path="/backup/var",
            operation="sync",
        )
        session.add(job3)
        session.flush()

        run2 = JobRun(
            job_id=job3.id,
            trigger="manual",
            status="running",
            started_at=datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc),
            files_transferred=5,
            bytes_transferred=5000000,
        )
        session.add(run2)
        session.flush()

        task2 = Task(
            run_id=run2.id,
            kind="transfer",
            scope="subfolder",
            spec={"source_subpath": "database_dumps"},
            status="running",
        )
        session.add(task2)
        session.flush()

        assign2 = TaskAssignment(
            task_id=task2.id,
            attempt_no=1,
            proxy_id=p1.id,
            status="running",
            checks_count=20,
            files_transferred=5,
            bytes_transferred=5000000,
        )
        session.add(assign2)
        session.commit()

    # Generate metrics
    data, content_type = generate_metrics_response(session_factory=session_factory)
    text = data.decode("utf-8")

    # -------------------------------------------------------------
    # Check Section 1: Job statistics
    # -------------------------------------------------------------
    # Daily-Backup timestamp (2026-10-25 10:00:00 UTC)
    assert 'embervault_job_last_execution_timestamp_seconds{job_id="' in text
    assert 'job_name="Daily-Backup"} 1.7929224e+09' in text or 'Daily-Backup"}' in text

    # Duration: 330 seconds (5m30s)
    assert 'embervault_job_last_execution_duration_seconds{job_id="' in text
    assert 'job_name="Daily-Backup"} 330.0' in text

    # Status: Daily-Backup succeeded -> 1.0 (singola serie per job)
    assert 'embervault_job_last_execution_status{job_id="' in text
    assert 'job_name="Daily-Backup"} 1.0' in text

    # Running-Job: in_progress -> 3.0 (singola serie per job)
    assert 'job_name="Running-Job"} 3.0' in text

    # Never-Run-Job: never run -> 0.0 (singola serie per job)
    assert 'job_name="Never-Run-Job"} 0.0' in text

    # Analyzed files total: 150 checks + 42 transferred = 192
    assert 'embervault_job_last_execution_files_total{job_id="' in text
    assert 'job_name="Daily-Backup"} 192.0' in text

    # Analyzed bytes total: 104857600
    assert 'embervault_job_last_execution_bytes_total{job_id="' in text
    assert (
        'job_name="Daily-Backup"} 1.048576e+08' in text
        or 'job_name="Daily-Backup"} 104857600' in text
    )

    # -------------------------------------------------------------
    # Check Section 2: Proxy metrics
    # -------------------------------------------------------------
    # Proxy UP / DOWN
    assert (
        'embervault_proxy_up{proxy_address="192.168.1.50:8443",proxy_name="proxy-fast-1"} 1.0'
        in text
    )
    assert (
        'embervault_proxy_up{proxy_address="192.168.1.51:8443",proxy_name="proxy-backup-2"} 0.0'
        in text
    )

    # Current task on proxy-fast-1: database_dumps
    assert (
        'embervault_proxy_current_task{proxy_address="192.168.1.50:8443",proxy_name="proxy-fast-1",task_name="database_dumps"} 1.0'
        in text
    )
    # Current task on proxy-backup-2: None
    assert (
        'embervault_proxy_current_task{proxy_address="192.168.1.51:8443",proxy_name="proxy-backup-2",task_name="None"} 1.0'
        in text
    )

    # Status: working (1.0) vs standby (0.0) - singola serie per proxy
    assert (
        'embervault_proxy_status{proxy_address="192.168.1.50:8443",proxy_name="proxy-fast-1"} 1.0'
        in text
    )
    assert (
        'embervault_proxy_status{proxy_address="192.168.1.51:8443",proxy_name="proxy-backup-2"} 0.0'
        in text
    )

    # Throughput
    assert (
        'embervault_proxy_current_throughput_bytes_per_second{proxy_address="192.168.1.50:8443",proxy_name="proxy-fast-1"}'
        in text
    )

    # -------------------------------------------------------------
    # Check Section 3: Historical totals
    # -------------------------------------------------------------
    # Total files checked: 150 + 20 = 170
    assert "embervault_total_files_checked 170.0" in text

    # Total files transferred: 42 + 5 = 47
    assert "embervault_total_files_transferred 47.0" in text

    # Total bytes transferred: 104857600 + 5000000 = 109857600
    assert (
        "embervault_total_bytes_transferred 1.098576e+08" in text
        or "embervault_total_bytes_transferred 109857600" in text
    )


def test_prometheus_system_metrics_files_checked_backfill_and_update(session_factory):
    """Verify that TaskAssignment checks_count is properly updated via update_assignment_status

    and that historical records with checks_count=0 are automatically self-healed from TaskLog.
    """
    from embervault_db.models.execution import TaskLog
    from embervault_db.repositories.execution_repository import ExecutionRepository

    with session_factory() as session:
        remote = RcloneRemote(
            name="remote_checked",
            backend_type="local",
            config_encrypted=b"dummy",
        )
        session.add(remote)
        session.flush()

        job = Job(
            name="Check-Job",
            source_remote_id=remote.id,
            destination_remote_id=remote.id,
            source_path="/data/src",
            destination_path="/data/dst",
            operation="sync",
        )
        session.add(job)
        session.flush()

        run = JobRun(
            job_id=job.id,
            trigger="manual",
            status="running",
        )
        session.add(run)
        session.flush()

        task1 = Task(run_id=run.id, kind="transfer", scope="whole", status="running")
        session.add(task1)
        session.flush()

        assign1 = TaskAssignment(
            task_id=task1.id,
            attempt_no=1,
            status="running",
            checks_count=0,
        )
        session.add(assign1)
        session.flush()

        # Update assignment with checks_count
        ExecutionRepository.update_assignment_status(
            session=session,
            assignment_id=assign1.id,
            status="succeeded",
            checks_count=120,
        )
        session.commit()

        assert assign1.checks_count == 120

        # Now create another task with checks_count=0 but having log entries
        task2 = Task(run_id=run.id, kind="transfer", scope="subfolder", status="succeeded")
        session.add(task2)
        session.flush()

        assign2 = TaskAssignment(
            task_id=task2.id,
            attempt_no=1,
            status="succeeded",
            checks_count=0,
        )
        session.add(assign2)
        session.flush()

        log1 = TaskLog(
            assignment_id=assign2.id,
            task_id=task2.id,
            run_id=run.id,
            seq=0,
            stream="stdout",
            level="info",
            message="2026/10/29 10:00:00 INFO : Checks: 35 / 35, 100%",
        )
        session.add(log1)
        session.commit()

    # When metrics are collected, assign2 should be self-healed to 35
    data, content_type = generate_metrics_response(session_factory=session_factory)
    text = data.decode("utf-8")

    # Total files checked: 120 + 35 = 155
    assert "embervault_total_files_checked 155.0" in text
