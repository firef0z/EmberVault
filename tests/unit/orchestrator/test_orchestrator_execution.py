"""Unit tests for Orchestrator job run triggering, reconciliation, and lease management (Milestones M1.4, M1.6)."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest
from flask.testing import FlaskClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models.base import Base
from embervault_db.models.proxy import Proxy
from embervault_db.repositories.execution_repository import ExecutionRepository
from embervault_db.repositories.job_repository import JobRepository
from embervault_db.repositories.proxy_repository import ProxyRepository
from embervault_db.repositories.remote_repository import RemoteRepository
from embervault_orchestrator.factory import create_orchestrator_app
from embervault_orchestrator.internal_api import set_proxy_client
from embervault_orchestrator.proxy_client import ProxyClient
from embervault_orchestrator.reconciler import ExecutionReconciler


@pytest.fixture
def test_setup() -> tuple[FlaskClient, sessionmaker[Session], MagicMock]:
    set_default_key_ring(KeyRing(keys={"v1": "test_encryption_key_32_characters_"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    mock_proxy_client = MagicMock(spec=ProxyClient)
    mock_proxy_client.dispatch_task.return_value = {"status": "accepted"}
    mock_proxy_client.get_task_status.return_value = {
        "status": "succeeded",
        "exit_code": 0,
        "progress": {"bytes_transferred": 5000, "files_transferred": 10},
    }
    mock_proxy_client.get_task_logs.return_value = {
        "lines": [{"seq": 0, "message": "Done", "level": "INFO"}],
    }
    mock_proxy_client.cancel_task.return_value = {"status": "cancelled"}
    set_proxy_client(mock_proxy_client)

    app = create_orchestrator_app(session_factory=session_factory)
    app.config["TESTING"] = True
    return app.test_client(), session_factory, mock_proxy_client


def test_orchestrator_job_run_flow(
    test_setup: tuple[FlaskClient, sessionmaker[Session], MagicMock],
) -> None:
    client, session_factory, mock_proxy_client = test_setup

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "src-local", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-local", "local", {"path": "/dst"})

        proxy_id = uuid.uuid4()
        proxy = Proxy(
            id=proxy_id,
            name="worker-1",
            host="127.0.0.1",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("a" * 32, proxy_id),
            cert_fingerprint_sha256="bb" * 32,
            is_enabled=True,
        )
        session.add(proxy)
        status = ProxyRepository.get_or_create_status(session, proxy_id)
        status.state = "online"

        job = JobRepository.create_job(
            session=session,
            name="orch-run-test",
            source_remote_id=r1.id,
            source_path="/photos",
            destination_remote_id=r2.id,
            destination_path="/photos-backup",
            parallelization="none",
        )
        session.commit()
        job_id = job.id

    # 1. Trigger job run via POST /internal/v1/jobs/<id>/run
    run_resp = client.post(f"/internal/v1/jobs/{job_id}/run")
    assert run_resp.status_code == 200
    run_data = run_resp.get_json()
    assert run_data["status"] == "dispatched"
    run_id = uuid.UUID(run_data["run_id"])
    assert run_data["planned_task_count"] == 1
    assert run_data["dispatched_count"] == 1

    # Verify proxy client dispatch was called
    mock_proxy_client.dispatch_task.assert_called_once()

    # 2. Query run details -> triggers reconciliation with proxy
    detail_resp = client.get(f"/internal/v1/runs/{run_id}")
    assert detail_resp.status_code == 200
    run_detail = detail_resp.get_json()["run"]
    assert run_detail["status"] == "succeeded"
    assert run_detail["tasks_succeeded"] == 1
    assert run_detail["bytes_transferred"] == 5000
    assert "proxies" in run_detail
    assert len(run_detail["proxies"]) == 1
    assert run_detail["proxies"][0]["name"] == "worker-1"
    assert run_detail["tasks"][0]["proxy_name"] == "worker-1"

    # 3. Check logs stored in DB
    task_id = run_detail["tasks"][0]["id"]
    logs_resp = client.get(f"/internal/v1/tasks/{task_id}/logs")
    assert logs_resp.status_code == 200
    assert len(logs_resp.get_json()["lines"]) >= 1

    # 4. Test cancel on completed run returns 400
    cancel_resp = client.post(f"/internal/v1/runs/{run_id}/cancel")
    assert cancel_resp.status_code == 400


def test_reconciler_cycle(test_setup: tuple[FlaskClient, sessionmaker[Session], MagicMock]) -> None:
    _, session_factory, mock_proxy_client = test_setup

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "src-rec", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-rec", "local", {"path": "/dst"})
        job = JobRepository.create_job(
            session=session,
            name="job-reconcile",
            source_remote_id=r1.id,
            source_path="/a",
            destination_remote_id=r2.id,
            destination_path="/b",
        )
        session.commit()
        job_id = job.id

        run = ExecutionRepository.create_job_run(session, job_id)
        from embervault_common.contracts.enums import TaskKind, TaskOperation, TaskScope
        from embervault_orchestrator.planner.spec import PlannedTask

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

    reconciler = ExecutionReconciler(
        session_factory=session_factory, proxy_client=mock_proxy_client
    )
    stats = reconciler.reconcile_once()
    assert stats["active_runs"] == 1


def test_trigger_job_run_by_subfolder_dynamic_discovery(
    test_setup: tuple[FlaskClient, sessionmaker[Session], MagicMock],
) -> None:
    """Verify that by_subfolder job run dynamically discovers subfolders and plans 1 root + N subfolder tasks."""
    client, session_factory, mock_proxy_client = test_setup

    mock_proxy_client.discover.return_value = {
        "status": "ok",
        "subfolders": ["folder1", "folder2", "folder3"],
        "root_files": ["readme.md"],
    }

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "src-dyn", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-dyn", "local", {"path": "/dst"})
        job = JobRepository.create_job(
            session=session,
            name="job-by-subfolder-dyn",
            source_remote_id=r1.id,
            source_path="/",
            destination_remote_id=r2.id,
            destination_path="/backup",
            operation="copy",
            parallelization="by_subfolder",
            max_parallel_tasks=4,
        )
        proxy_id = uuid.uuid4()
        p = Proxy(
            id=proxy_id,
            name="proxy-dyn",
            host="127.0.0.1",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("a" * 32, proxy_id),
            cert_fingerprint_sha256="aa" * 32,
            is_enabled=True,
            max_concurrent_tasks=4,
        )
        session.add(p)
        status = ProxyRepository.get_or_create_status(session, proxy_id)
        status.state = "online"
        status.capacity = 4
        session.commit()
        job_id = job.id

    resp = client.post(f"/internal/v1/jobs/{job_id}/run", json={"trigger": "manual"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "dispatched"
    assert data["planned_task_count"] == 4
    assert data["dispatched_count"] == 4

    run_id = uuid.UUID(data["run_id"])
    with session_factory() as session:
        run = ExecutionRepository.get_run_by_id(session, run_id)
        assert run is not None
        assert len(run.tasks) == 4

        root_tasks = [t for t in run.tasks if t.scope == "root_files"]
        sub_tasks = [t for t in run.tasks if t.scope == "subfolder"]
        assert len(root_tasks) == 1
        assert len(sub_tasks) == 3
        assert {t.spec.get("source_subpath") for t in sub_tasks} == {
            "folder1",
            "folder2",
            "folder3",
        }

    # Verify dispatched options in mock proxy client calls
    calls = mock_proxy_client.dispatch_task.call_args_list
    assert len(calls) == 4
    # Find call for root task
    root_calls = [c for c in calls if c.kwargs["payload"]["source"]["path"] == "/"]
    assert len(root_calls) == 1
    assert root_calls[0].kwargs["payload"]["options"].get("max_depth") == 1


def test_cancel_task_endpoint(
    test_setup: tuple[FlaskClient, sessionmaker[Session], MagicMock],
) -> None:
    """Verify that canceling a specific active task works and notifies the proxy."""
    client, session_factory, mock_proxy_client = test_setup

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "src-can", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-can", "local", {"path": "/dst"})
        proxy_id = uuid.uuid4()
        proxy = Proxy(
            id=proxy_id,
            name="worker-can",
            host="127.0.0.1",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("a" * 32, proxy_id),
            cert_fingerprint_sha256="cc" * 32,
            is_enabled=True,
        )
        session.add(proxy)
        status = ProxyRepository.get_or_create_status(session, proxy_id)
        status.state = "online"

        job = JobRepository.create_job(
            session=session,
            name="job-cancel-task",
            source_remote_id=r1.id,
            source_path="/data",
            destination_remote_id=r2.id,
            destination_path="/backup",
            parallelization="none",
        )
        session.commit()
        job_id = job.id

    run_resp = client.post(f"/internal/v1/jobs/{job_id}/run")
    assert run_resp.status_code == 200
    run_id = uuid.UUID(run_resp.get_json()["run_id"])

    with session_factory() as session:
        run = ExecutionRepository.get_run_by_id(session, run_id)
        assert run is not None
        task = run.tasks[0]
        task_id = task.id

    cancel_resp = client.post(f"/internal/v1/tasks/{task_id}/cancel")
    assert cancel_resp.status_code == 200
    assert cancel_resp.get_json()["status"] == "cancelled"

    # Verify proxy client cancel_task was invoked
    mock_proxy_client.cancel_task.assert_called_once()

    # Second cancel should return 400 as it's already terminal
    cancel_again = client.post(f"/internal/v1/tasks/{task_id}/cancel")
    assert cancel_again.status_code == 400


def test_cancel_run_notifies_proxies(
    test_setup: tuple[FlaskClient, sessionmaker[Session], MagicMock],
) -> None:
    """Verify that canceling a whole job run cancels active tasks and notifies all proxies running them."""
    client, session_factory, mock_proxy_client = test_setup

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "src-run-can", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-run-can", "local", {"path": "/dst"})
        proxy_id = uuid.uuid4()
        proxy = Proxy(
            id=proxy_id,
            name="worker-run-can",
            host="127.0.0.1",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("a" * 32, proxy_id),
            cert_fingerprint_sha256="dd" * 32,
            is_enabled=True,
        )
        session.add(proxy)
        status = ProxyRepository.get_or_create_status(session, proxy_id)
        status.state = "online"

        job = JobRepository.create_job(
            session=session,
            name="job-cancel-run",
            source_remote_id=r1.id,
            source_path="/data",
            destination_remote_id=r2.id,
            destination_path="/backup",
            parallelization="none",
        )
        session.commit()
        job_id = job.id

    run_resp = client.post(f"/internal/v1/jobs/{job_id}/run")
    assert run_resp.status_code == 200
    run_id = uuid.UUID(run_resp.get_json()["run_id"])

    # Reset mock to verify cancel_task is called specifically by cancel_run
    mock_proxy_client.cancel_task.reset_mock()

    cancel_resp = client.post(f"/internal/v1/runs/{run_id}/cancel")
    assert cancel_resp.status_code == 200
    assert cancel_resp.get_json()["status"] == "cancelled"

    # Verify proxy client cancel_task was invoked for active tasks of the run
    mock_proxy_client.cancel_task.assert_called_once()


def test_proxy_concurrency_limit_strictly_enforced(
    test_setup: tuple[FlaskClient, sessionmaker[Session], MagicMock],
) -> None:
    """Verify that a proxy with max_concurrent_tasks=1 receives only 1 task at a time."""
    client, session_factory, mock_proxy_client = test_setup

    mock_proxy_client.discover.return_value = {
        "status": "ok",
        "subfolders": ["sub1", "sub2"],
        "root_files": ["file1.txt"],
    }

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "src-conc", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-conc", "local", {"path": "/dst"})
        job = JobRepository.create_job(
            session=session,
            name="job-concurrency-test",
            source_remote_id=r1.id,
            source_path="/",
            destination_remote_id=r2.id,
            destination_path="/backup",
            operation="copy",
            parallelization="by_subfolder",
            max_parallel_tasks=4,
        )
        proxy_id = uuid.uuid4()
        p = Proxy(
            id=proxy_id,
            name="proxy-single-capacity",
            host="127.0.0.1",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("a" * 32, proxy_id),
            cert_fingerprint_sha256="ff" * 32,
            is_enabled=True,
            max_concurrent_tasks=1,  # Capacity is 1!
        )
        session.add(p)
        status = ProxyRepository.get_or_create_status(session, proxy_id)
        status.state = "online"
        status.capacity = 1
        status.running_tasks = 0
        session.commit()
        job_id = job.id

    # Trigger run: planned tasks will be 3 (1 root + 2 subfolders)
    resp = client.post(f"/internal/v1/jobs/{job_id}/run", json={"trigger": "manual"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["planned_task_count"] == 3
    # Exactly 1 task dispatched because proxy capacity is 1
    assert data["dispatched_count"] == 1

    # Check proxy running_tasks in DB is 1
    with session_factory() as session:
        status = ProxyRepository.get_or_create_status(session, proxy_id)
        assert status.running_tasks == 1

        run_id = uuid.UUID(data["run_id"])
        run = ExecutionRepository.get_run_by_id(session, run_id)
        assert run is not None
        assigned_tasks = [t for t in run.tasks if t.status == "assigned"]
        ready_tasks = [t for t in run.tasks if t.status == "ready"]
        assert len(assigned_tasks) == 1
        assert len(ready_tasks) == 2


def test_job_assigned_proxies_dispatch_restriction(
    test_setup: tuple[FlaskClient, sessionmaker[Session], MagicMock],
) -> None:
    """Verify that jobs with assigned proxies only lease those proxies."""
    client, session_factory, mock_proxy_client = test_setup

    p_assigned_id = uuid.uuid4()
    p_other_id = uuid.uuid4()

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "src-net", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-net", "local", {"path": "/dst"})

        # Proxy 1: Assigned to job
        p_assigned = Proxy(
            id=p_assigned_id,
            name="p-assigned",
            host="10.10.1.1",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("tok1" * 8, p_assigned_id),
            cert_fingerprint_sha256="11" * 32,
            is_enabled=True,
        )
        # Proxy 2: Other network proxy (online)
        p_other = Proxy(
            id=p_other_id,
            name="p-other",
            host="10.20.1.1",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("tok2" * 8, p_other_id),
            cert_fingerprint_sha256="22" * 32,
            is_enabled=True,
        )
        session.add_all([p_assigned, p_other])

        s_assigned = ProxyRepository.get_or_create_status(session, p_assigned_id)
        s_assigned.state = "online"
        s_assigned.capacity = 2
        s_assigned.running_tasks = 0

        s_other = ProxyRepository.get_or_create_status(session, p_other_id)
        s_other.state = "online"
        s_other.capacity = 5
        s_other.running_tasks = 0

        job = JobRepository.create_job(
            session=session,
            name="restricted-job",
            source_remote_id=r1.id,
            source_path="/data",
            destination_remote_id=r2.id,
            destination_path="/backup",
            parallelization="none",
            assigned_proxy_ids=[p_assigned_id],
        )
        session.commit()
        job_id = job.id

    # 1. Trigger job run: task must be dispatched ONLY to p_assigned
    resp = client.post(f"/internal/v1/jobs/{job_id}/run", json={"trigger": "manual"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["dispatched_count"] == 1

    with session_factory() as session:
        run = ExecutionRepository.get_run_by_id(session, uuid.UUID(data["run_id"]))
        assert run is not None
        assigned_task = run.tasks[0]
        assert len(assigned_task.assignments) == 1
        assert assigned_task.assignments[0].proxy_id == p_assigned_id
        # Snapshot contains assigned_proxy_ids
        assert str(p_assigned_id) in run.job_snapshot.get("assigned_proxy_ids", [])

    # 2. If assigned proxy goes offline, reconcile will NOT dispatch to p_other
    with session_factory() as session:
        s_assigned = ProxyRepository.get_or_create_status(session, p_assigned_id)
        s_assigned.state = "offline"

        job2 = JobRepository.create_job(
            session=session,
            name="restricted-job-offline",
            source_remote_id=r1.id,
            source_path="/data2",
            destination_remote_id=r2.id,
            destination_path="/backup2",
            parallelization="none",
            assigned_proxy_ids=[p_assigned_id],
        )
        session.commit()
        job2_id = job2.id

    resp2 = client.post(f"/internal/v1/jobs/{job2_id}/run", json={"trigger": "manual"})
    assert resp2.status_code == 200
    data2 = resp2.get_json()
    # 0 dispatched because assigned proxy is offline; p_other was ignored
    assert data2["dispatched_count"] == 0

    with session_factory() as session:
        run2 = ExecutionRepository.get_run_by_id(session, uuid.UUID(data2["run_id"]))
        assert run2 is not None
        assert run2.tasks[0].status == "ready"
        assert len(run2.tasks[0].assignments) == 0


def test_by_subfolder_run_fails_if_live_discovery_fails_no_fallback_to_stale_discovery(
    test_setup: tuple[FlaskClient, sessionmaker[Session], MagicMock],
) -> None:
    """Verify that by_subfolder NEVER falls back to an old cached discovery when live discovery fails."""
    client, session_factory, mock_proxy_client = test_setup

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "src-nofallback", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-nofallback", "local", {"path": "/dst"})
        old_disc = JobRepository.record_discovery(
            session=session,
            source_remote_id=r1.id,
            source_path="/",
            subfolders=["deleted_folder_from_months_ago"],
            root_file_count=1,
            trigger="job_form",
            status="succeeded",
            root_files=["file.txt"],
        )
        job = JobRepository.create_job(
            session=session,
            name="job-no-fallback",
            source_remote_id=r1.id,
            source_path="/",
            destination_remote_id=r2.id,
            destination_path="/dst",
            operation="copy",
            parallelization="by_subfolder",
            last_discovery_id=old_disc.id,
        )
        proxy_id = uuid.uuid4()
        proxy = Proxy(
            id=proxy_id,
            name="proxy-offline-disc",
            host="127.0.0.1",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("b" * 32, proxy_id),
            cert_fingerprint_sha256="ee" * 32,
            is_enabled=True,
            max_concurrent_tasks=2,
        )
        session.add(proxy)
        st = ProxyRepository.get_or_create_status(session, proxy_id)
        st.state = "online"
        session.commit()
        job_id = job.id

    # Simulate discovery failure on the proxy
    mock_proxy_client.discover.side_effect = Exception("Proxy network timeout")

    resp = client.post(f"/internal/v1/jobs/{job_id}/run", json={"trigger": "manual"})
    assert resp.status_code in (400, 409)
    data = resp.get_json()
    assert "Impossibile eseguire la discovery live delle cartelle sorgente" in data["message"]

    # Verify run in DB was marked failed and NO tasks were materialized for the stale deleted folder
    with session_factory() as session:
        from embervault_db.models.execution import JobRun

        runs = list(session.scalars(select(JobRun).where(JobRun.job_id == job_id)).all())
        assert len(runs) == 1
        assert runs[0].status == "failed"
        assert "Impossibile eseguire la discovery live" in (runs[0].error_message or "")
        assert len(runs[0].tasks) == 0


def test_by_subfolder_run_fails_over_to_second_proxy_if_first_fails(
    test_setup: tuple[FlaskClient, sessionmaker[Session], MagicMock],
) -> None:
    """Verify that if candidate proxy 1 fails discovery, candidate proxy 2 is tried and succeeds."""
    client, session_factory, mock_proxy_client = test_setup

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "src-failover", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-failover", "local", {"path": "/dst"})
        job = JobRepository.create_job(
            session=session,
            name="job-proxy-failover",
            source_remote_id=r1.id,
            source_path="/",
            destination_remote_id=r2.id,
            destination_path="/dst",
            operation="copy",
            parallelization="by_subfolder",
        )
        p1_id = uuid.uuid4()
        p1 = Proxy(
            id=p1_id,
            name="p1-flaky",
            host="127.0.0.1",
            port=8441,
            token_encrypted=ProxyRepository.encrypt_token("c" * 32, p1_id),
            cert_fingerprint_sha256="11" * 32,
            is_enabled=True,
            max_concurrent_tasks=2,
        )
        p2_id = uuid.uuid4()
        p2 = Proxy(
            id=p2_id,
            name="p2-good",
            host="127.0.0.1",
            port=8442,
            token_encrypted=ProxyRepository.encrypt_token("d" * 32, p2_id),
            cert_fingerprint_sha256="22" * 32,
            is_enabled=True,
            max_concurrent_tasks=2,
        )
        session.add_all([p1, p2])
        st1 = ProxyRepository.get_or_create_status(session, p1_id)
        st1.state = "online"
        st2 = ProxyRepository.get_or_create_status(session, p2_id)
        st2.state = "online"
        session.commit()
        job_id = job.id

    # Proxy 1 returns error, Proxy 2 returns ok with fresh folders
    def mock_discover_side_effect(**kwargs: Any) -> dict[str, Any]:
        if kwargs.get("port") == 8441:
            return {"status": "error", "message": "Disk I/O error on proxy 1"}
        return {
            "status": "ok",
            "subfolders": ["current_subfolder_a", "current_subfolder_b"],
            "root_files": ["root.log"],
        }

    mock_proxy_client.discover.side_effect = mock_discover_side_effect

    resp = client.post(f"/internal/v1/jobs/{job_id}/run", json={"trigger": "manual"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "dispatched"
    assert data["planned_task_count"] == 3  # 1 root + 2 subfolders


def test_discovery_executed_when_all_proxies_have_occupied_slots(
    test_setup: tuple[FlaskClient, sessionmaker[Session], MagicMock],
) -> None:
    """Verify that discovery is still executed when all online proxies have all slots occupied."""
    client, session_factory, mock_proxy_client = test_setup

    mock_proxy_client.discover.return_value = {
        "status": "ok",
        "subfolders": ["sub_1"],
        "root_files": ["root.txt"],
    }

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "src-full", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-full", "local", {"path": "/dst"})
        job1 = JobRepository.create_job(
            session=session,
            name="job-running",
            source_remote_id=r1.id,
            source_path="/",
            destination_remote_id=r2.id,
            destination_path="/dst",
            operation="copy",
            parallelization="none",
        )
        job2 = JobRepository.create_job(
            session=session,
            name="job-by-subfolder-discovery",
            source_remote_id=r1.id,
            source_path="/",
            destination_remote_id=r2.id,
            destination_path="/dst",
            operation="copy",
            parallelization="by_subfolder",
        )
        p_id = uuid.uuid4()
        p = Proxy(
            id=p_id,
            name="proxy-single-slot",
            host="127.0.0.1",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("p" * 32, p_id),
            cert_fingerprint_sha256="ff" * 32,
            is_enabled=True,
            max_concurrent_tasks=1,  # Only 1 slot!
        )
        session.add(p)
        st = ProxyRepository.get_or_create_status(session, p_id)
        st.state = "online"
        st.capacity = 1
        st.running_tasks = 1

        # Simulate 1 active task assignment so the proxy's slot is 100% full
        from embervault_common.contracts.enums import TaskKind, TaskOperation, TaskScope
        from embervault_orchestrator.planner.spec import PlannedTask

        run1 = ExecutionRepository.create_job_run(session, job1.id, trigger="manual")
        tasks1 = ExecutionRepository.materialize_planned_tasks(
            session,
            run1.id,
            [
                PlannedTask(
                    kind=TaskKind.TRANSFER, scope=TaskScope.WHOLE, operation=TaskOperation.COPY
                )
            ],
        )
        ExecutionRepository.create_assignment(session, tasks1[0].id, p_id)
        session.commit()
        job2_id = job2.id

    # Trigger job2 run: should NOT fail; discovery must ignore the proxy's occupied slot!
    resp = client.post(f"/internal/v1/jobs/{job2_id}/run", json={"trigger": "manual"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "dispatched"
    assert mock_proxy_client.discover.called
    assert mock_proxy_client.discover.call_args.kwargs["timeout_s"] == 30  # Default 30s!


def test_discovery_uses_configured_timeout_setting(
    test_setup: tuple[FlaskClient, sessionmaker[Session], MagicMock],
) -> None:
    """Verify that discovery uses the timeout from EmberVault settings."""
    client, session_factory, mock_proxy_client = test_setup

    mock_proxy_client.discover.return_value = {
        "status": "ok",
        "subfolders": ["sub_a"],
        "root_files": [],
    }

    with session_factory() as session:
        from embervault_db.settings_store import SettingsStore

        store = SettingsStore(session_factory)
        store.set_setting("discovery_timeout_s", 45)

        r1 = RemoteRepository.create_remote(session, "src-t", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-t", "local", {"path": "/dst"})
        job = JobRepository.create_job(
            session=session,
            name="job-timeout-test",
            source_remote_id=r1.id,
            source_path="/",
            destination_remote_id=r2.id,
            destination_path="/dst",
            operation="copy",
            parallelization="by_subfolder",
        )
        p_id = uuid.uuid4()
        p = Proxy(
            id=p_id,
            name="proxy-t",
            host="127.0.0.1",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("t" * 32, p_id),
            cert_fingerprint_sha256="tt" * 32,
            is_enabled=True,
            max_concurrent_tasks=2,
        )
        session.add(p)
        st = ProxyRepository.get_or_create_status(session, p_id)
        st.state = "online"
        session.commit()
        job_id = job.id

    resp = client.post(f"/internal/v1/jobs/{job_id}/run", json={"trigger": "manual"})
    assert resp.status_code == 200
    assert mock_proxy_client.discover.called
    assert mock_proxy_client.discover.call_args.kwargs["timeout_s"] == 45
