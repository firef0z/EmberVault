"""Unit tests for runs REST API and execution history UI views (Milestone M1.4 & M1.7)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from flask.testing import FlaskClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_app.factory import create_app
from embervault_app.orchestrator_client import OrchestratorClient
from embervault_common.config import AppSettings
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models import Base
from embervault_db.repositories.execution_repository import ExecutionRepository
from embervault_db.repositories.job_repository import JobRepository
from embervault_db.repositories.remote_repository import RemoteRepository
from embervault_db.seed import seed_initial_data


class FakeOrchestratorForRuns(OrchestratorClient):
    """Stub Orchestrator client for run tests."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        super().__init__()
        self.session_factory = session_factory

    def trigger_job_run(self, job_id: uuid.UUID, trigger: str = "manual") -> dict[str, Any]:
        with self.session_factory() as session:
            run = ExecutionRepository.create_job_run(session, job_id, trigger=trigger)
            from embervault_common.contracts.enums import TaskKind, TaskOperation, TaskScope
            from embervault_orchestrator.planner.spec import PlannedTask

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
            session.commit()
            return {
                "status": "dispatched",
                "run_id": str(run.id),
                "job_id": str(job_id),
                "planned_task_count": len(tasks),
                "dispatched_count": len(tasks),
                "message": "Run avviata",
            }

    def cancel_task(self, task_id: uuid.UUID) -> dict[str, Any]:
        with self.session_factory() as session:
            ExecutionRepository.cancel_task(session, task_id)
            session.commit()
            return {"status": "cancelled", "task_id": str(task_id), "message": "Task annullato"}

    def cancel_run(self, run_id: uuid.UUID) -> dict[str, Any]:
        with self.session_factory() as session:
            ExecutionRepository.cancel_run(session, run_id)
            session.commit()
            return {"status": "cancelled", "run_id": str(run_id), "message": "Run annullata"}

    def get_run(self, run_id: uuid.UUID) -> dict[str, Any]:
        with self.session_factory() as session:
            run = ExecutionRepository.get_run_by_id(session, run_id)
            if not run:
                return {"error": "not_found"}
            return {
                "status": "ok",
                "run": {
                    "id": str(run.id),
                    "job_id": str(run.job_id),
                    "job_name": run.job.name if run.job else "Test Job",
                    "status": run.status,
                    "tasks": [],
                },
            }

    def list_runs(self, job_id: uuid.UUID | None = None, limit: int = 50) -> dict[str, Any]:
        with self.session_factory() as session:
            runs = ExecutionRepository.list_runs(session, job_id=job_id, limit=limit)
            return {
                "status": "ok",
                "runs": [{"id": str(r.id), "status": r.status} for r in runs],
            }

    def get_task_logs(self, task_id: uuid.UUID, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "status": "ok",
            "task_id": str(task_id),
            "lines": [
                {
                    "seq": 0,
                    "ts": "2026-10-17T15:00:00Z",
                    "level": "info",
                    "message": "Task started",
                },
                {
                    "seq": 1,
                    "ts": "2026-10-17T15:00:02Z",
                    "level": "info",
                    "message": "Transferred 100%",
                },
            ],
        }


@pytest.fixture
def app_and_db() -> tuple[FlaskClient, sessionmaker[Session]]:
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    with session_factory() as session:
        seed_initial_data(session)

    settings = AppSettings(app_port=8080, dev_noauth=True)
    fake_orch = FakeOrchestratorForRuns(session_factory)
    app = create_app(
        settings=settings,
        session_factory=session_factory,
        orchestrator_client=fake_orch,
    )
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    return app.test_client(), session_factory


def test_runs_api_and_views(app_and_db: tuple[FlaskClient, sessionmaker[Session]]) -> None:
    client, session_factory = app_and_db

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "src-local", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-local", "local", {"path": "/dst"})
        job = JobRepository.create_job(
            session=session,
            name="job-run-test",
            source_remote_id=r1.id,
            source_path="/a",
            destination_remote_id=r2.id,
            destination_path="/b",
        )
        session.commit()
        job_id = job.id

    # 1. Trigger run via POST /api/ui/jobs/<id>/run
    run_resp = client.post(f"/api/ui/jobs/{job_id}/run")
    assert run_resp.status_code == 200
    run_data = run_resp.get_json()
    assert run_data["status"] == "dispatched"
    run_id = run_data["run_id"]

    # 2. Query list of runs via GET /api/ui/runs
    list_resp = client.get("/api/ui/runs")
    assert list_resp.status_code == 200
    runs = list_resp.get_json()["runs"]
    assert len(runs) >= 1

    # 3. Query run details via GET /api/ui/runs/<id>
    detail_resp = client.get(f"/api/ui/runs/{run_id}")
    assert detail_resp.status_code == 200
    assert detail_resp.get_json()["run"]["id"] == str(run_id)

    # 4. Fetch task logs via GET /api/ui/tasks/<id>/logs
    fake_task_id = uuid.uuid4()
    logs_resp = client.get(f"/api/ui/tasks/{fake_task_id}/logs")
    assert logs_resp.status_code == 200
    assert len(logs_resp.get_json()["lines"]) == 2

    # 5. Cancel task via POST /api/ui/tasks/<id>/cancel
    cancel_task_resp = client.post(f"/api/ui/tasks/{fake_task_id}/cancel")
    assert cancel_task_resp.status_code == 200
    assert cancel_task_resp.get_json()["status"] == "cancelled"

    # 6. Cancel run via POST /api/ui/runs/<id>/cancel
    cancel_resp = client.post(f"/api/ui/runs/{run_id}/cancel")
    assert cancel_resp.status_code == 200
    assert cancel_resp.get_json()["status"] == "cancelled"

    # 7. Test UI views: /runs and /runs/<id>
    ui_runs_resp = client.get("/runs")
    assert ui_runs_resp.status_code == 200
    assert (
        b"Tutte le Esecuzioni" in ui_runs_resp.data
        or b"All Executions" in ui_runs_resp.data
        or b"All Runs" in ui_runs_resp.data
    )

    ui_detail_resp = client.get(f"/runs/{run_id}")
    assert ui_detail_resp.status_code == 200
    assert b"job-run-test" in ui_detail_resp.data
    assert b"Task in esecuzione" in ui_detail_resp.data or b"Running Tasks" in ui_detail_resp.data
    assert b"Task in coda" in ui_detail_resp.data or b"Queued Tasks" in ui_detail_resp.data
    assert b"Task terminati" in ui_detail_resp.data or b"Finished Tasks" in ui_detail_resp.data
    assert b"Controllati" in ui_detail_resp.data or b"Checked" in ui_detail_resp.data
    assert b"Trasferiti" in ui_detail_resp.data or b"Transferred" in ui_detail_resp.data
    assert b'id="card-tasks-running"' in ui_detail_resp.data
    assert b'id="card-tasks-queued"' in ui_detail_resp.data
    assert b'id="card-tasks-finished"' in ui_detail_resp.data
    assert (
        b'id="body-tasks-running" class="collapsible-body" style="display: block;"'
        in ui_detail_resp.data
    )
    assert (
        b'id="body-tasks-queued" class="collapsible-body" style="display: none;"'
        in ui_detail_resp.data
    )
    assert (
        b'id="body-tasks-finished" class="collapsible-body" style="display: none;"'
        in ui_detail_resp.data
    )


def test_run_detail_subpath_truncation(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    """Verify that run_detail view truncates task subpath when > 10 characters."""
    client, session_factory = app_and_db

    with session_factory() as session:
        src = RemoteRepository.create_remote(session, "src-t", "local", {"path": "/src"})
        dst = RemoteRepository.create_remote(session, "dst-t", "local", {"path": "/dst"})
        job = JobRepository.create_job(
            session=session,
            name="job-subpath-truncation-test",
            source_remote_id=src.id,
            source_path="/a",
            destination_remote_id=dst.id,
            destination_path="/b",
        )
        run = ExecutionRepository.create_job_run(session, job.id, trigger="manual")

        from embervault_common.contracts.enums import TaskKind, TaskOperation, TaskScope
        from embervault_orchestrator.planner.spec import PlannedTask

        ExecutionRepository.materialize_planned_tasks(
            session,
            run.id,
            [
                PlannedTask(
                    kind=TaskKind.TRANSFER,
                    scope=TaskScope.SUBFOLDER,
                    operation=TaskOperation.COPY,
                    source_subpath="short_dir",  # 9 chars <= 10
                ),
                PlannedTask(
                    kind=TaskKind.TRANSFER,
                    scope=TaskScope.SUBFOLDER,
                    operation=TaskOperation.COPY,
                    source_subpath="long_subpath_name_here",  # 23 chars > 10
                ),
            ],
        )
        session.commit()
        run_id = run.id

    res = client.get(f"/runs/{run_id}")
    assert res.status_code == 200
    html = res.data.decode("utf-8")

    # Short subpath (<= 10 chars) is not truncated
    assert "short_dir" in html
    assert "short_dir..." not in html

    # Long subpath (> 10 chars) is truncated to 10 chars + '...' with full title
    assert 'title="long_subpath_name_here">long_subpa...</code>' in html
