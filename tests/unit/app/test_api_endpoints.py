"""Unit tests for frontend JSON API endpoints (/api/ui/*) and DEV_NOAUTH gating."""

from __future__ import annotations

import uuid
from collections.abc import Callable

import pytest
from flask.testing import FlaskClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_app.factory import create_app
from embervault_app.orchestrator_client import OrchestratorClient
from embervault_common.config import AppSettings
from embervault_common.contracts import ProxyProbeResponse
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models import AuditLog, Proxy, ProxyStatus
from embervault_db.models.base import Base

MakeClientFn = Callable[[bool], tuple[FlaskClient, sessionmaker[Session]]]


class FakeOrchestratorClient(OrchestratorClient):
    """Stub OrchestratorClient for testing."""

    def probe_proxy(self, host: str, port: int, token: str) -> ProxyProbeResponse:
        _ = (host, port, token)
        return ProxyProbeResponse(
            cert_fingerprint_sha256="f" * 64,
            status="ok",
            latency_ms=15.4,
            proxy_version="0.1.0",
            rclone_version="rclone v1.68.2",
        )


@pytest.fixture
def test_setup() -> MakeClientFn:
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    orch_client = FakeOrchestratorClient()

    def make_client(dev_noauth: bool) -> tuple[FlaskClient, sessionmaker[Session]]:
        settings = AppSettings(app_port=8080, dev_noauth=dev_noauth)
        app = create_app(
            settings=settings,
            session_factory=session_factory,
            orchestrator_client=orch_client,
        )
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False  # Disable CSRF for direct API unit testing
        return app.test_client(), session_factory

    return make_client


def test_status_endpoint(test_setup: MakeClientFn) -> None:
    """Test /api/ui/status returns accurate proxy and run metrics."""
    client, session_factory = test_setup(True)

    res = client.get("/api/ui/status")
    assert res.status_code == 200
    data = res.json
    assert data is not None
    assert data["status"] == "ok"
    assert data["dev_noauth"] is True
    assert "proxies" in data
    assert "runs" in data
    assert "timestamp" in data


def test_dev_noauth_disabled_blocks_registration_and_probe(test_setup: MakeClientFn) -> None:
    """Test that registration and probe return 403 Forbidden when DEV_NOAUTH is False."""
    client, _ = test_setup(False)

    # Probe blocked
    probe_res = client.post(
        "/api/ui/proxies/probe",
        json={"host": "192.168.1.5", "port": 8443, "token": "t" * 32},
    )
    assert probe_res.status_code == 403
    assert probe_res.json is not None
    assert "disabled in production without admin authentication" in probe_res.json["message"]

    # Register blocked
    reg_res = client.post(
        "/api/ui/proxies/register",
        json={
            "name": "proxy-test",
            "host": "192.168.1.5",
            "port": 8443,
            "token": "t" * 32,
            "cert_fingerprint_sha256": "f" * 64,
        },
    )
    assert reg_res.status_code == 403
    assert reg_res.json is not None
    assert "disabled without authentication" in reg_res.json["message"]


def test_probe_endpoint_success(test_setup: MakeClientFn) -> None:
    """Test proxy probe forward to orchestrator client when DEV_NOAUTH is True."""
    client, _ = test_setup(True)

    res = client.post(
        "/api/ui/proxies/probe",
        json={"host": "proxy-remote", "port": 8443, "token": "p" * 32},
    )
    assert res.status_code == 200
    assert res.json is not None
    assert res.json["cert_fingerprint_sha256"] == "f" * 64
    assert res.json["status"] == "ok"


def test_register_endpoint_validation_and_persistence(test_setup: MakeClientFn) -> None:
    """Test proxy registration persists encrypted token and records audit log."""
    client, session_factory = test_setup(True)

    # 1. Invalid short token
    short_token_res = client.post(
        "/api/ui/proxies/register",
        json={
            "name": "proxy-1",
            "host": "10.0.0.1",
            "port": 8443,
            "token": "too_short",
            "cert_fingerprint_sha256": "f" * 64,
        },
    )
    assert short_token_res.status_code == 400

    # 2. Valid registration
    valid_res = client.post(
        "/api/ui/proxies/register",
        json={
            "name": "proxy-alpha",
            "host": "10.0.0.1",
            "port": 8443,
            "token": "secret_token_at_least_32_characters_long",
            "cert_fingerprint_sha256": "a" * 64,
        },
    )
    assert valid_res.status_code == 201
    assert valid_res.json is not None
    assert valid_res.json["status"] == "created"

    # Verify DB state
    with session_factory() as session:
        proxy = session.query(Proxy).filter_by(name="proxy-alpha").first()
        assert proxy is not None
        assert proxy.cert_fingerprint_sha256 == "a" * 64
        assert proxy.token_encrypted is not None

        # ProxyStatus was initialized
        status = session.query(ProxyStatus).filter_by(proxy_id=proxy.id).first()
        assert status is not None
        assert status.state == "unknown"

        # AuditLog was recorded
        audit = session.query(AuditLog).filter_by(action="proxy.register").first()
        assert audit is not None
        assert audit.entity_id == str(proxy.id)

    # 3. Duplicate registration conflict (409)
    dup_res = client.post(
        "/api/ui/proxies/register",
        json={
            "name": "proxy-alpha",
            "host": "10.0.0.1",
            "port": 8443,
            "token": "secret_token_at_least_32_characters_long",
            "cert_fingerprint_sha256": "a" * 64,
        },
    )
    assert dup_res.status_code == 409


def test_proxy_update_and_delete_endpoints(test_setup: MakeClientFn) -> None:
    """Test updating and deleting proxies via API."""
    client, session_factory = test_setup(True)

    # 1. Register a proxy
    reg_res = client.post(
        "/api/ui/proxies/register",
        json={
            "name": "proxy-to-edit",
            "host": "10.0.1.5",
            "port": 8443,
            "token": "secret_token_at_least_32_characters_long",
            "cert_fingerprint_sha256": "b" * 64,
        },
    )
    assert reg_res.status_code == 201
    assert reg_res.json is not None
    proxy_id = reg_res.json["proxy_id"]

    # 2. Update proxy attributes
    update_res = client.put(
        f"/api/ui/proxies/{proxy_id}",
        json={
            "name": "proxy-edited-name",
            "host": "10.0.1.6",
            "port": 9443,
            "max_concurrent_tasks": 4,
            "is_enabled": False,
        },
    )
    assert update_res.status_code == 200
    assert update_res.json is not None
    assert update_res.json["status"] == "updated"

    # Verify updated in DB
    with session_factory() as session:
        proxy = session.get(Proxy, uuid.UUID(proxy_id))
        assert proxy is not None
        assert proxy.name == "proxy-edited-name"
        assert proxy.host == "10.0.1.6"
        assert proxy.port == 9443
        assert proxy.max_concurrent_tasks == 4
        assert proxy.is_enabled is False

    # 3. Create historical task assignment linked to this proxy
    with session_factory() as session:
        from embervault_db.models.execution import JobRun, Task, TaskAssignment
        from embervault_db.models.remotes import Job, RcloneRemote

        remote = RcloneRemote(
            name="test-remote",
            backend_type="local",
            config_encrypted=b"dummy",
            public_params={},
            secret_field_names=[],
        )
        session.add(remote)
        session.flush()
        job = Job(
            name="dummy-job",
            schedule_cron="0 0 * * *",
            source_remote_id=remote.id,
            source_path="/src",
            destination_remote_id=remote.id,
            destination_path="/dst",
        )
        session.add(job)
        session.flush()
        run = JobRun(job_id=job.id, status="succeeded", trigger="manual")
        session.add(run)
        session.flush()
        task = Task(run_id=run.id, kind="transfer", scope="whole", seq=1, spec={})
        session.add(task)
        session.flush()
        assignment = TaskAssignment(
            task_id=task.id,
            attempt_no=1,
            proxy_id=uuid.UUID(proxy_id),
            status="succeeded",
        )
        session.add(assignment)
        session.commit()
        assignment_id = assignment.id

    # 4. Delete proxy (now allowed even with historical assignment)
    del_res = client.delete(f"/api/ui/proxies/{proxy_id}")
    assert del_res.status_code == 200
    assert del_res.json is not None
    assert del_res.json["status"] == "deleted"

    # Verify deleted from DB and assignment proxy_id was unlinked (set to NULL)
    with session_factory() as session:
        proxy = session.get(Proxy, uuid.UUID(proxy_id))
        assert proxy is None
        assignment = session.get(TaskAssignment, assignment_id)
        assert assignment is not None
        assert assignment.proxy_id is None

    # 5. Deleting non-existent proxy returns 404
    del_404 = client.delete(f"/api/ui/proxies/{proxy_id}")
    assert del_404.status_code == 404


def test_proxy_retrust_endpoints(test_setup: MakeClientFn, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test probe and confirm retrust flow for an untrusted proxy."""
    client, session_factory = test_setup(True)

    # Register proxy with initial fingerprint
    old_fp = "a" * 64
    reg_res = client.post(
        "/api/ui/proxies/register",
        json={
            "name": "proxy-retrust-test",
            "host": "10.0.1.20",
            "port": 8443,
            "token": "secret_token_at_least_32_characters_long",
            "cert_fingerprint_sha256": old_fp,
        },
    )
    assert reg_res.status_code == 201
    proxy_id = reg_res.json["proxy_id"]

    # Mark proxy as untrusted in DB to simulate mismatch
    with session_factory() as session:
        from embervault_db.repositories.proxy_repository import ProxyRepository

        proxy = session.get(Proxy, uuid.UUID(proxy_id))
        ProxyRepository.apply_probe_result(
            session=session,
            proxy=proxy,
            new_state="untrusted",
            is_success=False,
            error_code="PROXY_CERT_MISMATCH",
            reason="Certificate mismatch",
        )
        session.commit()

    # Mock orchestrator probe response
    from unittest.mock import MagicMock
    from embervault_common.contracts.internal import ProxyProbeResponse

    new_fp = "f" * 64
    mock_orch = MagicMock()
    mock_orch.probe_proxy.return_value = ProxyProbeResponse(
        status="ok",
        cert_fingerprint_sha256=new_fp,
        latency_ms=12.0,
        proxy_version="1.0.0",
        rclone_version="rclone v1.65",
    )
    monkeypatch.setattr("embervault_app.blueprints.api.get_orchestrator", lambda: mock_orch)

    # 1. Retrust Probe
    probe_res = client.post(f"/api/ui/proxies/{proxy_id}/retrust-probe")
    assert probe_res.status_code == 200
    data = probe_res.json
    assert data["old_fingerprint"] == old_fp
    assert data["new_fingerprint"] == new_fp
    assert data["proxy_id"] == proxy_id

    # 2. Retrust Confirm
    confirm_res = client.post(
        f"/api/ui/proxies/{proxy_id}/retrust-confirm",
        json={"cert_fingerprint_sha256": new_fp},
    )
    assert confirm_res.status_code == 200
    assert confirm_res.json["status"] == "retrusted"

    # Verify updated in DB: fingerprint changed and status reset to unknown (ready to poll)
    with session_factory() as session:
        proxy = session.get(Proxy, uuid.UUID(proxy_id))
        assert proxy.cert_fingerprint_sha256 == new_fp
        status = session.get(ProxyStatus, uuid.UUID(proxy_id))
        assert status.state == "unknown"
        assert status.consecutive_failures == 0


def test_deactivate_proxy_with_active_tasks(test_setup: MakeClientFn) -> None:
    """Verify that deactivating a proxy with active tasks is allowed and returns an informative warning message in i18n."""
    client, session_factory = test_setup(True)

    # 1. Register a proxy
    fingerprint = "b" * 64
    reg_res = client.post(
        "/api/ui/proxies/register",
        json={
            "name": "proxy-with-active-task",
            "host": "10.0.2.1",
            "port": 8443,
            "token": "a" * 32,
            "cert_fingerprint_sha256": fingerprint,
        },
    )
    assert reg_res.status_code == 201
    proxy_id = reg_res.json["proxy_id"]

    # 2. Mark proxy status as having running tasks
    with session_factory() as session:
        status = session.get(ProxyStatus, uuid.UUID(proxy_id))
        assert status is not None
        status.running_tasks = 2
        session.commit()

    # 3. Deactivate proxy (IT default)
    deactivate_res = client.put(
        f"/api/ui/proxies/{proxy_id}",
        json={
            "name": "proxy-with-active-task",
            "host": "10.0.2.1",
            "port": 8443,
            "max_concurrent_tasks": 1,
            "is_enabled": False,
        },
    )
    assert deactivate_res.status_code == 200
    data = deactivate_res.json
    assert data["status"] == "updated"
    expected_msg_it = (
        "Il Proxy selezionato sta eseguendo uno o più task. "
        "L'esecuzione non verrà arrestata, ma al Proxy non verranno più assegnati task."
    )
    expected_msg_en = (
        "The selected proxy is executing one or more tasks. "
        "Execution will not be stopped, but no further tasks will be assigned to this proxy."
    )
    assert data["message"] in (expected_msg_it, expected_msg_en)
    assert data["warning"] in (expected_msg_it, expected_msg_en)

    # Verify DB: proxy is disabled
    with session_factory() as session:
        proxy = session.get(Proxy, uuid.UUID(proxy_id))
        assert proxy is not None
        assert proxy.is_enabled is False

    # 4. Deactivate again with Accept-Language: en
    deactivate_en_res = client.put(
        f"/api/ui/proxies/{proxy_id}",
        headers={"Accept-Language": "en"},
        json={
            "name": "proxy-with-active-task",
            "host": "10.0.2.1",
            "port": 8443,
            "max_concurrent_tasks": 1,
            "is_enabled": False,
        },
    )
    assert deactivate_en_res.status_code == 200
    data_en = deactivate_en_res.json
    assert data_en["status"] == "updated"
    expected_msg_en = (
        "The selected proxy is executing one or more tasks. "
        "Execution will not be stopped, but no further tasks will be assigned to this proxy."
    )
    assert data_en["message"] == expected_msg_en
    assert data_en["warning"] == expected_msg_en

    # 5. Test when running_tasks == 0 but an active TaskAssignment exists in DB
    with session_factory() as session:
        status = session.get(ProxyStatus, uuid.UUID(proxy_id))
        assert status is not None
        status.running_tasks = 0
        from embervault_db.models.execution import JobRun, Task, TaskAssignment
        from embervault_db.models.remotes import Job, RcloneRemote

        remote = RcloneRemote(
            name="r2",
            backend_type="local",
            config_encrypted=b"x",
            public_params={},
            secret_field_names=[],
        )
        session.add(remote)
        session.flush()
        job = Job(
            name="j2",
            schedule_cron="0 0 * * *",
            source_remote_id=remote.id,
            source_path="/s",
            destination_remote_id=remote.id,
            destination_path="/d",
        )
        session.add(job)
        session.flush()
        run = JobRun(job_id=job.id, status="running", trigger="manual")
        session.add(run)
        session.flush()
        task = Task(run_id=run.id, kind="transfer", scope="whole", seq=1, spec={})
        session.add(task)
        session.flush()
        asgn = TaskAssignment(
            task_id=task.id, attempt_no=1, proxy_id=uuid.UUID(proxy_id), status="running"
        )
        session.add(asgn)
        session.commit()

    deactivate_asgn_res = client.put(
        f"/api/ui/proxies/{proxy_id}",
        json={
            "name": "proxy-with-active-task",
            "host": "10.0.2.1",
            "port": 8443,
            "max_concurrent_tasks": 1,
            "is_enabled": False,
        },
    )
    assert deactivate_asgn_res.status_code == 200
    assert deactivate_asgn_res.json["warning"] in (expected_msg_it, expected_msg_en)
