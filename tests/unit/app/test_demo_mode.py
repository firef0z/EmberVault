"""Unit tests for EmberVault Demo Mode."""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from flask.testing import FlaskClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from embervault_app import create_app
from embervault_common.config import (
    CONFIG_REGISTRY,
    AppSettings,
    get_config_by_name,
    is_demo_mode,
)
from embervault_common.contracts.enums import RunState
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models import Base, Job, JobRun, Proxy, RcloneRemote, User
from embervault_db.repositories.job_repository import JobRepository
from embervault_db.seed import seed_demo_data, seed_initial_data
from embervault_db.settings_store import SettingsStore
from embervault_orchestrator.internal_api import execute_job_run


def test_demo_mode_config_registry_non_overridable() -> None:
    """Verify demo_mode is registered in CONFIG_REGISTRY and is NOT overridable from GUI."""
    key = get_config_by_name("demo_mode")
    assert key is not None
    assert key.env_var == "EMBERVAULT_DEMO_MODE"
    assert key.overridable_from_gui is False
    assert key.default is False
    assert key.service == "common"


def test_is_demo_mode_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify is_demo_mode correctly inspects settings and environment variable."""
    monkeypatch.delenv("EMBERVAULT_DEMO_MODE", raising=False)
    assert not is_demo_mode()

    monkeypatch.setenv("EMBERVAULT_DEMO_MODE", "true")
    assert is_demo_mode()

    monkeypatch.setenv("EMBERVAULT_DEMO_MODE", "1")
    assert is_demo_mode()

    monkeypatch.setenv("EMBERVAULT_DEMO_MODE", "false")
    assert not is_demo_mode()

    # Settings object override
    settings = AppSettings(demo_mode=True)
    assert is_demo_mode(settings)


def test_seed_demo_data_idempotency_and_entities() -> None:
    """Verify that seed_demo_data creates admin user, 2 remotes, 2 proxies, and 1 sync job idempotently."""
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    with session_factory() as session:
        seed_initial_data(session)
        seed_demo_data(session)

        # 1. User check
        demo_u = session.scalar(select(User).where(User.username == "demo"))
        assert demo_u is not None
        assert demo_u.role.name == "Administrator"
        assert demo_u.is_active is True

        # 2. Remotes check
        r1 = session.scalar(select(RcloneRemote).where(RcloneRemote.name == "Demo Local Source"))
        r2 = session.scalar(select(RcloneRemote).where(RcloneRemote.name == "Demo Cloud Destination"))
        assert r1 is not None
        assert r2 is not None

        # 3. Proxies check
        p1 = session.scalar(select(Proxy).where(Proxy.name == "Demo Edge Proxy 01"))
        p2 = session.scalar(select(Proxy).where(Proxy.name == "Demo Edge Proxy 02"))
        assert p1 is not None and p1.is_enabled is True
        assert p2 is not None and p2.is_enabled is True
        assert p1.status.state == "online"
        assert p2.status.state == "online"
        assert r1 in p1.reachable_remotes
        assert r2 in p1.reachable_remotes

        # 4. Job check
        job = session.scalar(select(Job).where(Job.name == "Demo Backup & Sync"))
        assert job is not None
        assert job.source_remote_id == r1.id
        assert job.source_path == "/"
        assert job.destination_remote_id == r2.id
        assert job.destination_path == "/"
        assert job.operation == "sync"
        assert len(job.assigned_proxies) == 2

        # 5. Idempotency run again
        seed_demo_data(session)
        users = session.scalars(select(User).where(User.username == "demo")).all()
        assert len(users) == 1
        jobs = session.scalars(select(Job).where(Job.name == "Demo Backup & Sync")).all()
        assert len(jobs) == 1


@pytest.fixture
def demo_app(monkeypatch: pytest.MonkeyPatch) -> tuple[FlaskClient, sessionmaker[Session]]:
    monkeypatch.setenv("EMBERVAULT_DEMO_MODE", "true")
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    settings = AppSettings(app_port=8080, demo_mode=True)
    app = create_app(
        settings=settings,
        session_factory=session_factory,
    )
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    return app.test_client(), session_factory


def test_demo_mode_login_screen_prefilled(demo_app: tuple[FlaskClient, sessionmaker[Session]]) -> None:
    """Verify login screen pre-fills username and password with 'demo' in demo mode."""
    client, _ = demo_app
    res = client.get("/login")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert 'value="demo"' in html
    assert "demo_mode" in html or "Modalità Demo" in html or "Demo Mode" in html


def test_demo_mode_auth_successful(demo_app: tuple[FlaskClient, sessionmaker[Session]]) -> None:
    """Verify that user demo with password demo successfully authenticates."""
    client, _ = demo_app
    res = client.post(
        "/login",
        data={"username": "demo", "password": "demo", "auth_source": "local"},
        follow_redirects=False,
    )
    # Redirects to dashboard on successful login
    assert res.status_code in (302, 303)
    assert res.headers["Location"].endswith("/") or "/" in res.headers["Location"]


def test_demo_mode_remote_test_simulated(demo_app: tuple[FlaskClient, sessionmaker[Session]]) -> None:
    """Verify that remote test returns simulated success without network operations."""
    client, _ = demo_app
    # Login first
    client.post("/login", data={"username": "demo", "password": "demo", "auth_source": "local"})

    res = client.post(
        "/api/ui/remotes/test",
        json={"backend_type": "local", "config": {"path": "/fake/path"}},
    )
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data["status"] == "ok"
    assert "simulata" in json_data["message"].lower() or "simulated" in json_data["message"].lower()


def test_demo_mode_browse_remote_simulated(demo_app: tuple[FlaskClient, sessionmaker[Session]]) -> None:
    """Verify that browse remote returns simulated file/directory tree in demo mode."""
    client, _ = demo_app
    client.post("/login", data={"username": "demo", "password": "demo", "auth_source": "local"})

    # Root browse
    res = client.post(
        "/api/ui/remotes/browse",
        json={"backend_type": "local", "config": {"path": "/fake/path"}, "path": "/"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert "documents" in data["directories"]
    assert "media" in data["directories"]

    # Subfolder browse
    res_sub = client.post(
        "/api/ui/remotes/browse",
        json={"backend_type": "local", "config": {"path": "/fake/path"}, "path": "/documents"},
    )
    assert res_sub.status_code == 200
    data_sub = res_sub.get_json()
    assert data_sub["status"] == "ok"
    assert "invoices" in data_sub["directories"]


def test_demo_mode_job_execution_simulation(demo_app: tuple[FlaskClient, sessionmaker[Session]]) -> None:
    """Verify job run execution is simulated to completion with tasks, logs, and throughput."""
    client, session_factory = demo_app
    with session_factory() as session:
        job = session.scalar(select(Job).where(Job.name == "Demo Backup & Sync"))
        assert job is not None

        settings_store = SettingsStore(session)
        result = execute_job_run(
            session=session,
            job_id=job.id,
            trigger="manual",
            settings_store=settings_store,
        )
        assert result["status"] == "completed"
        assert result["planned_task_count"] > 0
        assert "simulazione" in result["message"].lower() or "demo" in result["message"].lower()

        # Check DB run status
        run = session.scalar(select(JobRun).where(JobRun.job_id == job.id))
        assert run is not None
        assert run.status == RunState.SUCCEEDED.value
        assert run.tasks_succeeded > 0
        assert run.bytes_transferred > 0
        assert run.files_transferred > 0


def test_public_portal_url_and_share_redirect(demo_app: tuple[FlaskClient, sessionmaker[Session]], monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify public portal URL is properly prioritized and /share/<token> redirects from web app to portal."""
    from embervault_app.blueprints.api import _get_public_base_url

    monkeypatch.setenv("EMBERVAULT_PORTAL_URL", "http://192.168.1.100:8089")
    assert _get_public_base_url() == "http://192.168.1.100:8089"

    client, _ = demo_app
    resp = client.get("/share/demo-token-xyz")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "http://192.168.1.100:8089/share/demo-token-xyz"


def test_demo_mode_public_url_override_precedence(
    demo_app: tuple[FlaskClient, sessionmaker[Session]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify that configuring EMBERVAULT_PUBLIC_URL is respected over client Docker host IP in demo mode."""
    from embervault_app.blueprints.api import _get_public_base_url

    client, _ = demo_app

    # Scenario 1: EMBERVAULT_PUBLIC_URL set with port (e.g. 8088), EMBERVAULT_PORTAL_URL default localhost
    monkeypatch.setenv("EMBERVAULT_PUBLIC_URL", "http://demo.embervault.company:8088")
    monkeypatch.setenv("EMBERVAULT_PORTAL_URL", "http://localhost:8089")

    # In a request coming from Docker host IP 192.168.1.50:8088
    with client.application.test_request_context("/", headers={"Host": "192.168.1.50:8088"}):
        # Must use configured host 'demo.embervault.company' with portal port 8089, NOT 192.168.1.50:8089
        assert _get_public_base_url() == "http://demo.embervault.company:8089"

    # Scenario 2: EMBERVAULT_PUBLIC_URL behind reverse proxy (HTTPS, no port)
    monkeypatch.setenv("EMBERVAULT_PUBLIC_URL", "https://demo.embervault.company")
    monkeypatch.setenv("EMBERVAULT_PORTAL_URL", "http://localhost:8089")
    with client.application.test_request_context("/", headers={"Host": "192.168.1.50:8088"}):
        assert _get_public_base_url() == "https://demo.embervault.company"

    # Scenario 3: EMBERVAULT_PUBLIC_URL not set (default localhost) -> infers from request host
    monkeypatch.setenv("EMBERVAULT_PUBLIC_URL", "http://localhost:8088")
    monkeypatch.setenv("EMBERVAULT_PORTAL_URL", "http://localhost:8089")
    with client.application.test_request_context("/", headers={"Host": "192.168.1.50:8088"}):
        assert _get_public_base_url() == "http://192.168.1.50:8089"


