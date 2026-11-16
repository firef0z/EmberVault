"""Unit tests for Proxy <-> Remote reachability configuration and enforcement."""

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
from embervault_db.models.base import Base
from embervault_db.models.proxy import Proxy
from embervault_db.models.remotes import RcloneRemote
from embervault_db.repositories.job_repository import JobRepository
from embervault_db.repositories.proxy_repository import ProxyRepository
from embervault_db.repositories.remote_repository import RemoteRepository
from embervault_db.seed import seed_initial_data


class ReachabilityFakeOrchestrator(OrchestratorClient):
    """Mock orchestrator client recording candidate_proxy_ids and remote_id."""

    def __init__(self) -> None:
        self.last_test_call: dict[str, Any] = {}
        self.last_browse_call: dict[str, Any] = {}
        self.last_discovery_call: dict[str, Any] = {}

    def test_remote(
        self,
        backend_type: str,
        config: dict[str, Any],
        path: str = "",
        referenced_remotes: dict[str, dict[str, Any]] | list[dict[str, Any]] | None = None,
        remote_id: uuid.UUID | None = None,
        candidate_proxy_ids: list[uuid.UUID] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, Any]:
        self.last_test_call = {
            "backend_type": backend_type,
            "config": config,
            "remote_id": remote_id,
            "candidate_proxy_ids": candidate_proxy_ids,
        }
        return {"status": "ok", "message": "Success", "latency_ms": 1.0}

    def browse_remote(
        self,
        backend_type: str,
        config: dict[str, Any],
        path: str = "",
        referenced_remotes: dict[str, dict[str, Any]] | list[dict[str, Any]] | None = None,
        remote_id: uuid.UUID | None = None,
        candidate_proxy_ids: list[uuid.UUID] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, Any]:
        self.last_browse_call = {
            "backend_type": backend_type,
            "config": config,
            "path": path,
            "remote_id": remote_id,
            "candidate_proxy_ids": candidate_proxy_ids,
        }
        return {"status": "ok", "path": path, "directories": ["folder1"], "files": []}

    def create_discovery(
        self,
        source_remote_id: uuid.UUID,
        source_path: str = "",
        trigger: str = "manual",
        assigned_proxy_ids: list[uuid.UUID] | None = None,
    ) -> dict[str, Any]:
        self.last_discovery_call = {
            "source_remote_id": source_remote_id,
            "source_path": source_path,
            "assigned_proxy_ids": assigned_proxy_ids,
        }
        return {"status": "pending", "discovery_id": str(uuid.uuid4())}


@pytest.fixture
def reachability_app_and_db() -> tuple[
    FlaskClient, sessionmaker[Session], ReachabilityFakeOrchestrator
]:
    set_default_key_ring(KeyRing(keys={"v1": "test_encryption_key_32_characters_"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    with session_factory() as session:
        seed_initial_data(session)

    settings = AppSettings(app_port=8080, dev_noauth=True)
    fake_orch = ReachabilityFakeOrchestrator()
    app = create_app(
        settings=settings,
        session_factory=session_factory,
        orchestrator_client=fake_orch,
    )
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    client = app.test_client()
    return client, session_factory, fake_orch


def test_proxy_and_remote_reachability_defaults_and_customization(
    reachability_app_and_db: tuple[
        FlaskClient, sessionmaker[Session], ReachabilityFakeOrchestrator
    ],
) -> None:
    """Verify that by default all remotes/proxies are reachable, and custom subsets can be assigned."""
    client, session_factory, _ = reachability_app_and_db

    # Create two remotes
    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "rem-1", "local", {"path": "/data/1"})
        r2 = RemoteRepository.create_remote(session, "rem-2", "local", {"path": "/data/2"})
        session.commit()
        r1_id, r2_id = str(r1.id), str(r2.id)

    # 1. Register proxy without reachable_remote_ids (default: all remotes active)
    resp_p1 = client.post(
        "/api/ui/proxies/register",
        json={
            "name": "proxy-default",
            "host": "192.168.1.10",
            "port": 8443,
            "token": "tok1" * 8,
            "cert_fingerprint_sha256": "11" * 32,
        },
    )
    assert resp_p1.status_code == 201
    p1_id = resp_p1.get_json()["proxy_id"]

    with session_factory() as session:
        p1 = session.get(Proxy, uuid.UUID(p1_id))
        assert p1 is not None
        p1_remote_ids = {str(r.id) for r in p1.reachable_remotes}
        assert r1_id in p1_remote_ids
        assert r2_id in p1_remote_ids

    # 2. Register proxy with specific reachable_remote_ids (only r1)
    resp_p2 = client.post(
        "/api/ui/proxies/register",
        json={
            "name": "proxy-restricted",
            "host": "192.168.1.20",
            "port": 8443,
            "token": "tok2" * 8,
            "cert_fingerprint_sha256": "22" * 32,
            "reachable_remote_ids": [r1_id],
        },
    )
    assert resp_p2.status_code == 201
    p2_id = resp_p2.get_json()["proxy_id"]

    with session_factory() as session:
        p2 = session.get(Proxy, uuid.UUID(p2_id))
        assert p2 is not None
        p2_remote_ids = {str(r.id) for r in p2.reachable_remotes}
        assert p2_remote_ids == {r1_id}

    # 3. Create a new remote specifying reachable_proxy_ids (only p2)
    resp_r3 = client.post(
        "/api/ui/remotes",
        json={
            "name": "rem-3",
            "backend_type": "local",
            "config": {"path": "/data/3"},
            "reachable_proxy_ids": [p2_id],
        },
    )
    assert resp_r3.status_code == 201
    r3_id = resp_r3.get_json()["remote_id"]

    with session_factory() as session:
        r3 = session.get(RcloneRemote, uuid.UUID(r3_id))
        assert r3 is not None
        r3_proxy_ids = {str(p.id) for p in r3.proxies}
        assert r3_proxy_ids == {p2_id}

        # Check that p2 now has r3, while p1 does not
        p2 = session.get(Proxy, uuid.UUID(p2_id))
        assert uuid.UUID(r3_id) in {r.id for r in p2.reachable_remotes}
        p1 = session.get(Proxy, uuid.UUID(p1_id))
        assert uuid.UUID(r3_id) not in {r.id for r in p1.reachable_remotes}


def test_job_reachability_validation_blocks_unreachable_proxy(
    reachability_app_and_db: tuple[
        FlaskClient, sessionmaker[Session], ReachabilityFakeOrchestrator
    ],
) -> None:
    """Verify that assigning a proxy that cannot reach the job's source/destination remotes raises an error."""
    client, session_factory, _ = reachability_app_and_db

    with session_factory() as session:
        r_src = RemoteRepository.create_remote(session, "src-storage", "local", {"path": "/src"})
        r_dst = RemoteRepository.create_remote(session, "dst-storage", "local", {"path": "/dst"})
        pid = uuid.uuid4()
        # Proxy can only reach r_src, NOT r_dst
        p_limited = Proxy(
            id=pid,
            name="proxy-src-only",
            host="10.0.0.1",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("tok" * 10, pid),
            cert_fingerprint_sha256="aa" * 32,
            is_enabled=True,
            reachable_remotes=[r_src],
        )
        p_limited._explicitly_set_reachable_remotes = True
        session.add(p_limited)
        session.commit()
        src_id, dst_id, p_id = str(r_src.id), str(r_dst.id), str(pid)

    # Attempt to create job with proxy-src-only assigned -> must fail with 400
    res = client.post(
        "/api/ui/jobs",
        json={
            "name": "job-segregated-fail",
            "source_remote_id": src_id,
            "source_path": "/",
            "destination_remote_id": dst_id,
            "destination_path": "/backup",
            "operation": "copy",
            "assigned_proxy_ids": [p_id],
        },
    )
    assert res.status_code == 400
    err_json = res.get_json()
    assert (
        "non può raggiungere il remote" in err_json["message"]
        or "cannot reach" in err_json["message"]
    )
    assert "dst-storage" in err_json["message"]

    # Also verify that if no proxy is selected (all activated), validation fails because p_limited cannot reach dst-storage
    res_none_selected = client.post(
        "/api/ui/jobs",
        json={
            "name": "job-all-proxies-fail",
            "source_remote_id": src_id,
            "source_path": "/",
            "destination_remote_id": dst_id,
            "destination_path": "/backup",
            "operation": "copy",
            "assigned_proxy_ids": [],
        },
    )
    assert res_none_selected.status_code == 400
    assert "proxy-src-only" in res_none_selected.get_json()["message"]


def test_prevent_removing_remote_from_proxy_with_active_job(
    reachability_app_and_db: tuple[
        FlaskClient, sessionmaker[Session], ReachabilityFakeOrchestrator
    ],
) -> None:
    """Verify that removing a reachable remote from a proxy assigned to an active job is rejected."""
    client, session_factory, _ = reachability_app_and_db

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "vlan-src", "local", {"path": "/s"})
        r2 = RemoteRepository.create_remote(session, "vlan-dst", "local", {"path": "/d"})
        pid = uuid.uuid4()
        proxy = Proxy(
            id=pid,
            name="vlan-proxy",
            host="10.10.1.1",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("tok" * 10, pid),
            cert_fingerprint_sha256="cc" * 32,
            is_enabled=True,
            reachable_remotes=[r1, r2],
        )
        proxy._explicitly_set_reachable_remotes = True
        session.add(proxy)
        job = JobRepository.create_job(
            session=session,
            name="vlan-backup-job",
            source_remote_id=r1.id,
            source_path="/",
            destination_remote_id=r2.id,
            destination_path="/",
            assigned_proxy_ids=[pid],
        )
        session.commit()
        r1_id, r2_id, p_id = str(r1.id), str(r2.id), str(pid)

    # Attempt to edit proxy and remove r1 (vlan-src)
    res = client.put(
        f"/api/ui/proxies/{p_id}",
        json={
            "name": "vlan-proxy",
            "host": "10.10.1.1",
            "port": 8443,
            "reachable_remote_ids": [r2_id],  # removing r1
        },
    )
    assert res.status_code == 400
    err_json = res.get_json()
    assert (
        "Impossibile rimuovere il remote" in err_json["message"]
        or "Cannot remove remote" in err_json["message"]
    )
    assert "vlan-src" in err_json["message"]
    assert "vlan-backup-job" in err_json["message"]


def test_prevent_removing_proxy_from_remote_with_active_job(
    reachability_app_and_db: tuple[
        FlaskClient, sessionmaker[Session], ReachabilityFakeOrchestrator
    ],
) -> None:
    """Verify that removing a proxy from a remote's reachable list when assigned to an active job is rejected."""
    client, session_factory, _ = reachability_app_and_db

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "rem-prot-src", "local", {"path": "/s"})
        r2 = RemoteRepository.create_remote(session, "rem-prot-dst", "local", {"path": "/d"})
        pid = uuid.uuid4()
        proxy = Proxy(
            id=pid,
            name="prot-proxy",
            host="10.20.1.1",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("tok" * 10, pid),
            cert_fingerprint_sha256="dd" * 32,
            is_enabled=True,
            reachable_remotes=[r1, r2],
        )
        proxy._explicitly_set_reachable_remotes = True
        session.add(proxy)
        job = JobRepository.create_job(
            session=session,
            name="prot-backup-job",
            source_remote_id=r1.id,
            source_path="/",
            destination_remote_id=r2.id,
            destination_path="/",
            assigned_proxy_ids=[pid],
        )
        session.commit()
        r1_id, r2_id, p_id = str(r1.id), str(r2.id), str(pid)

    # Attempt to edit remote r1 and remove prot-proxy from reachable proxies
    res = client.put(
        f"/api/ui/remotes/{r1_id}",
        json={
            "name": "rem-prot-src",
            "backend_type": "local",
            "config": {"path": "/s"},
            "reachable_proxy_ids": [],  # removing all proxies including prot-proxy
        },
    )
    assert res.status_code == 400
    err_json = res.get_json()
    assert (
        "Impossibile rimuovere il proxy" in err_json["message"]
        or "Cannot remove proxy" in err_json["message"]
    )
    assert "prot-proxy" in err_json["message"]
    assert "prot-backup-job" in err_json["message"]


def test_remote_operations_pass_candidate_proxies_to_orchestrator(
    reachability_app_and_db: tuple[
        FlaskClient, sessionmaker[Session], ReachabilityFakeOrchestrator
    ],
) -> None:
    """Verify test_remote and browse_remote pass candidate_proxy_ids to OrchestratorClient."""
    client, session_factory, fake_orch = reachability_app_and_db

    p_uuid1 = str(uuid.uuid4())
    p_uuid2 = str(uuid.uuid4())

    # 1. Test connection with candidate proxies
    res_test = client.post(
        "/api/ui/remotes/test",
        json={
            "backend_type": "local",
            "config": {"path": "/test"},
            "candidate_proxy_ids": [p_uuid1, p_uuid2],
        },
    )
    assert res_test.status_code == 200
    assert fake_orch.last_test_call["candidate_proxy_ids"] == [p_uuid1, p_uuid2]

    # 2. Browse with candidate proxies
    res_browse = client.post(
        "/api/ui/remotes/browse",
        json={
            "backend_type": "local",
            "config": {"path": "/test"},
            "candidate_proxy_ids": [p_uuid1],
        },
    )
    assert res_browse.status_code == 200
    assert fake_orch.last_browse_call["candidate_proxy_ids"] == [p_uuid1]


def test_prevent_removing_remote_from_proxy_with_unassigned_cluster_job(
    reachability_app_and_db: tuple[
        FlaskClient, sessionmaker[Session], ReachabilityFakeOrchestrator
    ],
) -> None:
    """Verify that removing a remote from a proxy when a job has no assigned proxies (uses all cluster proxies) is rejected."""
    client, session_factory, _ = reachability_app_and_db

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "cluster-src", "local", {"path": "/s"})
        r2 = RemoteRepository.create_remote(session, "cluster-dst", "local", {"path": "/d"})
        pid = uuid.uuid4()
        proxy = Proxy(
            id=pid,
            name="cluster-proxy",
            host="10.30.1.1",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("tok" * 10, pid),
            cert_fingerprint_sha256="ee" * 32,
            is_enabled=True,
            reachable_remotes=[r1, r2],
        )
        proxy._explicitly_set_reachable_remotes = True
        session.add(proxy)
        # Create job with NO assigned proxies (unassigned = all proxies)
        job = JobRepository.create_job(
            session=session,
            name="cluster-backup-job",
            source_remote_id=r1.id,
            source_path="/",
            destination_remote_id=r2.id,
            destination_path="/",
            assigned_proxy_ids=None,
        )
        session.commit()
        r1_id, r2_id, p_id = str(r1.id), str(r2.id), str(pid)

    # Attempt to remove r1 from cluster-proxy
    res = client.put(
        f"/api/ui/proxies/{p_id}",
        json={
            "name": "cluster-proxy",
            "host": "10.30.1.1",
            "port": 8443,
            "max_concurrent_tasks": 1,
            "is_enabled": True,
            "reachable_remote_ids": [r2_id],  # removing r1
        },
    )
    assert res.status_code == 400
    err_json = res.get_json()
    assert (
        "Impossibile rimuovere il remote" in err_json["message"]
        or "Cannot remove remote" in err_json["message"]
    )
    assert "cluster-src" in err_json["message"]
    assert "cluster-backup-job" in err_json["message"]


def test_proxies_ui_renders_remote_job_usage(
    reachability_app_and_db: tuple[
        FlaskClient, sessionmaker[Session], ReachabilityFakeOrchestrator
    ],
) -> None:
    """Verify that GET /proxies template includes remote_job_usage data script."""
    client, session_factory, _ = reachability_app_and_db

    res = client.get("/proxies")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert 'id="remote-job-usage-data"' in html
    assert 'id="edit-proxy-remotes-warning"' in html
    assert 'id="edit-proxy-error"' in html
