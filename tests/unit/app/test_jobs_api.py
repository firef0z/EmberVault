"""Unit tests for Backup Jobs REST API, Discovery, and UI views (Milestone M1.3)."""

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
from embervault_db.repositories.remote_repository import RemoteRepository
from embervault_db.seed import seed_initial_data


class FakeOrchestratorForJobs(OrchestratorClient):
    """Stub Orchestrator client for job tests."""

    def create_discovery(
        self,
        source_remote_id: uuid.UUID,
        source_path: str,
        trigger: str = "job_form",
        assigned_proxy_ids: list[uuid.UUID] | None = None,
    ) -> dict[str, Any]:
        _ = (trigger, assigned_proxy_ids)
        return {
            "status": "ok",
            "discovery": {
                "id": str(uuid.uuid4()),
                "source_remote_id": str(source_remote_id),
                "source_path": source_path,
                "folder_count": 4,
                "root_file_count": 2,
                "task_count_estimate": 5,
                "level": "ok",
                "entries": {
                    "folders": ["photos/2024", "photos/2025", "docs", "archives"],
                    "root_files": ["README.txt", "manifest.json"],
                },
            },
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
    fake_orch = FakeOrchestratorForJobs()
    app = create_app(
        settings=settings,
        session_factory=session_factory,
        orchestrator_client=fake_orch,
    )
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    return app.test_client(), session_factory


def test_jobs_ui_and_crud(app_and_db: tuple[FlaskClient, sessionmaker[Session]]) -> None:
    client, session_factory = app_and_db

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "src-local", "local", {"path": "/data1"})
        r2 = RemoteRepository.create_remote(session, "dst-local", "local", {"path": "/data2"})
        session.commit()
        r1_id, r2_id = str(r1.id), str(r2.id)

    # 1. UI views return 200
    res = client.get("/jobs")
    assert res.status_code == 200
    assert b"Job di Backup" in res.data or b"Backup Jobs" in res.data

    res = client.get("/jobs/new")
    assert res.status_code == 200
    assert b"src-local" in res.data
    assert b"dst-local" in res.data

    # 2. Test Discovery endpoint
    disc_res = client.post(
        "/api/ui/jobs/discover",
        json={"source_remote_id": r1_id, "source_path": "/data"},
    )
    assert disc_res.status_code == 200
    disc_json = disc_res.get_json()
    assert disc_json["status"] == "ok"
    assert disc_json["discovery"]["folder_count"] == 4
    assert disc_json["discovery"]["level"] == "ok"
    disc_id = disc_json["discovery"]["id"]

    # 3. Create Job via POST /api/ui/jobs
    create_res = client.post(
        "/api/ui/jobs",
        json={
            "name": "Production Mirror Job",
            "source_remote_id": r1_id,
            "source_path": "/data",
            "destination_remote_id": r2_id,
            "destination_path": "/backup",
            "operation": "copy",
            "parallelization": "by_subfolder",
            "max_parallel_tasks": 4,
            "schedule_cron": "0 2 * * *",
            "last_discovery_id": disc_id,
            "enabled": True,
        },
    )
    assert create_res.status_code == 201
    job_id = create_res.get_json()["job_id"]

    # 4. List jobs via GET /api/ui/jobs
    list_res = client.get("/api/ui/jobs")
    assert list_res.status_code == 200
    jobs_list = list_res.get_json()["jobs"]
    assert len(jobs_list) == 1
    assert jobs_list[0]["name"] == "Production Mirror Job"
    assert jobs_list[0]["source_remote_name"] == "src-local"

    # 5. Get job details
    get_res = client.get(f"/api/ui/jobs/{job_id}")
    assert get_res.status_code == 200
    assert get_res.get_json()["job"]["max_parallel_tasks"] == 4

    # 6. Update job
    put_res = client.put(
        f"/api/ui/jobs/{job_id}",
        json={
            "name": "Production Mirror Job (Renamed)",
            "operation": "sync",
            "enabled": False,
        },
    )
    assert put_res.status_code == 200

    # 7. Edit UI returns 200
    edit_ui_res = client.get(f"/jobs/{job_id}/edit")
    assert edit_ui_res.status_code == 200
    assert b"Production Mirror Job (Renamed)" in edit_ui_res.data

    # 8. Delete job
    del_res = client.delete(f"/api/ui/jobs/{job_id}")
    assert del_res.status_code == 200
    assert del_res.get_json()["status"] == "deleted"

    # Verify deleted
    get_res_after = client.get(f"/api/ui/jobs/{job_id}")
    assert get_res_after.status_code == 404


def test_job_assigned_proxies_api(app_and_db: tuple[FlaskClient, sessionmaker[Session]]) -> None:
    from embervault_db.models.proxy import Proxy
    from embervault_db.repositories.proxy_repository import ProxyRepository

    client, session_factory = app_and_db

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "src-net-a", "local", {"path": "/net-a"})
        r2 = RemoteRepository.create_remote(session, "dst-net-b", "local", {"path": "/net-b"})
        p1 = Proxy(
            id=uuid.uuid4(),
            name="proxy-dmz-1",
            host="10.0.1.10",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("tok1" * 8, uuid.uuid4()),
            cert_fingerprint_sha256="aa" * 32,
            is_enabled=True,
            reachable_remotes=[r1, r2],
        )
        p2 = Proxy(
            id=uuid.uuid4(),
            name="proxy-dmz-2",
            host="10.0.1.20",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("tok2" * 8, uuid.uuid4()),
            cert_fingerprint_sha256="bb" * 32,
            is_enabled=True,
            reachable_remotes=[r1, r2],
        )
        session.add_all([p1, p2])
        session.commit()
        r1_id, r2_id = str(r1.id), str(r2.id)
        p1_id, p2_id = str(p1.id), str(p2.id)

    # 1. Create Job with p1 assigned
    create_res = client.post(
        "/api/ui/jobs",
        json={
            "name": "Segregated Network Job",
            "source_remote_id": r1_id,
            "source_path": "/",
            "destination_remote_id": r2_id,
            "destination_path": "/",
            "operation": "copy",
            "assigned_proxy_ids": [p1_id],
        },
    )
    assert create_res.status_code == 201
    job_id = create_res.get_json()["job_id"]

    # 2. Get details & verify p1 is in assigned_proxy_ids and assigned_proxies
    get_res = client.get(f"/api/ui/jobs/{job_id}")
    assert get_res.status_code == 200
    job_data = get_res.get_json()["job"]
    assert job_data["assigned_proxy_ids"] == [p1_id]
    assert len(job_data["assigned_proxies"]) == 1
    assert job_data["assigned_proxies"][0]["name"] == "proxy-dmz-1"

    # 3. List jobs & verify assigned proxies
    list_res = client.get("/api/ui/jobs")
    assert list_res.status_code == 200
    job_in_list = next(j for j in list_res.get_json()["jobs"] if j["id"] == job_id)
    assert job_in_list["assigned_proxy_ids"] == [p1_id]

    # 4. Update job to assign both p1 and p2
    put_res = client.put(
        f"/api/ui/jobs/{job_id}",
        json={"assigned_proxy_ids": [p1_id, p2_id]},
    )
    assert put_res.status_code == 200

    get_res2 = client.get(f"/api/ui/jobs/{job_id}")
    job_data2 = get_res2.get_json()["job"]
    assert set(job_data2["assigned_proxy_ids"]) == {p1_id, p2_id}

    # 5. Clear assigned proxies
    put_res3 = client.put(
        f"/api/ui/jobs/{job_id}",
        json={"assigned_proxy_ids": []},
    )
    assert put_res3.status_code == 200

    get_res3 = client.get(f"/api/ui/jobs/{job_id}")
    assert get_res3.get_json()["job"]["assigned_proxy_ids"] == []

    # 6. Verify error on invalid proxy id
    put_err = client.put(
        f"/api/ui/jobs/{job_id}",
        json={"assigned_proxy_ids": [str(uuid.uuid4())]},
    )
    assert put_err.status_code == 400


def test_job_notification_policy_crud(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    client, session_factory = app_and_db

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "notif-src", "local", {"path": "/tmp/s"})
        r2 = RemoteRepository.create_remote(session, "notif-dst", "local", {"path": "/tmp/d"})
        session.commit()
        r1_id, r2_id = str(r1.id), str(r2.id)

    # 1. Create with notification_policy = 'always'
    res = client.post(
        "/api/ui/jobs",
        json={
            "name": "job-notif-policy-test",
            "source_remote_id": r1_id,
            "source_path": "/data",
            "destination_remote_id": r2_id,
            "destination_path": "/backup",
            "operation": "copy",
            "notification_policy": "always",
        },
    )
    assert res.status_code == 201
    job_id = res.get_json()["job_id"]

    # 2. Get and verify policy
    get_res = client.get(f"/api/ui/jobs/{job_id}")
    assert get_res.status_code == 200
    assert get_res.get_json()["job"]["notification_policy"] == "always"

    # 3. Update to 'only_errors'
    put_res = client.put(
        f"/api/ui/jobs/{job_id}",
        json={"notification_policy": "only_errors"},
    )
    assert put_res.status_code == 200

    get_res2 = client.get(f"/api/ui/jobs/{job_id}")
    assert get_res2.get_json()["job"]["notification_policy"] == "only_errors"

    # 4. Update to empty (inherit default)
    put_res2 = client.put(
        f"/api/ui/jobs/{job_id}",
        json={"notification_policy": ""},
    )
    assert put_res2.status_code == 200

    get_res3 = client.get(f"/api/ui/jobs/{job_id}")
    assert get_res3.get_json()["job"]["notification_policy"] is None

    # 5. Invalid policy rejection
    put_err = client.put(
        f"/api/ui/jobs/{job_id}",
        json={"notification_policy": "invalid_policy"},
    )
    assert put_err.status_code == 400


def test_job_timezone_and_follow_dst_ui_and_api(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    client, session_factory = app_and_db

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "tz-ui-src", "local", {"path": "/tmp/tzs"})
        r2 = RemoteRepository.create_remote(session, "tz-ui-dst", "local", {"path": "/tmp/tzd"})
        session.commit()
        r1_id, r2_id = str(r1.id), str(r2.id)

    # 1. /jobs/new uses browser timezone cookie as default and follow_dst checked by default
    client.set_cookie("embervault_tz", "Europe/Rome")
    new_ui_res = client.get("/jobs/new")
    assert new_ui_res.status_code == 200
    html = new_ui_res.data.decode("utf-8")
    assert 'id="schedule-timezone"' in html
    assert '<option value="Europe/Rome" selected>Europe/Rome</option>' in html
    assert 'id="schedule-follow-dst"' in html
    assert "follow_dst" in html

    # 2. POST /api/ui/jobs without explicit timezone uses browser cookie timezone & follow_dst=True
    create_res = client.post(
        "/api/ui/jobs",
        json={
            "name": "Rome Nightly Job",
            "source_remote_id": r1_id,
            "source_path": "/data",
            "destination_remote_id": r2_id,
            "destination_path": "/backup",
            "operation": "copy",
            "schedule_cron": "0 1 * * *",
        },
    )
    assert create_res.status_code == 201
    job_id = create_res.get_json()["job_id"]

    get_res = client.get(f"/api/ui/jobs/{job_id}")
    assert get_res.status_code == 200
    job_json = get_res.get_json()["job"]
    assert job_json["timezone"] == "Europe/Rome"
    assert job_json["follow_dst"] is True

    list_res = client.get("/api/ui/jobs")
    assert list_res.status_code == 200
    listed_job = next(j for j in list_res.get_json()["jobs"] if j["id"] == job_id)
    assert listed_job["timezone"] == "Europe/Rome"
    assert listed_job["follow_dst"] is True

    # 3. PUT /api/ui/jobs/<id> updates timezone and follow_dst
    put_res = client.put(
        f"/api/ui/jobs/{job_id}",
        json={"timezone": "America/New_York", "follow_dst": False},
    )
    assert put_res.status_code == 200

    get_res2 = client.get(f"/api/ui/jobs/{job_id}")
    assert get_res2.status_code == 200
    job_json2 = get_res2.get_json()["job"]
    assert job_json2["timezone"] == "America/New_York"
    assert job_json2["follow_dst"] is False

    # 4. Edit UI renders saved timezone and unchecked follow_dst
    edit_res = client.get(f"/jobs/{job_id}/edit")
    assert edit_res.status_code == 200
    edit_html = edit_res.data.decode("utf-8")
    assert '<option value="America/New_York" selected>America/New_York</option>' in edit_html
    assert 'id="schedule-follow-dst"' in edit_html

    # 5. Invalid timezone is rejected with 400
    bad_res = client.post(
        "/api/ui/jobs",
        json={
            "name": "Invalid TZ Job",
            "source_remote_id": r1_id,
            "source_path": "/data",
            "destination_remote_id": r2_id,
            "destination_path": "/backup",
            "timezone": "Invalid/Zone",
        },
    )
    assert bad_res.status_code == 400


def test_job_run_policies_crud_and_validation(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    """Verify creating, updating, rendering, and validating all 4 Run Policies and notify flags."""
    client, session_factory = app_and_db

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "pol-src", "local", {"path": "/tmp/ps"})
        r2 = RemoteRepository.create_remote(session, "pol-dst", "local", {"path": "/tmp/pd"})
        session.commit()
        r1_id, r2_id = str(r1.id), str(r2.id)

    # 1. Create job with explicit run policies and selective independent notify toggles
    create_res = client.post(
        "/api/ui/jobs",
        json={
            "name": "Policy Configured Job",
            "source_remote_id": r1_id,
            "source_path": "/data",
            "destination_remote_id": r2_id,
            "destination_path": "/backup",
            "operation": "copy",
            "missed_run_policy": "fail",
            "overlap_policy": "cancel_previous",
            "pending_policy": "retry",
            "max_runtime_enabled": True,
            "max_runtime_minutes": 90,
            "missed_run_notify": False,
            "overlap_notify": True,
            "pending_notify": False,
            "max_runtime_notify": True,
        },
    )
    assert create_res.status_code == 201, create_res.get_json()
    job_id = create_res.get_json()["job_id"]

    # 2. Verify GET /api/ui/jobs/<id> returns all policy fields and independent notify flags
    get_res = client.get(f"/api/ui/jobs/{job_id}")
    assert get_res.status_code == 200
    job_data = get_res.get_json()["job"]
    assert job_data["missed_run_policy"] == "fail"
    assert job_data["overlap_policy"] == "cancel_previous"
    assert job_data["pending_policy"] == "retry"
    assert job_data["max_runtime_minutes"] == 90
    assert job_data["missed_run_notify"] is False
    assert job_data["overlap_notify"] is True
    assert job_data["pending_notify"] is False
    assert job_data["max_runtime_notify"] is True

    # 3. Verify edit screen pre-populates hours=1, minutes=30 and exact notify checked states
    edit_res = client.get(f"/jobs/{job_id}/edit?lang=it")
    assert edit_res.status_code == 200
    edit_html = edit_res.data.decode("utf-8")
    assert 'id="job-max-runtime-hours"' in edit_html
    assert 'value="1"' in edit_html
    assert 'value="30"' in edit_html

    # 4a. Update job using split max_runtime_hours / max_runtime_mins fields -> 135m
    put_split = client.put(
        f"/api/ui/jobs/{job_id}",
        json={
            "max_runtime_enabled": True,
            "max_runtime_hours": 2,
            "max_runtime_mins": 15,
        },
    )
    assert put_split.status_code == 200, put_split.get_json()
    assert client.get(f"/api/ui/jobs/{job_id}").get_json()["job"]["max_runtime_minutes"] == 135

    # 4b. Update job: clear max runtime, switch overlap='allow', enable pending_notify=True
    put_res = client.put(
        f"/api/ui/jobs/{job_id}",
        json={
            "overlap_policy": "allow",
            "max_runtime_enabled": False,
            "pending_notify": True,
            "overlap_notify": False,
        },
    )
    assert put_res.status_code == 200, put_res.get_json()

    get_res2 = client.get(f"/api/ui/jobs/{job_id}")
    job_data2 = get_res2.get_json()["job"]
    assert job_data2["overlap_policy"] == "allow"
    assert job_data2["max_runtime_minutes"] is None
    assert job_data2["pending_notify"] is True
    assert job_data2["overlap_notify"] is False
    assert job_data2["missed_run_notify"] is False
    assert job_data2["max_runtime_notify"] is True

    # 5. Max runtime enabled with 0 total minutes or 0h 0m must fail validation with HTTP 400
    bad_rt_res = client.post(
        "/api/ui/jobs",
        json={
            "name": "Zero Runtime Job",
            "source_remote_id": r1_id,
            "source_path": "/data",
            "destination_remote_id": r2_id,
            "destination_path": "/backup",
            "max_runtime_enabled": True,
            "max_runtime_hours": 0,
            "max_runtime_mins": 0,
        },
    )
    assert bad_rt_res.status_code == 400

    bad_rt_min_res = client.post(
        "/api/ui/jobs",
        json={
            "name": "Zero Minutes Runtime Job",
            "source_remote_id": r1_id,
            "source_path": "/data",
            "destination_remote_id": r2_id,
            "destination_path": "/backup",
            "max_runtime_enabled": True,
            "max_runtime_minutes": 0,
        },
    )
    assert bad_rt_min_res.status_code == 400

    # 6. Invalid policy choice must fail validation with HTTP 400
    bad_pol_res = client.post(
        "/api/ui/jobs",
        json={
            "name": "Bad Policy Job",
            "source_remote_id": r1_id,
            "source_path": "/data",
            "destination_remote_id": r2_id,
            "destination_path": "/backup",
            "pending_policy": "explode",
        },
    )
    assert bad_pol_res.status_code == 400


def test_job_default_run_policies_crud_and_ui(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    """Verify that jobs can be created and updated with default (None) policies,

    and that the UI renders the default option reflecting the general settings.
    """
    client, session_factory = app_and_db
    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "src-policy", "local", {"path": "/data1"})
        r2 = RemoteRepository.create_remote(session, "dst-policy", "local", {"path": "/data2"})
        session.commit()
        r1_id, r2_id = str(r1.id), str(r2.id)

    # 1. Update general settings with custom defaults
    put_settings = client.put(
        "/api/ui/settings/general",
        json={
            "default_missed_run_policy": "fail",
            "default_overlap_policy": "cancel_previous",
            "default_pending_policy": "retry",
        },
    )
    assert put_settings.status_code == 200
    settings_data = put_settings.get_json()["settings"]
    assert settings_data["default_missed_run_policy"] == "fail"
    assert settings_data["default_overlap_policy"] == "cancel_previous"
    assert settings_data["default_pending_policy"] == "retry"

    # 2. Create job with "default" policy values
    res = client.post(
        "/api/ui/jobs",
        json={
            "name": "Default Policies Job",
            "source_remote_id": r1_id,
            "source_path": "/data",
            "destination_remote_id": r2_id,
            "destination_path": "/backup",
            "operation": "copy",
            "missed_run_policy": "default",
            "overlap_policy": "default",
            "pending_policy": "default",
        },
    )
    assert res.status_code == 201, res.get_json()
    job_id = res.get_json()["job_id"]

    # 3. Verify job retrieval returns None for un-overridden policies
    get_res = client.get(f"/api/ui/jobs/{job_id}")
    assert get_res.status_code == 200
    job = get_res.get_json()["job"]
    assert job["missed_run_policy"] is None
    assert job["overlap_policy"] is None
    assert job["pending_policy"] is None

    # 4. Verify UI edit page renders with the default options indicating general settings defaults
    ui_edit_res = client.get(f"/jobs/{job_id}/edit")
    assert ui_edit_res.status_code == 200
    html = ui_edit_res.get_data(as_text=True)
    # The default option should be present and selected
    assert 'id="job-missed-run-policy"' in html
    assert 'id="job-overlap-policy"' in html
    assert 'id="job-pending-policy"' in html
    assert "Predefinito" in html or "Default" in html

    import re
    pending_select_match = re.search(r'<select[^>]*id="job-pending-policy"[^>]*>(.*?)</select>', html, re.DOTALL)
    assert pending_select_match is not None
    pending_options = re.findall(r'<option\b', pending_select_match.group(1))
    assert len(pending_options) == 3

    # 5. Update job to explicit values
    update_res = client.put(
        f"/api/ui/jobs/{job_id}",
        json={
            "missed_run_policy": "run_once",
            "overlap_policy": "allow",
            "pending_policy": "fail",
        },
    )
    assert update_res.status_code == 200
    get_after_update = client.get(f"/api/ui/jobs/{job_id}")
    assert get_after_update.status_code == 200
    job_updated = get_after_update.get_json()["job"]
    assert job_updated["missed_run_policy"] == "run_once"
    assert job_updated["overlap_policy"] == "allow"
    assert job_updated["pending_policy"] == "fail"

    # 6. Revert back to default via empty string / default
    revert_res = client.put(
        f"/api/ui/jobs/{job_id}",
        json={
            "missed_run_policy": "",
            "overlap_policy": "",
            "pending_policy": "",
        },
    )
    assert revert_res.status_code == 200
    get_after_revert = client.get(f"/api/ui/jobs/{job_id}")
    assert get_after_revert.status_code == 200
    job_reverted = get_after_revert.get_json()["job"]
    assert job_reverted["missed_run_policy"] is None
    assert job_reverted["overlap_policy"] is None
    assert job_reverted["pending_policy"] is None

