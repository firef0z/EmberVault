"""Unit tests for Job Edit Remote Browsing interactive UI and i18n support."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from embervault_app.factory import create_app
from embervault_common.config import AppSettings
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models.base import Base
from embervault_db.models.remotes import Job, RcloneRemote
from embervault_db.repositories.remote_repository import RemoteRepository


class FakeOrchestratorClient:
    """Mock Orchestrator client providing simulated remote browsing responses."""

    def browse_remote(
        self,
        backend_type: str,
        config: dict[str, Any],
        path: str = "",
        referenced_remotes: dict[str, dict[str, Any]] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, Any]:
        del backend_type, config, referenced_remotes
        if not path or path == "/":
            return {
                "status": "ok",
                "path": "",
                "directories": ["documents", "photos", "backups"],
                "files": [{"name": "notes.txt", "size": 128}],
            }
        elif path == "photos":
            return {
                "status": "ok",
                "path": "photos",
                "directories": ["2025", "2026"],
                "files": [{"name": "cover.jpg", "size": 20480}],
            }
        return {
            "status": "ok",
            "path": path,
            "directories": [],
            "files": [],
        }


@pytest.fixture
def test_setup():
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    fake_orch = FakeOrchestratorClient()
    settings = AppSettings(app_port=8080, dev_noauth=True)
    app = create_app(
        settings=settings,
        session_factory=session_factory,
        orchestrator_client=fake_orch,
    )
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    return app.test_client(), session_factory


def test_job_new_renders_browse_buttons_disabled(test_setup) -> None:
    """Verify that on new job creation without remotes selected, Browse buttons are rendered disabled."""
    client, _ = test_setup
    res = client.get("/jobs/new")
    assert res.status_code == 200
    html = res.data.decode("utf-8")

    # Both Browse buttons must exist
    assert 'id="btn-browse-source"' in html
    assert 'id="btn-browse-destination"' in html

    # On new job without pre-selected remotes, both must be disabled initially
    assert 'id="btn-browse-source"' in html
    assert 'id="btn-browse-destination"' in html
    # Modal and interactive elements must exist in the page
    assert 'id="modal-browse-remote"' in html
    assert 'id="browse-current-path-label"' in html
    assert 'id="btn-confirm-browse-path"' in html
    assert 'id="btn-browse-parent"' in html
    assert 'id="browse-list-container"' in html


def test_job_edit_renders_browse_buttons_enabled_when_remotes_set(test_setup) -> None:
    """Verify that on job edit with remotes configured, Browse buttons are enabled."""
    client, session_factory = test_setup

    with session_factory() as session:
        r1_id = uuid.uuid4()
        r2_id = uuid.uuid4()
        r1 = RcloneRemote(
            id=r1_id,
            name="local-source",
            backend_type="local",
            config_encrypted=RemoteRepository.encrypt_config({"path": "/tmp/source"}, r1_id),
            is_enabled=True,
        )
        r2 = RcloneRemote(
            id=r2_id,
            name="local-dest",
            backend_type="local",
            config_encrypted=RemoteRepository.encrypt_config({"path": "/tmp/dest"}, r2_id),
            is_enabled=True,
        )
        session.add_all([r1, r2])

        job_id = uuid.uuid4()
        job = Job(
            id=job_id,
            name="Backup Photos",
            source_remote_id=r1_id,
            source_path="/photos",
            destination_remote_id=r2_id,
            destination_path="/backup/photos",
            operation="copy",
            parallelization="none",
            max_parallel_tasks=4,
            enabled=True,
        )
        session.add(job)
        session.commit()

    res = client.get(f"/jobs/{job_id}/edit")
    assert res.status_code == 200
    html = res.data.decode("utf-8")

    # In edit mode with remotes selected, buttons should NOT have disabled attribute
    # Check source button section
    source_btn_start = html.find('id="btn-browse-source"')
    assert source_btn_start != -1
    source_btn_tag = html[source_btn_start : html.find(">", source_btn_start)]
    assert "disabled" not in source_btn_tag

    # Check destination button section
    dest_btn_start = html.find('id="btn-browse-destination"')
    assert dest_btn_start != -1
    dest_btn_tag = html[dest_btn_start : html.find(">", dest_btn_start)]
    assert "disabled" not in dest_btn_tag


def test_browse_remote_api_endpoint_with_remote_id(test_setup) -> None:
    """Verify /api/ui/remotes/browse endpoint returns directories and files for job configuration."""
    client, session_factory = test_setup

    with session_factory() as session:
        r_id = uuid.uuid4()
        remote = RcloneRemote(
            id=r_id,
            name="source-vault",
            backend_type="s3",
            config_encrypted=RemoteRepository.encrypt_config({"bucket": "photos-vault"}, r_id),
            is_enabled=True,
        )
        session.add(remote)
        session.commit()

    # Browse root
    res_root = client.post(
        "/api/ui/remotes/browse",
        json={"remote_id": str(r_id), "path": ""},
    )
    assert res_root.status_code == 200
    data_root = res_root.json
    assert data_root["status"] == "ok"
    assert "photos" in data_root["directories"]
    assert "documents" in data_root["directories"]
    assert len(data_root["files"]) > 0

    # Browse subfolder
    res_sub = client.post(
        "/api/ui/remotes/browse",
        json={"remote_id": str(r_id), "path": "photos"},
    )
    assert res_sub.status_code == 200
    data_sub = res_sub.json
    assert data_sub["status"] == "ok"
    assert "2026" in data_sub["directories"]
    assert any(f["name"] == "cover.jpg" for f in data_sub["files"])
