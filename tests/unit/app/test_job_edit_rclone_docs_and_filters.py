"""Unit tests for RClone documentation links and second-level filter disabling in Job Edit."""

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


@pytest.fixture
def test_setup():
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    settings = AppSettings(app_port=8080, dev_noauth=True)
    app = create_app(
        settings=settings,
        session_factory=session_factory,
    )
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    return app.test_client(), session_factory


def test_job_edit_rclone_documentation_links(test_setup) -> None:
    """Verify that RClone advanced parameters link to the official documentation."""
    client, session_factory = test_setup

    with session_factory() as session:
        r1_id = uuid.uuid4()
        r2_id = uuid.uuid4()
        r1 = RcloneRemote(
            id=r1_id,
            name="src",
            backend_type="local",
            config_encrypted=RemoteRepository.encrypt_config({"path": "/tmp/s"}, r1_id),
            is_enabled=True,
        )
        r2 = RcloneRemote(
            id=r2_id,
            name="dst",
            backend_type="local",
            config_encrypted=RemoteRepository.encrypt_config({"path": "/tmp/d"}, r2_id),
            is_enabled=True,
        )
        session.add_all([r1, r2])

        job_id = uuid.uuid4()
        job = Job(
            id=job_id,
            name="Test Job",
            source_remote_id=r1_id,
            source_path="/",
            destination_remote_id=r2_id,
            destination_path="/backup",
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

    # Official RClone docs links must be present for advanced parameters
    assert "https://rclone.org/docs/#checkers-int" in html
    assert "https://rclone.org/docs/#transfers-int" in html
    assert "https://rclone.org/docs/#order-by-string" in html
    assert "https://rclone.org/docs/#check-first" in html
    assert "https://rclone.org/docs/#max-depth-int" in html
    assert "https://rclone.org/filtering/" in html

    # Verify target="_blank" and rel="noopener noreferrer"
    assert 'target="_blank"' in html
    assert 'rel="noopener noreferrer"' in html

    # Verify updated parameter titles
    assert "Thread di confronto file" in html or "File comparison threads" in html
    assert "Thread di trasferimento file" in html or "File transfer threads" in html
    assert "Ordine di trasferimento" in html or "Transfer order" in html
    assert "Confronto a blocchi" in html or "Batch comparison" in html
    assert "Ricorsione delle cartelle" in html or "Folder recursion" in html

    # Verify "Documentazione" is removed from RClone links
    assert "RClone: --checkers" in html
    assert "RClone: --transfers" in html
    assert "RClone: --order-by" in html
    assert "RClone: --check-first" in html
    assert "RClone: --max-depth" in html
    assert "RClone: Filtering" in html
    assert "Documentazione RClone" not in html


def test_job_edit_second_level_filters_disabled_when_parallelization_none(test_setup) -> None:
    """Verify that if parallelization is 'none', the second-level filters textarea is disabled."""
    client, session_factory = test_setup

    with session_factory() as session:
        r1_id = uuid.uuid4()
        r2_id = uuid.uuid4()
        r1 = RcloneRemote(
            id=r1_id,
            name="src",
            backend_type="local",
            config_encrypted=RemoteRepository.encrypt_config({"path": "/tmp/s"}, r1_id),
            is_enabled=True,
        )
        r2 = RcloneRemote(
            id=r2_id,
            name="dst",
            backend_type="local",
            config_encrypted=RemoteRepository.encrypt_config({"path": "/tmp/d"}, r2_id),
            is_enabled=True,
        )
        session.add_all([r1, r2])

        job_id = uuid.uuid4()
        job = Job(
            id=job_id,
            name="Single Non-Parallel Job",
            source_remote_id=r1_id,
            source_path="/",
            destination_remote_id=r2_id,
            destination_path="/backup",
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

    # Check that job-second-level-filters has disabled attribute
    idx = html.find('id="job-second-level-filters"')
    assert idx != -1
    tag = html[idx : html.find(">", idx)]
    assert "disabled" in tag


def test_job_edit_second_level_filters_enabled_when_parallelization_by_subfolder(
    test_setup,
) -> None:
    """Verify that if parallelization is 'by_subfolder', the second-level filters textarea is enabled."""
    client, session_factory = test_setup

    with session_factory() as session:
        r1_id = uuid.uuid4()
        r2_id = uuid.uuid4()
        r1 = RcloneRemote(
            id=r1_id,
            name="src",
            backend_type="local",
            config_encrypted=RemoteRepository.encrypt_config({"path": "/tmp/s"}, r1_id),
            is_enabled=True,
        )
        r2 = RcloneRemote(
            id=r2_id,
            name="dst",
            backend_type="local",
            config_encrypted=RemoteRepository.encrypt_config({"path": "/tmp/d"}, r2_id),
            is_enabled=True,
        )
        session.add_all([r1, r2])

        job_id = uuid.uuid4()
        job = Job(
            id=job_id,
            name="Parallel Subfolder Job",
            source_remote_id=r1_id,
            source_path="/",
            destination_remote_id=r2_id,
            destination_path="/backup",
            operation="copy",
            parallelization="by_subfolder",
            max_parallel_tasks=4,
            enabled=True,
        )
        session.add(job)
        session.commit()

    res = client.get(f"/jobs/{job_id}/edit")
    assert res.status_code == 200
    html = res.data.decode("utf-8")

    # Check that job-second-level-filters does NOT have disabled attribute
    idx = html.find('id="job-second-level-filters"')
    assert idx != -1
    tag = html[idx : html.find(">", idx)]
    assert "disabled" not in tag


def test_job_new_second_level_filters_disabled_by_default(test_setup) -> None:
    """Verify that when creating a new job, second-level filters textarea is disabled by default."""
    client, _ = test_setup
    res = client.get("/jobs/new")
    assert res.status_code == 200
    html = res.data.decode("utf-8")

    idx = html.find('id="job-second-level-filters"')
    assert idx != -1
    tag = html[idx : html.find(">", idx)]
    assert "disabled" in tag


def test_job_edit_additional_parameters_html_and_docs_links(test_setup) -> None:
    """Verify that 'Altri parametri' textbox, add button, list, and doc links are present."""
    client, _ = test_setup
    res = client.get("/jobs/new")
    assert res.status_code == 200
    html = res.data.decode("utf-8")

    # Textbox, button, and container
    assert 'id="input-additional-param"' in html
    assert 'id="btn-add-additional-param"' in html
    assert 'id="additional-params-list"' in html

    # Documentation links for RClone Sync and Copy
    assert "https://rclone.org/commands/rclone_sync/" in html
    assert "https://rclone.org/commands/rclone_copy/" in html
    assert "RClone Sync" in html
    assert "RClone Copy" in html


def test_job_edit_prepopulated_additional_parameters(test_setup) -> None:
    """Verify that existing additional parameters are loaded into JS state in edit view."""
    client, session_factory = test_setup

    with session_factory() as session:
        r1_id = uuid.uuid4()
        r2_id = uuid.uuid4()
        r1 = RcloneRemote(
            id=r1_id,
            name="src",
            backend_type="local",
            config_encrypted=RemoteRepository.encrypt_config({"path": "/tmp/s"}, r1_id),
            is_enabled=True,
        )
        r2 = RcloneRemote(
            id=r2_id,
            name="dst",
            backend_type="local",
            config_encrypted=RemoteRepository.encrypt_config({"path": "/tmp/d"}, r2_id),
            is_enabled=True,
        )
        session.add_all([r1, r2])

        job_id = uuid.uuid4()
        job = Job(
            id=job_id,
            name="Job with extra args",
            source_remote_id=r1_id,
            source_path="/",
            destination_remote_id=r2_id,
            destination_path="/backup",
            operation="copy",
            parallelization="none",
            max_parallel_tasks=4,
            enabled=True,
            rclone_options={"additional_args": ["--fast-list", "--min-size 10M", "-u"]},
        )
        session.add(job)
        session.commit()

    res = client.get(f"/jobs/{job_id}/edit")
    assert res.status_code == 200
    html = res.data.decode("utf-8")

    # In the rendered JS block, additionalParamsList should receive the serialized array
    assert '["--fast-list", "--min-size 10M", "-u"]' in html


def test_job_api_create_and_update_with_additional_args(test_setup) -> None:
    """Verify that creating and updating a job via API sanitizes and persists additional_args."""
    client, session_factory = test_setup

    with session_factory() as session:
        r1_id = uuid.uuid4()
        r2_id = uuid.uuid4()
        r1 = RcloneRemote(
            id=r1_id,
            name="src",
            backend_type="local",
            config_encrypted=RemoteRepository.encrypt_config({"path": "/tmp/s"}, r1_id),
            is_enabled=True,
        )
        r2 = RcloneRemote(
            id=r2_id,
            name="dst",
            backend_type="local",
            config_encrypted=RemoteRepository.encrypt_config({"path": "/tmp/d"}, r2_id),
            is_enabled=True,
        )
        session.add_all([r1, r2])
        session.commit()

    # 1. Create Job with valid and invalid/forbidden additional args
    payload = {
        "name": "API Job with Extra Params",
        "enabled": True,
        "source_remote_id": str(r1_id),
        "source_path": "/src",
        "destination_remote_id": str(r2_id),
        "destination_path": "/dst",
        "operation": "sync",
        "parallelization": "none",
        "rclone_options": {
            "checkers": 16,
            "additional_args": [
                "--fast-list",
                "invalid_flag_no_dash",
                "--min-size 10M",
                "--rc",  # forbidden
                "--fast-list",  # duplicate
            ],
        },
    }

    create_resp = client.post("/api/ui/jobs", json=payload)
    assert create_resp.status_code in (200, 201)
    job_data = create_resp.get_json()
    created_id = job_data.get("job_id") or job_data.get("id") or job_data.get("job", {}).get("id")

    # Verify in DB that additional_args was sanitized
    with session_factory() as session:
        saved_job = session.query(Job).filter(Job.id == uuid.UUID(created_id)).first()
        assert saved_job is not None
        assert saved_job.rclone_options.get("additional_args") == ["--fast-list", "--min-size 10M"]

    # 2. Update Job with new additional_args
    update_payload = dict(payload)
    update_payload["rclone_options"] = {
        "checkers": 8,
        "additional_args": ["-u", "--ignore-existing"],
    }

    put_resp = client.put(f"/api/ui/jobs/{created_id}", json=update_payload)
    assert put_resp.status_code == 200

    with session_factory() as session:
        updated_job = session.query(Job).filter(Job.id == uuid.UUID(created_id)).first()
        assert updated_job is not None
        assert updated_job.rclone_options.get("additional_args") == ["-u", "--ignore-existing"]


def test_job_edit_rclone_titles_and_links_i18n_multilingual(test_setup) -> None:
    """Verify that parameter titles and RClone links are properly translated in English and German."""
    client, _ = test_setup

    # Test English (?lang=en)
    res_en = client.get("/jobs/new?lang=en")
    assert res_en.status_code == 200
    html_en = res_en.data.decode("utf-8")

    assert "File comparison threads" in html_en
    assert "File transfer threads" in html_en
    assert "Transfer order" in html_en
    assert "Batch comparison" in html_en
    assert "Folder recursion" in html_en
    assert "RClone: --checkers" in html_en
    assert "RClone: --transfers" in html_en
    assert "RClone: --order-by" in html_en
    assert "RClone: --check-first" in html_en
    assert "RClone: --max-depth" in html_en
    assert "RClone: Filtering" in html_en
    assert "documentation" not in html_en.lower().split("rclone:")[1].split("</a>")[0]

    # Test German (?lang=de)
    res_de = client.get("/jobs/new?lang=de")
    assert res_de.status_code == 200
    html_de = res_de.data.decode("utf-8")

    assert "Dateivergleichs-Threads" in html_de
    assert "Dateiübertragungs-Threads" in html_de
    assert "Übertragungsreihenfolge" in html_de
    assert "Stapelweiser Vergleich" in html_de
    assert "Ordner-Rekursion" in html_de
    assert "RClone: --checkers" in html_de
    assert "RClone: --transfers" in html_de
    assert "RClone: --order-by" in html_de
    assert "RClone: --check-first" in html_de
    assert "RClone: --max-depth" in html_de
    assert "RClone: Filtering" in html_de
