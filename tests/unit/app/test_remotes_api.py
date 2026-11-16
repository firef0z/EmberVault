"""Unit tests for RClone Remotes REST API and UI views (Milestone M1.2)."""

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


class FakeOrchestratorForRemotes(OrchestratorClient):
    """Stub Orchestrator client for remote testing."""

    def __init__(self) -> None:
        self.last_call: dict[str, Any] = {}

    def test_remote(
        self,
        backend_type: str,
        config: dict[str, Any],
        path: str = "",
        referenced_remotes: dict[str, dict[str, Any]] | list[dict[str, Any]] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, Any]:
        self.last_call = {
            "backend_type": backend_type,
            "config": config,
            "path": path,
            "referenced_remotes": referenced_remotes,
        }
        if backend_type == "invalid_dummy":
            return {"status": "error", "message": "Backend non valido"}
        return {
            "status": "ok",
            "message": f"Connessione verificata per {backend_type}",
            "latency_ms": 12.5,
            "items_found": 3,
        }

    def browse_remote(
        self,
        backend_type: str,
        config: dict[str, Any],
        path: str = "",
        referenced_remotes: dict[str, dict[str, Any]] | list[dict[str, Any]] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, Any]:
        self.last_call = {
            "backend_type": backend_type,
            "config": config,
            "path": path,
            "referenced_remotes": referenced_remotes,
        }
        return {
            "status": "ok",
            "path": path,
            "directories": ["subfolder_a", "subfolder_b"],
            "files": [{"name": "file1.txt", "size": 100}],
        }

    def download_remote(
        self,
        backend_type: str,
        config: dict[str, Any],
        base_path: str = "",
        items: list[dict[str, Any]] | None = None,
        referenced_remotes: dict[str, dict[str, Any]] | list[dict[str, Any]] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        import io
        import requests

        resp = requests.Response()
        resp.status_code = 200
        is_single_file = len(items or []) == 1 and (items or [])[0].get("type") == "file"
        if is_single_file:
            fname = (items or [])[0].get("name", "file1.txt")
            resp.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
            resp.headers["Content-Type"] = "application/octet-stream"
            resp.raw = io.BytesIO(b"single file binary content")
        else:
            resp.headers["Content-Disposition"] = 'attachment; filename="archive.zip"'
            resp.headers["Content-Type"] = "application/zip"
            resp.raw = io.BytesIO(b"fake zip archive content")
        return resp


@pytest.fixture
def app_and_db() -> tuple[FlaskClient, sessionmaker[Session]]:
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    with session_factory() as session:
        seed_initial_data(session)

    settings = AppSettings(app_port=8080, dev_noauth=True)
    fake_orch = FakeOrchestratorForRemotes()
    app = create_app(
        settings=settings,
        session_factory=session_factory,
        orchestrator_client=fake_orch,
    )
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app.test_client(), session_factory


def test_remotes_catalog_endpoint(app_and_db: tuple[FlaskClient, sessionmaker[Session]]) -> None:
    client, _ = app_and_db
    res = client.get("/api/ui/remotes/catalog")
    assert res.status_code == 200
    data = res.json
    assert data is not None
    assert data["status"] == "ok"
    backends = {b["backend_type"] for b in data["backends"]}
    assert {"s3", "b2", "sftp", "webdav", "smb", "local", "drive"}.issubset(backends)


def test_remote_crud_lifecycle(app_and_db: tuple[FlaskClient, sessionmaker[Session]]) -> None:
    client, session_factory = app_and_db

    # 1. Create S3 Remote
    create_res = client.post(
        "/api/ui/remotes",
        json={
            "name": "backup-aws-s3",
            "backend_type": "s3",
            "config": {
                "provider": "AWS",
                "region": "eu-central-1",
                "access_key_id": "AKIA1111222233334444",
                "secret_access_key": "SECRETKEY1234567890ABCDEF",
                "acl": "private",
            },
            "is_enabled": True,
        },
    )
    assert create_res.status_code == 201
    create_data = create_res.json
    assert create_data is not None
    remote_id = create_data["remote_id"]
    assert remote_id is not None

    # Verify secret is encrypted in database
    with session_factory() as session:
        r = RemoteRepository.get_remote_by_id(session, uuid.UUID(remote_id))
        assert r is not None
        assert b"SECRETKEY1234567890ABCDEF" not in r.config_encrypted
        decrypted = RemoteRepository.get_decrypted_config(r)
        assert decrypted["secret_access_key"] == "SECRETKEY1234567890ABCDEF"

    # 2. List remotes -> secret is masked as '***'
    list_res = client.get("/api/ui/remotes")
    assert list_res.status_code == 200
    list_data = list_res.json
    assert list_data is not None
    items = list_data["remotes"]
    assert len(items) == 1
    assert items[0]["name"] == "backup-aws-s3"
    assert "secret_access_key" not in items[0]["public_params"]
    assert "secret_access_key" in items[0]["secret_field_names"]

    # 3. Get remote details -> masked config has '***'
    get_res = client.get(f"/api/ui/remotes/{remote_id}")
    assert get_res.status_code == 200
    detail_data = get_res.json
    assert detail_data is not None
    assert detail_data["remote"]["config"]["secret_access_key"] == "***"
    assert detail_data["remote"]["config"]["access_key_id"] == "***"
    assert detail_data["remote"]["config"]["region"] == "eu-central-1"

    # 4. Update remote preserving masked secret
    update_res = client.put(
        f"/api/ui/remotes/{remote_id}",
        json={
            "name": "backup-aws-s3-renamed",
            "config": {
                "provider": "AWS",
                "region": "eu-west-1",
                "access_key_id": "***",  # Keep existing
                "secret_access_key": "***",  # Keep existing
                "acl": "private",
            },
        },
    )
    assert update_res.status_code == 200
    update_data = update_res.json
    assert update_data is not None
    assert update_data["name"] == "backup-aws-s3-renamed"
    assert update_data["version"] == 2

    # Verify existing secrets were preserved
    with session_factory() as session:
        r = RemoteRepository.get_remote_by_id(session, uuid.UUID(remote_id))
        assert r is not None
        decrypted = RemoteRepository.get_decrypted_config(r)
        assert decrypted["secret_access_key"] == "SECRETKEY1234567890ABCDEF"
        assert decrypted["region"] == "eu-west-1"

    # 5. Test Remote Connection
    test_res = client.post(
        "/api/ui/remotes/test",
        json={"remote_id": remote_id},
    )
    assert test_res.status_code == 200
    test_data = test_res.json
    assert test_data is not None
    assert test_data["status"] == "ok"
    assert "latency_ms" in test_data

    # 6. Delete remote
    del_res = client.delete(f"/api/ui/remotes/{remote_id}")
    assert del_res.status_code == 200
    del_data = del_res.json
    assert del_data is not None
    assert del_data["status"] == "deleted"

    # Verify remote is gone
    with session_factory() as session:
        assert RemoteRepository.get_remote_by_id(session, uuid.UUID(remote_id)) is None


def test_remotes_ui_views(app_and_db: tuple[FlaskClient, sessionmaker[Session]]) -> None:
    client, session_factory = app_and_db

    # Create one remote for list view
    with session_factory() as session:
        RemoteRepository.create_remote(
            session=session,
            name="test-sftp",
            backend_type="sftp",
            raw_config={"host": "sftp.test", "user": "test", "pass": "secret"},
        )
        session.commit()
        r = RemoteRepository.get_remote_by_name(session, "test-sftp")
        assert r is not None
        remote_id = r.id

    # 1. Remotes list page
    res_list = client.get("/remotes")
    assert res_list.status_code == 200
    assert "test-sftp" in res_list.data.decode("utf-8")
    assert "Nuovo Remote" in res_list.data.decode("utf-8") or "New Remote" in res_list.data.decode(
        "utf-8"
    )

    # 2. New remote page
    res_new = client.get("/remotes/new")
    assert res_new.status_code == 200
    res_new_text = res_new.data.decode("utf-8")
    assert (
        "Configura Nuovo Remote" in res_new_text
        or "Nuovo Remote" in res_new_text
        or "New Remote" in res_new_text
        or "New RClone Remote" in res_new_text
        or "Configure New Remote" in res_new_text
    )

    # 3. Edit remote page
    res_edit = client.get(f"/remotes/{remote_id}/edit")
    assert res_edit.status_code == 200
    assert "Modifica Remote" in res_edit.data.decode(
        "utf-8"
    ) or "Edit Remote" in res_edit.data.decode("utf-8")
    assert "test-sftp" in res_edit.data.decode("utf-8")


def test_alias_remote_resolves_referenced_smb(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    """Verify that an Alias remote pointing to an SMB remote resolves the SMB configuration."""
    client, session_factory = app_and_db

    # 1. Create SMB remote
    with session_factory() as session:
        smb_remote = RemoteRepository.create_remote(
            session=session,
            name="my_smb",
            backend_type="smb",
            raw_config={
                "host": "192.168.1.100",
                "user": "backupuser",
                "pass": "smb_secret_pass",
                "domain": "WORKGROUP",
            },
        )
        session.commit()
        assert smb_remote is not None

        # Verify extract_referenced_remote_names
        refs = RemoteRepository.extract_referenced_remote_names(
            "alias", {"remote": "my_smb:shared/folder"}
        )
        assert refs == ["my_smb"]

        # Verify resolve_referenced_remotes
        resolved = RemoteRepository.resolve_referenced_remotes(
            session=session,
            backend_type="alias",
            config={"remote": "my_smb:shared/folder"},
        )
        assert "my_smb" in resolved
        assert resolved["my_smb"]["backend_type"] == "smb"
        assert resolved["my_smb"]["config"]["host"] == "192.168.1.100"
        assert resolved["my_smb"]["config"]["pass"] == "smb_secret_pass"

    # 2. Test connection endpoint for new alias pointing to my_smb:shared
    test_res = client.post(
        "/api/ui/remotes/test",
        json={
            "backend_type": "alias",
            "config": {"remote": "my_smb:shared"},
            "path": "",
        },
    )
    assert test_res.status_code == 200
    test_data = test_res.json
    assert test_data is not None
    assert test_data["status"] == "ok"


def test_remote_browse_endpoint(app_and_db: tuple[FlaskClient, sessionmaker[Session]]) -> None:
    """Test /api/ui/remotes/browse endpoint for browsing directories and files."""
    client, session_factory = app_and_db

    # 1. Browse on non-persisted configuration (during creation)
    browse_res = client.post(
        "/api/ui/remotes/browse",
        json={
            "backend_type": "s3",
            "config": {
                "provider": "AWS",
                "access_key_id": "test_access_key",
                "secret_access_key": "test_secret_key",
                "region": "us-east-1",
            },
            "path": "photos",
        },
    )
    assert browse_res.status_code == 200
    browse_data = browse_res.json
    assert browse_data is not None
    assert browse_data["status"] == "ok"
    assert "subfolder_a" in browse_data["directories"]
    assert len(browse_data["files"]) > 0

    # 2. Browse with missing backend_type
    err_res = client.post("/api/ui/remotes/browse", json={"backend_type": "", "config": {}})
    assert err_res.status_code == 400

    # 3. Browse on existing remote
    with session_factory() as session:
        created = RemoteRepository.create_remote(
            session=session,
            name="existing-s3-browse",
            backend_type="s3",
            raw_config={
                "provider": "AWS",
                "region": "eu-central-1",
                "access_key_id": "s3key",
                "secret_access_key": "s3sec",
            },
            is_enabled=True,
        )
        session.commit()
        remote_id = created.id

    browse_exist_res = client.post(
        "/api/ui/remotes/browse",
        json={
            "remote_id": str(remote_id),
            "path": "deep/path",
        },
    )
    assert browse_exist_res.status_code == 200
    exist_data = browse_exist_res.json
    assert exist_data is not None
    assert exist_data["status"] == "ok"
    assert exist_data["path"] == "deep/path"


def test_remote_download_endpoints(app_and_db: tuple[FlaskClient, sessionmaker[Session]]) -> None:
    """Test /api/ui/remotes/download for single file and multi-file/zip archive."""
    client, session_factory = app_and_db

    # Create test remote
    with session_factory() as session:
        created = RemoteRepository.create_remote(
            session=session,
            name="download-vault",
            backend_type="s3",
            raw_config={
                "provider": "AWS",
                "region": "eu-west-1",
                "access_key_id": "test_s3_key",
                "secret_access_key": "test_s3_sec",
            },
            is_enabled=True,
        )
        session.commit()
        remote_id = str(created.id)

    # 1. Single file download
    res_single = client.post(
        "/api/ui/remotes/download",
        json={
            "remote_id": remote_id,
            "base_path": "documents",
            "items": [{"name": "notes.txt", "type": "file"}],
        },
    )
    assert res_single.status_code == 200
    assert res_single.headers.get("Content-Type") == "application/octet-stream"
    assert 'attachment; filename="notes.txt"' in res_single.headers.get("Content-Disposition", "")
    assert res_single.data == b"single file binary content"

    # 2. Multi-file / folder download (ZIP archive)
    res_zip = client.post(
        "/api/ui/remotes/download",
        json={
            "remote_id": remote_id,
            "base_path": "documents",
            "items": [
                {"name": "subfolder", "type": "directory"},
                {"name": "readme.md", "type": "file"},
            ],
        },
    )
    assert res_zip.status_code == 200
    assert res_zip.headers.get("Content-Type") == "application/zip"
    assert "attachment; filename=" in res_zip.headers.get("Content-Disposition", "")
    assert res_zip.data == b"fake zip archive content"

    # 3. Form-data submission (browser hidden form submit)
    res_form = client.post(
        "/api/ui/remotes/download",
        data={
            "remote_id": remote_id,
            "base_path": "photos",
            "items": '[{"name": "photo.jpg", "type": "file"}]',
        },
    )
    assert res_form.status_code == 200
    assert 'attachment; filename="photo.jpg"' in res_form.headers.get("Content-Disposition", "")

    # 4. Error: empty items
    res_empty = client.post(
        "/api/ui/remotes/download",
        json={
            "remote_id": remote_id,
            "base_path": "",
            "items": [],
        },
    )
    assert res_empty.status_code == 400

    # 5. Error: invalid remote ID
    res_invalid = client.post(
        "/api/ui/remotes/download",
        json={
            "remote_id": "not-a-uuid",
            "items": [{"name": "file.txt", "type": "file"}],
        },
    )
    assert res_invalid.status_code == 400


def test_remotes_page_browse_search_bar(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    """Verify that the remotes view renders the browse search bar and wildcard scripts."""
    client, _ = app_and_db
    res = client.get("/remotes")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert 'id="browse-search-input"' in html
    assert 'id="btn-browse-clear-search"' in html
    assert "matchesWildcard" in html
    assert "Cerca nel percorso corrente" in html or "Search in current path" in html
    assert "noSearchResults" in html


def test_remotes_page_browse_size_and_mod_time_columns(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    """Verify that remotes navigation window includes Dimensione and Ultima Modifica columns with formatters."""
    client, _ = app_and_db
    res = client.get("/remotes")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "browse_col_name" in html or "colName" in html
    assert "browse_col_size" in html or "colSize" in html
    assert "browse_col_mod_time" in html or "colModTime" in html
    assert "formatBytes" in html
    assert "formatDate" in html
    assert "browse-table-check-all" in html


def test_remote_role_visibility_e2e() -> None:
    """Verify that remote visibility is enforced based on user roles across listing, browsing, and jobs."""
    from embervault_db.models.auth import Role
    from embervault_db.repositories.job_repository import JobRepository
    from embervault_db.repositories.user_repository import UserRepository
    from sqlalchemy import select

    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    with session_factory() as session:
        seed_initial_data(session)

    settings = AppSettings(app_port=8080, dev_noauth=False)
    fake_orch = FakeOrchestratorForRemotes()
    app = create_app(
        settings=settings,
        session_factory=session_factory,
        orchestrator_client=fake_orch,
    )
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    client = app.test_client()

    # 1. Login initial admin & set password
    client.post("/login", data={"username": "admin", "password": "admin"})
    client.post(
        "/change-password",
        data={
            "current_password": "admin",
            "new_password": "Password123456!",
            "confirm_password": "Password123456!",
        },
    )

    with session_factory() as session:
        roles = list(session.scalars(select(Role)).all())
        role_map = {r.name.lower(): r for r in roles}
        op_role = role_map["operator"]
        view_role = role_map["viewer"]

        # Create Operator user
        u_op = UserRepository.create_user(
            session=session,
            username="operator1",
            email="operator1@example.com",
            password="OperatorPassword123!",
            role_id=op_role.id,
        )
        u_op.must_change_password = False

        # Create Viewer user
        u_view = UserRepository.create_user(
            session=session,
            username="viewer1",
            email="viewer1@example.com",
            password="ViewerPassword123!",
            role_id=view_role.id,
        )
        u_view.must_change_password = False

        session.commit()

        # Admin creates Remote A (only Operator can see)
        remote_a = RemoteRepository.create_remote(
            session=session,
            name="remote-a-operator-only",
            backend_type="local",
            raw_config={},
            allowed_role_ids=[op_role.id],
        )
        # Admin creates Remote B (both Operator and Viewer can see)
        remote_b = RemoteRepository.create_remote(
            session=session,
            name="remote-b-shared",
            backend_type="local",
            raw_config={},
            allowed_role_ids=[op_role.id, view_role.id],
        )

        # Admin creates Job using Remote A as source and Remote B as destination
        job = JobRepository.create_job(
            session=session,
            name="job-using-remote-a",
            source_remote_id=remote_a.id,
            source_path="/data",
            destination_remote_id=remote_b.id,
            destination_path="/backup",
        )
        session.commit()
        remote_a_id = remote_a.id
        remote_b_id = remote_b.id
        job_id = job.id

    # 2. Login as Viewer
    client.get("/logout")
    client.post("/login", data={"username": "viewer1", "password": "ViewerPassword123!"})

    # Viewer lists remotes: sees Remote B, does NOT see Remote A
    res_list = client.get("/api/ui/remotes")
    assert res_list.status_code == 200
    remotes_data = res_list.get_json()["remotes"]
    remote_ids = [r["id"] for r in remotes_data]
    assert str(remote_b_id) in remote_ids
    assert str(remote_a_id) not in remote_ids

    # Viewer tries to get details of Remote A -> 403
    res_detail = client.get(f"/api/ui/remotes/{remote_a_id}")
    assert res_detail.status_code == 403

    # Viewer tries to browse Remote A -> 403
    res_browse = client.post("/api/ui/remotes/browse", json={"remote_id": str(remote_a_id)})
    assert res_browse.status_code == 403

    # Viewer tries to create a job using Remote A -> 403
    res_create_job = client.post(
        "/api/ui/jobs",
        json={
            "name": "viewer-illegal-job",
            "source_remote_id": str(remote_a_id),
            "source_path": "/",
            "destination_remote_id": str(remote_b_id),
            "destination_path": "/",
        },
    )
    assert res_create_job.status_code == 403

    # 3. Login as Operator
    client.get("/logout")
    client.post("/login", data={"username": "operator1", "password": "OperatorPassword123!"})

    # Operator sees BOTH remotes
    res_op_list = client.get("/api/ui/remotes")
    assert res_op_list.status_code == 200
    op_remote_ids = [r["id"] for r in res_op_list.get_json()["remotes"]]
    assert str(remote_a_id) in op_remote_ids
    assert str(remote_b_id) in op_remote_ids

    # Operator edits job: changing remote to Remote B succeeds
    res_update_job = client.put(
        f"/api/ui/jobs/{job_id}",
        json={
            "source_remote_id": str(remote_b_id),
        },
    )
    assert res_update_job.status_code == 200
    assert res_update_job.get_json()["status"] == "updated"
