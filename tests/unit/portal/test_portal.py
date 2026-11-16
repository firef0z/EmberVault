"""Unit tests for EmberVault Portal service."""

from __future__ import annotations

import io
from typing import Any
import pytest
from flask.testing import FlaskClient
import requests

from embervault_portal.factory import create_app
from embervault_portal.orchestrator_client import OrchestratorPortalClient


class FakeOrchestratorPortalClient(OrchestratorPortalClient):
    """Mock Orchestrator client for Portal unit tests."""

    def __init__(self) -> None:
        super().__init__(base_url="http://fake-orchestrator:8081")

    def validate_share(self, token: str, username: str, password: str) -> dict[str, Any]:
        if token == "valid_token" and username == "guest_user" and password == "secret123":
            return {
                "status_code": 200,
                "data": {
                    "status": "ok",
                    "token": token,
                    "remote_name": "TestRemote",
                    "base_path": "folderb",
                    "expires_at": "2026-11-10T12:00:00Z",
                    # Crucial constraint: NO note field here!
                },
            }
        return {
            "status_code": 401,
            "data": {"status": "error", "message": "Credenziali non valide."},
        }

    def browse_share(self, token: str, subpath: str = "") -> dict[str, Any]:
        if token != "valid_token":
            return {"status_code": 404, "data": {"status": "error", "message": "Token non valido."}}
        return {
            "status_code": 200,
            "data": {
                "status": "ok",
                "path": subpath,
                "directories": [{"name": "folder1"}, {"name": "folder2"}],
                "files": [{"name": "fileA.txt", "size": 1024, "mod_time": "2026-11-01T10:00:00Z"}],
            },
        }

    def download_share(
        self,
        token: str,
        subpath: str = "",
        items: list[dict[str, Any]] | None = None,
    ) -> requests.Response:
        resp = requests.Response()
        resp.status_code = 200
        is_single_file = len(items or []) == 1 and (items or [])[0].get("type") == "file"
        if is_single_file:
            fname = (items or [])[0].get("name", "fileA.txt")
            resp.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
            resp.headers["Content-Type"] = "application/octet-stream"
            resp.raw = io.BytesIO(b"file A test streaming content")
        else:
            resp.headers["Content-Disposition"] = 'attachment; filename="archive.zip"'
            resp.headers["Content-Type"] = "application/zip"
            resp.raw = io.BytesIO(b"fake zip archive streaming content")
        return resp

    def get_portal_branding(self) -> dict[str, Any]:
        return getattr(
            self,
            "_portal_branding",
            {
                "status": "ok",
                "app_name": "EmberVault public portal",
                "custom_app_name": "",
                "has_custom_logo": False,
                "logo_data": None,
            },
        )


@pytest.fixture
def portal_client() -> FlaskClient:
    app = create_app({"TESTING": True, "SECRET_KEY": "test-portal-key"})
    app.extensions["orchestrator_client"] = FakeOrchestratorPortalClient()
    return app.test_client()


def test_portal_healthz(portal_client: FlaskClient) -> None:
    res = portal_client.get("/healthz")
    assert res.status_code == 200
    assert res.json == {"status": "ok", "service": "portal"}


def test_portal_unauthenticated_flow(portal_client: FlaskClient) -> None:
    # 1. Visiting /share/<token> without auth returns login page
    res = portal_client.get("/share/valid_token")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Shared Area" in html or "Area Condivisa" in html
    assert "Username" in html
    assert "Password" in html

    # 2. Browse without auth returns 401
    browse_res = portal_client.get("/share/valid_token/browse")
    assert browse_res.status_code == 401

    # 3. Download without auth returns 401
    down_res = portal_client.post(
        "/share/valid_token/download", json={"items": [{"name": "fileA.txt", "type": "file"}]}
    )
    assert down_res.status_code == 401


def test_portal_login_and_browse_flow(portal_client: FlaskClient) -> None:
    # 1. Invalid login
    bad_login = portal_client.post(
        "/share/valid_token/login",
        json={"username": "wrong", "password": "bad"},
    )
    assert bad_login.status_code == 401
    assert (
        "Invalid credentials" in bad_login.json["message"]
        or "Credenziali non valide" in bad_login.json["message"]
    )

    # 2. Valid login
    login_res = portal_client.post(
        "/share/valid_token/login",
        json={"username": "guest_user", "password": "secret123"},
    )
    assert login_res.status_code == 200
    assert login_res.json["status"] == "ok"

    # 3. Visit share view while authenticated -> browse page
    view_res = portal_client.get("/share/valid_token")
    assert view_res.status_code == 200
    html = view_res.data.decode("utf-8")
    assert "Explore Shared Files" in html or "Esplora File Condivisi" in html
    assert "guest_user" in html
    assert "Download" in html or "Scarica" in html

    # CRITICAL: Confirm note is NEVER exposed to the end user in HTML
    assert "Nota riservata" not in html

    # 4. Browse API
    browse_res = portal_client.get("/share/valid_token/browse?subpath=")
    assert browse_res.status_code == 200
    bdata = browse_res.json
    assert bdata["status"] == "ok"
    dirs = [d["name"] for d in bdata["directories"]]
    assert "folder1" in dirs
    assert "folder2" in dirs
    assert len(bdata["files"]) == 1
    assert bdata["files"][0]["name"] == "fileA.txt"
    assert bdata["files"][0]["size"] == 1024
    assert bdata["files"][0]["mod_time"] == "2026-11-01T10:00:00Z"

    # 5. Download single file (streaming)
    down_single = portal_client.post(
        "/share/valid_token/download",
        json={"items": [{"name": "fileA.txt", "type": "file"}]},
    )
    assert down_single.status_code == 200
    assert "fileA.txt" in down_single.headers.get("Content-Disposition", "")
    assert b"file A test streaming content" in down_single.data

    # 6. Download multiple items / folder as zip
    down_zip = portal_client.post(
        "/share/valid_token/download",
        json={
            "items": [
                {"name": "folder1", "type": "directory"},
                {"name": "fileA.txt", "type": "file"},
            ]
        },
    )
    assert down_zip.status_code == 200
    assert "archive.zip" in down_zip.headers.get("Content-Disposition", "")
    assert b"fake zip archive streaming content" in down_zip.data

    # 7. Logout
    logout_res = portal_client.post("/share/valid_token/logout")
    assert logout_res.status_code == 302

    # Verify session cleared
    after_logout = portal_client.get("/share/valid_token")
    assert "Shared Area" in after_logout.data.decode(
        "utf-8"
    ) or "Area Condivisa" in after_logout.data.decode("utf-8")


def test_portal_logo_route_and_branding(portal_client: FlaskClient) -> None:
    # 1. Default logo serves SVG
    res_default = portal_client.get("/share-logo")
    assert res_default.status_code == 200
    assert "svg" in res_default.headers.get("Content-Type", "")
    assert b"<svg" in res_default.data

    # 2. Mock custom logo response in orchestrator
    mock_orch = portal_client.application.extensions["orchestrator_client"]
    svg_data = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="30" height="30"><rect fill="green"/></svg>'
    )
    import base64

    b64_svg = base64.b64encode(svg_data.encode("utf-8")).decode("ascii")
    data_uri = f"data:image/svg+xml;base64,{b64_svg}"

    mock_orch._portal_branding = {
        "status": "ok",
        "app_name": "Custom Company Share",
        "custom_app_name": "Custom Company Share",
        "has_custom_logo": True,
        "logo_data": data_uri,
    }

    # Custom logo served
    res_custom = portal_client.get("/share-logo")
    assert res_custom.status_code == 200
    assert "svg" in res_custom.headers.get("Content-Type", "")
    assert res_custom.data.decode("utf-8") == svg_data

    # Share login page displays custom name
    login_page = portal_client.get("/share/valid_token")
    assert login_page.status_code == 200
    assert "Custom Company Share" in login_page.data.decode("utf-8")


def test_portal_disabled_returns_403(portal_client: FlaskClient) -> None:
    mock_orch = portal_client.application.extensions["orchestrator_client"]
    mock_orch._portal_branding = {
        "status": "ok",
        "enabled": False,
        "app_name": "EmberVault public portal",
        "custom_app_name": "",
        "has_custom_logo": False,
        "logo_data": None,
    }

    # HTML request to /share returns 403
    res_share = portal_client.get("/share")
    assert res_share.status_code == 403
    assert (
        "unavailable" in res_share.data.decode("utf-8").lower()
        or "non disponibile" in res_share.data.decode("utf-8").lower()
    )

    # Accessing specific share returns 403
    res_token = portal_client.get("/share/valid_token")
    assert res_token.status_code == 403
    assert (
        "unavailable" in res_token.data.decode("utf-8").lower()
        or "non disponibile" in res_token.data.decode("utf-8").lower()
    )

    # API login returns 403 JSON
    res_login = portal_client.post(
        "/share/valid_token/login", json={"username": "a", "password": "b"}
    )
    assert res_login.status_code == 403
    assert (
        "disabled" in res_login.get_json()["message"].lower()
        or "disattivato" in res_login.get_json()["message"].lower()
    )


def test_portal_language_rendering(portal_client: FlaskClient) -> None:
    mock_orch = portal_client.application.extensions["orchestrator_client"]

    # 1. Italian (default)
    mock_orch._portal_branding = {
        "status": "ok",
        "enabled": True,
        "language": "it",
        "app_name": "EmberVault public portal",
        "custom_app_name": "",
        "has_custom_logo": False,
        "logo_data": None,
    }
    res_it = portal_client.get("/share/valid_token")
    assert res_it.status_code == 200
    it_html = res_it.data.decode("utf-8")
    assert 'lang="it"' in it_html
    assert "Area Condivisa" in it_html
    assert "Accedi ai file" in it_html

    # Check root layout landing message in Italian
    res_layout_it = portal_client.get("/")
    assert res_layout_it.status_code == 200
    assert (
        "Accesso consentito esclusivamente tramite un link pubblico valido con token."
        in res_layout_it.data.decode("utf-8")
    )

    # 2. English
    mock_orch._portal_branding["language"] = "en"
    res_en = portal_client.get("/share/valid_token")
    assert res_en.status_code == 200
    en_html = res_en.data.decode("utf-8")
    assert 'lang="en"' in en_html
    assert "Shared Area" in en_html
    assert "Access Files" in en_html

    # Check root layout landing message in English
    res_layout_en = portal_client.get("/")
    assert res_layout_en.status_code == 200
    assert (
        "Access is allowed only via a valid public link with token."
        in res_layout_en.data.decode("utf-8")
    )

    # Login and check browse page in English
    login_res = portal_client.post(
        "/share/valid_token/login",
        json={"username": "guest_user", "password": "secret123"},
    )
    assert login_res.status_code == 200

    res_browse_en = portal_client.get("/share/valid_token")
    assert res_browse_en.status_code == 200
    browse_en_html = res_browse_en.data.decode("utf-8")
    assert "Explore Shared Files" in browse_en_html
    assert "Download" in browse_en_html
    assert "Logout" in browse_en_html

    # 3. German
    portal_client.post("/share/valid_token/logout")
    mock_orch._portal_branding["language"] = "de"
    res_de = portal_client.get("/share/valid_token")
    assert res_de.status_code == 200
    de_html = res_de.data.decode("utf-8")
    assert 'lang="de"' in de_html
    assert "Geteilter Bereich" in de_html
    assert "Auf Dateien zugreifen" in de_html

    # Check root layout landing message in German
    res_layout_de = portal_client.get("/")
    assert res_layout_de.status_code == 200
    assert (
        "Der Zugriff ist nur über einen gültigen öffentlichen Link mit Token gestattet."
        in res_layout_de.data.decode("utf-8")
    )

    # Check unauthenticated browse message in German
    browse_unauth_de = portal_client.get("/share/valid_token/browse")
    assert browse_unauth_de.status_code == 401
    assert "Nicht authentifizierte Sitzung." in browse_unauth_de.get_json()["message"]

    # 4. English disabled page
    mock_orch._portal_branding["enabled"] = False
    mock_orch._portal_branding["language"] = "en"
    res_dis_en = portal_client.get("/share")
    assert res_dis_en.status_code == 403
    dis_en_html = res_dis_en.data.decode("utf-8")
    assert "Portal Unavailable" in dis_en_html
    assert "temporarily disabled" in dis_en_html


def test_portal_browse_search_bar(portal_client: FlaskClient) -> None:
    # Login and visit browse page
    portal_client.post(
        "/share/valid_token/login",
        json={"username": "guest_user", "password": "secret123"},
    )
    res = portal_client.get("/share/valid_token")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert 'id="portal-search-input"' in html
    assert 'id="btn-portal-clear-search"' in html
    assert 'id="portal-items-count"' in html
    assert "matchesWildcard" in html
    assert "Search in current path" in html or "Cerca nel percorso corrente" in html


def test_orchestrator_client_network_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that OrchestratorPortalClient returns clean 503 errors on connection timeouts."""
    client = OrchestratorPortalClient(
        base_url="http://192.168.0.211:8081", timeout_seconds=5, connect_timeout=1.0
    )

    def mock_post_timeout(*args: Any, **kwargs: Any) -> Any:
        raise requests.exceptions.ConnectTimeout(
            "Connection to 192.168.0.211 timed out. (connect timeout=1.0)"
        )

    def mock_get_timeout(*args: Any, **kwargs: Any) -> Any:
        raise requests.exceptions.ConnectTimeout("Connection to 192.168.0.211 timed out.")

    monkeypatch.setattr(requests, "post", mock_post_timeout)
    monkeypatch.setattr(requests, "get", mock_get_timeout)

    val_res = client.validate_share("token123", "user", "pass")
    assert val_res["status_code"] == 503
    assert "orchestrator" not in val_res["data"]["message"].lower()
    assert "192.168.0.211" not in val_res["data"]["message"]

    browse_res = client.browse_share("token123", "")
    assert browse_res["status_code"] == 503
    assert "orchestrator" not in browse_res["data"]["message"].lower()
    assert "192.168.0.211" not in browse_res["data"]["message"]

    branding = client.get_portal_branding()
    assert branding["status"] == "ok"
    assert "app_name" in branding


def test_portal_service_unavailable_login_and_browse() -> None:
    """Test that Portal routes return generic user-friendly messages without mentioning Orchestrator."""
    app = create_app({"TESTING": True, "SECRET_KEY": "test-key"})

    class FailingClient(FakeOrchestratorPortalClient):
        def validate_share(self, token: str, username: str, password: str) -> dict[str, Any]:
            return {"status_code": 503, "data": {"status": "error"}}

        def browse_share(self, token: str, subpath: str = "") -> dict[str, Any]:
            return {"status_code": 503, "data": {"status": "error"}}

        def download_share(
            self, token: str, subpath: str = "", items: list[dict[str, Any]] | None = None
        ) -> Any:
            raise requests.exceptions.ConnectTimeout("Connection to 192.168.0.211 timed out.")

    app.extensions["orchestrator_client"] = FailingClient()
    client = app.test_client()

    # Form login POST returns 503 with generic error message in HTML
    res_form = client.post(
        "/share/any_token/login",
        data={"username": "test_user", "password": "password"},
    )
    assert res_form.status_code == 503
    html = res_form.data.decode("utf-8")
    assert (
        "Service temporarily unavailable" in html
        or "Servizio momentaneamente non disponibile" in html
    )
    assert "orchestrator" not in html.lower()
    assert "192.168" not in html

    # JSON login POST returns 503 with generic message
    res_json = client.post(
        "/share/any_token/login",
        json={"username": "test_user", "password": "password"},
    )
    assert res_json.status_code == 503
    json_data = res_json.get_json()
    assert (
        "Service temporarily unavailable" in json_data["message"]
        or "Servizio momentaneamente non disponibile" in json_data["message"]
    )
    assert "orchestrator" not in json_data["message"].lower()

    # Authenticate in session to test browse and download
    with client.session_transaction() as sess:
        sess["auth_tok1"] = {"token": "tok1", "username": "test_user"}

    # Browse returns 503 with generic message
    res_browse = client.get("/share/tok1/browse")
    assert res_browse.status_code == 503
    browse_json = res_browse.get_json()
    assert (
        "Service temporarily unavailable" in browse_json["message"]
        or "Servizio momentaneamente non disponibile" in browse_json["message"]
    )
    assert "orchestrator" not in browse_json["message"].lower()

    # Download returns 503 with generic message (no traceback or raw URL leaked)
    res_dl = client.post(
        "/share/tok1/download",
        json={"items": [{"type": "file", "name": "test.txt"}]},
    )
    assert res_dl.status_code == 503
    dl_json = res_dl.get_json()
    assert (
        "Service temporarily unavailable" in dl_json["message"]
        or "Servizio momentaneamente non disponibile" in dl_json["message"]
    )
    assert "orchestrator" not in dl_json["message"].lower()
    assert "192.168" not in dl_json["message"]
